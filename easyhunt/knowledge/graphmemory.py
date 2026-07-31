"""Graph memory — what the engagement knows, and how it connects.

The problem this solves is specific. A long engagement accumulates thousands of
observations: hosts, technologies, endpoints, credentials, findings. By phase
six, "what do I already know about `api.example.com`?" is a question the agent
cannot answer from its context window, and re-running recon to find out is both
slow and rude to the target.

So observations go into a graph as they are made, and recall is a neighbourhood
query: give me this host, everything one hop away, and the findings attached to
any of it. That is a paragraph of context instead of a re-scan.

This is PentAGI's Graphiti/Neo4j pattern, with one deliberate difference: the
native backend is the default and needs no database. An adjacency-list graph over
a few tens of thousands of nodes is unremarkable in memory, and requiring
operators to stand up Neo4j to get engagement memory would mean most of them
simply do not get engagement memory. Neo4j is available for people who want
cross-engagement persistence and Cypher.

What is stored is deliberately narrow: entities, relationships, and pointers to
findings. Response bodies, credentials, and evidence blobs stay on disk in the
workspace — memory is an index, not a second copy of the loot.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("easyhunt.graphmemory")

__all__ = ["Entity", "GraphMemory", "Relationship", "neo4j_available"]

# Relationship vocabulary. Closed on purpose: an open one becomes a thousand
# near-synonyms and recall stops working.
RELATIONS = {
    "resolves_to",      # host      → ip
    "serves",           # host      → url
    "runs",             # host/url  → technology
    "hosts",            # ip        → host
    "exposes",          # host/url  → endpoint
    "leaks",            # url/file  → secret
    "delegates_to",     # host      → provider (CNAME)
    "belongs_to",       # anything  → organization
    "affected_by",      # asset     → finding
    "discovered_by",    # asset     → tool
    "related_to",       # generic fallback
}


@dataclass
class Entity:
    """A thing the engagement observed."""

    id: str
    kind: str
    name: str = ""
    #: Which phase/tool first saw it — lets recall explain its own provenance.
    source: str = ""
    engagement: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    source: str
    relation: str
    target: str
    confidence: float = 1.0
    observed_by: str = ""
    at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def key(self) -> tuple[str, str, str]:
        return (self.source, self.relation, self.target)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GraphMemory:
    """Entity/relationship store with neighbourhood recall.

    Native by default; mirrors into Neo4j when configured. Neo4j failures are
    logged and swallowed — losing the graph database must not lose the
    engagement, and the native copy remains authoritative.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        neo4j_uri: str | None = None,
        neo4j_user: str = "neo4j",
        neo4j_password: str = "",
        engagement: str = "",
    ) -> None:
        self.path = Path(path) if path else None
        self.engagement = engagement
        self._entities: dict[str, Entity] = {}
        self._out: dict[str, list[Relationship]] = defaultdict(list)
        self._in: dict[str, list[Relationship]] = defaultdict(list)
        self._seen: set[tuple[str, str, str]] = set()
        self._lock = threading.Lock()

        self._driver = None
        if neo4j_uri:
            self._connect_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        if self.path and self.path.exists():
            self.load(self.path)

    def _connect_neo4j(self, uri: str, user: str, password: str) -> None:
        try:
            from neo4j import GraphDatabase  # noqa: PLC0415

            self._driver = GraphDatabase.driver(uri, auth=(user, password))
            self._driver.verify_connectivity()
            log.info("graph memory: mirroring into Neo4j at %s", uri)
        except Exception as exc:  # noqa: BLE001
            # Degrade rather than fail: the native graph is the source of truth.
            log.warning("graph memory: Neo4j unavailable (%s); using the native graph", exc)
            self._driver = None

    # -- writing ------------------------------------------------------------ #

    def observe(self, entity: Entity) -> Entity:
        """Record an entity, merging with anything already known about it."""
        with self._lock:
            existing = self._entities.get(entity.id)
            if existing:
                existing.last_seen = datetime.now(UTC).isoformat()
                existing.attributes.update(entity.attributes)
                if entity.name and not existing.name:
                    existing.name = entity.name
                return existing
            entity.engagement = entity.engagement or self.engagement
            self._entities[entity.id] = entity
        self._mirror_entity(entity)
        return entity

    def relate(
        self,
        source: str,
        relation: str,
        target: str,
        *,
        confidence: float = 1.0,
        observed_by: str = "",
    ) -> Relationship | None:
        """Record a relationship. Unknown relation names are rejected.

        Rejecting rather than coercing keeps the vocabulary closed, which is what
        makes ``recall`` predictable — a caller inventing ``points_at`` alongside
        ``resolves_to`` silently splits the graph in half.
        """
        if relation not in RELATIONS:
            log.warning(
                "graph memory: unknown relation %r (known: %s)", relation, sorted(RELATIONS)
            )
            return None

        edge = Relationship(
            source=source, relation=relation, target=target,
            confidence=confidence, observed_by=observed_by,
        )
        with self._lock:
            if edge.key() in self._seen:
                return edge
            self._seen.add(edge.key())
            # Endpoints must exist so recall never dead-ends on a missing node.
            for node_id in (source, target):
                if node_id not in self._entities:
                    self._entities[node_id] = Entity(
                        id=node_id, kind="unknown", name=node_id, engagement=self.engagement
                    )
            self._out[source].append(edge)
            self._in[target].append(edge)
        self._mirror_relationship(edge)
        return edge

    def observe_asset(self, asset: Any) -> Entity:
        """Ingest an :class:`~easyhunt.knowledge.findings.Asset`."""
        entity = self.observe(
            Entity(
                id=f"{asset.kind}:{asset.value}",
                kind=asset.kind,
                name=asset.value,
                source=asset.source,
                attributes=dict(asset.attributes),
            )
        )
        if asset.host and asset.host != asset.value:
            self.relate(f"host:{asset.host}", "serves", entity.id, observed_by=asset.source)
        return entity

    def observe_finding(self, finding: Any) -> Entity:
        """Ingest a finding and attach it to the asset it concerns."""
        entity = self.observe(
            Entity(
                id=f"finding:{finding.id}",
                kind="finding",
                name=finding.title,
                source=finding.source_tool,
                attributes={
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "rule_id": finding.rule_id,
                },
            )
        )
        asset_id = f"url:{finding.asset}" if finding.asset.startswith("http") else f"host:{finding.asset}"
        self.observe(Entity(id=asset_id, kind="asset", name=finding.asset))
        self.relate(asset_id, "affected_by", entity.id, observed_by=finding.source_tool)
        return entity

    # -- reading ------------------------------------------------------------ #

    def recall(self, subject: str, *, depth: int = 1, limit: int = 60) -> dict[str, Any]:
        """Everything known about a subject and its neighbourhood.

        The answer to "what do I already know about this host" — returned as a
        structure small enough to put in a prompt, instead of a re-scan.
        """
        matches = self._resolve(subject)
        if not matches:
            return {
                "subject": subject,
                "known": False,
                "message": f"nothing recorded about {subject!r}",
            }

        root = matches[0]
        visited: set[str] = {root.id}
        neighbourhood: list[dict[str, Any]] = []
        queue: deque[tuple[str, int]] = deque([(root.id, 0)])

        while queue and len(neighbourhood) < limit:
            node_id, distance = queue.popleft()
            if distance >= depth:
                continue
            for edge in [*self._out.get(node_id, []), *self._in.get(node_id, [])]:
                other_id = edge.target if edge.source == node_id else edge.source
                other = self._entities.get(other_id)
                if other is None or other_id in visited:
                    continue
                visited.add(other_id)
                neighbourhood.append(
                    {
                        "entity": other.to_dict(),
                        "relation": edge.relation,
                        "direction": "out" if edge.source == node_id else "in",
                        "observed_by": edge.observed_by,
                    }
                )
                queue.append((other_id, distance + 1))

        findings = [n for n in neighbourhood if n["entity"]["kind"] == "finding"]
        return {
            "subject": subject,
            "known": True,
            "entity": root.to_dict(),
            "also_matched": [m.id for m in matches[1:5]],
            "neighbourhood": neighbourhood,
            "related_findings": findings,
            "summary": self._summarize(root, neighbourhood),
        }

    def _resolve(self, subject: str) -> list[Entity]:
        """Find entities by exact id, then by name, then by substring."""
        if subject in self._entities:
            return [self._entities[subject]]
        lowered = subject.lower()
        exact = [e for e in self._entities.values() if e.name.lower() == lowered]
        if exact:
            return exact
        return [e for e in self._entities.values() if lowered in e.name.lower()][:10]

    @staticmethod
    def _summarize(root: Entity, neighbourhood: list[dict[str, Any]]) -> str:
        """One sentence a prompt can carry instead of the whole structure."""
        if not neighbourhood:
            return f"{root.kind} {root.name}: no relationships recorded."
        by_relation: dict[str, int] = {}
        for item in neighbourhood:
            by_relation[item["relation"]] = by_relation.get(item["relation"], 0) + 1
        parts = ", ".join(f"{count} {relation}" for relation, count in by_relation.items())
        findings = sum(1 for n in neighbourhood if n["entity"]["kind"] == "finding")
        sentence = f"{root.kind} {root.name}: {parts}."
        if findings:
            sentence += f" {findings} finding(s) attached."
        return sentence

    def neighbours(self, entity_id: str, relation: str | None = None) -> list[Entity]:
        out = []
        for edge in self._out.get(entity_id, []):
            if relation is None or edge.relation == relation:
                target = self._entities.get(edge.target)
                if target:
                    out.append(target)
        return out

    def by_kind(self, kind: str) -> list[Entity]:
        return [e for e in self._entities.values() if e.kind == kind]

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for entity in self._entities.values():
            by_kind[entity.kind] = by_kind.get(entity.kind, 0) + 1
        by_relation: dict[str, int] = {}
        for edges in self._out.values():
            for edge in edges:
                by_relation[edge.relation] = by_relation.get(edge.relation, 0) + 1
        return {
            "entities": len(self._entities),
            "relationships": len(self._seen),
            "by_kind": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
            "by_relation": dict(sorted(by_relation.items(), key=lambda kv: -kv[1])),
            "backend": "neo4j+native" if self._driver else "native",
        }

    # -- persistence -------------------------------------------------------- #

    def save(self, path: Path | None = None) -> Path:
        target = Path(path or self.path or "graph-memory.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "engagement": self.engagement,
                    "saved_at": datetime.now(UTC).isoformat(),
                    "entities": [e.to_dict() for e in self._entities.values()],
                    "relationships": [
                        edge.to_dict() for edges in self._out.values() for edge in edges
                    ],
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return target

    def load(self, path: Path) -> int:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        known_entity = set(Entity.__dataclass_fields__)
        known_edge = set(Relationship.__dataclass_fields__)
        for record in payload.get("entities", []):
            with self._lock:
                entity = Entity(**{k: v for k, v in record.items() if k in known_entity})
                self._entities[entity.id] = entity
        loaded = 0
        for record in payload.get("relationships", []):
            edge = Relationship(**{k: v for k, v in record.items() if k in known_edge})
            with self._lock:
                if edge.key() in self._seen:
                    continue
                self._seen.add(edge.key())
                self._out[edge.source].append(edge)
                self._in[edge.target].append(edge)
            loaded += 1
        return loaded

    # -- Neo4j mirror ------------------------------------------------------- #

    def _mirror_entity(self, entity: Entity) -> None:
        if self._driver is None:
            return
        try:
            with self._driver.session() as session:
                session.run(
                    "MERGE (e:EasyHuntEntity {id: $id}) "
                    "SET e.kind = $kind, e.name = $name, e.source = $source, "
                    "    e.engagement = $engagement, e.last_seen = $last_seen",
                    id=entity.id, kind=entity.kind, name=entity.name,
                    source=entity.source, engagement=entity.engagement,
                    last_seen=entity.last_seen,
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("graph memory: entity mirror failed: %s", exc)

    def _mirror_relationship(self, edge: Relationship) -> None:
        if self._driver is None:
            return
        try:
            with self._driver.session() as session:
                # Relation is interpolated because Cypher cannot parameterize a
                # relationship type — safe because RELATIONS is a closed set of
                # identifiers validated in relate().
                session.run(
                    "MATCH (a:EasyHuntEntity {id: $source}), (b:EasyHuntEntity {id: $target}) "
                    f"MERGE (a)-[r:{edge.relation.upper()}]->(b) "
                    "SET r.confidence = $confidence, r.observed_by = $observed_by",
                    source=edge.source, target=edge.target,
                    confidence=edge.confidence, observed_by=edge.observed_by,
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("graph memory: relationship mirror failed: %s", exc)

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def __len__(self) -> int:
        return len(self._entities)


def neo4j_available() -> bool:
    try:
        import neo4j  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def ingest_engagement(memory: GraphMemory, engagement: Any) -> dict[str, int]:
    """Load an engagement's assets and findings into graph memory."""
    assets = 0
    for asset in engagement.assets.all():
        memory.observe_asset(asset)
        assets += 1
    findings = 0
    for finding in engagement.findings.all():
        memory.observe_finding(finding)
        findings += 1
    return {"assets": assets, "findings": findings}


def relations_from_dns(memory: GraphMemory, records: Iterable[dict[str, Any]]) -> int:
    """Turn dns_resolve output into graph relationships.

    A CNAME with no address record becomes ``delegates_to`` with nothing behind
    it — which is the takeover shape, now queryable rather than only logged.
    """
    count = 0
    for record in records:
        host = str(record.get("host") or "")
        if not host:
            continue
        host_id = f"host:{host}"
        memory.observe(Entity(id=host_id, kind="host", name=host, source="dnsx"))
        for address in list(record.get("a") or []) + list(record.get("aaaa") or []):
            memory.observe(Entity(id=f"ip:{address}", kind="ip", name=str(address), source="dnsx"))
            if memory.relate(host_id, "resolves_to", f"ip:{address}", observed_by="dnsx"):
                count += 1
        for cname in record.get("cname") or []:
            memory.observe(
                Entity(id=f"host:{cname}", kind="host", name=str(cname), source="dnsx")
            )
            if memory.relate(host_id, "delegates_to", f"host:{cname}", observed_by="dnsx"):
                count += 1
    return count

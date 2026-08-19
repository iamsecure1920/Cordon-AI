"""Attack-path graph — turning a list of misconfigurations into reachability.

A cloud posture scan produces a checklist: forty controls failed, sorted by a
severity someone assigned in the abstract. What a program actually needs to know
is different — *which of these can an attacker reach, starting from outside, and
what do they get when they arrive.*

That is a graph question. Nodes are principals, resources, and entry points;
edges are the relationships that let an attacker move (assume a role, read a
bucket, invoke a function). A path from an internet-facing entry point to a
high-value target is a finding with its impact statement already written:

    public Lambda `api-handler`
      → assumes role `lambda-exec`
        → can read `s3://customer-exports`

Three misconfigurations that each looked medium in isolation are one high-severity
chain, and the difference is only visible in the graph.

Two backends, same interface:

* **native** (default, no dependencies) — builds the graph from Prowler findings
  and discovered assets, then does bounded breadth-first search.
* **cartography** — queries an existing Cartography/Neo4j database, which knows
  far more about the account than a scan can infer.

Path *ranking* is deliberately not just length. A two-hop path to a role that can
read customer data outranks a one-hop path to an empty dev bucket, so scoring
weighs what the destination is worth against how exposed the entry point is.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cordon.knowledge.findings import Severity

log = logging.getLogger("cordon.attackgraph")

__all__ = [
    "AttackGraph",
    "AttackPath",
    "Edge",
    "Node",
    "FindingChain",
    "build_from_prowler",
    "find_finding_chains",
]


# --------------------------------------------------------------------------- #
# Finding-level chains (web/API engagements, not cloud)
# --------------------------------------------------------------------------- #

#: Named chains across *findings*: two or more separately-medium findings that
#: become one higher-severity story when they touch the same asset. This is the
#: manual-class evidence the blueprint asks for — IDOR and business logic have
#: no scanner of their own, but a chain (XSS + no CSP, SSRF + cloud metadata,
#: open redirect + OAuth) is the reachability argument that upgrades them from
#: "candidate" toward "worth a human's hour".
#:
#: Each pattern is a predicate over the finding list and a severity-upgrade
#: suggestion applied when the chain matches. Ported in concept from
#: autopentest-ai's ``knowledge_graph`` CHAIN_PATTERNS (MIT, bhavsec); the
#: predicates here are reimplemented against Cordon's Finding model.
CHAIN_PATTERNS: dict[str, dict[str, Any]] = {
    "xss-no-csp": {
        "name": "Reflected XSS on a host with no CSP",
        "description": (
            "A Content-Security-Policy is the mitigation that makes most reflected "
            "XSS unexploitable. An XSS finding on the same host where the policy "
            "is absent or permissive is the difference between a finding a triager "
            "downgrades and one they escalate."
        ),
        "upgrade_to": "high",
        "requires": ("xss", "no-csp"),
    },
    "ssrf-cloud-metadata": {
        "name": "SSRF reaching cloud metadata",
        "description": (
            "An SSRF that can reach 169.254.169.254 or the cloud metadata service "
            "is a pivot to credentials — the single most impactful SSRF chain. "
            "Look for the loopback/metadata address in the SSRF finding's observed "
            "output or the presence of a cloud-hosted asset."
        ),
        "upgrade_to": "critical",
        "requires": ("ssrf", "cloud"),
    },
    "idor-admin": {
        "name": "IDOR toward an admin/privilege endpoint",
        "description": (
            "An object reference on an administrative or privilege-changing route "
            "is access-control impact rather than mere information disclosure — "
            "the chain that separates an IDOR worth reporting from one that is not."
        ),
        "upgrade_to": "high",
        "requires": ("idor", "admin"),
    },
    "open-redirect-oauth": {
        "name": "Open redirect on an OAuth/SSO surface",
        "description": (
            "An open redirect on a login/OAuth endpoint turns into token theft: "
            "the redirect destination carries the authorization code or token. "
            "A redirect finding on an auth-shaped URL is an account-takeover chain, "
            "not a phishing footnote."
        ),
        "upgrade_to": "high",
        "requires": ("redirect", "oauth"),
    },
    "reflected-input-authz": {
        "name": "Reflected input on an authenticated endpoint",
        "description": (
            "Reflected user input on a route that carries authorization data is a "
            "token/cookie-exfiltration primitive; the same reflection on a public "
            "page is self-XSS. The chain is what tells the difference."
        ),
        "upgrade_to": "medium",
        "requires": ("reflected", "auth"),
    },
}

#: Severity rank table for upgrades.
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Marker substrings used by the predicates. A finding matches a marker when any
#: of these appears in its title/tags/rule_id (lowercased).
_XSS_MARKERS = ("xss", "cross-site scripting", "script injection")
_NO_CSP_MARKERS = ("csp", "content-security-policy", "content security policy")
_SSRF_MARKERS = ("ssrf", "server-side request forgery", "server side request forgery")
_CLOUD_MARKERS = ("169.254.169.254", "metadata", "aws", "gcp", "azure", "cloud")
_IDOR_MARKERS = ("idor", "object reference", "access control", "authorization")
_ADMIN_MARKERS = ("admin", "privilege", "role", "impersonat")
_REDIRECT_MARKERS = ("open redirect", "open-redirect", "redirect")
_OAUTH_MARKERS = ("oauth", "sso", "saml", "oidc", "login", "sign-in", "authorize", "token")
_REFLECTED_MARKERS = ("reflected", "reflection")
_AUTH_MARKERS = ("authenticated", "auth", "session", "cookie", "logged-in", "csrf")


def _finding_text(finding: Any) -> str:
    return " ".join(
        str(part).lower()
        for part in (
            finding.title,
            finding.rule_id or "",
            " ".join(finding.tags or []),
            finding.how_found,
        )
    )


def _asset_key(finding: Any) -> str:
    """The host an asset-level chain should bind to.

    A URL asset binds to its hostname; a hostname binds to itself. This is what
    lets an XSS on ``https://app.example.com/x`` chain with a CSP finding on
    ``https://app.example.com`` — same host, same mitigation story.
    """
    from urllib.parse import urlsplit

    asset = str(finding.asset or "")
    if "://" in asset:
        host = urlsplit(asset).hostname
        return (host or asset).lower()
    return asset.lower()


def _matches(finding: Any, markers: tuple[str, ...]) -> bool:
    text = _finding_text(finding)
    return any(marker in text for marker in markers)


@dataclass
class FindingChain:
    """One matched chain: the pattern, the findings, and the upgrade suggested."""

    pattern_id: str
    name: str
    description: str
    findings: list[Any]
    upgrade_to: str
    asset: str

    @property
    def ids(self) -> list[str]:
        return [f.id for f in self.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "upgrade_to": self.upgrade_to,
            "asset": self.asset,
            "finding_ids": self.ids,
            "titles": [f.title for f in self.findings],
        }


def find_finding_chains(findings: Iterable[Any]) -> list[FindingChain]:
    """Find chain patterns across a finding list, per asset.

    Each pattern needs two *different* findings on the same asset matching its
    two required markers. Chains are computed only over reportable findings
    (the caller filters); a chain is evidence for a human, never a status change
    by itself — the report surfaces the upgrade as a suggestion, and a triager
    or the agent decides.
    """
    items = list(findings)
    by_asset: dict[str, list[Any]] = {}
    for finding in items:
        by_asset.setdefault(_asset_key(finding), []).append(finding)

    chains: list[FindingChain] = []
    for pattern_id, pattern in CHAIN_PATTERNS.items():
        first_marker, second_marker = pattern["requires"]
        marker_sets: dict[str, tuple[str, ...]] = {
            "xss": _XSS_MARKERS,
            "no-csp": _NO_CSP_MARKERS,
            "ssrf": _SSRF_MARKERS,
            "cloud": _CLOUD_MARKERS,
            "idor": _IDOR_MARKERS,
            "admin": _ADMIN_MARKERS,
            "redirect": _REDIRECT_MARKERS,
            "oauth": _OAUTH_MARKERS,
            "reflected": _REFLECTED_MARKERS,
            "auth": _AUTH_MARKERS,
        }
        first_markers = marker_sets[first_marker]
        second_markers = marker_sets[second_marker]
        for asset, asset_findings in by_asset.items():
            firsts = [f for f in asset_findings if _matches(f, first_markers)]
            seconds = [f for f in asset_findings if _matches(f, second_markers)]
            # Same finding cannot satisfy both sides (an XSS finding is not a
            # CSP finding).
            seconds = [f for f in seconds if f not in firsts]
            if firsts and seconds:
                chains.append(
                    FindingChain(
                        pattern_id=pattern_id,
                        name=pattern["name"],
                        description=pattern["description"],
                        findings=firsts[:2] + seconds[:2],
                        upgrade_to=pattern["upgrade_to"],
                        asset=asset,
                    )
                )
    return chains

# What a node is worth to an attacker who reaches it. Drives path scoring, so a
# short path to something worthless ranks below a longer path to real data.
TARGET_VALUE: dict[str, int] = {
    "data_store": 90,
    "secret": 95,
    "admin_role": 100,
    "role": 50,
    "compute": 40,
    "function": 40,
    "bucket": 70,
    "database": 90,
    "queue": 30,
    "network": 20,
    "user": 60,
    "unknown": 10,
}

# How exposed an entry point is. An unauthenticated internet-facing endpoint is
# a far better starting position than something needing valid credentials.
ENTRY_EXPOSURE: dict[str, int] = {
    "public_unauthenticated": 100,
    "public_authenticated": 60,
    "partner": 40,
    "internal": 20,
}

# Edges that represent an attacker *moving*, as opposed to describing structure.
TRAVERSABLE = {
    "assumes", "can_assume", "invokes", "reads", "writes", "admin_of",
    "member_of", "attached_to", "can_escalate_to", "routes_to", "trusts",
}


@dataclass
class Node:
    """A principal, resource, or entry point."""

    id: str
    kind: str
    name: str = ""
    #: True when reachable from the internet without credentials.
    entry_point: bool = False
    exposure: str = "internal"
    #: Findings that made this node interesting.
    finding_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def value(self) -> int:
        return TARGET_VALUE.get(self.kind, TARGET_VALUE["unknown"])

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "value": self.value}


@dataclass
class Edge:
    """A relationship an attacker can traverse."""

    source: str
    target: str
    relation: str
    #: Why this edge exists — quoted in the report so the path is checkable.
    reason: str = ""
    finding_id: str | None = None

    @property
    def traversable(self) -> bool:
        return self.relation in TRAVERSABLE

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "traversable": self.traversable}


@dataclass
class AttackPath:
    """One route from an entry point to something worth reaching."""

    nodes: list[Node]
    edges: list[Edge]
    score: float
    severity: Severity

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def entry(self) -> Node:
        return self.nodes[0]

    @property
    def target(self) -> Node:
        return self.nodes[-1]

    def narrative(self) -> str:
        """The path as a sentence a report can use verbatim."""
        parts = [f"{self.entry.kind} `{self.entry.name or self.entry.id}`"]
        for edge, node in zip(self.edges, self.nodes[1:], strict=True):
            parts.append(f"  → {edge.relation.replace('_', ' ')} `{node.name or node.id}`")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hops": self.hops,
            "score": round(self.score, 1),
            "severity": self.severity.value,
            "entry": self.entry.to_dict(),
            "target": self.target.to_dict(),
            "narrative": self.narrative(),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


class AttackGraph:
    """Directed graph of cloud principals and resources, with path search."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = {}

    # -- construction ------------------------------------------------------- #

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing:
            # Merge rather than replace: two sources may each know part of it.
            existing.finding_ids = sorted(set(existing.finding_ids) | set(node.finding_ids))
            existing.attributes.update(node.attributes)
            existing.entry_point = existing.entry_point or node.entry_point
            if node.exposure != "internal":
                existing.exposure = node.exposure
            if node.name and not existing.name:
                existing.name = node.name
            return existing
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        # Both endpoints must exist; an edge to nowhere is a silent dead end.
        for node_id in (edge.source, edge.target):
            if node_id not in self.nodes:
                self.add_node(Node(id=node_id, kind="unknown", name=node_id))
        self.edges.append(edge)
        self._out.setdefault(edge.source, []).append(edge)
        return edge

    # -- search ------------------------------------------------------------- #

    def entry_points(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.entry_point]

    def find_paths(
        self, *, max_hops: int = 5, min_target_value: int = 50, limit: int = 50
    ) -> list[AttackPath]:
        """Breadth-first search from every entry point to anything worth reaching.

        Bounded by ``max_hops`` because an unbounded search over a large account
        produces thousands of paths nobody reads. Five hops is well past the
        point where a chain stops being a plausible narrative.
        """
        paths: list[AttackPath] = []
        seen_targets: set[tuple[str, str]] = set()

        for entry in self.entry_points():
            queue: deque[tuple[list[str], list[Edge]]] = deque([([entry.id], [])])
            while queue:
                node_ids, edges = queue.popleft()
                if len(edges) >= max_hops:
                    continue

                for edge in self._out.get(node_ids[-1], []):
                    if not edge.traversable or edge.target in node_ids:
                        continue  # no cycles, no structural edges
                    target = self.nodes[edge.target]
                    next_ids = [*node_ids, edge.target]
                    next_edges = [*edges, edge]

                    if target.value >= min_target_value:
                        key = (entry.id, target.id)
                        # Keep the shortest route to each target; BFS reaches it first.
                        if key not in seen_targets:
                            seen_targets.add(key)
                            nodes = [self.nodes[i] for i in next_ids]
                            score = self._score(nodes, next_edges)
                            paths.append(
                                AttackPath(
                                    nodes=nodes,
                                    edges=next_edges,
                                    score=score,
                                    severity=self._severity(score),
                                )
                            )
                    queue.append((next_ids, next_edges))

        paths.sort(key=lambda p: -p.score)
        return paths[:limit]

    @staticmethod
    def _score(nodes: list[Node], edges: list[Edge]) -> float:
        """Value of the destination, discounted by how far the attacker must travel.

        A one-hop path to an admin role beats a four-hop path to the same role,
        but a four-hop path to customer data still beats a one-hop path to an
        empty dev bucket — which is the ordering a triager actually wants.
        """
        entry, target = nodes[0], nodes[-1]
        exposure = ENTRY_EXPOSURE.get(entry.exposure, ENTRY_EXPOSURE["internal"])
        distance_penalty = 0.85 ** (len(edges) - 1)
        return target.value * distance_penalty * (exposure / 100)

    @staticmethod
    def _severity(score: float) -> Severity:
        if score >= 70:
            return Severity.CRITICAL
        if score >= 45:
            return Severity.HIGH
        if score >= 25:
            return Severity.MEDIUM
        return Severity.LOW

    # -- serialization ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "entry_points": [n.id for n in self.entry_points()],
        }

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        return path

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for node in self.nodes.values():
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "traversable_edges": sum(1 for e in self.edges if e.traversable),
            "entry_points": len(self.entry_points()),
            "by_kind": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        }

    def __len__(self) -> int:
        return len(self.nodes)


# --------------------------------------------------------------------------- #
# Native backend: build from Prowler findings
# --------------------------------------------------------------------------- #

# Prowler check-id fragments → what they tell us about the graph. Keyed on
# substrings because check ids differ across Prowler versions.
_PUBLIC_MARKERS = (
    "public", "internet", "0.0.0.0/0", "anonymous", "unauthenticated",
    "publicly_accessible", "public_access",
)
_ADMIN_MARKERS = ("administratoraccess", "admin", "*:*", "full_access", "poweruser")
_DATA_MARKERS = ("s3", "bucket", "rds", "dynamodb", "database", "backup", "snapshot")


def _classify(resource_type: str, name: str, check_id: str) -> str:
    """What kind of thing this resource is.

    Deliberately keyed on the resource, not on the failed check. A role that
    fails an AdministratorAccess control is still a *role* — its privilege is an
    edge to what it can reach, not a change to what it is. Collapsing the two
    loses the edge, and an admin privilege with no edge can never appear as the
    destination of a path.
    """
    haystack = f"{resource_type} {name}".lower()
    if "role" in haystack:
        return "role"
    if "lambda" in haystack or "function" in haystack:
        return "function"
    if any(m in haystack for m in _DATA_MARKERS):
        return "data_store"
    if "secret" in haystack or "kms" in haystack or "parameter" in haystack:
        return "secret"
    if "ec2" in haystack or "instance" in haystack or "container" in haystack:
        return "compute"
    if "user" in haystack:
        return "user"
    if "vpc" in haystack or "subnet" in haystack or "security_group" in haystack:
        return "network"
    return "unknown"


def build_from_prowler(records: Iterable[dict[str, Any]]) -> AttackGraph:
    """Infer a graph from Prowler OCSF findings.

    This is inference, not ground truth: Prowler reports control failures, not
    relationships, so edges here are the ones a failed control implies. The
    Cartography backend knows the real topology and should be preferred when it
    is available — which is why paths from this backend are labelled as inferred.
    """
    graph = AttackGraph()

    for record in records:
        finding_info = record.get("finding_info") or {}
        check_id = str(finding_info.get("uid") or record.get("check_id") or "")
        title = str(finding_info.get("title") or record.get("message") or "")
        resources = record.get("resources") or [{}]
        severity = str(record.get("severity") or "").lower()

        for resource in resources:
            uid = str(resource.get("uid") or resource.get("name") or "")
            if not uid:
                continue
            name = str(resource.get("name") or uid)
            resource_type = str(resource.get("type") or "")
            haystack = f"{check_id} {title}".lower()

            is_public = any(marker in haystack for marker in _PUBLIC_MARKERS)
            node = graph.add_node(
                Node(
                    id=uid,
                    kind=_classify(resource_type, name, check_id),
                    name=name,
                    entry_point=is_public,
                    exposure="public_unauthenticated" if is_public else "internal",
                    finding_ids=[check_id] if check_id else [],
                    attributes={"resource_type": resource_type, "severity": severity},
                )
            )

            # A failed privilege control implies the principal can escalate. The
            # privilege becomes an edge to a high-value node, so it can be the
            # destination of a path rather than a property nothing points at.
            if any(marker in haystack for marker in _ADMIN_MARKERS):
                admin = graph.add_node(
                    Node(id=f"{uid}:admin", kind="admin_role", name=f"{name} (admin privileges)")
                )
                graph.add_edge(
                    Edge(
                        source=node.id,
                        target=admin.id,
                        relation="can_escalate_to",
                        reason=f"{check_id}: {title}"[:200],
                        finding_id=check_id,
                    )
                )

    return graph


# --------------------------------------------------------------------------- #
# Cartography backend
# --------------------------------------------------------------------------- #

#: Cartography's schema, queried for the relationships that matter for movement.
CARTOGRAPHY_QUERY = """
MATCH path = (source)-[r*1..%(max_hops)d]->(target)
WHERE (source:AWSRole OR source:AWSUser OR source:EC2Instance OR source:AWSLambda)
  AND (target:AWSRole OR target:S3Bucket OR target:RDSInstance OR target:SecretsManagerSecret)
  AND source <> target
RETURN source, relationships(path) AS rels, nodes(path) AS path_nodes
LIMIT %(limit)d
"""


def cartography_available() -> bool:
    try:
        import neo4j  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def build_from_cartography(
    uri: str, user: str, password: str, *, max_hops: int = 4, limit: int = 500
) -> AttackGraph:
    """Query a Cartography-populated Neo4j database for real topology.

    Preferred over the inferred backend when available: Cartography walks the
    provider APIs and records actual trust relationships, so its paths are
    observed rather than implied.
    """
    from neo4j import GraphDatabase  # noqa: PLC0415

    graph = AttackGraph()
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            result = session.run(CARTOGRAPHY_QUERY % {"max_hops": max_hops, "limit": limit})
            for record in result:
                path_nodes = record.get("path_nodes") or []
                relationships = record.get("rels") or []

                ids: list[str] = []
                for raw in path_nodes:
                    properties = dict(raw)
                    labels = list(getattr(raw, "labels", []) or [])
                    uid = str(properties.get("arn") or properties.get("id") or properties.get("name"))
                    kind = _cartography_kind(labels)
                    exposed = bool(
                        properties.get("publicly_accessible")
                        or properties.get("anonymous_access")
                        or properties.get("exposed_internet")
                    )
                    graph.add_node(
                        Node(
                            id=uid,
                            kind=kind,
                            name=str(properties.get("name") or uid),
                            entry_point=exposed,
                            exposure="public_unauthenticated" if exposed else "internal",
                            attributes={"labels": labels},
                        )
                    )
                    ids.append(uid)

                for index, relationship in enumerate(relationships):
                    if index + 1 >= len(ids):
                        break
                    graph.add_edge(
                        Edge(
                            source=ids[index],
                            target=ids[index + 1],
                            relation=str(getattr(relationship, "type", "routes_to")).lower(),
                            reason="observed by Cartography",
                        )
                    )
    finally:
        driver.close()
    return graph


def _cartography_kind(labels: list[str]) -> str:
    joined = " ".join(labels).lower()
    if "awsrole" in joined:
        return "role"
    if "s3bucket" in joined:
        return "data_store"
    if "rdsinstance" in joined or "dynamodb" in joined:
        return "database"
    if "secret" in joined:
        return "secret"
    if "lambda" in joined:
        return "function"
    if "ec2instance" in joined:
        return "compute"
    if "awsuser" in joined:
        return "user"
    return "unknown"

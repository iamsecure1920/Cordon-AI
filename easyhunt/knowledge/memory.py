"""Engagement memory: a reusable PoC knowledge base and optional graph memory.

Two pieces, deliberately separable:

**PoC store (always available, no dependencies).** Every confirmed finding's proof
is recorded with its vulnerability class, technology context, and the reproduction
that worked. On the next engagement, a candidate of the same shape retrieves the
proofs that previously succeeded — RapidPen's insight that validation gets cheaper
when you stop re-deriving it. Retrieval is BM25-style keyword scoring over a JSONL
file: unimpressive, dependency-free, and good enough for a corpus that will never
exceed a few thousand entries.

**Graph memory (optional, needs Neo4j).** PentAGI's pattern for long engagements
where "what did I already learn about this host" stops fitting in a context
window. Absent Neo4j, the interface degrades to the JSONL store rather than
failing — nothing in EasyHunt requires a database to run.

Nothing here stores credentials or response bodies. Memory holds *methods* — what
worked and against what shape of target — because that is the part worth carrying
between engagements, and the rest is someone else's data.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easyhunt.util.parse import stable_id

__all__ = ["MemoryEntry", "PoCMemory", "graph_memory_available"]

_WORD = re.compile(r"[a-z0-9_.-]{2,}")

# Never persisted into memory, regardless of what a caller passes.
_FORBIDDEN_KEYS = {"credential", "secret", "token", "password", "cookie", "session", "body"}


def _tokenize(text: str) -> list[str]:
    return _WORD.findall((text or "").lower())


@dataclass
class MemoryEntry:
    """One remembered method — a PoC that worked, and the context it worked in."""

    vuln_class: str
    #: What was done. The reusable part.
    technique: str
    #: Copy-pasteable steps, with target-specific values already generalized.
    reproduction: str
    #: Technologies/frameworks present when it worked.
    context: list[str] = field(default_factory=list)
    outcome: str = "confirmed"
    #: Engagement name, not the target host — memory should not accumulate a
    #: list of who was tested and when.
    engagement: str = ""
    notes: str = ""
    id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    uses: int = 0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.vuln_class, self.technique, self.reproduction)

    def searchable(self) -> str:
        return " ".join([self.vuln_class, self.technique, *self.context, self.notes])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PoCMemory:
    """Append-only JSONL store of validated techniques, with keyword retrieval."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, MemoryEntry] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        known = set(MemoryEntry.__dataclass_fields__)
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    entry = MemoryEntry(**{k: v for k, v in record.items() if k in known})
                except (TypeError, ValueError):
                    continue
                self._entries[entry.id] = entry

    # -- writing ------------------------------------------------------------ #

    def remember(self, entry: MemoryEntry) -> MemoryEntry:
        """Record a technique. Re-remembering the same one increments its use count."""
        with self._lock:
            existing = self._entries.get(entry.id)
            if existing is not None:
                existing.uses += 1
                self._append(existing)
                return existing
            self._entries[entry.id] = entry
            self._append(entry)
            return entry

    def remember_finding(self, finding: Any, *, engagement_name: str = "") -> MemoryEntry | None:
        """Extract the reusable method from a confirmed finding.

        Only confirmed findings are remembered: an unproven candidate is a guess,
        and a memory full of guesses makes the next engagement worse, not better.
        """
        if getattr(finding, "poc", None) is None:
            return None

        from easyhunt.knowledge.findings import Status

        if getattr(finding, "status", None) is not Status.CONFIRMED:
            return None

        technologies = [t for t in getattr(finding, "tags", []) if t not in {"confirmed"}]
        return self.remember(
            MemoryEntry(
                vuln_class=str(getattr(finding, "rule_id", "") or "unknown").split(".")[0],
                technique=str(finding.title),
                # Host-specific values are generalized so the memory is about the
                # method, not about someone's infrastructure.
                reproduction=_generalize(finding.poc.reproduction, finding.asset),
                context=technologies,
                outcome="confirmed",
                engagement=engagement_name,
                notes=finding.poc.impact_limit_note,
            )
        )

    def _append(self, entry: MemoryEntry) -> None:
        payload = {k: v for k, v in entry.to_dict().items() if k.lower() not in _FORBIDDEN_KEYS}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")

    # -- retrieval ---------------------------------------------------------- #

    def recall(
        self, query: str, *, vuln_class: str | None = None, limit: int = 5
    ) -> list[dict[str, Any]]:
        """Retrieve prior techniques ranked by relevance to a query.

        BM25-ish scoring: term frequency in an entry, weighted by how rare the
        term is across the corpus, so 'ssrf' outranks 'the'.
        """
        candidates = [
            e for e in self._entries.values()
            if vuln_class is None or e.vuln_class == vuln_class
        ]
        if not candidates:
            return []

        terms = _tokenize(query)
        if not terms:
            return [
                {**e.to_dict(), "score": 0.0}
                for e in sorted(candidates, key=lambda e: -e.uses)[:limit]
            ]

        document_frequency = Counter()
        tokenized: dict[str, list[str]] = {}
        for entry in candidates:
            tokens = _tokenize(entry.searchable())
            tokenized[entry.id] = tokens
            for token in set(tokens):
                document_frequency[token] += 1

        total = len(candidates)
        scored: list[tuple[float, MemoryEntry]] = []
        for entry in candidates:
            tokens = tokenized[entry.id]
            counts = Counter(tokens)
            score = 0.0
            for term in terms:
                if term not in counts:
                    continue
                idf = math.log(1 + (total / (1 + document_frequency[term])))
                score += idf * (counts[term] / max(1, len(tokens))) * 10
            # A technique that has worked repeatedly is worth surfacing.
            score += 0.1 * entry.uses
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda pair: -pair[0])
        return [{**entry.to_dict(), "score": round(score, 3)} for score, entry in scored[:limit]]

    def by_class(self, vuln_class: str) -> list[MemoryEntry]:
        return [e for e in self._entries.values() if e.vuln_class == vuln_class]

    def stats(self) -> dict[str, Any]:
        by_class = Counter(e.vuln_class for e in self._entries.values())
        return {
            "path": str(self.path),
            "entries": len(self._entries),
            "by_class": dict(by_class.most_common()),
            "most_used": [
                {"technique": e.technique, "uses": e.uses}
                for e in sorted(self._entries.values(), key=lambda e: -e.uses)[:5]
            ],
        }

    def __len__(self) -> int:
        return len(self._entries)


def _generalize(text: str, asset: str) -> str:
    """Replace the specific host with a placeholder so the method transfers."""
    if not asset:
        return text
    from easyhunt.util.parse import host_of

    host = host_of(asset)
    out = text
    if host:
        out = out.replace(host, "{TARGET_HOST}")
    return out.replace(asset, "{TARGET_URL}")


def graph_memory_available() -> bool:
    """Whether the optional Neo4j-backed graph memory can be used."""
    try:
        import neo4j  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True

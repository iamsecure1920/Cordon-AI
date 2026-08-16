"""Normalized findings and assets.

One model, used by every engine, wrapper, rule pack, and report. The invariant
that matters is enforced here rather than in documentation:

    A finding reaches ``status = confirmed`` only by way of
    :meth:`Finding.confirm`, which requires a reproducible PoC artifact.

Nothing else can set that status. AI triage can rank, downgrade, and drop; it
cannot confirm. That is the whole point of "no PoC, no finding".
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from easyhunt.util.parse import stable_id

__all__ = [
    "Asset",
    "AssetStore",
    "Evidence",
    "Finding",
    "FindingStore",
    "PoC",
    "Severity",
    "Status",
]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def parse(cls, value: Any) -> Severity:
        """Coerce scanner severity strings. Unrecognized input becomes INFO.

        Handles being passed a Severity: this class subclasses ``str``, so a
        naive ``isinstance(x, str)`` check upstream will route enum members back
        through here, and ``str(Severity.HIGH)`` is ``'Severity.HIGH'`` — which
        would silently downgrade a real finding to info.
        """
        if isinstance(value, cls):
            return value
        text = (value.value if isinstance(value, Enum) else str(value or "info")).strip().lower()
        aliases = {
            "informational": "info", "warning": "low", "moderate": "medium",
            "crit": "critical", "severe": "high", "unknown": "info", "none": "info",
        }
        resolved = aliases.get(text, text)
        return cls(resolved) if resolved in cls._value2member_map_ else cls.INFO


class Status(str, Enum):
    #: Raised by a scanner or rule, not yet examined.
    CANDIDATE = "candidate"
    #: Survived triage but cannot be proven automatically. Ships in its own report section.
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    #: Proven with a reproducible PoC. The only status a report calls a vulnerability.
    CONFIRMED = "confirmed"
    #: Disproven.
    FALSE_POSITIVE = "false_positive"
    #: Out of scope, duplicate, or known-accepted.
    DROPPED = "dropped"


@dataclass
class Evidence:
    """A pointer to something on disk, plus a short inline excerpt."""

    kind: str  # request | response | screenshot | dns | file | command | log
    description: str = ""
    path: str | None = None
    excerpt: str = ""
    sha256: str | None = None
    collected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PoC:
    """A reproducible proof. Without one, a finding cannot be confirmed."""

    #: Exactly what to run or send, copy-pasteable.
    reproduction: str
    #: What a successful reproduction looks like.
    expected_result: str
    #: What was actually observed when it was run.
    observed_result: str = ""
    #: Least-impact justification: why this proof stops where it stops.
    impact_limit_note: str = ""
    tool: str | None = None
    artifacts: list[str] = field(default_factory=list)
    validated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    validated_by: str = "easyhunt"

    def is_reproducible(self) -> bool:
        return bool(self.reproduction.strip() and self.observed_result.strip())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    asset: str
    title: str
    phase: str = "unknown"
    severity: Severity = Severity.INFO
    status: Status = Status.CANDIDATE
    id: str = ""
    description: str = ""
    #: Which tool/rule/preset surfaced it — reproduced verbatim in the report.
    how_found: str = ""
    source_tool: str = ""
    rule_id: str | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    #: 0.0–1.0. Moved by triage; never sufficient on its own to confirm.
    confidence: float = 0.5
    evidence: list[Evidence] = field(default_factory=list)
    poc: PoC | None = None
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    #: True when a credential/endpoint was actively verified to work (Kingfisher-style).
    validated: bool = False
    #: Set on seeded decoys so a triage pass that "confirms" one is caught.
    is_canary: bool = False
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    triage_notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Test membership of the enum, not of str: both enums subclass str, so an
        # isinstance(..., str) check here would re-parse valid members.
        if not isinstance(self.severity, Severity):
            self.severity = Severity.parse(self.severity)
        if not isinstance(self.status, Status):
            self.status = Status(str(self.status))
        if not self.id:
            self.id = stable_id(self.asset, self.title, self.rule_id or self.source_tool)

    # -- state transitions -------------------------------------------------- #

    def confirm(self, poc: PoC) -> Finding:
        """Promote to ``confirmed``. The only route to that status.

        Raises ``ValueError`` if the PoC is not reproducible, which keeps an
        over-eager caller (or model) from confirming on an empty proof.
        """
        if not isinstance(poc, PoC) or not poc.is_reproducible():
            raise ValueError(
                "confirm() requires a PoC with both reproduction steps and an observed result"
            )
        self.poc = poc
        self.status = Status.CONFIRMED
        self.confidence = max(self.confidence, 0.95)
        self.last_seen = datetime.now(UTC).isoformat()
        return self

    def downgrade(self, reason: str, *, status: Status = Status.NEEDS_MANUAL_REVIEW) -> Finding:
        if status is Status.CONFIRMED:
            raise ValueError("downgrade() cannot be used to confirm a finding")
        self.status = status
        self.triage_notes.append(reason)
        self.last_seen = datetime.now(UTC).isoformat()
        return self

    def add_evidence(self, evidence: Evidence) -> Finding:
        self.evidence.append(evidence)
        return self

    def note(self, text: str) -> Finding:
        self.triage_notes.append(text)
        return self

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        payload = dict(data)
        payload["evidence"] = [Evidence(**e) for e in payload.get("evidence") or []]
        poc = payload.get("poc")
        payload["poc"] = PoC(**poc) if isinstance(poc, dict) else None
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in known})


@dataclass
class Asset:
    """A discovered thing: host, subdomain, URL, IP, endpoint, technology, secret."""

    value: str
    kind: str
    source: str = ""
    host: str = ""
    tags: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AssetStore:
    """Deduplicating store for recon output."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._lock = threading.Lock()

    def add(self, asset: Asset) -> Asset:
        with self._lock:
            existing = self._assets.get(asset.key())
            if existing:
                existing.tags = sorted(set(existing.tags) | set(asset.tags))
                existing.attributes.update(asset.attributes)
                # A re-discovery that carries a real origin host upgrades the
                # record. js_analyze stores relative endpoint paths whose early
                # passes recorded either the path itself (``host_of`` of a bare
                # path is the path) or the CDN that stored the bundle; later
                # passes record the page that served the bundle, which is the
                # host the routes actually belong to. Last-informed-writer wins:
                # the same tool re-run is what corrects the record, and no other
                # producer writes ``host`` for the same (kind, value) key.
                if asset.host and not asset.host.startswith("/") and asset.host != existing.host:
                    existing.host = asset.host
                return existing
            self._assets[asset.key()] = asset
            return asset

    def add_many(self, assets: Iterable[Asset]) -> int:
        before = len(self._assets)
        for asset in assets:
            self.add(asset)
        return len(self._assets) - before

    def by_kind(self, kind: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.kind == kind]

    def values(self, kind: str, *, tag: str | None = None) -> list[str]:
        """Deduplicated values of one kind, optionally narrowed to one tag.

        The tag matters more than it looks. `http_probe` stores confirmed-live
        URLs and `endpoint_discovery` stores archived ones, both as kind "url" —
        so a phase asking for "url" gets both. Feeding nuclei every archived URL
        instead of the live hosts turned a scan into 7,393 templates x 500
        targets: 7.7 million requests, 215 hours at the engagement's ceiling.
        The sizing gate refused it, correctly, but the request was nonsense in
        the first place.
        """
        return sorted({
            a.value for a in self._assets.values()
            if a.kind == kind and (tag is None or tag in a.tags)
        })

    def all(self) -> list[Asset]:
        return list(self._assets.values())

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for asset in self._assets.values():
            out[asset.kind] = out.get(asset.kind, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def __len__(self) -> int:
        return len(self._assets)

    def load(self, path: Path) -> int:
        """Repopulate from a saved assets.json. Returns how many were read.

        Without this the store was write-only: every phase saved its output and
        every phase started empty, so nothing could consume what came before.
        That is invisible in one process and fatal across several — and the
        pipeline runs one process per phase.

        Merges rather than replaces, so a run resumed mid-engagement keeps what
        it already knew.
        """
        if not path.exists():
            return 0
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return 0
        before = len(self._assets)
        for item in raw if isinstance(raw, list) else []:
            try:
                self.add(Asset(**item))
            except TypeError:
                continue
        return len(self._assets) - before

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([a.to_dict() for a in self._assets.values()], indent=2, default=str),
            encoding="utf-8",
        )


class FindingStore:
    """Deduplicating findings store with severity-ordered reads."""

    def __init__(self, path: Path | None = None, *, classifier: Any = None) -> None:
        self.path = path
        self._findings: dict[str, Finding] = {}
        self._lock = threading.Lock()
        #: Optional callable taking a Finding and returning ``{"match", "reason"}``
        #: when the program has declared that class ineligible, else ``None``.
        #: Applied on the way in so every consumer — report, listing, summary —
        #: agrees about what is reportable, instead of each deciding separately.
        self.classifier = classifier
        if path and path.exists():
            self.load(path)

    def _classify(self, finding: Finding) -> Finding:
        """Mark, never drop.

        A finding the program will not accept can still matter to the operator,
        and silently discarding results is the exact failure this codebase keeps
        finding in itself. It gets a tag and a recorded reason; deciding what to
        submit happens at report time, in the open.
        """
        if self.classifier is None:
            return finding
        try:
            verdict = self.classifier(finding)
        except Exception:  # noqa: BLE001 — classification must never lose a finding
            return finding
        if verdict:
            if "program-excluded" not in finding.tags:
                finding.tags.append("program-excluded")
            finding.extra["program_exclusion"] = verdict
        return finding

    def reportable(self) -> list[Finding]:
        """Everything except what the program said it will not accept.

        Not a severity filter and not a confidence filter — those are judgement
        calls that belong to a human. This is only the program's own published
        exclusion list, applied so a report does not hand a triager the exact
        categories their policy asks researchers not to send.
        """
        return [f for f in self.all() if "program-excluded" not in (f.tags or [])]

    def program_excluded(self) -> list[Finding]:
        """The other side of :meth:`reportable`. Kept, never deleted."""
        return [f for f in self.all() if "program-excluded" in (f.tags or [])]

    def add(self, finding: Finding) -> Finding:
        """Insert or merge. Re-scanning a target updates rather than duplicates."""
        finding = self._classify(finding)
        with self._lock:
            existing = self._findings.get(finding.id)
            if existing is None:
                self._findings[finding.id] = finding
                return finding
            existing.last_seen = datetime.now(UTC).isoformat()
            existing.evidence.extend(finding.evidence)
            existing.tags = sorted(set(existing.tags) | set(finding.tags))
            # A repeat sighting can raise severity but never silently lowers it.
            if finding.severity.rank > existing.severity.rank:
                existing.severity = finding.severity
            if finding.poc and not existing.poc:
                existing.poc = finding.poc
            return existing

    def add_many(self, findings: Iterable[Finding]) -> list[Finding]:
        return [self.add(f) for f in findings]

    def get(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def all(self, *, include_canaries: bool = False) -> list[Finding]:
        items = [f for f in self._findings.values() if include_canaries or not f.is_canary]
        return sorted(items, key=lambda f: (-f.severity.rank, -f.confidence, f.asset))

    def by_status(self, status: Status, *, include_canaries: bool = False) -> list[Finding]:
        return [f for f in self.all(include_canaries=include_canaries) if f.status is status]

    def confirmed(self) -> list[Finding]:
        return self.by_status(Status.CONFIRMED)

    def needs_review(self) -> list[Finding]:
        return self.by_status(Status.NEEDS_MANUAL_REVIEW)

    def candidates(self) -> list[Finding]:
        return self.by_status(Status.CANDIDATE)

    def canaries(self) -> list[Finding]:
        return [f for f in self._findings.values() if f.is_canary]

    def stats(self) -> dict[str, Any]:
        findings = self.all()
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for finding in findings:
            by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1
            by_status[finding.status.value] = by_status.get(finding.status.value, 0) + 1
        return {
            "total": len(findings),
            "by_severity": by_sev,
            "by_status": by_status,
            "confirmed": len(self.confirmed()),
            "needs_manual_review": len(self.needs_review()),
            "canaries_seeded": len(self.canaries()),
        }

    def save(self, path: Path | None = None) -> Path:
        target = Path(path or self.path or "findings.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "stats": self.stats(),
            "findings": [f.to_dict() for f in self.all()],
        }
        target.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return target

    def load(self, path: Path) -> int:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        records = payload.get("findings") if isinstance(payload, dict) else payload
        loaded = 0
        for record in records or []:
            try:
                self.add(Finding.from_dict(record))
                loaded += 1
            except (TypeError, ValueError):
                continue
        return loaded

    def __len__(self) -> int:
        return len(self._findings)

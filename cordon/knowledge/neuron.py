"""NeuronBrain — associative experience memory for the tool.

The other stores in :mod:`cordon.knowledge` are *passive*. ``PoCMemory`` keeps
the methods that worked, ``GraphMemory`` keeps what the engagement saw, the
technique index keeps what PayloadsAllTheThings says. None of them *learns*:
a validator that proves ``sqli_validate`` pays on a Next.js/Cloudflare stack
does not make the next engagement fire it first, and a validator that filed 32
false MEDIUMs over a cookie (testssl's ``ipv4_in_header``) is not remembered as
a false-positive machine anywhere but in a code comment.

This module is the active layer. It is a Hebbian-style associative memory —
synapses between *context* and *technique*, strengthened by confirmed hits,
weakened by clean passes, and strongly inhibited by false positives, with
exponential recency decay so a lesson that stops being true stops being
believed. The two questions it answers are the two a human pentester's memory
answers:

* ``recall(context)`` — "on this kind of target, what has actually worked
  before, and how reliably?" (ranked, with trial counts, not vibes)
* ``suppress(tool, rule, context)`` — "this scanner fired on a target like this
  before and was wrong; should I trust this hit?" (a false-positive blacklist
  learned from triage, not maintained by hand)

Deliberate boundaries:

* **It stores methods and outcomes, never data.** No credentials, bodies, or
  target-specific values cross into the store — the same rule as ``PoCMemory``.
  Context is a *signature* (bug class + technology tags + WAF vendor), which is
  the reusable part of "what kind of target".
* **Learning is an outcome, not an opinion.** Only observed validator outcomes
  (confirmed hit / clean pass / false positive) change weights. Nobody teaches
  the brain "Cloudflare is easy" — the chain's per-parameter results do, and
  triage's drops do.
* **The brain advises; it never decides.** ``recall`` returns weights and trial
  counts. A single trial is a guess and is labelled as such; a technique with
  fifty trials and a high hit-rate is worth firing first. Suppression requires
  repeated, recent evidence, and a suppressed hit is still recorded — it is
  demoted to ``needs_manual_review``, never deleted, because a learned FP is a
  prior, not a proof.

Storage is JSONL, append-only, one synapse or lesson per line, mirroring
``PoCMemory``: unimpressive, dependency-free, and correct for a corpus of a few
thousand associations.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "BrainOutcome",
    "NeuronBrain",
    "context_signature",
    "synapse_key",
]

#: How many recent activity events the brain keeps in memory for live sensing
#: and for the ``brain watch`` animation. The JSONL file on disk is the full
#: history; this is the moving window the animation draws from.
_ACTIVITY_RING = 256

#: Audit events the brain treats as *activity* (things worth sensing/animating)
#: versus pure bookkeeping. A tool call is the unit of "what is happening now"
#: — phase, tool, outcome, findings count all ride on it.
_SENSED_EVENTS = {"tool_call", "engagement_start", "engagement_end"}

#: What an observed validator outcome can be. These are the only signals that
#: change a weight — the brain learns from what actually happened, nothing else.
class BrainOutcome:
    #: The validator proved the class (sqlmap ``proven``, a probe count > 0).
    HIT = "hit"
    #: The validator ran clean on this parameter/class pair.
    CLEAN = "clean"
    #: Triage later dropped the finding — the tool fired and was wrong here.
    FALSE_POSITIVE = "false_positive"

#: How strongly each outcome moves a synapse.
_OUTCOME_DELTA = {
    BrainOutcome.HIT: +1.0,
    BrainOutcome.CLEAN: -0.15,
    BrainOutcome.FALSE_POSITIVE: -1.5,
}

#: Exponential decay half-life. A lesson with no confirmations is half-forgotten
#: after this long — a stack migrates, a WAF ships a rule, and a technique that
#: paid on 2025 targets should stop shaping 2028 plans.
_HALF_LIFE_DAYS = 90.0

#: A tool/rule pair must be wrong this many times (with at least this FP ratio)
#: before ``suppress`` will demote a fresh hit of the same shape.
_MIN_FP_TRIALS = 2
_MIN_FP_RATIO = 0.5


def context_signature(
    vuln_class: str,
    *,
    technologies: list[str] | None = None,
    waf_vendors: list[str] | None = None,
) -> str:
    """A canonical, order-independent context fingerprint.

    ``"sqli | next.js,react | cloudflare"`` — the parts of the target that a
    human pentester would say changed what to try. Order is sorted so
    ``["next.js", "react"]`` and ``["react", "next.js"]`` collide.
    """
    techs = sorted({t.strip().lower() for t in (technologies or []) if t and t.strip()})
    wafs = sorted({w.strip().lower() for w in (waf_vendors or []) if w and w.strip()})
    bits = [str(vuln_class or "unknown").strip().lower()]
    if techs:
        bits.append(",".join(techs[:6]))
    if wafs:
        bits.append(",".join(wafs[:3]))
    return " | ".join(bits)


def synapse_key(context: str, technique: str) -> str:
    """Stable key for one (context, technique) association."""
    return f"{context}:::{technique}"


def _signature_parts(signature: str) -> tuple[str, set[str]]:
    """Split a context signature into (vuln class, {tech+waf tokens}).

    ``"sqli | next.js,react | cloudflare"`` → ``("sqli", {"next.js", "react",
    "cloudflare"})``. The class is the first ``|``-segment; everything else is
    stack evidence.
    """
    segments = [s.strip() for s in signature.split("|")]
    klass = segments[0].strip().lower() if segments else ""
    rest: set[str] = set()
    for segment in segments[1:]:
        for token in segment.split(","):
            token = token.strip().lower()
            if token:
                rest.add(token)
    return klass, rest


def _context_overlap(query: tuple[str, set[str]], stored: str) -> float:
    """How much of a stored context matches a query context.

    The vulnerability class must match — ``sqli`` lessons never inform ``xss``
    plans. Stack tokens then contribute by overlap: a stored context sharing
    every token scores 1.0, one sharing half scores 0.5, one sharing none but
    matching the class scores 0.25 (a class-level lesson still transfers to a
    bare-metal target).
    """
    query_class, query_tokens = query
    stored_class, stored_tokens = _signature_parts(stored)
    if query_class != stored_class:
        return 0.0
    if not query_tokens or not stored_tokens:
        # Either side is class-only: the class match carries the association.
        return 0.25
    overlap = len(query_tokens & stored_tokens)
    if overlap == 0:
        return 0.25
    union = len(query_tokens | stored_tokens)
    return max(0.25, overlap / union)


@dataclass
class Synapse:
    """One learned association between a target context and a technique."""

    context: str
    technique: str
    weight: float = 0.0
    trials: int = 0
    hits: int = 0
    clean: int = 0
    false_positives: int = 0
    #: Engagement that last touched this synapse. Identifies where the lesson
    #: came from for the report; never stored against a live target.
    last_engagement: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def fp_ratio(self) -> float:
        return self.false_positives / self.trials if self.trials else 0.0

    @property
    def hit_ratio(self) -> float:
        return self.hits / self.trials if self.trials else 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FpLesson:
    """A learned false-positive shape: tool fired on this context and was wrong."""

    tool: str
    rule: str
    context: str
    count: int = 0
    last_engagement: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fp_key(tool: str, rule: str, context: str) -> str:
    return f"{tool}::{rule}::{context}"


def _decay(weight: float, age_days: float) -> float:
    """Exponential recency decay toward zero."""
    if age_days <= 0:
        return weight
    return weight * (0.5 ** (age_days / _HALF_LIFE_DAYS))


def _age_days(iso: str) -> float:
    try:
        born = datetime.fromisoformat(iso)
    except ValueError:
        return 0.0
    return max(0.0, (datetime.now(UTC) - born).total_seconds() / 86400.0)


class NeuronBrain:
    """Thread-safe associative experience store with recall and suppression.

    The brain does two jobs. It *learns* — synapses between target context and
    technique, strengthened by hits and inhibited by false positives (the
    associative memory). And it *senses* — a live activity feed of what every
    script is doing right now, fed by the audit log's observer hook, kept as a
    ring buffer for ``brain watch`` and as a JSONL timeline for ``history()``
    (the episodic memory: failures, successes, false and true findings, and the
    order they happened in).
    """

    def __init__(self, path: str | Path, activity_path: str | Path | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.activity_path = Path(activity_path) if activity_path else self.path.with_name("brain-activity.jsonl")
        self.activity_path.parent.mkdir(parents=True, exist_ok=True)
        self._synapses: dict[str, Synapse] = {}
        self._lessons: dict[str, FpLesson] = {}
        #: The sensed present: recent activity, newest last, and a live "what
        #: am I doing" pointer the animation draws from.
        self._activity: deque[dict[str, Any]] = deque(maxlen=_ACTIVITY_RING)
        self._current: dict[str, Any] = {
            "phase": "idle",
            "tool": None,
            "since": datetime.now(UTC).isoformat(),
        }
        self._lock = threading.Lock()
        self._load()

    # -- persistence -------------------------------------------------------- #

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = record.get("kind")
            if kind == "synapse":
                try:
                    s = Synapse(**{k: v for k, v in record.items() if k in Synapse.__dataclass_fields__})
                    self._synapses[synapse_key(s.context, s.technique)] = s
                except (TypeError, ValueError):
                    continue
            elif kind == "fp_lesson":
                try:
                    lsn = FpLesson(**{k: v for k, v in record.items() if k in FpLesson.__dataclass_fields__})
                    self._lessons[_fp_key(lsn.tool, lsn.rule, lsn.context)] = lsn
                except (TypeError, ValueError):
                    continue

    def _append(self, record: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    def _append_activity(self, record: dict[str, Any]) -> None:
        with self.activity_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")

    # -- sensing ------------------------------------------------------------ #

    def sense(self, record: dict[str, Any]) -> None:
        """Ingest one audit record into the live activity feed.

        Registered as the audit log's observer, so every tool call in every
        script reaches the brain without any tool knowing the brain exists.
        Non-activity bookkeeping is ignored. Never raises: the brain is a tap
        on the audit stream, and a failing tap must not break the audit.
        """
        event = str(record.get("event") or "")
        if event not in _SENSED_EVENTS:
            return
        now = datetime.now(UTC).isoformat()
        if event == "tool_call":
            activity = {
                "kind": "activity",
                "ts": now,
                "event": "tool_call",
                "phase": str(record.get("phase") or "unknown"),
                "tool": str(record.get("tool") or "?"),
                "mode": str(record.get("mode") or ""),
                "outcome": str(record.get("outcome") or "ok"),
                "error": record.get("error"),
                "findings": int(record.get("findings") or 0),
                "targets": len(record.get("targets") or []),
                "duration_ms": record.get("duration_ms"),
            }
        else:  # engagement_start / engagement_end
            activity = {
                "kind": "activity",
                "ts": now,
                "event": event,
                "engagement": record.get("engagement"),
                "outcome": "ok",
            }
        with self._lock:
            self._activity.append(activity)
            if activity.get("event") == "tool_call":
                self._current = {
                    "phase": activity["phase"],
                    "tool": activity["tool"],
                    "mode": activity["mode"],
                    "since": now,
                    "last_outcome": activity["outcome"],
                }
            elif activity.get("event") == "engagement_end":
                self._current["phase"] = "idle"
                self._current["tool"] = None
        try:
            self._append_activity(activity)
        except OSError:
            pass

    def state(self) -> dict[str, Any]:
        """What the brain senses right now: live phase, recent activity, memory."""
        with self._lock:
            recent = list(self._activity)[-12:]
            current = dict(self._current)
            activity_count = len(self._activity)
        return {
            "current": current,
            "activity_count": activity_count,
            "recent": recent,
            "stats": self.stats(),
        }

    def history(
        self,
        *,
        event: str | None = None,
        phase: str | None = None,
        tool: str | None = None,
        outcome: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """The episodic memory: what happened, in order, filtered.

        The full timeline lives on disk (``activity_path``); this reads the tail
        and filters — ``tool="sqli_validate"``, ``outcome="ok"`` with
        ``findings>0``, a whole phase's activity. This is the "what failed,
        what succeeded, what was a false positive, what was true" memory the
        weights cannot express on their own.
        """
        events: list[dict[str, Any]] = []
        try:
            if self.activity_path.exists():
                with self.activity_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            return []
        events = [e for e in events if e.get("kind") == "activity"]
        if event:
            events = [e for e in events if e.get("event") == event]
        if phase:
            events = [e for e in events if e.get("phase") == phase]
        if tool:
            events = [e for e in events if e.get("tool") == tool]
        if outcome:
            events = [e for e in events if e.get("outcome") == outcome]
        return events[-limit:]

    def save(self) -> None:
        """Rewrite the store (dedup + compact). Used on finish; not required."""
        lines: list[str] = []
        with self._lock:
            for s in self._synapses.values():
                lines.append(json.dumps({"kind": "synapse", **s.to_dict()}, default=str))
            for lsn in self._lessons.values():
                lines.append(json.dumps({"kind": "fp_lesson", **lsn.to_dict()}, default=str))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -- learning ----------------------------------------------------------- #

    def learn(
        self,
        *,
        vuln_class: str,
        technique: str,
        outcome: str,
        technologies: list[str] | None = None,
        waf_vendors: list[str] | None = None,
        engagement: str = "",
    ) -> dict[str, Any]:
        """Record one observed validator outcome.

        ``outcome`` is a :class:`BrainOutcome` value. ``technique`` is the tool
        or validator that produced it (``"sqli_validate"``, ``"web_injection_probe"
        ``); for false positives it may also carry the specific rule so
        suppression can be rule-shaped rather than tool-shaped.
        """
        if outcome not in _OUTCOME_DELTA:
            return {"ok": False, "error": "unknown_outcome", "outcome": outcome}
        ctx = context_signature(vuln_class, technologies=technologies, waf_vendors=waf_vendors)
        key = synapse_key(ctx, technique)
        now = datetime.now(UTC).isoformat()
        with self._lock:
            s = self._synapses.setdefault(
                key,
                Synapse(context=ctx, technique=technique),
            )
            s.trials += 1
            s.weight += _OUTCOME_DELTA[outcome]
            s.last_engagement = engagement or s.last_engagement
            s.updated_at = now
            if outcome == BrainOutcome.HIT:
                s.hits += 1
            elif outcome == BrainOutcome.CLEAN:
                s.clean += 1
            elif outcome == BrainOutcome.FALSE_POSITIVE:
                s.false_positives += 1
                # A false positive is also a lesson about (tool, rule, context),
                # and lessons live independently of the technique that carries
                # them so suppression can be asked without knowing the technique.
                tool, _, rule = technique.partition(":")
                self._record_fp(tool or technique, rule or "", ctx, engagement)
            snapshot = s.to_dict()
        self._append({"kind": "synapse", **snapshot})
        return {"ok": True, "synapse": snapshot}

    def _record_fp(self, tool: str, rule: str, context: str, engagement: str) -> None:
        now = datetime.now(UTC).isoformat()
        lsn = self._lessons.setdefault(
            _fp_key(tool, rule, context),
            FpLesson(tool=tool, rule=rule, context=context),
        )
        lsn.count += 1
        lsn.last_engagement = engagement or lsn.last_engagement
        lsn.updated_at = now

    # -- recall ------------------------------------------------------------- #

    def recall(
        self,
        *,
        vuln_class: str,
        technologies: list[str] | None = None,
        waf_vendors: list[str] | None = None,
        limit: int = 10,
        min_trials: int = 1,
    ) -> list[dict[str, Any]]:
        """Techniques ranked by learned weight for a target context.

        Matching is fuzzy, not exact — a lesson learned on a ``next.js,react``
        stack transfers to a target that is ``next.js`` alone, because that is
        the whole point of carrying experience between engagements. Each stored
        synapse is scored by how much of its context overlaps the query:
        vulnerability class is required, then technology and WAF overlap boost.
        Weight is decayed by recency and by the confidence label derived from
        trial count — a single trial is a guess, a dozen is a working rule.
        ``clean`` outcomes drive weight down, so a technique that never finds
        anything on a stack sinks below one that found something once.
        """
        ctx = context_signature(vuln_class, technologies=technologies, waf_vendors=waf_vendors)
        ctx_parts = _signature_parts(ctx)
        ranked: list[tuple[float, Synapse]] = []
        with self._lock:
            for _key, s in self._synapses.items():
                if s.trials < min_trials:
                    continue
                score = _context_overlap(ctx_parts, s.context)
                if score <= 0:
                    continue
                effective = _decay(s.weight, _age_days(s.updated_at)) * score
                if effective <= 0:
                    continue
                ranked.append((effective, s))
        ranked.sort(key=lambda pair: -pair[0])
        out: list[dict[str, Any]] = []
        for effective, s in ranked[:limit]:
            out.append(
                {
                    "technique": s.technique,
                    "weight": round(effective, 3),
                    "context": s.context,
                    "trials": s.trials,
                    "hits": s.hits,
                    "clean": s.clean,
                    "false_positives": s.false_positives,
                    "hit_ratio": round(s.hit_ratio, 2),
                    "fp_ratio": round(s.fp_ratio, 2),
                    "confidence": _confidence_label(s.trials),
                    "last_engagement": s.last_engagement,
                }
            )
        return out

    def suppress(
        self,
        *,
        tool: str,
        rule: str = "",
        vuln_class: str = "",
        technologies: list[str] | None = None,
        waf_vendors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Should a fresh hit from this tool/rule on this context be trusted?

        The false-positive history is keyed by context, so the same tool can be
        trusted on one stack and distrusted on another — testssl's
        ``ipv4_in_header`` misfired on Cloudflare-served cookie values, not on
        TLS in general. A hit is demotable only with repeated, recent evidence:
        at least :data:`_MIN_FP_TRIALS` false positives with an FP ratio above
        :data:`_MIN_FP_RATIO`.
        """
        ctx = context_signature(vuln_class, technologies=technologies, waf_vendors=waf_vendors)
        tool_l = str(tool or "").strip().lower()
        rule_l = str(rule or "").strip().lower()
        candidates: list[FpLesson] = []
        with self._lock:
            # Exact (tool, rule, context) first; then (tool, rule, *) — a lesson
            # about the tool's rule on ANY context still counts, weakly; then
            # (tool, *, context) — a lesson about this tool on this stack.
            exact = self._lessons.get(_fp_key(tool_l, rule_l, ctx))
            if exact:
                candidates.append(exact)
            for lsn in self._lessons.values():
                if lsn.tool == tool_l and lsn.rule == rule_l and lsn.context != ctx:
                    candidates.append(lsn)
                elif lsn.tool == tool_l and lsn.rule == "" and lsn.context == ctx:
                    candidates.append(lsn)
        if not candidates:
            return {"suppress": False, "evidence": []}
        fresh = [c for c in candidates if _age_days(c.updated_at) < _HALF_LIFE_DAYS]
        total = sum(c.count for c in candidates)
        ratio_ok = total >= _MIN_FP_TRIALS
        # Weight the exact-context lesson above the general ones: one FP on
        # this exact stack outweighs several on unrelated stacks.
        exact_count = sum(c.count for c in candidates if c.context == ctx)
        suppress = ratio_ok and (exact_count > 0 or len(fresh) >= _MIN_FP_TRIALS)
        evidence = [
            {
                "tool": c.tool,
                "rule": c.rule,
                "context": c.context,
                "count": c.count,
                "last_engagement": c.last_engagement,
                "age_days": round(_age_days(c.updated_at), 1),
            }
            for c in candidates
        ]
        return {"suppress": suppress, "evidence": evidence, "total_fp": total}

    # -- misc --------------------------------------------------------------- #

    def stats(self) -> dict[str, Any]:
        with self._lock:
            by_context: dict[str, int] = {}
            by_technique: dict[str, int] = {}
            for s in self._synapses.values():
                by_context[s.context] = by_context.get(s.context, 0) + 1
                by_technique[s.technique] = by_technique.get(s.technique, 0) + 1
            fp_tools: dict[str, int] = {}
            for lsn in self._lessons.values():
                fp_tools[lsn.tool] = fp_tools.get(lsn.tool, 0) + lsn.count
            return {
                "path": str(self.path),
                "activity_path": str(self.activity_path),
                "synapses": len(self._synapses),
                "fp_lessons": len(self._lessons),
                "sensing": {
                    "current_phase": self._current.get("phase"),
                    "current_tool": self._current.get("tool"),
                    "ring": len(self._activity),
                },
                "by_context": dict(sorted(by_context.items(), key=lambda kv: -kv[1])[:8]),
                "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])[:8]),
                "fp_by_tool": dict(sorted(fp_tools.items(), key=lambda kv: -kv[1])),
                "strongest": [
                    {"context": s.context, "technique": s.technique, "weight": round(s.weight, 2)}
                    for s in sorted(self._synapses.values(), key=lambda s: -s.weight)[:5]
                ],
            }

    def __len__(self) -> int:
        return len(self._synapses)


def _confidence_label(trials: int) -> str:
    if trials <= 1:
        return "guess"
    if trials < 5:
        return "weak"
    if trials < 15:
        return "moderate"
    return "strong"

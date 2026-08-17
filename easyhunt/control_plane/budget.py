"""Engagement ceilings.

Four independent limits — LLM spend, wall clock, request count, tool seconds —
plus per-phase token allowances. Exceeding any of them aborts cleanly: the run
stops issuing new work and the reporter emits a *partial* report from whatever is
already in the findings store, rather than dying mid-scan with nothing to show.

The ledger is persisted to the engagement directory, so resuming a run continues
spending against the same budget instead of silently starting over.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from easyhunt.errors import BudgetExceeded

__all__ = ["Budget", "BudgetLimits", "Ledger"]


@dataclass
class BudgetLimits:
    #: Master switch, **off by default**. When ``False`` no ceiling is enforced:
    #: ``check()`` never raises and ``remaining()`` reports unlimited. The
    #: counters below still run, so a report can say what a run cost and how
    #: many requests it sent — the accounting is useful, stopping the run
    #: partway through was not.
    #:
    #: It defaults off because a budget ceiling is a *cost* control that
    #: presents as a *safety* control, and the two behave differently when they
    #: fire. A rate limit protects the target and must bind. A budget ceiling
    #: protects the operator's wallet, and when it trips mid-engagement it
    #: truncates coverage — leaving phases unrun, which this project treats as
    #: UNTESTED rather than clean. An operator who wants ceilings writes
    #: ``budget.enforce: true`` in the engagement's scope file and sets them
    #: deliberately; nothing is removed, only the default is reversed.
    enforce: bool = False
    llm_usd: float = 5.0
    wall_clock_minutes: float = 240.0
    max_requests: int = 50_000
    max_tool_seconds: float = 14_400.0
    phase_token_budget: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, phase_tokens: dict[str, int] | None = None) -> BudgetLimits:
        data = data or {}
        return cls(
            # Default is False: a scope that says nothing about budget gets no
            # ceilings. Opting in is explicit (``budget.enforce: true``), which
            # is the right way round for a control that truncates coverage
            # rather than protecting the target.
            enforce=bool(data.get("enforce", False)),
            llm_usd=float(data.get("llm_usd", 5.0)),
            wall_clock_minutes=float(data.get("wall_clock_minutes", 240)),
            max_requests=int(data.get("max_requests", 50_000)),
            max_tool_seconds=float(data.get("max_tool_seconds", 14_400)),
            phase_token_budget=dict(phase_tokens or data.get("phase_token_budget") or {}),
        )


@dataclass
class Ledger:
    llm_usd: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    requests: int = 0
    tool_seconds: float = 0.0
    started_at: float = field(default_factory=time.time)
    llm_calls: int = 0
    tool_calls: int = 0
    by_phase_tokens: dict[str, int] = field(default_factory=dict)
    by_phase_usd: dict[str, float] = field(default_factory=dict)
    by_tier_usd: dict[str, float] = field(default_factory=dict)


class Budget:
    """Mutable spend tracker with hard ceilings."""

    def __init__(self, limits: BudgetLimits, *, path: str | Path | None = None) -> None:
        self.limits = limits
        self.path = Path(path) if path else None
        self.ledger = Ledger()
        self._lock = threading.Lock()
        self.aborted_reason: str | None = None
        if self.path and self.path.exists():
            self._load()

    # -- persistence -------------------------------------------------------- #

    def _load(self) -> None:
        # A real guard rather than an assert: `python -O` strips asserts, and
        # control-plane behaviour must not depend on the optimization flag.
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        known = {f for f in Ledger.__dataclass_fields__}
        self.ledger = Ledger(**{k: v for k, v in data.items() if k in known})

    def persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self.ledger), indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- queries ------------------------------------------------------------ #

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.ledger.started_at

    def remaining(self) -> dict[str, float]:
        if not self.limits.enforce:
            # Unlimited: every consumer (sizing, decorators, report) sees a
            # ceiling that cannot be hit, so nothing narrows or refuses on
            # budget grounds. Ledger still records what was spent.
            return {
                "llm_usd": float("inf"),
                "wall_clock_seconds": float("inf"),
                "requests": float("inf"),
                "tool_seconds": float("inf"),
            }
        return {
            "llm_usd": max(0.0, self.limits.llm_usd - self.ledger.llm_usd),
            "wall_clock_seconds": max(
                0.0, self.limits.wall_clock_minutes * 60 - self.elapsed_seconds
            ),
            "requests": max(0, self.limits.max_requests - self.ledger.requests),
            "tool_seconds": max(0.0, self.limits.max_tool_seconds - self.ledger.tool_seconds),
        }

    @property
    def llm_disabled(self) -> bool:
        """``llm_usd: 0`` means "run without any model", not "already broke".

        Distinguishing these matters: a zero LLM budget is a legitimate offline
        configuration, and treating it as an exhausted ceiling would refuse every
        tool call in the engagement — including the scans that need no model at all.
        """
        return self.limits.llm_usd <= 0

    def exhausted(self) -> str | None:
        """Name of the first exhausted ceiling, or ``None``."""
        if not self.limits.enforce:
            return None
        if not self.llm_disabled and self.ledger.llm_usd >= self.limits.llm_usd:
            return "llm_usd"
        if self.elapsed_seconds >= self.limits.wall_clock_minutes * 60:
            return "wall_clock"
        if self.ledger.requests >= self.limits.max_requests:
            return "max_requests"
        if self.ledger.tool_seconds >= self.limits.max_tool_seconds:
            return "max_tool_seconds"
        return None

    def check(self, *, need_requests: int = 0, need_usd: float = 0.0) -> None:
        """Pre-flight check. Raises :class:`BudgetExceeded` when a ceiling is hit.

        Called by the tool decorator *before* work starts, so an over-budget run
        never issues the request in the first place. With ``enforce: false`` in
        the scope this is a no-op — the operator said they do not want ceilings.
        """
        if not self.limits.enforce:
            return
        hit = self.exhausted()
        if hit:
            self.aborted_reason = hit
            raise BudgetExceeded(
                f"engagement budget exhausted: {hit}",
                limit=hit,
                spent=self.snapshot(),
                remaining=self.remaining(),
            )
        remaining = self.remaining()
        if need_requests and need_requests > remaining["requests"]:
            self.aborted_reason = "max_requests"
            raise BudgetExceeded(
                f"call would need {need_requests} requests, {remaining['requests']:.0f} remain",
                limit="max_requests",
                remaining=remaining,
            )
        if need_usd and self.llm_disabled:
            raise BudgetExceeded(
                "LLM spending is disabled for this engagement (budget.llm_usd is 0). "
                "Scanning and rule-based detection still work; AI triage and report "
                "synthesis do not.",
                limit="llm_usd",
                disabled=True,
            )
        if need_usd and need_usd > remaining["llm_usd"]:
            self.aborted_reason = "llm_usd"
            raise BudgetExceeded(
                f"call would need ${need_usd:.4f}, ${remaining['llm_usd']:.4f} remains",
                limit="llm_usd",
                remaining=remaining,
            )

    def phase_tokens_remaining(self, phase: str) -> int | None:
        """Tokens left for a phase, or ``None`` when the phase is unbudgeted."""
        allowance = self.limits.phase_token_budget.get(phase)
        if allowance is None:
            return None
        return max(0, allowance - self.ledger.by_phase_tokens.get(phase, 0))

    # -- charges ------------------------------------------------------------ #

    def charge_llm(
        self,
        *,
        usd: float,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        phase: str = "unknown",
        tier: str = "unknown",
    ) -> None:
        with self._lock:
            self.ledger.llm_usd += max(0.0, usd)
            self.ledger.prompt_tokens += max(0, prompt_tokens)
            self.ledger.completion_tokens += max(0, completion_tokens)
            self.ledger.llm_calls += 1
            total = max(0, prompt_tokens) + max(0, completion_tokens)
            self.ledger.by_phase_tokens[phase] = self.ledger.by_phase_tokens.get(phase, 0) + total
            self.ledger.by_phase_usd[phase] = round(
                self.ledger.by_phase_usd.get(phase, 0.0) + max(0.0, usd), 6
            )
            self.ledger.by_tier_usd[tier] = round(
                self.ledger.by_tier_usd.get(tier, 0.0) + max(0.0, usd), 6
            )
        self.persist()

    def charge_requests(self, count: int = 1) -> None:
        with self._lock:
            self.ledger.requests += max(0, count)

    def charge_tool(self, *, seconds: float, requests: int = 1) -> None:
        with self._lock:
            self.ledger.tool_seconds += max(0.0, seconds)
            self.ledger.requests += max(0, requests)
            self.ledger.tool_calls += 1
        self.persist()

    # -- reporting ---------------------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        return {
            "llm_usd": round(self.ledger.llm_usd, 6),
            "llm_calls": self.ledger.llm_calls,
            "prompt_tokens": self.ledger.prompt_tokens,
            "completion_tokens": self.ledger.completion_tokens,
            "requests": self.ledger.requests,
            "tool_calls": self.ledger.tool_calls,
            "tool_seconds": round(self.ledger.tool_seconds, 1),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
        }

    def cost_summary(self) -> dict[str, Any]:
        """Per-phase / per-tier breakdown for the end-of-run report."""
        return {
            "limits": asdict(self.limits),
            "spent": self.snapshot(),
            "remaining": self.remaining(),
            "by_phase_usd": dict(sorted(self.ledger.by_phase_usd.items(), key=lambda kv: -kv[1])),
            "by_phase_tokens": dict(
                sorted(self.ledger.by_phase_tokens.items(), key=lambda kv: -kv[1])
            ),
            "by_tier_usd": self.ledger.by_tier_usd,
            "aborted_reason": self.aborted_reason,
        }

"""Human-in-the-loop approval gate.

Aggressive and state-changing calls stop here until a person accepts them.
Exploitation is never auto-run.

Two backends cover the transports that matter today, because the MCP spec in this
area is still moving:

* ``elicitation`` — server-initiated structured prompt to the MCP client, which is
  what the Claude CLI surfaces to the operator.
* ``pending``     — the call returns ``approval_required`` with a token, and the
  agent (or an out-of-band operator) resolves it via the ``approval_respond``
  tool. Works with any client, including ones without elicitation support.

Both funnel into the same :class:`ApprovalGate`, so a tool never learns which one
is in use. Every path fails closed: an unsupported client, a timeout, or an
exception all resolve to *declined*.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol

from easyhunt.control_plane.scope import Scope
from easyhunt.errors import ApprovalDenied, ApprovalRequired

__all__ = [
    "ApprovalDecision",
    "ApprovalGate",
    "ApprovalRequest",
    "Decision",
    "DenyBackend",
    "ElicitationBackend",
    "PendingBackend",
    "PolicyBackend",
    "build_backend",
]

log = logging.getLogger("easyhunt.approval")


class Decision(str, Enum):
    ACCEPT = "accept"
    DECLINE = "decline"
    CANCEL = "cancel"
    PENDING = "pending"


@dataclass(frozen=True)
class ApprovalRequest:
    """Everything a human needs to make the call, and nothing they don't."""

    tool: str
    phase: str
    mode: str
    targets: list[str]
    command: str | None = None
    rationale: str = ""
    risk_notes: list[str] = field(default_factory=list)
    estimated_requests: int | None = None

    def key(self) -> str:
        return f"{self.tool}|{','.join(sorted(self.targets))}"

    def prompt(self) -> str:
        lines = [
            f"EasyHunt is requesting approval to run an {self.mode.upper()} action.",
            "",
            f"  tool    : {self.tool}",
            f"  phase   : {self.phase}",
            f"  target  : {', '.join(self.targets) or '(none)'}",
        ]
        if self.command:
            lines.append(f"  command : {self.command}")
        if self.estimated_requests:
            lines.append(f"  est. requests: {self.estimated_requests}")
        if self.rationale:
            lines += ["", f"Why: {self.rationale}"]
        if self.risk_notes:
            lines += ["", "Risk notes:"] + [f"  - {note}" for note in self.risk_notes]
        lines += ["", "Approve this action?"]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "phase": self.phase,
            "mode": self.mode,
            "targets": self.targets,
            "command": self.command,
            "rationale": self.rationale,
            "risk_notes": self.risk_notes,
            "estimated_requests": self.estimated_requests,
        }


@dataclass
class ApprovalDecision:
    decision: Decision
    approver: str = "unknown"
    note: str | None = None
    remember: bool = False
    at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    token: str | None = None

    @property
    def accepted(self) -> bool:
        return self.decision is Decision.ACCEPT

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "approver": self.approver,
            "note": self.note,
            "remember": self.remember,
            "at": self.at,
            "token": self.token,
        }


class ApprovalBackend(Protocol):
    name: str

    async def ask(self, request: ApprovalRequest, ctx: Any | None) -> ApprovalDecision: ...


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #


@dataclass
class ElicitationResponse:
    """Flat primitive schema — what the MCP elicitation spec permits."""

    approve: bool
    note: str = ""
    remember_for_this_target: bool = False


class ElicitationBackend:
    """Ask the MCP client to prompt the operator."""

    name = "elicitation"

    def __init__(self, timeout: float = 300.0, *, fallback: ApprovalBackend | None = None) -> None:
        self.timeout = timeout
        # Used when the connected client cannot elicit. Defaults to refusal.
        self.fallback = fallback or DenyBackend(
            reason="client does not support elicitation; set approval.backend to 'pending'"
        )

    async def ask(self, request: ApprovalRequest, ctx: Any | None) -> ApprovalDecision:
        if ctx is None or not hasattr(ctx, "elicit"):
            return await self.fallback.ask(request, ctx)
        try:
            result = await asyncio.wait_for(
                ctx.elicit(request.prompt(), response_type=ElicitationResponse),
                timeout=self.timeout,
            )
        except TimeoutError:
            return ApprovalDecision(
                Decision.DECLINE, approver="timeout", note=f"no response within {self.timeout:g}s"
            )
        except Exception as exc:  # noqa: BLE001 — any client failure is a refusal
            return await self.fallback.ask(request, ctx) if self.fallback else ApprovalDecision(
                Decision.DECLINE, approver="error", note=f"elicitation failed: {exc}"
            )

        action = getattr(result, "action", None)
        if action == "decline":
            return ApprovalDecision(Decision.DECLINE, approver="human", note="declined")
        if action == "cancel":
            return ApprovalDecision(Decision.CANCEL, approver="human", note="cancelled")

        data = getattr(result, "data", None)
        approve = bool(getattr(data, "approve", False)) if data is not None else False
        note = getattr(data, "note", "") or None
        remember = bool(getattr(data, "remember_for_this_target", False))
        return ApprovalDecision(
            Decision.ACCEPT if approve else Decision.DECLINE,
            approver="human",
            note=note,
            remember=remember and approve,
        )


class DenyBackend:
    """Refuse everything. The right default for unattended runs."""

    name = "deny"

    def __init__(self, reason: str = "approval backend is 'deny'") -> None:
        self.reason = reason

    async def ask(self, request: ApprovalRequest, ctx: Any | None) -> ApprovalDecision:
        return ApprovalDecision(Decision.DECLINE, approver="policy", note=self.reason)


class PolicyBackend:
    """Config-driven decisions, no human present.

    Only tools explicitly named in ``auto_approve`` run; everything else is
    refused. An empty allowlist therefore behaves exactly like ``DenyBackend``.
    """

    name = "policy"

    def __init__(self, auto_approve: list[str] | None = None, auto_deny: list[str] | None = None) -> None:
        self.auto_approve = set(auto_approve or [])
        self.auto_deny = set(auto_deny or [])
        # A tool in both lists is a config that contradicts itself. Deny wins
        # because deny is checked first, but that is an accident of ordering
        # rather than a decision anybody made, and an operator reading the file
        # cannot tell which list is in force. Resolve it toward safety and say
        # so out loud — silently picking one is how a config stops describing
        # what the system does.
        both = self.auto_approve & self.auto_deny
        if both:
            self.auto_approve -= both
            log.warning(
                "approval.policy: %s appear in BOTH auto_approve and auto_deny; "
                "treating them as DENIED. Remove them from auto_approve to make "
                "the config say what it does.",
                ", ".join(sorted(both)),
            )

    async def ask(self, request: ApprovalRequest, ctx: Any | None) -> ApprovalDecision:
        if request.tool in self.auto_deny:
            return ApprovalDecision(
                Decision.DECLINE, approver="policy", note="tool is in approval.policy.auto_deny"
            )
        if request.tool in self.auto_approve:
            return ApprovalDecision(
                Decision.ACCEPT, approver="policy", note="tool is in approval.policy.auto_approve"
            )
        return ApprovalDecision(
            Decision.DECLINE, approver="policy", note="not in approval.policy.auto_approve"
        )


@dataclass
class _Pending:
    request: ApprovalRequest
    created: float
    future: asyncio.Future[ApprovalDecision]


class PendingBackend:
    """Poll-style gate for clients without elicitation.

    Parks the call, hands back a token, and waits for ``approval_respond``. The
    tool call itself surfaces ``approval_required`` to the agent immediately if
    ``block`` is false, which keeps the MCP session responsive during long waits.
    """

    name = "pending"

    def __init__(self, timeout: float = 300.0, *, block: bool = True) -> None:
        self.timeout = timeout
        self.block = block
        self._pending: dict[str, _Pending] = {}

    async def ask(self, request: ApprovalRequest, ctx: Any | None) -> ApprovalDecision:
        token = "apr_" + secrets.token_urlsafe(12)
        loop = asyncio.get_running_loop()
        entry = _Pending(request=request, created=time.monotonic(), future=loop.create_future())
        self._pending[token] = entry

        if not self.block:
            return ApprovalDecision(Decision.PENDING, approver="pending", token=token)
        try:
            return await asyncio.wait_for(entry.future, timeout=self.timeout)
        except TimeoutError:
            return ApprovalDecision(
                Decision.DECLINE,
                approver="timeout",
                note=f"no response within {self.timeout:g}s",
                token=token,
            )
        finally:
            self._pending.pop(token, None)

    def respond(self, token: str, decision: Decision, *, note: str | None = None, approver: str = "human") -> bool:
        entry = self._pending.get(token)
        if entry is None:
            return False
        result = ApprovalDecision(decision, approver=approver, note=note, token=token)
        if not entry.future.done():
            entry.future.set_result(result)
        return True

    def list_pending(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        return [
            {"token": token, "waiting_seconds": round(now - e.created, 1), **e.request.to_dict()}
            for token, e in self._pending.items()
        ]


def build_backend(config: dict[str, Any] | None) -> ApprovalBackend:
    """Construct the configured backend. Unknown names fail closed to ``deny``."""
    config = config or {}
    name = str(config.get("backend") or "deny").lower()
    timeout = float(config.get("timeout") or 300)
    if name == "elicitation":
        return ElicitationBackend(timeout=timeout, fallback=PendingBackend(timeout=timeout))
    if name == "pending":
        return PendingBackend(timeout=timeout, block=bool(config.get("block", True)))
    if name == "policy":
        policy = config.get("policy") or {}
        return PolicyBackend(policy.get("auto_approve"), policy.get("auto_deny"))
    return DenyBackend(reason=f"unknown approval backend {name!r}; failing closed")


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #


class ApprovalGate:
    """Single entry point for every aggressive call."""

    def __init__(
        self,
        backend: ApprovalBackend,
        *,
        scope: Scope | None = None,
        remember_ttl: float = 0.0,
    ) -> None:
        self.backend = backend
        self.scope = scope
        self.remember_ttl = float(remember_ttl)
        self._remembered: dict[str, tuple[float, ApprovalDecision]] = {}
        self.history: list[dict[str, Any]] = []

    def _cached(self, request: ApprovalRequest) -> ApprovalDecision | None:
        if self.remember_ttl <= 0:
            return None
        entry = self._remembered.get(request.key())
        if entry is None:
            return None
        expires, decision = entry
        if time.monotonic() > expires:
            self._remembered.pop(request.key(), None)
            return None
        return decision

    async def require(self, request: ApprovalRequest, ctx: Any | None = None) -> ApprovalDecision:
        """Obtain approval or raise.

        Order matters: a program that forbids aggressive testing is refused before
        a human is ever asked, so nobody can approve something the authorization
        artifact does not permit.
        """
        if self.scope is not None:
            rules = self.scope.rules
            if request.mode in {"aggressive", "exploit"} and not rules.allow_aggressive:
                raise ApprovalDenied(
                    "engagement rules forbid aggressive actions (scope.rules.allow_aggressive)",
                    tool=request.tool,
                    mode=request.mode,
                )
            if request.mode == "exploit" and not rules.allow_exploitation:
                raise ApprovalDenied(
                    "engagement rules forbid exploitation (scope.rules.allow_exploitation)",
                    tool=request.tool,
                    mode=request.mode,
                )

        cached = self._cached(request)
        if cached is not None:
            decision = ApprovalDecision(
                cached.decision,
                approver=cached.approver,
                note="reusing a remembered approval for this tool+target",
                remember=True,
            )
        else:
            decision = await self.backend.ask(request, ctx)
            if decision.accepted and decision.remember and self.remember_ttl > 0:
                self._remembered[request.key()] = (
                    time.monotonic() + self.remember_ttl,
                    decision,
                )

        self.history.append({"request": request.to_dict(), "decision": decision.to_dict()})

        if decision.decision is Decision.PENDING:
            raise ApprovalRequired(
                "human approval required; resolve it with approval_respond",
                tool=request.tool,
                token=decision.token,
                request=request.to_dict(),
            )
        if not decision.accepted:
            raise ApprovalDenied(
                f"human approval not granted for {request.tool} ({decision.decision.value})",
                tool=request.tool,
                decision=decision.decision.value,
                note=decision.note,
            )
        return decision

    def respond(self, token: str, decision: str, *, note: str | None = None) -> bool:
        """Resolve a parked request. Only meaningful for the ``pending`` backend."""
        backend = self.backend
        if isinstance(backend, ElicitationBackend):
            backend = backend.fallback  # type: ignore[assignment]
        if not isinstance(backend, PendingBackend):
            return False
        try:
            parsed = Decision(decision.lower())
        except ValueError:
            return False
        return backend.respond(token, parsed, note=note)

    def pending(self) -> list[dict[str, Any]]:
        backend = self.backend
        if isinstance(backend, ElicitationBackend):
            backend = backend.fallback  # type: ignore[assignment]
        return backend.list_pending() if isinstance(backend, PendingBackend) else []

    def stats(self) -> dict[str, Any]:
        accepted = sum(1 for h in self.history if h["decision"]["decision"] == "accept")
        return {
            "backend": self.backend.name,
            "requested": len(self.history),
            "accepted": accepted,
            "refused": len(self.history) - accepted,
            "remembered": len(self._remembered),
        }

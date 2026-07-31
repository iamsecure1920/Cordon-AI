"""Exception hierarchy.

Every control-plane refusal is an exception subclass carrying a machine-readable
``code`` and a ``details`` dict. The tool decorator turns these into structured
MCP errors *and* an audit record — a refusal is as much an engagement artifact as
a successful scan.
"""

from __future__ import annotations

from typing import Any


class EasyHuntError(Exception):
    """Base class. ``code`` is what ends up in the audit log and MCP payload."""

    code = "easyhunt_error"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": self.code, "message": self.message, **self.details}


class ConfigError(EasyHuntError):
    code = "config_error"


class ScopeError(EasyHuntError):
    code = "scope_error"


class OutOfScopeError(ScopeError):
    """Target is not covered by the authorization artifact, or is denied by it."""

    code = "out_of_scope"


class StaleScopeError(ScopeError):
    """Scope artifact is older than ``max_age_days`` and the run refuses to guess."""

    code = "stale_scope"


class SanitizeError(EasyHuntError):
    """Argument rejected. Never sanitized-and-run — rejected."""

    code = "argument_rejected"


class ApprovalRequired(EasyHuntError):
    """An aggressive call reached the gate and no human accepted it."""

    code = "approval_required"


class ApprovalDenied(ApprovalRequired):
    code = "approval_denied"


class BudgetExceeded(EasyHuntError):
    """An engagement ceiling (USD, wall clock, requests, tool seconds) was hit."""

    code = "budget_exceeded"


class RateLimited(EasyHuntError):
    code = "rate_limited"


class ToolUnavailable(EasyHuntError):
    """Binary/image/library for a wrapped tool is not installed."""

    code = "tool_unavailable"


class ToolFailed(EasyHuntError):
    code = "tool_failed"


class PluginError(EasyHuntError):
    code = "plugin_error"


class LLMError(EasyHuntError):
    code = "llm_error"


class PinMismatch(EasyHuntError):
    """A tool definition changed after being pinned (rug-pull detection)."""

    code = "pin_mismatch"

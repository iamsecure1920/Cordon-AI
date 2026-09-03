"""Typed output schemas for the MCP surface.

Agents need machine-readable results, not prose. Every schema here is a
pydantic model attached to its tool via FastMCP's ``output_schema=`` — the
client sees the shape before calling, and the response validates against it,
so a schema drift fails loudly at registration time instead of silently
changing what an agent parses.

Two rules for what belongs here:

* A schema must be the honest contract of its tool: every field the tool
  actually returns must be present (with ``None`` default when a run may
  legitimately omit it), and no field may promise what the tool does not
  deliver.
* Findings and assets stay dictionaries inside the payload (their real
  shape lives in ``cordon/knowledge/findings.py``); the schemas type the
  *envelope* — status, counts, lists — which is what a caller dispatches on.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = [
    "FindingDict",
    "ScopeVerdictDict",
    "ToolRunDict",
    "UntestedError",
    "ToolResult",
    "JobHandle",
    "ScopeCheckResult",
    "BrainRecallResult",
]

FindingDict = dict[str, Any]
ScopeVerdictDict = dict[str, Any]
ToolRunDict = dict[str, Any]


class UntestedError(BaseModel):
    """The envelope a tool returns when it could not run.

    ``untested: True`` is the machine-readable form of "absence is not a clean
    result" — a client can branch on it directly instead of pattern-matching
    prose.
    """

    ok: Literal[False] = False
    error: str = "tool_unavailable"
    untested: Literal[True] = True
    message: str = Field(description="Why the surface is UNTESTED, never 'clean'")
    tools: list[ToolRunDict] = Field(default_factory=list)


class ToolResult(BaseModel):
    """Common envelope for tool payloads (loose by design: tools vary)."""

    ok: bool
    tool: str | None = Field(default=None, description="Tool name, injected by the decorator")
    phase: str | None = Field(default=None, description="Phase name, injected by the decorator")
    complete: bool | None = Field(default=None, description="True = finished; False/None = partial")
    count: int | None = Field(default=None, description="Number of results, when meaningful")
    findings: list[FindingDict] = Field(default_factory=list)
    tools: list[ToolRunDict] = Field(default_factory=list)
    note: str | None = None
    next_step: str | None = None


class JobHandle(BaseModel):
    """What a long-running tool returns when it went to the background."""

    ok: Literal[True] = True
    job_id: str = Field(description="Poll with job_status / job_fetch / fetch_slice")
    completed: Literal[False] = False
    status: str | None = None
    progress: str | None = None
    next_step: str = Field(
        description="Always tells the caller how to collect the result"
    )


class ScopeCheckResult(BaseModel):
    ok: Literal[True] = True
    in_scope: list[str]
    out_of_scope: list[dict[str, Any]]
    verdicts: list[ScopeVerdictDict]


class BrainRecallResult(BaseModel):
    ok: Literal[True] = True
    vuln_class: str
    techniques: list[dict[str, Any]] = Field(
        description="Ranked techniques with weight, trials, hit ratio, confidence"
    )
    stats: dict[str, Any] = Field(default_factory=dict)

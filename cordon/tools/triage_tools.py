"""MCP tools for AI triage.

Triage is passive — it reads the findings store and sends distilled records to a
model. It touches no target, so it does not need approval. What it *cannot* do is
enforced in :mod:`cordon.llm.triage`: rank, downgrade, drop, escalate. Never
confirm.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cordon.control_plane.context import get_engagement
from cordon.errors import ConfigError
from cordon.knowledge.findings import Status
from cordon.llm.openrouter import LLMClient
from cordon.llm.triage import Taskflow, run_taskflow, seed_canaries
from cordon.tools.base import cordon_tool

__all__ = ["triage_findings", "triage_taskflows"]


def _taskflow_dir(engagement: Any) -> Path:
    return engagement.config.path("triage.taskflows_dir", "./taskflows") or Path("./taskflows")


@cordon_tool(
    phase="triage", mode="passive", targets_arg=None, timeout=1800,
    name="triage_findings", tags={"triage"}, estimated_requests=0,
)
async def triage_findings(
    taskflow: str | None = None,
    min_severity: str = "info",
    max_findings: int = 200,
) -> dict[str, Any]:
    """Run AI triage over candidate findings to cut false positives.

    Fabricated canary findings are mixed into the batch; a pass that "confirms"
    one has its verdicts weighted down, and the measurement is reported.

    Triage never confirms anything. Escalated findings go to validate_findings.
    """
    engagement = get_engagement()
    from cordon.knowledge.findings import Severity

    threshold = Severity.parse(min_severity).rank
    candidates = [
        f for f in engagement.findings.all()
        if f.status is Status.CANDIDATE and f.severity.rank >= threshold
    ][: max(1, min(max_findings, 500))]

    if not candidates:
        return {
            "ok": True,
            "triaged": 0,
            "message": "no candidate findings to triage — run a scan first",
        }

    name = taskflow or str(engagement.config.get("triage.default_taskflow", "default-triage.yaml"))
    path = _taskflow_dir(engagement) / name
    if not path.exists():
        available = sorted(p.name for p in _taskflow_dir(engagement).glob("*.y*ml"))
        raise ConfigError(
            f"taskflow {name!r} not found in {_taskflow_dir(engagement)}",
            available=available,
        )
    flow = Taskflow.load(path)

    client = LLMClient(engagement)
    if not client.enabled:
        return {
            "ok": False,
            "error": "llm_unavailable",
            "message": (
                "AI triage needs an OpenRouter API key ($OPENROUTER_API_KEY). "
                "Without one, triage the candidates by hand — the findings store "
                "and rule metadata are all there."
            ),
            "candidates": len(candidates),
        }

    if not bool(engagement.config.get("triage.canaries_enabled", True)):
        flow.canaries = 0

    return await run_taskflow(
        client, flow, candidates, engagement=engagement,
        canaries_enabled=flow.canaries > 0,
    )


@cordon_tool(
    phase="triage", mode="passive", targets_arg=None, timeout=60,
    name="triage_taskflows", tags={"triage"}, estimated_requests=0,
)
async def triage_taskflows() -> dict[str, Any]:
    """List available triage taskflows and their steps."""
    engagement = get_engagement()
    directory = _taskflow_dir(engagement)
    flows: list[dict[str, Any]] = []
    problems: list[dict[str, str]] = []

    for path in sorted(directory.glob("*.y*ml")):
        try:
            flow = Taskflow.load(path)
        except ConfigError as exc:
            problems.append({"file": path.name, "error": exc.message})
            continue
        flows.append(
            {
                "name": flow.name,
                "file": path.name,
                "description": flow.description,
                "canaries": flow.canaries,
                "steps": [
                    {
                        "name": s.name,
                        "role": s.role,
                        "tier": s.tier,
                        "filter": s.filter,
                        "allowed_verdicts": s.allowed_verdicts,
                    }
                    for s in flow.steps
                ],
            }
        )

    return {
        "ok": True,
        "directory": str(directory),
        "taskflows": flows,
        "rejected": problems,
        "note": "No taskflow may declare a 'confirm' verdict — the loader refuses it.",
    }


@cordon_tool(
    phase="triage", mode="passive", targets_arg=None, timeout=60,
    name="triage_canary_preview", tags={"triage"}, estimated_requests=0,
)
async def triage_canary_preview(count: int = 3) -> dict[str, Any]:
    """Show the fabricated canary findings triage would mix into a batch.

    Useful for confirming the decoys look plausible enough to be a real test. They
    always live on a ``.invalid`` host, which by RFC 2606 can never resolve.
    """
    canaries = seed_canaries(max(1, min(count, 10)))
    return {
        "ok": True,
        "canaries": [
            {"title": c.title, "asset": c.asset, "severity": c.severity.value} for c in canaries
        ],
        "note": (
            "These are never reported and are removed from the findings store after "
            "triage. A pass that keeps or escalates one is hallucinating, and its "
            "verdicts are weighted down accordingly."
        ),
    }

"""Strix — optional deep application exploitation, always sandboxed and gated.

Strix is an autonomous multi-agent pentester that develops and runs exploits.
That is exactly the capability this project treats most carefully, so it is:

* disabled by default (``engines.strix.enabled``),
* ``mode="exploit"``, meaning it is refused outright when the engagement forbids
  exploitation and otherwise stops for explicit human approval,
* run only inside the container sandbox — never on the host, with no host-network
  fallback, because the whole point of Strix is that it writes and executes code.

Even with the wrapper disabled, Strix's discipline is worth copying and is
implemented throughout EasyHunt: results are only ever "confirmed" when a
reproducible PoC validated them.
"""

from __future__ import annotations

import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Evidence, Finding, PoC, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool, guarded_run
from easyhunt.tools.common import register_spec
from easyhunt.util.parse import parse_jsonl

__all__ = ["strix_deep"]

SPEC = register_spec(
    ToolSpec(
        name="strix",
        binary="strix",
        image="usestrix/strix:latest",
        license="Apache-2.0",
        homepage="https://github.com/usestrix/strix",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="strix",
            allowed_flags={"--target", "--instruction", "--output", "--max-iterations", "--format"},
            value_patterns={
                "--target": re.compile(r"[A-Za-z0-9._:/-]{1,512}"),
                "--format": re.compile(r"json|jsonl"),
            },
            numeric_caps={"--max-iterations": 40},
            allow_positional=False,
            max_argv=16,
        ),
    )
)


def _ingest(engagement: Any, text: str) -> list[Finding]:
    """Import Strix results, honouring its own PoC gating.

    A Strix result that carries a validated PoC is imported as confirmed; one
    that does not is imported as needing manual review. We do not re-grade its
    judgement upward, and we never grade it upward on our own.
    """
    findings: list[Finding] = []
    for record in parse_jsonl(text):
        title = str(record.get("title") or record.get("name") or "Strix finding")
        asset = str(record.get("target") or record.get("url") or "")
        if not engagement.scope.check(asset).in_scope:
            engagement.audit.record("finding_dropped", reason="out_of_scope", asset=asset)
            continue

        finding = Finding(
            asset=asset,
            title=title,
            phase="exploit",
            severity=Severity.parse(record.get("severity")),
            status=Status.NEEDS_MANUAL_REVIEW,
            description=str(record.get("description") or ""),
            how_found="Strix autonomous exploitation agent",
            source_tool="strix",
            rule_id=str(record.get("id") or "strix"),
            confidence=0.6,
            evidence=[
                Evidence(
                    kind="log",
                    description="Strix agent transcript excerpt",
                    excerpt=str(record.get("evidence") or record)[:4000],
                )
            ],
            remediation=str(record.get("remediation") or ""),
            tags=["strix"],
        )

        reproduction = str(record.get("reproduction") or record.get("poc") or "").strip()
        observed = str(record.get("observed") or record.get("proof") or "").strip()
        if record.get("validated") and reproduction and observed:
            finding.confirm(
                PoC(
                    reproduction=reproduction,
                    expected_result=str(record.get("expected") or "Vulnerability reproduces"),
                    observed_result=observed,
                    tool="strix",
                    validated_by="strix",
                    impact_limit_note="Imported from Strix; re-run before submitting.",
                )
            )
        else:
            finding.note("Strix did not attach a validated PoC — manual review required.")

        engagement.findings.add(finding)
        findings.append(finding)
    return findings


async def _run(job: Job, *, target: str, instruction: str, max_iterations: int) -> dict[str, Any]:
    engagement = get_engagement()
    job.progress = "running strix agent"
    result = await guarded_run(
        SPEC,
        [
            "--target", target,
            "--instruction", instruction,
            "--max-iterations", str(max_iterations),
            "--format", "jsonl",
        ],
        timeout=7200,
        output_name="strix",
        engagement=engagement,
        check=False,
    )
    findings = _ingest(engagement, result.stdout)
    engagement.findings.save()
    return {
        "ok": True,
        "target": target,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "count": len(findings),
        "confirmed": sum(1 for f in findings if f.status is Status.CONFIRMED),
        "needs_review": sum(1 for f in findings if f.status is Status.NEEDS_MANUAL_REVIEW),
        "findings": [f.to_dict() for f in findings],
        "note": (
            "Strix findings imported as-is. Re-run each PoC yourself before "
            "submitting — importing someone else's validation is not validation."
        ),
    }


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=7200,
    name="strix_deep",
    spec=SPEC,
    tags={"engine", "optional", "exploitation"},
    estimated_requests=2000,
    risk_notes=[
        "Autonomously develops and executes exploit code against the target.",
        "Runs only inside the container sandbox; there is no host fallback.",
        "Highest-impact tool in EasyHunt — approve only for a target you are certain of.",
    ],
)
async def strix_deep(
    target: str,
    instruction: str = "Find and validate exploitable vulnerabilities. Prove each with a minimal PoC.",
    max_iterations: int = 20,
) -> dict[str, Any]:
    """Delegate deep application exploitation to Strix, then ingest its results.

    Disabled by default. Requires exploitation to be permitted by the engagement
    and explicit human approval per call.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.strix.enabled", False):
        raise ToolUnavailable(
            "strix engine is disabled. Enable engines.strix.enabled only for a target "
            "where autonomous exploitation is explicitly authorized.",
            tool="strix",
        )

    # No host fallback: an agent that writes and runs exploit code stays in a
    # container even if that means the tool is simply unavailable.
    if engagement.sandbox.config.mode != "docker" or not engagement.sandbox.runtime_available():
        raise ToolUnavailable(
            "strix requires the container sandbox (sandbox.mode: docker with a working "
            "runtime). It is never run on the host.",
            tool="strix",
        )

    job = engagement.jobs.launch(
        lambda j: _run(j, target=target, instruction=instruction, max_iterations=max_iterations),
        tool="strix_deep",
        phase="exploit",
        targets=[target],
    )
    return {
        "job_id": job.id,
        "completed": False,
        "next_step": f"Poll job_status('{job.id}'). Strix runs for a long time.",
    }

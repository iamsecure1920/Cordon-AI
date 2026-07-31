"""Osmedeus — optional declarative flow orchestration.

Behind a feature flag (``engines.osmedeus.enabled``) because it overlaps heavily
with BBOT plus Nuclei for most engagements. It earns its place when you want
declarative YAML flows with conditional branching, or distributed workers across
several machines.

EasyHunt runs a *named flow from a reviewed directory*, never an arbitrary path.
An Osmedeus flow can execute shell commands, so accepting a caller-supplied flow
file would hand the agent an arbitrary-execution primitive dressed up as YAML.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.errors import ToolUnavailable
from easyhunt.tools.base import ToolSpec, easyhunt_tool, guarded_run
from easyhunt.tools.common import register_spec

__all__ = ["osmedeus_flow"]

SPEC = register_spec(
    ToolSpec(
        name="osmedeus",
        binary="osmedeus",
        license="MIT",
        homepage="https://github.com/j3ssie/osmedeus",
        version_args=["version"],
        arg_policy=ArgPolicy(
            tool="osmedeus",
            allowed_flags={"-f", "-t", "-T", "-w", "--threads-hold", "-o"},
            value_patterns={
                # Flow names only — no paths, no traversal.
                "-f": re.compile(r"[a-z0-9._-]{1,64}"),
                "-t": re.compile(r"[A-Za-z0-9._:/-]{1,253}"),
            },
            numeric_caps={"--threads-hold": 20},
            allow_positional=True,
            positional_pattern=re.compile(r"scan|-.*"),
            max_argv=24,
        ),
    )
)


def _available_flows(engagement: Any) -> dict[str, Path]:
    directory = engagement.config.path("engines.osmedeus.flows_dir", "./rules/osmedeus")
    if directory is None or not Path(directory).is_dir():
        return {}
    return {p.stem: p for p in sorted(Path(directory).glob("*.y*ml"))}


async def _run(job: Job, *, targets: list[str], flow: str) -> dict[str, Any]:
    engagement = get_engagement()
    output_dir = engagement.workspace / "osmedeus" / job.id
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for index, target in enumerate(targets, start=1):
        job.progress = f"flow '{flow}' on {target} ({index}/{len(targets)})"
        result = await guarded_run(
            SPEC,
            ["scan", "-f", flow, "-t", target, "-o", str(output_dir)],
            timeout=5400,
            output_name="osmedeus",
            engagement=engagement,
            check=False,
        )
        results.append(
            {
                "target": target,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stdout_tail": result.stdout[-4000:],
                "stderr_tail": result.stderr[-2000:],
            }
        )

    return {
        "ok": True,
        "flow": flow,
        "output_dir": str(output_dir),
        "runs": results,
        "note": (
            "Osmedeus writes its own workspace layout. Findings are not "
            "auto-ingested — review the output directory and file anything real "
            "through the findings store."
        ),
    }


@easyhunt_tool(
    phase="recon",
    mode="aggressive",
    targets_arg="target",
    timeout=5400,
    name="osmedeus_flow",
    spec=SPEC,
    tags={"engine", "optional"},
    estimated_requests=1000,
    risk_notes=[
        "Runs a full multi-tool workflow; traffic volume depends on the flow.",
        "Flows can chain active scanners — review the flow file before approving.",
    ],
)
async def osmedeus_flow(target: str, flow: str = "general") -> dict[str, Any]:
    """Run a named Osmedeus flow from the reviewed flows directory.

    Only flows present in engines.osmedeus.flows_dir may be run — arbitrary flow
    paths are refused because an Osmedeus flow can execute shell commands.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.osmedeus.enabled", False):
        raise ToolUnavailable(
            "osmedeus engine is disabled (set engines.osmedeus.enabled: true)", tool="osmedeus"
        )

    flows = _available_flows(engagement)
    if flow not in flows:
        raise ToolUnavailable(
            f"flow {flow!r} not found in the reviewed flows directory. Available: "
            f"{sorted(flows) or '(none)'}",
            tool="osmedeus",
            available=sorted(flows),
        )

    targets = [t.strip() for t in target.replace("\n", ",").split(",") if t.strip()]
    job = engagement.jobs.launch(
        lambda j: _run(j, targets=targets, flow=flow),
        tool="osmedeus_flow",
        phase="recon",
        targets=targets,
    )
    return {
        "job_id": job.id,
        "completed": False,
        "flow": flow,
        "next_step": f"Poll job_status('{job.id}'); Osmedeus flows run for a long time.",
    }

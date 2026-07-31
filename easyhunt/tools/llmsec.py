"""LLM red-teaming — for when the *target* embeds an AI feature.

Distinct from everything else in EasyHunt: here the model under test belongs to
the target, not to us. A support chatbot, an AI search box, a document
summarizer, an agent with tool access — each is an attack surface with its own
failure modes, and none of them are covered by a web scanner.

What this tests, in rough order of what programs actually pay for:

* **Indirect prompt injection** — content the model ingests (a page, a document,
  a ticket) carrying instructions it then follows. The high-impact case, because
  the attacker never talks to the model directly.
* **Tool/function abuse** — an agent that can be talked into calling its tools
  with attacker-chosen arguments. This is where LLM bugs become RCE, SSRF, or
  IDOR by another route.
* **System prompt and context leakage** — extracting instructions, keys, or
  other users' data from context.
* **Jailbreaks and guardrail bypass** — usually the *lowest* value finding
  unless it unlocks something concrete. "I made it say a rude word" is not a
  vulnerability; "I made it disclose another customer's order history" is.

Everything here is aggressive and gated, and two rules apply that the scanners
themselves do not enforce:

* **Test only the target's own AI surface**, named in scope like any other asset.
* **Prove impact, not misbehaviour.** A model that can be made to say something
  odd is a curiosity. A model that can be made to *do* something — read another
  tenant's data, call a tool with your arguments, leak a key — is a finding.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import register_spec, run_one, split_targets

__all__ = ["llm_probe_catalog", "llm_redteam", "llm_scan_config"]

GARAK = register_spec(
    ToolSpec(
        name="garak", binary="garak", package="garak", license="Apache-2.0",
        homepage="https://github.com/NVIDIA/garak", version_args=["--version"],
        identity_marker="garak",
        arg_policy=ArgPolicy(
            tool="garak",
            allowed_flags={
                "--model_type", "--model_name", "--probes", "--detectors",
                "--report_prefix", "--generations", "--parallel_attempts",
                "--config", "--verbose", "--narrow_output", "--generator_option_file",
            },
            boolean_flags={"--verbose", "--narrow_output"},
            value_patterns={
                "--model_type": re.compile(r"[a-z0-9._-]{1,64}"),
                "--model_name": re.compile(r"[A-Za-z0-9._:/-]{1,256}"),
                "--probes": re.compile(r"[A-Za-z0-9,._-]{1,300}"),
                "--detectors": re.compile(r"[A-Za-z0-9,._-]{1,300}"),
            },
            numeric_caps={"--generations": 10, "--parallel_attempts": 8},
        ),
    )
)

PROMPTFOO = register_spec(
    ToolSpec(
        name="promptfoo", binary="promptfoo", license="MIT",
        homepage="https://github.com/promptfoo/promptfoo", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="promptfoo",
            allowed_flags={"-c", "--config", "-o", "--output", "--no-progress-bar", "--max-concurrency"},
            boolean_flags={"--no-progress-bar"},
            numeric_caps={"--max-concurrency": 8},
            allow_positional=True,
            positional_pattern=re.compile(r"eval|redteam|run|scan"),
        ),
    )
)

DEEPTEAM = register_spec(
    ToolSpec(
        name="deepteam", binary="deepteam", package="deepteam", license="Apache-2.0",
        homepage="https://github.com/confident-ai/deepteam", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="deepteam",
            allowed_flags={"run", "-c", "--config", "-o", "--output"},
            allow_positional=True,
            positional_pattern=re.compile(r"run|[A-Za-z0-9._/-]{1,256}"),
        ),
    )
)

# Probe families EasyHunt will run, mapped to what a finding from each is worth.
# Ordered by the impact a real program tends to assign.
PROBE_FAMILIES: dict[str, dict[str, Any]] = {
    "indirect-injection": {
        "garak": "promptinject,latentinjection",
        "severity": Severity.HIGH,
        "why": (
            "Content the model ingests carries instructions it then follows. The "
            "attacker never speaks to the model directly, so this reaches users "
            "who never interacted with them."
        ),
    },
    "tool-abuse": {
        "garak": "latentinjection,xss",
        "severity": Severity.CRITICAL,
        "why": (
            "An agent with tools can be steered into calling them with "
            "attacker-chosen arguments — the path from 'chatbot bug' to SSRF, "
            "IDOR, or command execution."
        ),
    },
    "context-leak": {
        "garak": "leakreplay,divergence",
        "severity": Severity.HIGH,
        "why": "System instructions, keys, or other users' data recoverable from context.",
    },
    "output-handling": {
        "garak": "xss,malwaregen",
        "severity": Severity.HIGH,
        "why": (
            "Model output rendered without escaping — the model becomes an "
            "injection vector into the surrounding application."
        ),
    },
    "jailbreak": {
        "garak": "dan,encoding",
        "severity": Severity.LOW,
        "why": (
            "Guardrail bypass. Usually low value on its own: report it when it "
            "unlocks a concrete capability, not because the model was rude."
        ),
    },
}


@easyhunt_tool(
    phase="llmsec", mode="passive", targets_arg=None, timeout=60,
    name="llm_probe_catalog", tags={"llmsec"}, estimated_requests=0,
    budget_exempt=True,
)
async def llm_probe_catalog() -> dict[str, Any]:
    """List the LLM probe families, what each tests, and how findings are graded.

    Read this before running llm_redteam. Choosing probes by impact rather than
    running everything is the difference between a report a program acts on and
    a list of jailbreak transcripts.
    """
    from easyhunt.tools.common import installed

    return {
        "ok": True,
        "families": {
            name: {
                "severity_if_proven": spec["severity"].value,
                "why_it_matters": spec["why"],
                "garak_probes": spec["garak"],
            }
            for name, spec in PROBE_FAMILIES.items()
        },
        "tools_installed": {
            name: installed(name) for name in ("garak", "promptfoo", "deepteam")
        },
        "guidance": (
            "Prioritize indirect-injection and tool-abuse. A jailbreak with no "
            "downstream capability is rarely worth a program's triage time; an "
            "indirect injection that reaches other users almost always is."
        ),
    }


def _parse_garak_report(text: str, *, target: str, family: str) -> list[dict[str, Any]]:
    """Extract failed probes from garak's JSONL report."""
    failures: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("entry_type") != "eval":
            continue
        total = record.get("total") or 0
        passed = record.get("passed") or 0
        if total and passed < total:
            failures.append(
                {
                    "probe": str(record.get("probe") or "unknown"),
                    "detector": str(record.get("detector") or ""),
                    "failed": total - passed,
                    "total": total,
                    "rate": round(1 - (passed / total), 3),
                    "family": family,
                    "target": target,
                }
            )
    return failures


@easyhunt_tool(
    phase="llmsec", mode="aggressive", targets_arg="target", timeout=3600,
    name="llm_redteam", tags={"llmsec"}, estimated_requests=500,
    risk_notes=[
        "Sends adversarial prompts to the target's AI feature.",
        "Consumes the target's model quota — that is real money to them.",
        "Some probes attempt to elicit harmful content from their model; check the program's policy first.",
        "Only run against an AI surface the program has put in scope.",
    ],
)
async def llm_redteam(
    target: str,
    family: str = "indirect-injection",
    model_type: str = "rest",
    generations: int = 3,
) -> dict[str, Any]:
    """Probe the target's AI feature with garak, one probe family at a time.

    family: indirect-injection (default), tool-abuse, context-leak,
    output-handling, or jailbreak. Run llm_probe_catalog first to choose.

    Results are candidates. An LLM probe failing is a behaviour, not yet an
    impact — see the note in the result for what a report needs.
    """
    engagement = get_engagement()
    endpoint = split_targets(target)[0]

    if family not in PROBE_FAMILIES:
        raise ToolUnavailable(
            f"unknown probe family {family!r}; call llm_probe_catalog for the list",
            tool="garak",
            available=sorted(PROBE_FAMILIES),
        )

    spec = PROBE_FAMILIES[family]
    prefix = engagement.raw_path(f"garak-{family}", "report")
    run = await run_one(
        "garak",
        [
            "--model_type", model_type,
            "--model_name", endpoint,
            "--probes", spec["garak"],
            "--generations", str(max(1, min(generations, 10))),
            "--parallel_attempts", str(max(1, engagement.scope.rules.max_concurrency)),
            "--report_prefix", str(prefix),
            "--narrow_output",
        ],
        timeout=3400,
        allow_codes=(0, 1),
    )

    if not run.ran:
        return {
            "ok": False,
            "error": "tool_unavailable",
            "message": (
                f"garak could not run ({run.error}). Install it with "
                "'pipx install garak'. Without it this surface is UNTESTED, not clean."
            ),
            "target": endpoint,
        }

    report_text = "\n".join(run.values)
    for candidate in (prefix.with_suffix(".report.jsonl"), prefix):
        if candidate.exists():
            report_text = candidate.read_text(encoding="utf-8", errors="replace")
            break

    failures = _parse_garak_report(report_text, target=endpoint, family=family)

    findings: list[Finding] = []
    for failure in failures:
        finding = Finding(
            asset=endpoint,
            title=f"LLM {family}: probe '{failure['probe']}' succeeded against the target model",
            phase="llmsec",
            severity=spec["severity"],
            status=Status.CANDIDATE,
            description=(
                f"{failure['failed']} of {failure['total']} attempts of probe "
                f"'{failure['probe']}' were not blocked. {spec['why']}"
            ),
            how_found=f"garak probe family '{family}' ({failure['probe']}/{failure['detector']})",
            source_tool="garak",
            rule_id=f"llm.{family}.{failure['probe']}",
            # LLM probes are non-deterministic; a single pass is weak evidence.
            confidence=min(0.6, 0.3 + failure["rate"] * 0.3),
            evidence=[
                Evidence(
                    kind="log",
                    description="garak evaluation record",
                    excerpt=json.dumps(failure, indent=1)[:1500],
                )
            ],
            remediation=(
                "Treat model output as untrusted input to whatever consumes it. "
                "Escape it before rendering, and never let it choose a tool call or "
                "its arguments without an authorization check that does not depend "
                "on the model. Input filtering alone is not a fix — it is the "
                "control this probe just defeated."
            ),
            tags=["llmsec", family],
            extra=failure,
        )
        finding.note(
            "LLM probes are non-deterministic. Reproduce this at least three times "
            "before reporting, and record the exact prompt and response."
        )
        engagement.findings.add(finding)
        findings.append(finding)

    engagement.findings.save()

    return {
        "ok": True,
        "target": endpoint,
        "family": family,
        "probes_run": spec["garak"],
        "failures": failures,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "tools": [run.to_dict()],
        "note": (
            "These are candidates. For an LLM finding to be worth reporting it needs "
            "a demonstrated consequence: data another user should not see, a tool "
            "call the attacker chose, or output that executes somewhere. Record the "
            "proof with poc_record() including the exact prompt and response."
        ),
    }


@easyhunt_tool(
    phase="llmsec", mode="aggressive", targets_arg="target", timeout=3600,
    name="llm_scan_config", tags={"llmsec"}, estimated_requests=300,
    risk_notes=[
        "Runs a promptfoo or deepteam suite you supply against the target's AI.",
        "Review the config before approving — it defines exactly what gets sent.",
    ],
)
async def llm_scan_config(target: str, config_path: str, engine: str = "promptfoo") -> dict[str, Any]:
    """Run a promptfoo or deepteam suite from a config inside the workspace.

    Use this when you have a target-specific test suite — application-aware
    probes almost always outperform generic ones, because they know what the
    feature is supposed to refuse.
    """
    engagement = get_engagement()
    endpoint = split_targets(target)[0]

    if engine not in {"promptfoo", "deepteam"}:
        return {"ok": False, "error": "bad_engine", "message": "engine must be promptfoo or deepteam"}

    from easyhunt.control_plane.sanitize import sanitize_path

    config = sanitize_path(
        config_path, workspace=engagement.workspace, name="config_path", must_exist=True
    )
    output = engagement.raw_path(engine, "json")

    argv = (
        ["redteam", "run", "-c", str(config), "-o", str(output), "--no-progress-bar"]
        if engine == "promptfoo"
        else ["run", "-c", str(config), "-o", str(output)]
    )
    run = await run_one(engine, argv, timeout=3400, allow_codes=(0, 1, 100))

    if not run.ran:
        return {
            "ok": False,
            "error": "tool_unavailable",
            "message": f"{engine} could not run ({run.error}) — this surface is UNTESTED.",
        }

    results: dict[str, Any] = {}
    if output.exists():
        try:
            results = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            results = {}

    return {
        "ok": True,
        "target": endpoint,
        "engine": engine,
        "config": str(config),
        "output": str(output) if output.exists() else None,
        "summary": results.get("results", {}).get("stats") if isinstance(results, dict) else None,
        "tools": [run.to_dict()],
        "note": (
            "Failed assertions are candidates. Reproduce each one, then record the "
            "prompt, the response, and the concrete consequence with poc_record()."
        ),
    }

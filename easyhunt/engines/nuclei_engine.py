"""Nuclei — the vulnerability core, and EasyHunt's primary rule DSL.

Wraps both template selection (``-t``, ``-tags``, ``-severity``) and workflows
(``-w``, conditional template chaining). Community templates and everything under
``rules/nuclei/`` are scanned together, so a user-authored template is a
first-class detection with no code change.

Three things are enforced here rather than left to the caller:

* The rate limit comes from ``scope.yaml`` and is not a caller-supplied argument.
  A tool argument the agent can set is a rate limit the agent can raise.
* ``dos``, ``fuzz``, and ``intrusive`` tags are excluded, and ``-itags`` (which
  re-enables them) is not on the argument allowlist.
* Every result lands as a *candidate*. Nuclei is a very good scanner and it is
  still not a PoC.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool, guarded_run
from easyhunt.tools.common import register_spec
from easyhunt.util.parse import parse_jsonl

log = logging.getLogger("easyhunt.engines.nuclei")

__all__ = ["nuclei_scan", "parse_nuclei_results"]

# Tags whose templates exist to break things, not to find things.
DENIED_TAGS = {"dos", "fuzz", "intrusive", "bruteforce", "brute-force"}

SPEC = register_spec(
    ToolSpec(
        name="nuclei",
        binary="nuclei",
        image="projectdiscovery/nuclei:latest",
        license="MIT",
        homepage="https://github.com/projectdiscovery/nuclei",
        version_args=["-version"],
        user_agent_flag="-H",
        arg_policy=ArgPolicy(
            tool="nuclei",
            allowed_flags={
                "-u", "-l", "-t", "-w", "-tags", "-etags", "-severity", "-es",
                "-rate-limit", "-c", "-timeout", "-retries", "-jsonl", "-silent",
                "-no-color", "-duc", "-nc", "-H", "-nh", "-ni", "-stats", "-me",
                "-disable-update-check", "-header", "-follow-redirects", "-mhe",
            },
            boolean_flags={
                "-jsonl", "-silent", "-no-color", "-duc", "-nc", "-stats", "-nh", "-ni",
                "-disable-update-check", "-follow-redirects",
            },
            # -itags is deliberately absent: it re-enables dos/fuzz/intrusive.
            denied_flags={"-itags", "-headless", "-proxy", "-si", "-interactsh-server"},
            value_patterns={
                "-severity": re.compile(r"[a-z,]+"),
                "-es": re.compile(r"[a-z,]+"),
                "-tags": re.compile(r"[a-z0-9,._-]+"),
                "-etags": re.compile(r"[a-z0-9,._-]+"),
            },
            numeric_caps={"-rate-limit": 150, "-c": 50, "-timeout": 60, "-retries": 3, "-mhe": 30},
            denied_values={"-tags": DENIED_TAGS},
            allow_positional=False,
            max_argv=64,
            relaxed_chars=frozenset("()"),
        ),
    )
)

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def parse_nuclei_results(text: str, *, phase: str = "vuln_scan") -> list[Finding]:
    """Turn Nuclei JSONL into normalized candidate findings."""
    findings: list[Finding] = []
    for record in parse_jsonl(text):
        info = record.get("info") or {}
        template_id = str(record.get("template-id") or record.get("templateID") or "unknown")
        matched = str(record.get("matched-at") or record.get("host") or "")
        severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)

        evidence: list[Evidence] = []
        if record.get("request"):
            evidence.append(
                Evidence(kind="request", description="Nuclei request", excerpt=str(record["request"])[:4000])
            )
        if record.get("response"):
            evidence.append(
                Evidence(kind="response", description="Nuclei response", excerpt=str(record["response"])[:4000])
            )
        if record.get("extracted-results"):
            evidence.append(
                Evidence(
                    kind="log",
                    description="Extracted values",
                    excerpt=", ".join(str(v) for v in record["extracted-results"])[:2000],
                )
            )

        classification = info.get("classification") or {}
        cvss_score = classification.get("cvss-score")

        findings.append(
            Finding(
                asset=matched,
                title=str(info.get("name") or template_id),
                phase=phase,
                severity=severity,
                status=Status.CANDIDATE,
                description=str(info.get("description") or "").strip(),
                how_found=f"Nuclei template '{template_id}' matched at {matched}",
                source_tool="nuclei",
                rule_id=template_id,
                cvss=float(cvss_score) if isinstance(cvss_score, (int, float)) else None,
                cvss_vector=classification.get("cvss-metrics"),
                # Scanner-grade confidence: enough to investigate, never enough
                # to report. Only a PoC moves this past 0.95.
                confidence=0.55 if severity.rank >= 3 else 0.45,
                evidence=evidence,
                remediation=str(info.get("remediation") or "").strip(),
                tags=[str(t) for t in (info.get("tags") or [])],
                references=[str(r) for r in (info.get("reference") or []) if r],
                extra={
                    "matcher_name": record.get("matcher-name"),
                    "type": record.get("type"),
                    "curl_command": record.get("curl-command"),
                    "template_path": record.get("template"),
                },
            )
        )
    return findings


def _template_args(engagement: Any, templates: list[str] | None, workflow: str | None) -> list[str]:
    """Resolve template/workflow selection, always including custom rules."""
    args: list[str] = []
    if workflow:
        args += ["-w", workflow]
        return args

    explicit = list(templates or [])
    for template in explicit:
        args += ["-t", template]

    # Custom templates from the rule layer always participate.
    from easyhunt.plugins.loader import get_registry

    custom_dirs = sorted({str(Path(p).parent) for p in get_registry().nuclei_paths()})
    for directory in custom_dirs:
        args += ["-t", directory]

    # The main library is included whenever the caller did not name specific
    # templates. This used to be an `if not args` fallback, which meant a single
    # custom rule silently *replaced* all 13,391 upstream templates: nuclei then
    # exited with "no templates provided for scan" for any tag the custom rule
    # did not carry. Custom rules add to the library, they do not stand in for it.
    if not explicit:
        configured = engagement.config.get("engines.nuclei.templates_dir")
        if configured:
            expanded = Path(str(configured)).expanduser()
            if expanded.is_dir():
                args += ["-t", str(expanded)]
    return args


async def _run(
    job: Job,
    *,
    targets: list[str],
    templates: list[str] | None,
    workflow: str | None,
    tags: str | None,
    severity: str,
    concurrency: int,
) -> dict[str, Any]:
    engagement = get_engagement()
    rules = engagement.scope.rules

    targets_file = engagement.workspace / "raw" / f"nuclei-targets-{job.id}.txt"
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    argv: list[str] = [
        "-l", str(targets_file),
        "-jsonl", "-silent", "-nc", "-duc", "-disable-update-check",
        # Rate limit and concurrency come from the engagement, not the caller.
        "-rate-limit", str(max(1, int(rules.max_rps))),
        "-c", str(max(1, min(concurrency, rules.max_concurrency))),
        "-severity", severity,
        # Excluded regardless of what the caller asked for.
        "-etags", ",".join(sorted(DENIED_TAGS)),
        "-timeout", "15",
        "-retries", "1",
    ]
    argv += _template_args(engagement, templates, workflow)
    if tags:
        argv += ["-tags", tags]

    job.progress = f"scanning {len(targets)} target(s)"
    result = await guarded_run(
        SPEC,
        argv,
        timeout=3600,
        output_name="nuclei",
        engagement=engagement,
        # Nuclei exits 1 when it finds nothing on some builds; that is not an error.
        allow_codes=(0, 1),
        check=False,
    )
    if result.timed_out:
        job.progress = "timed out"

    parsed = parse_nuclei_results(result.stdout)
    stored: list[Finding] = []
    dropped = 0
    for finding in parsed:
        # Third scope check: a template can follow a redirect off-scope.
        if engagement.scope.check(finding.asset).in_scope:
            engagement.findings.add(finding)
            stored.append(finding)
        else:
            dropped += 1
            engagement.audit.record(
                "finding_dropped", reason="out_of_scope", asset=finding.asset, rule=finding.rule_id
            )
    engagement.findings.save()
    job.events_seen = len(stored)

    by_severity: dict[str, int] = {}
    for finding in stored:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

    # Nuclei exits 1 both for "found nothing" and for fatal startup errors, so the
    # exit code alone cannot distinguish them. A [FTL] line means the scan never
    # ran — and reporting ok=True there turns "nuclei was misconfigured" into
    # "this estate is clean", which is the most expensive lie this tool can tell.
    fatal = ""
    for line in (result.stderr or "").splitlines():
        if "[FTL]" in line or "Could not run nuclei" in line:
            fatal = line.strip()
            break

    return {
        "ok": not fatal,
        "error": "nuclei_failed" if fatal else None,
        "message": (
            f"nuclei did not run: {fatal}. Zero findings here means UNTESTED, "
            "not clean."
        ) if fatal else None,
        "targets": len(targets),
        "raw_output": str(result.output_path) if result.output_path else None,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stderr_tail": result.stderr[-1000:] if result.stderr else "",
        # Counts reflect what was kept, not what the scanner printed.
        "count": len(stored),
        "dropped_out_of_scope": dropped,
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in sorted(stored, key=lambda f: -f.severity.rank)],
        # A timed-out scan covered an unknown fraction of the template set. It is
        # not a clean result and must never be summarized as one: nuclei works
        # through templates in order, so a kill at the wall clock means the tail
        # of the selection was never sent at all.
        "complete": not (result.timed_out or bool(fatal)),
        "coverage": "partial" if result.timed_out else ("none" if fatal else "full"),
        "note": (
            (
                "INCOMPLETE: killed at the execution timeout after covering an "
                "unknown fraction of the selected templates. "
                + (
                    "Zero findings here means UNTESTED, not clean — narrow the "
                    "template selection or raise the timeout and re-run."
                    if not stored
                    else "The findings below are real, but absence of others proves nothing."
                )
                + " "
            )
            if result.timed_out
            else ""
        ) + (
            "All results are CANDIDATES. Run triage, then validate the survivors "
            "with a PoC before any of them is reported as confirmed."
        ),
    }


@easyhunt_tool(
    phase="vuln_scan",
    mode="aggressive",
    targets_arg="target",
    timeout=3600,
    name="nuclei_scan",
    spec=SPEC,
    tags={"engine", "vuln"},
    estimated_requests=500,
    risk_notes=[
        "Sends template payloads directly to the target.",
        "Rate limited to the program's published ceiling, but still visible in logs.",
        "dos/fuzz/intrusive templates are excluded and cannot be re-enabled.",
    ],
)
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    workflow: str | None = None,
    tags: str | None = None,
    severity: str = "low,medium,high,critical",
    concurrency: int = 10,
    wait_seconds: float = 120.0,
) -> dict[str, Any]:
    """Scan in-scope targets with Nuclei templates or a workflow.

    templates: template files/dirs/ids to run. Custom rules under rules/nuclei/
    are always included. workflow: a workflow file for conditional chaining.
    tags: comma-separated template tags (dos/fuzz/intrusive are refused).

    Returns inline if it finishes within wait_seconds, otherwise a job_id.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.nuclei.enabled", True):
        raise ToolUnavailable("nuclei engine is disabled in config", tool="nuclei")

    if tags:
        requested = {t.strip().lower() for t in tags.split(",")}
        overlap = requested & DENIED_TAGS
        if overlap:
            raise ToolUnavailable(
                f"tags {sorted(overlap)} are disruptive and are never run by EasyHunt",
                tool="nuclei",
                tags=sorted(overlap),
            )

    targets = [t.strip() for t in target.replace("\n", ",").split(",") if t.strip()]
    job = engagement.jobs.launch(
        lambda j: _run(
            j,
            targets=targets,
            templates=templates,
            workflow=workflow,
            tags=tags,
            severity=severity,
            concurrency=concurrency,
        ),
        tool="nuclei_scan",
        phase="vuln_scan",
        targets=targets,
    )

    payload = await engagement.jobs.wait(job.id, timeout=max(0.0, min(wait_seconds, 300)))
    if payload.get("ready") and payload.get("ok"):
        return {"job_id": job.id, "completed": True, **payload["result"]}
    return {
        "job_id": job.id,
        "completed": False,
        "status": payload.get("status"),
        "progress": payload.get("progress"),
        "error": payload.get("error"),
        "next_step": (
            f"Still scanning. Poll job_status('{job.id}'), then pull results with "
            f"fetch_slice('{job.id}', path='findings', where='high|critical')."
        ),
    }

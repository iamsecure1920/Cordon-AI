"""Semgrep — plugin class D: static analysis over source-available targets.

The only engine here that reads code rather than sending packets, which makes it
the one genuinely **passive** scanner in the set: it runs against files already
in the engagement workspace and touches nothing belonging to the target.

Three things it is good for in a bug bounty context:

* **Source-available targets** — open-source components, published SDKs, or a
  repository the program has put in scope.
* **Infrastructure-as-code** — Terraform, CloudFormation, Kubernetes manifests,
  and CI configs, where a misconfiguration is a finding without any runtime.
* **Client-side bundles** — Semgrep's JavaScript rules find sinks that a regex
  scan over the same file cannot, because it parses rather than matches.

Semgrep runs offline (``--metrics=off``, no registry fetch) unless a config is
explicitly requested, so scanning a client's code does not ship it anywhere.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.control_plane.sanitize import ArgPolicy, sanitize_path
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool, guarded_run
from easyhunt.tools.common import register_spec

log = logging.getLogger("easyhunt.engines.semgrep")

__all__ = ["parse_semgrep_output", "semgrep_scan"]

SPEC = register_spec(
    ToolSpec(
        name="semgrep",
        binary="semgrep",
        image="semgrep/semgrep:latest",
        license="LGPL-2.1",
        homepage="https://github.com/semgrep/semgrep",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="semgrep",
            allowed_flags={
                "--config", "-c", "--json", "--output", "-o", "--quiet", "--metrics",
                "--timeout", "--max-target-bytes", "--jobs", "--severity",
                "--exclude", "--include", "--no-git-ignore", "--disable-version-check",
                "--error", "--max-memory", "--scan-unknown-extensions",
            },
            boolean_flags={
                "--json", "--quiet", "--no-git-ignore", "--disable-version-check",
                "--error", "--scan-unknown-extensions",
            },
            value_patterns={
                "--metrics": re.compile(r"on|off|auto"),
                "--severity": re.compile(r"INFO|WARNING|ERROR"),
                "--exclude": re.compile(r"[A-Za-z0-9._*/-]{1,120}"),
                "--include": re.compile(r"[A-Za-z0-9._*/-]{1,120}"),
            },
            numeric_caps={
                "--timeout": 300, "--jobs": 8, "--max-target-bytes": 10_000_000,
                "--max-memory": 8000,
            },
            allow_positional=True,
            positional_pattern=re.compile(r"scan|ci|[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)

# Semgrep severity → ours. Semgrep's ERROR is a finding, not a tool failure.
_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def parse_semgrep_output(text: str, *, workspace: Path | None = None) -> list[dict[str, Any]]:
    """Parse ``semgrep --json`` output into plain records."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []

    records: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = str(result.get("path") or "")
        # Report paths relative to the workspace: an absolute path leaks the
        # analyst's directory layout into a document the program will read.
        if workspace:
            try:
                path = str(Path(path).resolve().relative_to(Path(workspace).resolve()))
            except (ValueError, OSError):
                path = Path(path).name

        records.append(
            {
                "check_id": str(result.get("check_id") or "unknown"),
                "path": path,
                "line": (result.get("start") or {}).get("line"),
                "end_line": (result.get("end") or {}).get("line"),
                "severity": str(extra.get("severity") or "INFO").upper(),
                "message": str(extra.get("message") or "").strip(),
                "snippet": str(extra.get("lines") or "")[:1000],
                "cwe": metadata.get("cwe"),
                "owasp": metadata.get("owasp"),
                "confidence": str(metadata.get("confidence") or "").upper(),
                "references": [str(r) for r in (metadata.get("references") or [])][:5],
                "fix": extra.get("fix"),
            }
        )
    return records


def _configs(engagement: Any, requested: str | None) -> list[str]:
    """Resolve which rule sets to run. Local rules always participate."""
    configs: list[str] = []
    local = engagement.config.path("rules.semgrep_dir", "./rules/semgrep")
    if local and Path(local).is_dir() and any(Path(local).glob("*.y*ml")):
        configs.append(str(local))

    if requested:
        # Registry shorthands only (p/xxx, r/xxx) or a path inside the workspace.
        if re.fullmatch(r"[pr]/[A-Za-z0-9._-]{1,64}", requested):
            configs.append(requested)
        else:
            configs.append(
                str(sanitize_path(requested, workspace=engagement.workspace, name="config"))
            )
    elif not configs:
        configs.append("auto")
    return configs


async def _run(job: Job, *, scan_path: Path, configs: list[str], severity: str | None) -> dict[str, Any]:
    engagement = get_engagement()
    output = engagement.raw_path("semgrep", "json")

    argv: list[str] = ["scan", "--json", "--output", str(output), "--quiet"]
    for config in configs:
        argv += ["--config", config]
    # Never phone home with a client's source tree in scope.
    argv += [
        "--metrics", "off",
        "--disable-version-check",
        "--timeout", "120",
        "--jobs", str(max(1, min(engagement.scope.rules.max_concurrency, 8))),
        "--max-target-bytes", "5000000",
    ]
    if severity:
        argv += ["--severity", severity]
    argv.append(str(scan_path))

    job.progress = f"analyzing {scan_path.name} with {len(configs)} config(s)"
    result = await guarded_run(
        SPEC,
        argv,
        timeout=1800,
        output_name="semgrep",
        engagement=engagement,
        # 1 = findings present, 2 = partial failure but results still written.
        allow_codes=(0, 1, 2),
        check=False,
    )

    text = output.read_text(encoding="utf-8", errors="replace") if output.exists() else result.stdout
    records = parse_semgrep_output(text, workspace=engagement.workspace)

    findings: list[Finding] = []
    for record in records:
        finding = Finding(
            asset=f"{record['path']}:{record['line'] or '?'}",
            title=record["message"][:200] or record["check_id"],
            phase="vuln_scan",
            severity=_SEVERITY.get(record["severity"], Severity.LOW),
            status=Status.CANDIDATE,
            description=record["message"],
            how_found=f"Semgrep rule '{record['check_id']}' matched {record['path']}:{record['line']}",
            source_tool="semgrep",
            rule_id=record["check_id"],
            # Static analysis finds reachable-looking sinks, not proven exploits.
            # HIGH-confidence metadata nudges it, nothing more.
            confidence=0.6 if record["confidence"] == "HIGH" else 0.45,
            evidence=[
                Evidence(
                    kind="file",
                    description=f"{record['path']} lines {record['line']}–{record['end_line']}",
                    excerpt=record["snippet"],
                )
            ],
            remediation=(
                f"Suggested fix: {record['fix']}" if record.get("fix") else
                "Review the flagged sink and confirm the input reaching it is untrusted."
            ),
            references=record["references"],
            tags=["semgrep", "sast"] + ([str(record["owasp"])] if record.get("owasp") else []),
            extra={"cwe": record.get("cwe"), "owasp": record.get("owasp")},
        )
        finding.note(
            "Static finding. Confirm the code path is actually reachable in the "
            "deployed application before reporting — an unreachable sink is not a "
            "vulnerability."
        )
        engagement.findings.add(finding)
        findings.append(finding)

    engagement.findings.save()
    job.events_seen = len(findings)

    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

    return {
        "ok": True,
        "path": str(scan_path),
        "configs": configs,
        "count": len(findings),
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in findings[:200]],
        "report": str(output) if output.exists() else None,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "note": (
            "Static analysis produces candidates. The question a PoC has to settle "
            "is reachability: can untrusted input actually get to this sink in the "
            "deployed application?"
        ),
    }


@easyhunt_tool(
    phase="vuln_scan",
    mode="passive",
    targets_arg=None,
    timeout=1800,
    name="semgrep_scan",
    spec=SPEC,
    tags={"engine", "sast", "rules"},
    estimated_requests=0,
)
async def semgrep_scan(
    path: str = "source",
    config: str | None = None,
    severity: str | None = None,
    wait_seconds: float = 120.0,
) -> dict[str, Any]:
    """Run Semgrep (plugin class D) over source in the engagement workspace.

    Passive: reads files already fetched into the workspace and sends nothing to
    the target. Rules in rules/semgrep/ always participate; config may add a
    registry pack ('p/security-audit') or another workspace path.

    Use source_fetch first to bring a repository into the workspace.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.semgrep.enabled", True):
        raise ToolUnavailable("semgrep engine is disabled in config", tool="semgrep")

    scan_path = sanitize_path(path, workspace=engagement.workspace, name="path")
    if not scan_path.exists():
        return {
            "ok": False,
            "error": "path_not_found",
            "message": (
                f"{scan_path} does not exist. Bring code into the workspace with "
                "source_fetch(repo_url=...) first — Semgrep only reads what is already there."
            ),
        }

    configs = _configs(engagement, config)
    job = engagement.jobs.launch(
        lambda j: _run(j, scan_path=scan_path, configs=configs, severity=severity),
        tool="semgrep_scan",
        phase="vuln_scan",
        targets=[str(scan_path)],
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
        "next_step": f"Poll job_status('{job.id}'), then fetch_slice('{job.id}', path='findings').",
    }

"""Code audit: the white-box pre-recon deliverable.

For a source-available engagement, the fastest route to the attack surface is
the source itself. ``code_audit`` runs the two static tools that read code —
Semgrep (parsing rules over the source) and gitleaks (secret regexes over the
files, no git history) — and merges them into one structured deliverable:
``code-audit.json`` and ``code-audit.md`` in the workspace, plus a summary the
caller can act on before a single live request is made.

Three honest boundaries:

* **It reads only what is already in the workspace.** ``source_fetch`` is the
  separate, audited step that brings a repository in; this phase never fetches.
  With no source present it degrades to a clear "white-box phase, nothing to
  read" rather than pretending to have audited anything.
* **Semgrep hits are filed as CANDIDATE findings; gitleaks hits are not.**
  Semgrep's parsing rules find sinks nothing else in the pipeline will, so
  they belong in the findings store (reachability is a later question). A
  gitleaks regex hit is unvalidated, the secret-scanning phase owns that class,
  and a raw secret must not ride inside a report — so gitleaks results live in
  the deliverable, redacted, never in the findings store.
* **Everything the deliverable writes is redacted.** A secret value read from
  a client's source is exactly the thing that must not be copied into a
  document that may reach the program or a model context.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from cordon.control_plane.context import get_engagement
from cordon.control_plane.sanitize import sanitize_path
from cordon.engines.semgrep_engine import SPEC as SEMGREP_SPEC
from cordon.engines.semgrep_engine import parse_semgrep_output
from cordon.knowledge.findings import Evidence, Finding, Severity, Status
from cordon.tools.base import cordon_tool, guarded_run
from cordon.tools.secrets import GITLEAKS

log = logging.getLogger("cordon.tools.code_audit")

__all__ = ["code_audit"]

_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

#: Paths that add no signal and only inflate the audit (build output, vendored
#: dependencies, lockfiles). Mirrors what a human would skim past.
_NOISE = re.compile(
    r"(^|/)(node_modules|vendor|dist|build|\.git|__pycache__|\.next|target)/|"
    r"(package-lock\.json|yarn\.lock|poetry\.lock|go\.sum|Gemfile\.lock|\.min\.js)$"
)


def _redact(value: str) -> str:
    """A secret value is never written into the deliverable."""
    return "[redacted]"


def _parse_gitleaks(text: str) -> list[dict[str, Any]]:
    """Parse gitleaks JSON output into redacted records.

    Gitleaks emits an array of leak objects (``RuleID``, ``File``, ``Line``,
    ``Secret``, ``Match``, ...). The secret itself and its surrounding match
    are replaced with a marker; everything that identifies *where* the leak is
    survives.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    records: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        file = str(item.get("File") or item.get("file") or "")
        if _NOISE.search(file):
            continue
        records.append(
            {
                "rule": str(item.get("RuleID") or item.get("rule") or "unknown"),
                "description": str(item.get("Description") or ""),
                "file": file,
                "line": item.get("Line") or item.get("line"),
                "start_line": item.get("StartLine") or item.get("startLine"),
                "end_line": item.get("EndLine") or item.get("endLine"),
                "secret": _redact(str(item.get("Secret") or "")),
                "match": _redact(str(item.get("Match") or "")),
                "entropy": item.get("Entropy"),
                "tags": item.get("Tags") or [],
            }
        )
    return records


async def _run_semgrep(engagement: Any, scan_path: Path) -> list[dict[str, Any]]:
    """Semgrep over the source, returning parsed records (not findings yet)."""
    from cordon.engines.semgrep_engine import _configs

    configs = _configs(engagement, None)
    output = engagement.raw_path("code_audit_semgrep", "json")

    argv: list[str] = ["scan", "--json", "--output", str(output), "--quiet"]
    for config in configs:
        argv += ["--config", config]
    argv += [
        "--metrics", "off",
        "--disable-version-check",
        "--timeout", "120",
        "--jobs", str(max(1, min(engagement.scope.rules.max_concurrency, 8))),
        "--max-target-bytes", "5000000",
        str(scan_path),
    ]

    result = await guarded_run(
        SEMGREP_SPEC,
        argv,
        timeout=1800,
        output_name="code_audit_semgrep",
        engagement=engagement,
        allow_codes=(0, 1, 2),
        check=False,
    )
    text = (
        output.read_text(encoding="utf-8", errors="replace") if output.exists() else result.stdout
    )
    return parse_semgrep_output(text, workspace=engagement.workspace)


async def _run_gitleaks(engagement: Any, scan_path: Path) -> list[dict[str, Any]]:
    """gitleaks over the files (no git history), returning redacted records."""
    output = engagement.raw_path("code_audit_gitleaks", "json")
    argv = [
        "detect", "--source", str(scan_path),
        "--report-format", "json", "--report-path", str(output),
        "--no-banner", "--no-git",
    ]
    result = await guarded_run(
        GITLEAKS,
        argv,
        timeout=900,
        output_name="code_audit_gitleaks",
        engagement=engagement,
        # gitleaks exits 1 when leaks are found; that is a result, not a failure.
        allow_codes=(0, 1),
        check=False,
    )
    text = (
        output.read_text(encoding="utf-8", errors="replace") if output.exists() else result.stdout
    )
    return _parse_gitleaks(text)


def _surface_implications(records: list[dict[str, Any]]) -> list[str]:
    """What the static hits imply about the live attack surface.

    A semgrep finding is a reachability question, not an answer; but the *set*
    of sinks it names is a map of where the live engagement should spend its
    budget. This derives that map from the CWE/OWASP tags without claiming any
    finding is exploitable.
    """
    implications: list[str] = []
    cwes: dict[str, int] = {}
    paths: dict[str, int] = {}
    for record in records:
        cwe = record.get("cwe")
        if cwe:
            cwes[str(cwe)] = cwes.get(str(cwe), 0) + 1
        file = record.get("path")
        if file:
            top = file.split("/")[0] if "/" in file else "(root)"
            paths[top] = paths.get(top, 0) + 1
    for cwe, count in sorted(cwes.items(), key=lambda kv: -kv[1])[:5]:
        implications.append(f"{count} finding(s) tagged {cwe}")
    for top, count in sorted(paths.items(), key=lambda kv: -kv[1])[:5]:
        implications.append(f"{count} hit(s) in {top}/ — a focus area for live testing")
    if not implications:
        implications.append("No static sinks reached the severity threshold; "
                            "surface shaping should come from recon, not source.")
    return implications


def _render_markdown(
    *,
    source: str,
    semgrep: list[dict[str, Any]],
    gitleaks: list[dict[str, Any]],
    implications: list[str],
) -> str:
    lines = [
        "# Code audit deliverable",
        "",
        f"- **Source**: `{source}`",
        "- **Tools**: semgrep (parsing rules) + gitleaks (secret regexes, no history)",
        f"- **Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        "| Tool | Findings |",
        "| --- | --- |",
        f"| Semgrep (CANDIDATE, reachability unproven) | {len(semgrep)} |",
        f"| Gitleaks (redacted, unvalidated, not filed) | {len(gitleaks)} |",
        "",
        "## Attack-surface implications",
        "",
    ]
    lines += [f"- {item}" for item in implications]
    lines += ["", "## Semgrep findings", ""]
    if not semgrep:
        lines += ["_No findings at the configured severity._", ""]
    by_severity: dict[str, list[dict[str, Any]]] = {}
    for record in semgrep:
        by_severity.setdefault(record["severity"], []).append(record)
    for severity in ("ERROR", "WARNING", "INFO"):
        for record in by_severity.get(severity, []):
            lines += [
                f"### [{severity}] {record['message'][:160]}",
                "",
                f"- **Rule**: `{record['check_id']}`",
                f"- **Location**: `{record['path']}:{record['line']}`",
                f"- **CWE**: {record.get('cwe') or '—'} · **OWASP**: {record.get('owasp') or '—'}",
                "",
                "```",
                (record.get("snippet") or "")[:800],
                "```",
                "",
            ]
    lines += ["## Secrets (gitleaks, redacted)", ""]
    if not gitleaks:
        lines += ["_No secret-pattern hits._", ""]
    for record in gitleaks:
        lines += [
            f"- `{record['file']}:{record['line']}` — {record['rule']} "
            f"({record['description'][:80]})",
        ]
    lines += [
        "",
        "---",
        "Secrets are redacted in this document. Validate any gitleaks hit against "
        "the issuing service before acting on it; an unvalidated regex match is "
        "a candidate, not a credential.",
    ]
    return "\n".join(lines)


@cordon_tool(
    phase="vuln_scan",
    mode="passive",
    targets_arg=None,
    timeout=1800,
    name="code_audit",
    tags={"sast", "whitebox", "deliverable"},
    estimated_requests=0,
    risk_notes=[
        "Runs semgrep and gitleaks over source already in the workspace.",
        "Sends nothing to the target; reads local files only.",
    ],
    rationale=(
        "White-box pre-recon deliverable: semgrep parsing rules + gitleaks "
        "secret scan over source fetched into the workspace, merged into "
        "code-audit.json/.md with attack-surface implications. Passive; "
        "sends nothing."
    ),
)
async def code_audit(
    path: str = "source",
    wait_seconds: float = 300.0,
) -> dict[str, Any]:
    """Run the white-box code audit over source in the engagement workspace.

    Scans ``path`` (relative to the workspace, default ``source`` — the
    directory ``source_fetch`` clones into) with Semgrep's parsing rules and
    gitleaks, then writes a merged deliverable:

    * ``code-audit.json`` — structured, redacted records from both tools.
    * ``code-audit.md`` — human-readable audit with attack-surface
      implications.

    Semgrep hits are filed as CANDIDATE findings (reachability is a later
    question — static analysis finds sinks, not exploits). Gitleaks hits are
    redacted and kept in the deliverable only: unvalidated regex matches are
    not findings, and the secret-scanning phase owns that class.

    With no source in the workspace the phase reports ``count: 0`` — run
    ``source_fetch(repo_url=...)`` first and confirm the repository belongs to
    the program.
    """
    engagement = get_engagement()
    scan_path = sanitize_path(path, workspace=engagement.workspace, name="path")
    if not scan_path.exists():
        return {
            "ok": True,
            "count": 0,
            "path": str(scan_path),
            "message": (
                "no source in the workspace — this is the white-box phase. "
                "Run source_fetch(repo_url=...) first, confirm the repository "
                "belongs to the program, then re-run code_audit."
            ),
        }

    semgrep_records = await _run_semgrep(engagement, scan_path)
    gitleaks_records = await _run_gitleaks(engagement, scan_path)

    # File semgrep hits as candidates: nothing else in the pipeline would find
    # a parsing-level sink, so they belong in the findings store for the
    # reachability question later phases ask.
    findings: list[Finding] = []
    for record in semgrep_records:
        finding = Finding(
            asset=f"{record['path']}:{record['line'] or '?'}",
            title=record["message"][:200] or record["check_id"],
            phase="vuln_scan",
            severity=_SEVERITY.get(record["severity"], Severity.LOW),
            status=Status.CANDIDATE,
            description=record["message"],
            how_found=f"Code audit: Semgrep rule '{record['check_id']}' matched {record['path']}:{record['line']}",
            source_tool="semgrep",
            rule_id=record["check_id"],
            confidence=0.6 if record["confidence"] == "HIGH" else 0.45,
            evidence=[
                Evidence(
                    kind="file",
                    description=f"{record['path']} lines {record['line']}–{record['end_line']}",
                    excerpt=record["snippet"],
                )
            ],
            remediation=(
                f"Suggested fix: {record['fix']}" if record.get("fix")
                else "Review the flagged sink and confirm the input reaching it is untrusted."
            ),
            references=record["references"],
            tags=["semgrep", "sast", "code_audit"] + ([str(record["owasp"])] if record.get("owasp") else []),
            extra={"cwe": record.get("cwe"), "owasp": record.get("owasp")},
        )
        finding.note(
            "Static finding from the white-box audit. Confirm the code path is "
            "actually reachable in the deployed application before reporting."
        )
        findings.append(finding)
        engagement.findings.add(finding)
    engagement.findings.save()

    implications = _surface_implications(semgrep_records)

    deliverable_json = {
        "scope": engagement.scope.name,
        "source": str(scan_path),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "semgrep": len(semgrep_records),
            "gitleaks": len(gitleaks_records),
            "findings_filed": len(findings),
        },
        "implications": implications,
        "semgrep": semgrep_records,
        "gitleaks": gitleaks_records,
    }
    json_path = engagement.workspace / "code-audit.json"
    json_path.write_text(json.dumps(deliverable_json, indent=2, default=str), encoding="utf-8")
    md_path = engagement.workspace / "code-audit.md"
    md_path.write_text(
        _render_markdown(
            source=str(scan_path),
            semgrep=semgrep_records,
            gitleaks=gitleaks_records,
            implications=implications,
        ),
        encoding="utf-8",
    )

    by_severity: dict[str, int] = {}
    for record in semgrep_records:
        by_severity[record["severity"]] = by_severity.get(record["severity"], 0) + 1

    return {
        "ok": True,
        "path": str(scan_path),
        "count": len(semgrep_records) + len(gitleaks_records),
        "semgrep_count": len(semgrep_records),
        "gitleaks_count": len(gitleaks_records),
        "findings_filed": len(findings),
        "by_severity": by_severity,
        "implications": implications,
        "deliverables": {"json": str(json_path), "markdown": str(md_path)},
        "note": (
            "Semgrep hits are CANDIDATE findings awaiting a reachability check. "
            "Gitleaks hits are redacted in the deliverable and not filed — "
            "validate them against the issuing service before acting."
        ),
    }

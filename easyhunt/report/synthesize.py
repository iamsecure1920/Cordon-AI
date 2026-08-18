"""Report generation.

The report is the deliverable, and its structure encodes the project's central
rule. **Confirmed findings** come first, each with a reproduction a triager can
run without asking a question. **Needs manual review** is a separate section,
explicitly labelled unproven — never blended in to make the report look fuller.

Everything a reader needs to check the work is included: how each finding was
found (tool and rule id), the scope artifact that authorized the test, the tool
inventory with licenses and versions, the task graph showing why each step
happened, and the cost/coverage numbers.

The strong model only ever sees distilled findings. Raw tool output stays on disk
and is referenced by path.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easyhunt.knowledge.attackgraph import find_finding_chains
from easyhunt.knowledge.findings import Finding
from easyhunt.report.templates import (
    AUDIT_NOTE,
    CONFIRMED_INTRO,
    EMPTY_CONFIRMED,
    NEEDS_REVIEW_INTRO,
    NO_POC_NOTE,
    PARTIAL_BANNER,
    closing_statement,
    finding_header,
    poc_block,
    severity_guidance,
)

__all__ = ["generate_report"]

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _cvss_hint(finding: Finding) -> str:
    if finding.cvss:
        return f"{finding.cvss:.1f}" + (f" ({finding.cvss_vector})" if finding.cvss_vector else "")
    return "not scored"


def _finding_section(finding: Finding, index: int) -> str:
    lines = finding_header(finding, index)

    if finding.description:
        lines += ["**Description**", "", finding.description.strip(), ""]

    if finding.poc:
        lines += poc_block(finding.poc)
    else:
        lines += ["**Proof of concept**", "", NO_POC_NOTE, ""]

    if finding.evidence:
        lines += ["**Evidence**", ""]
        for evidence in finding.evidence[:5]:
            excerpt = (evidence.excerpt or "").strip()
            lines.append(f"- `{evidence.kind}` — {evidence.description or 'captured artifact'}")
            if excerpt:
                trimmed = excerpt[:600] + ("…" if len(excerpt) > 600 else "")
                lines += ["", "  ```", *(f"  {line}" for line in trimmed.splitlines()[:12]), "  ```"]
            if evidence.path:
                lines.append(f"  (full artifact: `{evidence.path}`)")
        lines.append("")

    if finding.triage_notes:
        lines += ["**Triage notes**", ""]
        lines += [f"- {note}" for note in finding.triage_notes[:6]]
        lines.append("")

    if finding.remediation:
        lines += ["**Remediation**", "", finding.remediation.strip(), ""]

    if finding.references:
        lines += ["**References**", ""]
        lines += [f"- {ref}" for ref in finding.references[:6]]
        lines.append("")

    return "\n".join(lines)


def _severity_table(findings: list[Finding]) -> str:
    counts = {name: 0 for name in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] += 1
    rows = ["| Severity | Count |", "| --- | --- |"]
    rows += [f"| {name.title()} | {counts[name]} |" for name in _SEVERITY_ORDER if counts[name]]
    return "\n".join(rows) if len(rows) > 2 else "_No findings._"


def chain_escalation_note(chains: list[Any]) -> str:
    """One sentence on how to use chain upgrades, written for the report."""
    if not chains:
        return ""
    total = len(chains)
    upgraded = sum(1 for c in chains if c.upgrade_to in {"high", "critical"})
    return (
        f"**{total} chain(s) matched; {upgraded} suggest a high-or-critical upgrade.** "
        "Re-read each chained finding with the chain in mind: the pair is the "
        "impact statement, and the suggested severity applies only if a human "
        "confirms the reachability (the XSS is actually exploitable, the SSRF "
        "really reaches metadata). Chain evidence alone never changes a status."
    )


def _markdown(engagement: Any, summary: dict[str, Any], executive: str) -> str:
    reportable = {f.id for f in engagement.findings.reportable()}
    reportable_findings = [f for f in engagement.findings.reportable()]
    confirmed = [f for f in engagement.findings.confirmed() if f.id in reportable]
    review = [f for f in engagement.findings.needs_review() if f.id in reportable]
    candidates = [f for f in engagement.findings.candidates() if f.id in reportable]
    excluded = engagement.findings.program_excluded()
    scope = engagement.scope

    parts: list[str] = [
        f"# Security Assessment — {scope.name}",
        "",
        f"*Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} by EasyHunt AI*",
        "",
        "## Authorization",
        "",
        f"- **Basis:** {scope.authorization}",
        f"- **Program policy:** {scope.engagement.get('program_url') or 'n/a'}",
        f"- **Scope artifact:** `{scope.source}` (fingerprint `{scope.fingerprint()}`)",
        f"- **Policy last read:** {scope.engagement.get('fetched_at') or 'not recorded'}"
        + (f" ({scope.age_days():.1f} days ago)" if scope.age_days() is not None else ""),
        f"- **Researcher:** {scope.researcher_handle or 'not recorded'}",
        "",
        "## Executive summary",
        "",
        executive.strip() or "_No summary generated._",
        "",
        "### Findings by severity",
        "",
        _severity_table(engagement.findings.all()),
        "",
        f"- **Confirmed (reproducible PoC):** {len(confirmed)}",
        f"- **Needs manual review (unproven):** {len(review)}",
        f"- **Untriaged candidates:** {len(candidates)}",
        "",
    ]

    parts += ["---", "", "## Confirmed findings", ""]
    if confirmed:
        parts += [CONFIRMED_INTRO, ""]
        for index, finding in enumerate(confirmed, start=1):
            parts.append(_finding_section(finding, index))
    else:
        parts += [EMPTY_CONFIRMED, ""]

    parts += ["---", "", "## Needs manual review", ""]
    if review:
        parts += [NEEDS_REVIEW_INTRO, ""]
        for index, finding in enumerate(review, start=1):
            parts.append(_finding_section(finding, index))
    else:
        parts += ["_Nothing outstanding._", ""]

    if candidates:
        parts += ["---", "", "## Untriaged candidates", "", "| Severity | Asset | Title | Source |", "| --- | --- | --- | --- |"]
        for finding in candidates[:100]:
            title = finding.title.replace("|", "\\|")[:80]
            parts.append(
                f"| {finding.severity.value} | `{finding.asset[:60]}` | {title} | {finding.source_tool} |"
            )
        if len(candidates) > 100:
            parts.append(f"| … | | {len(candidates) - 100} more in findings.json | |")
        parts.append("")

    parts += ["---", "", "## Finding chains", ""]

    chains = find_finding_chains(reportable_findings)
    if chains:
        parts += [
            "Two or more findings on the same asset that together tell a higher-",
            "severity story than either alone. The upgrade is a suggestion for a ",
            "triager — chain evidence is not a status change by itself.",
            "",
            "| Pattern | Asset | Upgrade to | Findings |",
            "| --- | --- | --- | --- |",
        ]
        for chain in chains:
            titles = [f.title for f in chain.findings[:4]]
            parts.append(
                f"| {chain.name} | `{chain.asset[:60]}` | **{chain.upgrade_to}** | "
                f"{'; '.join(titles)[:120]} |"
            )
        parts += ["", chain_escalation_note(chains)]
    else:
        parts += [
            "_No cross-finding chains matched on the reportable findings._",
            "",
            "A chain needs two findings on the same asset (e.g. XSS + missing CSP).",
            "",
        ]

    parts += ["---", "", "## Scope", "",
        "```yaml",
        json.dumps(scope.summary(), indent=2, default=str),
        "```",
        "",
        "## Methodology",
        "",
        "Phases executed, in order, with every action recorded in `audit.log`:",
        "",
    ]
    phases = summary.get("taskgraph", {}).get("by_phase", {})
    if phases:
        parts += [f"- **{phase}** — {count} task(s)" for phase, count in phases.items()]
    else:
        parts.append("- (task graph empty — run driven directly rather than by the planner)")
    parts += [
        "",
        "The task graph below shows how each discovery created the work that followed.",
        "",
        "```mermaid",
        engagement.taskgraph.to_mermaid(max_nodes=40),
        "```",
        "",
        "## Tool inventory",
        "",
        "| Tool | Version | License | Used |",
        "| --- | --- | --- | --- |",
    ]
    for name, spec, version, used in _tool_inventory(engagement):
        parts.append(f"| {name} | {version} | {spec.license} | {'yes' if used else 'no'} |")

    parts += [
        "",
        "## Coverage",
        "",
        "```json",
        json.dumps(
            {
                "assets": summary.get("assets", {}),
                "rate_limit": summary.get("rate_limit", {}),
                "approvals": summary.get("approvals", {}),
                "jobs": summary.get("jobs", {}),
            },
            indent=2,
            default=str,
        ),
        "```",
        "",
        "### Vulnerability-class coverage (runtime ledger)",
        "",
    ]
    ledger = engagement.coverage
    ledger_rows = ledger.rows()
    if ledger_rows:
        parts += [
            "What this engagement actually touched, per class — as distinct from the",
            "static capability matrix. `not_attempted` means the class was not tested",
            "this run, which is an honest gap, not a clean bill.",
            "",
            "| Class | Status | Tool | Note |",
            "| --- | --- | --- | --- |",
        ]
        parts += [
            f"| {row['class']} | {row['status']} | {row.get('tool', '')} | "
            f"{str(row.get('note', ''))[:60]} |"
            for row in ledger_rows
        ]
        parts.append("")
        ledger_summary = ledger.summary()
        parts.append(
            f"**{ledger_summary['validated_or_disproven']}/{ledger_summary['tracked']} "
            "classes validated or disproven; "
            f"{ledger_summary['not_attempted']} not attempted; "
            f"{ledger_summary['detected']} detected but unproven.**"
        )
    else:
        parts.append(
            "_No runtime ledger records — the exploit chain (or a phase that writes "
            "coverage) has not run in this workspace._"
        )
    parts += [
        "",
        "## Audit trail",
        "",
        f"- Records: {len(engagement.audit.read_all())}",
        f"- Hash chain: {'intact' if engagement.audit.verify()[0] else 'BROKEN — investigate'}",
        f"- File: `{engagement.audit.path.name}`",
        "",
        AUDIT_NOTE,
        "",
        "## Severity rubric",
        "",
        "What each rating means in this report, so a reader can check it rather than",
        "take it on trust:",
        "",
    ] + [f"- **{k.title()}** — {v}" for k, v in severity_guidance().items()] + [
        "",
        "---",
        "",
        closing_statement(exploitation_ran=any(f.poc for f in engagement.findings.all())),
        "",
    ]
    if excluded:
        by_reason: dict[str, int] = {}
        for f in excluded:
            reason = str((f.extra or {}).get("program_exclusion", {}).get("reason", "unspecified"))
            by_reason[reason] = by_reason.get(reason, 0) + 1
        parts += [
            "",
            "## Withheld — classes this program does not accept",
            "",
            f"{len(excluded)} finding(s) matched the program's own published "
            "out-of-scope list and are not reported above. They are listed here so "
            "nothing is hidden, not because they are submittable.",
            "",
            "| n | The program's stated reason |",
            "| --- | --- |",
        ]
        parts += [f"| {n} | {reason} |" for reason, n in sorted(
            by_reason.items(), key=lambda kv: -kv[1]
        )]

    return "\n".join(parts)


#: Wrapper tool -> binaries it drives. The audit records binary_run events at
#: the guarded_run chokepoint, but engagements started before that instrumentation
#: (or wrappers that invoke binaries outside it) only have the wrapper's tool_call
#: event. Without this map, an inventory taken from such an audit would report
#: sqlmap/dalfox/commix/sstimap as "did not run" on the very engagement where the
#: exploit chain drove all of them. The map is the honest fallback: a wrapper
#: that completed ok marks every binary it is known to drive as used.
_WRAPPER_BINARIES: dict[str, tuple[str, ...]] = {
    # Verified against the wrappers' own run_one() calls; a binary listed here
    # is one the wrapper is known to invoke, so a wrapper success marks it used.
    "subdomain_enum": ("subfinder", "assetfinder", "findomain", "amass", "theHarvester"),
    "dns_resolve": ("dnsx", "dig"),
    "dns_permute": ("alterx", "dnsx"),
    "netblock_lookup": ("asnmap", "amass"),
    "whois_lookup": ("whois",),
    "http_probe": ("httpx",),
    "waf_detect": ("wafw00f",),
    "tls_audit": ("testssl", "tlsx"),
    "cors_audit": ("corscanner",),
    "endpoint_discovery": ("katana", "gau", "waybackurls", "waymore", "paramspider", "netsanitizer"),
    "js_analyze": ("linkfinder", "jsluice", "secretfinder"),
    "takeover_detect": ("subjack", "subzy", "dnsreaper", "nuclei"),
    "nuclei_scan": ("nuclei",),
    "content_discovery": ("ffuf",),
    "param_discovery": ("arjun",),
    "port_scan": ("naabu",),
    "service_scan": ("nmap",),
    "nikto_scan": ("nikto",),
    "wapiti_scan": ("wapiti",),
    "secret_scan": ("kingfisher", "noseyparker", "gitleaks"),
    "secret_validate": ("kingfisher",),
    "pattern_scan": ("gf",),
    "graphql_audit": ("graphql-cop",),
    "websocket_probe": ("websocat",),
    "cdn_check": ("cdncheck",),
    "ssrf_probe": ("ssrfmap",),
    "ssti_probe": ("sstimap",),
    "cmdi_probe": ("commix",),
    "smuggling_probe": ("smuggler",),
    "nosqli_probe": ("nosqli",),
    # sqli_validate and xss_validate are driven by the exploit chain, not by
    # standalone run_one calls, so they are listed under the chain below.
    "exploit_chain": ("sqlmap", "dalfox", "xsstrike"),
}


def _tool_inventory(engagement: Any) -> list[tuple[str, Any, str, bool]]:
    """Which tools exist, their licenses, and whether this run used them.

    Loads every capability module first: the catalog is populated by import side
    effects, so an inventory taken from a partially-imported process would
    silently omit tools — and the licenses column is exactly the part nobody
    should have to trust to import order.

    "Used" has two sources, both read from the audit: ``binary_run`` events
    (the binary itself executed) and ``tool_call`` events of wrappers that
    completed ok (whose driven binaries are resolved through
    ``_WRAPPER_BINARIES``). Either marks the tool; a wrapper success counts for
    its binaries even when no binary_run event was recorded (pre-instrumentation
    engagements).
    """
    from easyhunt.mcp_server import load_capabilities
    from easyhunt.tools.common import CATALOG, installed

    load_capabilities()

    used: set[str] = set()
    for record in engagement.audit.read_all():
        if record.get("event") == "tool_call" and record.get("outcome") == "ok":
            wrapper = str(record.get("tool"))
            used.add(wrapper)
            used.update(_WRAPPER_BINARIES.get(wrapper, ()))
        elif record.get("event") == "binary_run" and record.get("ran"):
            # The binary itself executed: subfinder, testssl, sqlmap... These
            # events are written by guarded_run, so a wrapper that drives several
            # binaries (subdomain_enum -> subfinder/assetfinder/findomain)
            # marks every one of them as used — the audit's wrapper name alone
            # could not.
            used.add(str(record.get("tool")))

    rows: list[tuple[str, Any, str, bool]] = []
    for name, spec in sorted(CATALOG.items()):
        present = installed(name)
        rows.append((name, spec, "installed" if present else "not installed", name in used))
    return rows


def _write_csv(path: Path, findings: list[Finding]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["id", "severity", "status", "confidence", "asset", "title", "source_tool",
             "rule_id", "cvss", "validated", "has_poc", "how_found"]
        )
        for finding in findings:
            writer.writerow(
                [
                    finding.id, finding.severity.value, finding.status.value,
                    f"{finding.confidence:.2f}", finding.asset, finding.title,
                    finding.source_tool, finding.rule_id or "", finding.cvss or "",
                    "yes" if finding.validated else "no",
                    "yes" if finding.poc else "no", finding.how_found,
                ]
            )


async def generate_report(
    engagement: Any,
    *,
    formats: list[str] | None = None,
    partial_reason: str | None = None,
) -> dict[str, Any]:
    """Write the engagement's report set into ``reports/``.

    ``partial_reason`` is set when a budget ceiling stopped the run: the report
    still gets written, clearly labelled as partial. A run that dies with nothing
    to show is worse than one that stops early and says so.
    """
    formats = formats or list(engagement.config.get("report.formats", ["md", "csv", "json"]))
    reports_dir = engagement.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    summary = engagement.summary()

    # Findings the program has declared ineligible, matched against its own
    # published exclusion list. Separated rather than deleted: they are reported
    # in their own section with the program's reason quoted, so an operator sees
    # what was withheld and why instead of wondering where it went.
    #
    # This matters more than it looks. A first pass over 20 hosts produced 111
    # findings, every one of them a class the program had said in writing it
    # would not accept. Putting them in a report is the specific thing the policy
    # asks researchers not to do.
    excluded = [f for f in engagement.findings.all() if "program-excluded" in (f.tags or [])]
    summary["program_excluded"] = len(excluded)
    summary["excluded_reasons"] = sorted(
        {
            str((f.extra or {}).get("program_exclusion", {}).get("reason", ""))
            for f in excluded
        }
        - {""}
    )

    # Summarize the *reportable* surface — confirmed and needs-review — the two
    # statuses a human actually reads as findings. Candidates are untriaged and
    # belong in their own table, not folded into the prose. But when there is
    # nothing reportable and candidates exist, saying "No findings" while the
    # table below lists seven is a contradiction the reader will catch, and it
    # reads as the tool hiding work. State the real state instead.
    confirmed = engagement.findings.confirmed()
    review = engagement.findings.needs_review()
    candidates = engagement.findings.candidates()
    executive = ""
    try:
        from easyhunt.llm.openrouter import LLMClient
        from easyhunt.llm.summarize import summarize_findings

        client = LLMClient(engagement)
        result = await summarize_findings(
            client,
            confirmed + review,
            phase="report",
            tier="t2",
        )
        executive = str(result.get("summary") or "")
        if not (confirmed or review) and candidates:
            executive = (
                f"No findings were confirmed or escalated to manual review. "
                f"{len(candidates)} scanner candidate(s) are listed below as "
                "untriaged — each needs a human-reproduced proof of concept "
                "before it can be reported."
            )
    except Exception as exc:  # noqa: BLE001 — a report must not fail on the model
        executive = (
            f"_Automated summary unavailable ({exc.__class__.__name__}). Findings "
            "below are complete and unaffected._"
        )

    if partial_reason:
        executive = PARTIAL_BANNER.format(reason=partial_reason) + f"\n\n{executive}"

    written: dict[str, str] = {}

    if "md" in formats:
        path = reports_dir / "Report.md"
        path.write_text(_markdown(engagement, summary, executive), encoding="utf-8")
        written["md"] = str(path)

    if "csv" in formats:
        path = reports_dir / "Report.csv"
        _write_csv(path, engagement.findings.reportable())
        written["csv"] = str(path)

    if "json" in formats:
        path = reports_dir / "findings.json"
        path.write_text(
            json.dumps(
                {
                    "engagement": engagement.scope.name,
                    "generated_at": datetime.now(UTC).isoformat(),
                    "partial": bool(partial_reason),
                    "partial_reason": partial_reason,
                    "scope": engagement.scope.summary(),
                    "summary": summary,
                    "findings": [f.to_dict() for f in engagement.findings.reportable()],
                    "program_excluded": [f.to_dict() for f in excluded],
                    "coverage": {
                        "rows": engagement.coverage.rows(),
                        "summary": engagement.coverage.summary(),
                    },
                    "chains": [c.to_dict() for c in find_finding_chains(engagement.findings.reportable())],
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        written["json"] = str(path)

    graph_path = reports_dir / "taskgraph.mmd"
    graph_path.write_text(engagement.taskgraph.to_mermaid(), encoding="utf-8")
    written["taskgraph"] = str(graph_path)

    # Rendered graphs. SVG and DOT always; PNG when a converter exists.
    try:
        from easyhunt.report.graphs import render_attack_paths, render_task_graph

        if len(engagement.taskgraph):
            for fmt, path in render_task_graph(engagement.taskgraph).write(
                reports_dir / "taskgraph"
            ).items():
                written[f"taskgraph_{fmt}"] = path

        # Attack paths were stashed on findings by cloud_attack_paths.
        paths = [
            f.extra["path"]
            for f in engagement.findings.all()
            if isinstance(f.extra, dict) and isinstance(f.extra.get("path"), dict)
        ]
        if paths:
            for fmt, path in render_attack_paths(paths).write(
                reports_dir / "attack-paths"
            ).items():
                written[f"attack_paths_{fmt}"] = path
    except Exception as exc:  # noqa: BLE001 — a diagram must never fail the report
        engagement.audit.record("graph_render_failed", error=str(exc)[:300])

    engagement.audit.record(
        "report_generated",
        formats=sorted(written),
        confirmed=len(engagement.findings.confirmed()),
        needs_review=len(engagement.findings.needs_review()),
        partial=bool(partial_reason),
    )

    return {
        "ok": True,
        "reports": written,
        "workspace": str(engagement.workspace),
        "confirmed": len(engagement.findings.confirmed()),
        "needs_manual_review": len(engagement.findings.needs_review()),
        "untriaged": len(engagement.findings.candidates()),
        "partial": bool(partial_reason),
        "evidence_dir": str(engagement.evidence_dir),
        "audit_log": str(engagement.audit.path),
    }

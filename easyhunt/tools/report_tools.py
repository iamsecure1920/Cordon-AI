"""MCP tools for reporting and findings inspection."""

from __future__ import annotations

from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.errors import EasyHuntError
from easyhunt.knowledge.findings import Severity, Status
from easyhunt.report.synthesize import generate_report
from easyhunt.tools.base import easyhunt_tool

__all__ = ["findings_list", "job_status", "report_generate", "technique_lookup", "wstg_lookup"]


@easyhunt_tool(
    phase="report", mode="passive", targets_arg=None, timeout=900,
    name="report_generate", tags={"report"}, estimated_requests=0,
    text_args=("partial_reason",), budget_exempt=True,
)
async def report_generate(
    formats: list[str] | None = None, partial_reason: str | None = None
) -> dict[str, Any]:
    """Write Report.md, Report.csv, findings.json, and the task graph to reports/.

    Confirmed findings (those with a reproducible PoC) are reported separately
    from unproven leads. Pass partial_reason when a run stopped early so the
    report says so on its first page.
    """
    engagement = get_engagement()
    budget_stop = engagement.budget.aborted_reason
    if budget_stop and not partial_reason:
        partial_reason = f"engagement budget ceiling reached ({budget_stop})"
    return await generate_report(engagement, formats=formats, partial_reason=partial_reason)


@easyhunt_tool(
    phase="report", mode="passive", targets_arg=None, timeout=60,
    name="findings_list", tags={"report"}, estimated_requests=0, budget_exempt=True,
)
async def findings_list(
    status: str | None = None,
    min_severity: str = "info",
    limit: int = 50,
    detail: bool = False,
) -> dict[str, Any]:
    """List findings, optionally filtered by status and severity.

    Returns a compact table by default. Set detail=True for full records — prefer
    the compact form while planning; it costs a fraction of the tokens.
    """
    engagement = get_engagement()
    threshold = Severity.parse(min_severity).rank

    findings = engagement.findings.all()
    if status:
        try:
            wanted = Status(status)
        except ValueError:
            return {
                "ok": False,
                "message": f"unknown status {status!r}",
                "valid": [s.value for s in Status],
            }
        findings = [f for f in findings if f.status is wanted]
    findings = [f for f in findings if f.severity.rank >= threshold][: max(1, min(limit, 500))]

    if detail:
        items: list[dict[str, Any]] = [f.to_dict() for f in findings]
    else:
        items = [
            {
                "id": f.id,
                "severity": f.severity.value,
                "status": f.status.value,
                "asset": f.asset,
                "title": f.title,
                "source": f.source_tool,
                "has_poc": f.poc is not None,
                "confidence": round(f.confidence, 2),
            }
            for f in findings
        ]

    return {
        "ok": True,
        "count": len(items),
        "findings": items,
        "stats": engagement.findings.stats(),
    }


@easyhunt_tool(
    phase="report", mode="passive", targets_arg=None, timeout=60,
    name="finding_detail", tags={"report"}, estimated_requests=0, budget_exempt=True,
)
async def finding_detail(finding_id: str) -> dict[str, Any]:
    """Full record for one finding, including evidence and PoC."""
    engagement = get_engagement()
    finding = engagement.findings.get(finding_id)
    if finding is None:
        raise EasyHuntError(
            f"no finding with id {finding_id!r}",
            code="unknown_finding",
            known=[f.id for f in engagement.findings.all()[:20]],
        )
    return {"ok": True, "finding": finding.to_dict()}


@easyhunt_tool(
    phase="report", mode="passive", targets_arg=None, timeout=60,
    name="finding_note", tags={"report"}, estimated_requests=0,
    text_args=("note",), budget_exempt=True,
)
async def finding_note(finding_id: str, note: str) -> dict[str, Any]:
    """Attach an analyst note to a finding. Notes appear in the report."""
    engagement = get_engagement()
    finding = engagement.findings.get(finding_id)
    if finding is None:
        raise EasyHuntError(f"no finding with id {finding_id!r}", code="unknown_finding")
    finding.note(note)
    engagement.findings.save()
    return {"ok": True, "finding_id": finding_id, "notes": finding.triage_notes}


@easyhunt_tool(
    phase="inspection", mode="passive", targets_arg=None, timeout=330,
    name="job_status", tags={"inspection"}, estimated_requests=0,
    budget_exempt=True,
)
async def job_status(
    job_id: str | None = None, wait_seconds: float = 0.0, status: str | None = None
) -> dict[str, Any]:
    """Check, wait on, or list long-running scans.

    Tools that can outlast a single MCP call — nuclei_scan, bbot_scan,
    osmedeus_flow — hand back ``{"completed": false, "job_id": ...}`` once their
    internal wait (capped at 300s) elapses. This is how the result is collected
    afterwards. Without it a scan longer than five minutes finishes into a job
    nothing can read.

    Omit ``job_id`` to list jobs. ``wait_seconds`` blocks for up to 300s, so a
    nearly-finished scan can be collected in one call instead of polled.
    """
    engagement = get_engagement()

    if job_id is None:
        return {"ok": True, "jobs": engagement.jobs.list(status=status)}

    if wait_seconds > 0:
        payload = await engagement.jobs.wait(
            job_id, timeout=max(0.0, min(wait_seconds, 300.0))
        )
    else:
        payload = engagement.jobs.fetch(job_id)

    if payload.get("ready") and payload.get("ok"):
        return {"ok": True, "job_id": job_id, "completed": True, **(payload.get("result") or {})}
    return {
        "ok": True,
        "job_id": job_id,
        "completed": False,
        "status": payload.get("status"),
        "progress": payload.get("progress"),
        "error": payload.get("error"),
        "hint": "call again with wait_seconds to block until it finishes",
    }


@easyhunt_tool(
    phase="method", mode="passive", targets_arg=None, timeout=30,
    name="wstg_lookup", tags={"method", "inspection"},
    estimated_requests=0, budget_exempt=True,
)
async def wstg_lookup(
    query: str | None = None,
    test_id: str | None = None,
    phase: str | None = None,
    technologies: str | None = None,
) -> dict[str, Any]:
    """Query the OWASP Web Security Testing Guide for what to test next.

    Four ways in, most specific first:

    * ``test_id``      — one test in full ("WSTG-INPV-05")
    * ``technologies`` — comma-separated stack from http_probe ("Java,Tomcat,OAuth")
    * ``query``        — free text ("session fixation", "file upload")
    * ``phase``        — everything in a phase (recon, authentication, input_validation …)

    Retrieval, not automation. A WSTG test says what to check and why; whether it
    applies to this target is a judgement no detector makes for you. Touches
    nothing and costs no budget.
    """
    from easyhunt.knowledge.wstg import load_index

    index = load_index()
    if not index.available:
        return {
            "ok": False,
            "error": "index_not_built",
            "message": (
                "The WSTG index has not been built. Run: "
                "python3 scripts/fetch_wstg.py --fetch"
            ),
        }

    attribution = {
        "source": index.source.get("attribution"),
        "license": index.source.get("license"),
        "pinned_commit": (index.source.get("commit") or "")[:12],
    }

    if test_id:
        test = index.get(test_id)
        if test is None:
            return {
                "ok": False,
                "error": "unknown_test",
                "message": f"No WSTG test with id {test_id!r}.",
                "attribution": attribution,
            }
        return {"ok": True, "test": test, "attribution": attribution}

    if technologies:
        techs = [t.strip() for t in technologies.split(",") if t.strip()]
        matches = index.for_stack(techs)
        return {
            "ok": True,
            "matched_on": techs,
            "count": len(matches),
            "tests": [
                {k: t[k] for k in ("id", "title", "phase", "objectives")} for t in matches
            ],
            "attribution": attribution,
            "note": (
                "Ranked by how often each category was implied by the observed "
                "stack. Read the full test with test_id before acting on it."
            ),
        }

    if query:
        matches = index.search(query)
        return {
            "ok": True,
            "query": query,
            "count": len(matches),
            "tests": [
                {k: t[k] for k in ("id", "title", "phase", "summary")} for t in matches
            ],
            "attribution": attribution,
        }

    if phase:
        matches = index.by_phase(phase)
        return {
            "ok": True,
            "phase": phase,
            "count": len(matches),
            "tests": [{k: t[k] for k in ("id", "title", "objectives")} for t in matches],
            "attribution": attribution,
        }

    return {
        "ok": True,
        "total_tests": len(index.tests),
        "phases": index.phases(),
        "attribution": attribution,
        "note": "Call again with query, test_id, phase, or technologies.",
    }


@easyhunt_tool(
    phase="method", mode="passive", targets_arg=None, timeout=30,
    name="technique_lookup", tags={"method", "inspection"},
    estimated_requests=0, budget_exempt=True,
)
async def technique_lookup(
    query: str | None = None,
    class_name: str | None = None,
    phase: str | None = None,
    technologies: str | None = None,
    tool: str | None = None,
) -> dict[str, Any]:
    """Query the PayloadsAllTheThings technique index for how to test a bug class.

    The counterpart to ``wstg_lookup``: WSTG says what to check, this says how.
    Each record names the EasyHunt tools that test the class, the vetted payload
    lists, and the gf pattern packs that correspond to it. Retrieval, not
    automation — nothing here fires anything, and it costs no budget.

    Five ways in, most specific first:

    * ``class_name``  — one technique in full ("sql-injection", "open-redirect")
    * ``tool``        — every technique a given EasyHunt tool covers ("sqli_validate")
    * ``technologies``— comma-separated stack from http_probe ("Rails,MongoDB,GraphQL")
    * ``query``       — free text ("jwt forgery", "deserialization")
    * ``phase``       — everything in a phase (input_validation, authentication …)
    """
    from easyhunt.knowledge.techniques import load_index

    index = load_index()
    if not index.available:
        return {
            "ok": False,
            "error": "index_not_built",
            "message": (
                "The technique index has not been built. Run: "
                "python3 scripts/fetch_pat.py --fetch"
            ),
        }

    attribution = {
        "source": index.source.get("attribution"),
        "license": index.source.get("license"),
        "pinned_commit": (index.source.get("commit") or "")[:12],
    }

    if class_name:
        tech = index.get(class_name)
        if tech is None:
            return {
                "ok": False,
                "error": "unknown_class",
                "message": f"No technique with class {class_name!r}.",
                "attribution": attribution,
                "known_classes": index.classes(),
            }
        return {"ok": True, "technique": tech, "attribution": attribution}

    if tool:
        matches = index.for_tool(tool)
        return {
            "ok": True,
            "tool": tool,
            "count": len(matches),
            "techniques": [
                {k: t[k] for k in ("class", "title", "phase", "tools")} for t in matches
            ],
            "attribution": attribution,
        }

    if technologies:
        techs = [t.strip() for t in technologies.split(",") if t.strip()]
        matches = index.for_stack(techs)
        return {
            "ok": True,
            "matched_on": techs,
            "count": len(matches),
            "techniques": [
                {k: t[k] for k in ("class", "title", "phase", "tools")} for t in matches
            ],
            "attribution": attribution,
        }

    if query:
        matches = index.search(query)
        return {
            "ok": True,
            "query": query,
            "count": len(matches),
            "techniques": [
                {k: t[k] for k in ("class", "title", "phase", "summary")} for t in matches
            ],
            "attribution": attribution,
        }

    if phase:
        matches = index.by_phase(phase)
        return {
            "ok": True,
            "phase": phase,
            "count": len(matches),
            "techniques": [
                {k: t[k] for k in ("class", "title", "tools", "payloads", "gf")}
                for t in matches
            ],
            "attribution": attribution,
        }

    return {
        "ok": True,
        "total_techniques": len(index.techniques),
        "classes": index.classes(),
        "attribution": attribution,
        "note": "Call again with class_name, tool, technologies, query, or phase.",
    }

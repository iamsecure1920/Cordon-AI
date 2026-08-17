"""Reporting: confirmed and unproven findings must never blur together."""

from __future__ import annotations

import csv
import json

import pytest

import easyhunt.tools.report_tools  # noqa: F401 — registers the tools
from easyhunt.knowledge.findings import Evidence, Finding, PoC, Severity, Status
from easyhunt.report.synthesize import generate_report
from easyhunt.tools.base import REGISTRY


@pytest.fixture
def populated(engagement):
    confirmed = Finding(
        asset="https://www.example.com/.env",
        title="Exposed .env with live credentials",
        phase="vuln_scan",
        severity=Severity.CRITICAL,
        source_tool="nuclei",
        rule_id="exposed-env-file",
        how_found="Nuclei template 'exposed-env-file' matched at https://www.example.com/.env",
        description="The environment file is served from the web root.",
        remediation="Move it out of the web root and rotate every credential.",
        cvss=9.1,
        evidence=[Evidence(kind="response", description="GET /.env", excerpt="DB_PASSWORD=…")],
    )
    confirmed.confirm(
        PoC(
            reproduction="curl -sS https://www.example.com/.env",
            expected_result="HTTP 200 serving key=value pairs",
            observed_result="HTTP 200, 14 environment variables including DB_PASSWORD",
            impact_limit_note="Single GET; contents read but not retained.",
        )
    )
    engagement.findings.add(confirmed)

    unproven = Finding(
        asset="https://api.example.com/v1/users",
        title="Possible IDOR on user endpoint",
        severity=Severity.HIGH,
        status=Status.NEEDS_MANUAL_REVIEW,
        source_tool="manual",
        how_found="Analyst review of endpoint_discovery output",
    )
    unproven.note("Automatic validation did not prove this (authz): needs a human.")
    engagement.findings.add(unproven)

    engagement.findings.add(
        Finding(
            asset="https://www.example.com/",
            title="Server version disclosed in banner",
            severity=Severity.LOW,
            status=Status.CANDIDATE,
            source_tool="httpx",
        )
    )
    engagement.discovered("dangling_cname", "cdn.example.com", source="dns_resolve")
    return engagement


class TestMarkdown:
    async def test_sections_are_separate(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()

        confirmed_at = text.index("## Confirmed findings")
        review_at = text.index("## Needs manual review")
        assert confirmed_at < review_at

        confirmed_section = text[confirmed_at:review_at]
        assert "Exposed .env" in confirmed_section
        # The unproven finding must not appear among confirmed ones.
        assert "Possible IDOR" not in confirmed_section

    async def test_unproven_section_says_so_plainly(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        review = text[text.index("## Needs manual review") :]
        assert "**These are not confirmed vulnerabilities.**" in review
        assert "so the report looks longer" in review

    async def test_confirmed_finding_is_reproducible_from_the_report_alone(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "curl -sS https://www.example.com/.env" in text
        assert "*Expected:*" in text and "*Observed:*" in text
        assert "*Impact limited to:*" in text

    async def test_how_found_names_the_tool_and_rule(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "Nuclei template 'exposed-env-file'" in text
        assert "rule `exposed-env-file`" in text

    async def test_authorization_and_scope_are_recorded(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "## Authorization" in text
        assert populated.scope.fingerprint() in text
        assert "## Scope" in text

    async def test_tool_inventory_lists_licenses(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "## Tool inventory" in text
        # TruffleHog's AGPL status matters for redistribution and must be visible.
        assert "AGPL-3.0" in text

    async def test_inventory_marks_wrapper_driven_binaries_as_used(self, populated) -> None:
        # The catalog lists binaries (subfinder, testssl, sqlmap...); the audit
        # records wrappers (subdomain_enum, tls_audit, sqli_validate...). A
        # binary_run event from guarded_run must mark the catalog entry used, or
        # a fully-driven engagement shows half the fleet as "no".
        populated.audit.record(
            "binary_run", tool="testssl", ran=True, exit_code=0, timed_out=False
        )
        populated.audit.record(
            "binary_run", tool="sqlmap", ran=True, exit_code=0, timed_out=False
        )
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "| testssl |" in text and "| testssl |" in text.split("## Coverage")[0]
        assert "| sqlmap |" in text

    async def test_task_graph_is_rendered(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "```mermaid" in text and "takeover_verify" in text

    async def test_audit_chain_state_is_reported(self, populated) -> None:
        await generate_report(populated, formats=["md"])
        text = (populated.reports_dir / "Report.md").read_text()
        assert "Hash chain: intact" in text

    async def test_empty_confirmed_section_is_honest(self, engagement) -> None:
        engagement.findings.add(
            Finding(asset="https://www.example.com/", title="Just a candidate", severity=Severity.LOW)
        )
        await generate_report(engagement, formats=["md"])
        text = (engagement.reports_dir / "Report.md").read_text()
        assert "_No findings were confirmed with a reproducible proof of concept._" in text
        assert "This is a real result, not an empty one" in text

    async def test_executive_summary_does_not_contradict_candidates(self, engagement) -> None:
        """'No findings' above a table of seven candidates reads as concealment."""
        engagement.findings.add(
            Finding(asset="https://www.example.com/", title="Just a candidate", severity=Severity.LOW)
        )
        await generate_report(engagement, formats=["md"])
        text = (engagement.reports_dir / "Report.md").read_text()
        # The executive summary must acknowledge the candidates exist, not say
        # "No findings." and then list them in the table below.
        assert "No findings were confirmed" in text
        assert "scanner candidate(s) are listed below" in text
        assert "No findings." not in text


class TestPartialReports:
    async def test_partial_reason_is_on_the_first_page(self, populated) -> None:
        await generate_report(populated, formats=["md"], partial_reason="wall clock ceiling reached")
        text = (populated.reports_dir / "Report.md").read_text()
        assert "**PARTIAL REPORT**" in text
        assert "absence of a finding as unknown" in text

    async def test_budget_abort_marks_the_report_partial(self, populated) -> None:
        from easyhunt.errors import BudgetExceeded

        # Ceilings are opt-in since the default flipped to enforce: false;
        # this test exercises the ceiling, so it must ask for one.
        populated.budget.limits.enforce = True
        populated.budget.charge_llm(usd=populated.budget.limits.llm_usd, phase="x", tier="t2")
        with pytest.raises(BudgetExceeded):
            populated.budget.check()

        result = await REGISTRY["report_generate"].fn()
        assert result["partial"] is True
        assert "PARTIAL REPORT" in (populated.reports_dir / "Report.md").read_text()


class TestOtherFormats:
    async def test_csv_marks_which_findings_have_a_poc(self, populated) -> None:
        await generate_report(populated, formats=["csv"])
        with (populated.reports_dir / "Report.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        by_title = {r["title"]: r for r in rows}
        assert by_title["Exposed .env with live credentials"]["has_poc"] == "yes"
        assert by_title["Possible IDOR on user endpoint"]["has_poc"] == "no"

    async def test_json_is_platform_ready(self, populated) -> None:
        await generate_report(populated, formats=["json"])
        payload = json.loads((populated.reports_dir / "findings.json").read_text())
        assert payload["engagement"] == "test-engagement"
        assert payload["scope"]["fingerprint"] == populated.scope.fingerprint()
        assert len(payload["findings"]) == 3

    async def test_all_artifacts_are_produced(self, populated) -> None:
        result = await generate_report(populated)
        for key in ("md", "csv", "json", "taskgraph"):
            assert key in result["reports"]
        assert (populated.evidence_dir).is_dir()
        assert (populated.audit.path).exists()


class TestFindingsTools:
    async def test_compact_listing_by_default(self, populated) -> None:
        result = await REGISTRY["findings_list"].fn()
        assert "evidence" not in result["findings"][0]
        assert result["findings"][0]["has_poc"] in {True, False}

    async def test_filter_by_status(self, populated) -> None:
        result = await REGISTRY["findings_list"].fn(status="confirmed")
        assert result["count"] == 1

    async def test_filter_by_severity(self, populated) -> None:
        result = await REGISTRY["findings_list"].fn(min_severity="high")
        assert all(f["severity"] in {"high", "critical"} for f in result["findings"])

    async def test_unknown_status_is_explained(self, populated) -> None:
        result = await REGISTRY["findings_list"].fn(status="probably")
        assert result["ok"] is False and "valid" in result

    async def test_detail_and_notes(self, populated) -> None:
        finding_id = populated.findings.confirmed()[0].id
        detail = await REGISTRY["finding_detail"].fn(finding_id=finding_id)
        assert detail["finding"]["poc"]["reproduction"]

        await REGISTRY["finding_note"].fn(
            finding_id=finding_id, note="Triager asked for a second screenshot; it's in evidence/."
        )
        assert any("screenshot" in n for n in populated.findings.get(finding_id).triage_notes)

    async def test_report_tools_are_passive(self) -> None:
        for name in ("report_generate", "findings_list", "finding_detail", "finding_note"):
            assert REGISTRY[name].mode == "passive"

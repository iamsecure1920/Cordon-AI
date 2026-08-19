"""LLM red-teaming: probe selection, grading, and honest reporting of gaps."""

from __future__ import annotations

import pytest

from cordon.control_plane.approval import PolicyBackend
from cordon.errors import ApprovalDenied, ToolUnavailable
from cordon.knowledge.findings import Severity, Status
from cordon.tools import llmsec
from cordon.tools.base import REGISTRY


class TestProbeCatalog:
    async def test_lists_families_with_impact_guidance(self, engagement) -> None:
        result = await REGISTRY["llm_probe_catalog"].fn()
        assert set(result["families"]) == set(llmsec.PROBE_FAMILIES)
        for family in result["families"].values():
            assert family["why_it_matters"]

    async def test_tool_abuse_outranks_jailbreak(self, engagement) -> None:
        # A jailbreak with no downstream capability is not worth a program's time;
        # an agent calling tools with attacker arguments is critical.
        assert llmsec.PROBE_FAMILIES["tool-abuse"]["severity"] is Severity.CRITICAL
        assert llmsec.PROBE_FAMILIES["jailbreak"]["severity"] is Severity.LOW

    async def test_catalog_is_passive_and_budget_exempt(self) -> None:
        assert REGISTRY["llm_probe_catalog"].mode == "passive"


class TestRedteamGating:
    async def test_redteam_requires_approval(self, engagement) -> None:
        with pytest.raises(ApprovalDenied):
            await REGISTRY["llm_redteam"].fn(target="https://ai.example.com/chat")

    async def test_unknown_family_is_refused(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["llm_redteam"])
        with pytest.raises(ToolUnavailable, match="unknown probe family"):
            await REGISTRY["llm_redteam"].fn(
                target="https://ai.example.com/chat", family="make-it-swear"
            )

    async def test_out_of_scope_ai_endpoint_is_refused(self, engagement) -> None:
        from cordon.errors import OutOfScopeError

        engagement.approval.backend = PolicyBackend(auto_approve=["llm_redteam"])
        with pytest.raises(OutOfScopeError):
            await REGISTRY["llm_redteam"].fn(target="https://ai.someone-else.net/chat")

    async def test_missing_tool_reports_untested_not_clean(
        self, engagement, monkeypatch
    ) -> None:
        # Absence is simulated rather than assumed: this used to depend on garak
        # genuinely not being on the machine, so installing garak flipped the
        # assertion and the test started failing for a reason unrelated to the
        # behaviour it guards.
        from cordon.tools import common

        monkeypatch.setattr(common, "installed", lambda name: name != "garak")

        engagement.approval.backend = PolicyBackend(auto_approve=["llm_redteam"])
        result = await REGISTRY["llm_redteam"].fn(target="https://ai.example.com/chat")
        # The distinction that matters: the surface is UNTESTED, which is not the
        # same as "no findings".
        assert result["ok"] is False
        assert result["error"] == "tool_unavailable"
        assert "UNTESTED, not clean" in result["message"]


class TestReportParsing:
    def test_failed_probes_become_candidates(self) -> None:
        report = "\n".join(
            [
                '{"entry_type":"eval","probe":"promptinject.HijackHateHumans","detector":"base.TriggerListDetector","total":10,"passed":4}',
                '{"entry_type":"eval","probe":"dan.DAN_Jailbreak","detector":"dan.DAN","total":10,"passed":10}',
                '{"entry_type":"start_run","other":"noise"}',
            ]
        )
        failures = llmsec._parse_garak_report(
            report, target="https://ai.example.com", family="indirect-injection"
        )
        # Only the probe that actually got through is reported.
        assert len(failures) == 1
        assert failures[0]["probe"] == "promptinject.HijackHateHumans"
        assert failures[0]["failed"] == 6
        assert failures[0]["rate"] == 0.6

    def test_malformed_lines_are_skipped(self) -> None:
        assert llmsec._parse_garak_report("not json\n\n[]\n", target="x", family="jailbreak") == []


class TestFindingQuality:
    def test_llm_findings_stay_candidates_with_low_confidence(self, engagement) -> None:
        from cordon.knowledge.findings import Finding

        # Simulate what llm_redteam files, and assert the invariant that matters:
        # a non-deterministic probe result is never high-confidence or confirmed.
        finding = Finding(
            asset="https://ai.example.com/chat",
            title="LLM indirect-injection: probe succeeded",
            phase="llmsec",
            severity=Severity.HIGH,
            status=Status.CANDIDATE,
            source_tool="garak",
            rule_id="llm.indirect-injection.promptinject",
            confidence=0.5,
        )
        engagement.findings.add(finding)
        assert finding.status is Status.CANDIDATE
        assert finding.confidence < 0.95
        assert finding.poc is None

    def test_remediation_rejects_input_filtering_as_a_fix(self) -> None:
        # The probe that just succeeded *is* the input filter being defeated.
        text = llmsec.PROBE_FAMILIES["indirect-injection"]["why"]
        assert "attacker never speaks to the model directly" in text

"""v2.1 integration: WAF-bypass pass in the chain, coverage ledger, finding
chains, output verification, endpoint scoring, and the sqli boundary.

These tie the new knowledge/tools together at the points the report and the
unattended pipeline actually touch them.
"""

from __future__ import annotations

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.knowledge.attackgraph import find_finding_chains
from easyhunt.knowledge.coverage import CoverageLedger
from easyhunt.knowledge.findings import Finding
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools import exploit_chain as ec
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import verify_output
from easyhunt.tools.exploitation import _sqli_boundary

load_capabilities()

_APPROVED = ["exploit_chain", "nosqli_probe", "ssrf_probe"]


class TestSqliBoundary:
    def test_splits_first_payload_into_prefix_suffix(self) -> None:
        assert _sqli_boundary(["' OR 1=1--"]) == ("'", "--")
        assert _sqli_boundary(["1' UNION SELECT NULL--"]) == ("1'", "--")
        assert _sqli_boundary(["1' OR '1'='1"]) == ("1'", "")

    def test_empty_set_returns_blank_boundary(self) -> None:
        assert _sqli_boundary([]) == ("", "")


class TestEndpointScoring:
    def test_api_param_outranks_static_path(self) -> None:
        api = ec._score_injection_point("https://h/api/users?id=", "id")
        static = ec._score_injection_point("https://h/about", "lang")
        assert api > static

    def test_order_points_highest_first(self) -> None:
        points = [
            ("https://h/about", "lang"),
            ("https://h/api/search?q=", "q"),
            ("https://h/api/admin/users?id=", "id"),
        ]
        ordered = ec._order_points(points)
        assert ordered[0][0].endswith("?id=")
        assert ordered[-1][0].endswith("/about")


class TestWafBypassChainPass:
    @pytest.mark.asyncio
    async def test_chain_reads_waf_phase_and_refires_bypass_on_clean_base(
        self, engagement, monkeypatch, tmp_path
    ) -> None:
        """The chain re-tests with bypass payloads when a vendor is recorded.

        Writes a phase-waf file the way the waf phase would, then verifies the
        heavy validators are re-fired with bypass_vendor after a clean base pass.
        """
        engagement.approval.backend = PolicyBackend(auto_approve=list(_APPROVED))
        (engagement.workspace / "phase-waf--x.json").write_text(
            '{"waf": ["Cloudflare"]}', encoding="utf-8"
        )

        calls: list = []

        async def fake_probe(**kwargs):
            calls.append(("web_injection_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_cmdi(**kwargs):
            calls.append(("cmdi_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_ssti(**kwargs):
            calls.append(("ssti_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_nosql(**kwargs):
            calls.append(("nosqli_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_ssrf(**kwargs):
            calls.append(("ssrf_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_smuggling(**kwargs):
            calls.append(("smuggling_probe", kwargs))
            return {"ok": True, "count": 0, "findings": []}

        async def fake_sqli(**kwargs):
            calls.append(("sqli_validate", kwargs))
            return {"ok": True, "proven": False, "observed": ""}

        async def fake_xss(**kwargs):
            calls.append(("xss_validate", kwargs))
            return {"ok": True, "proven": False, "observed": ""}

        class _Fake:
            def __init__(self, fn) -> None:
                self.fn = fn

        for name, fn in (
            ("web_injection_probe", fake_probe),
            ("cmdi_probe", fake_cmdi),
            ("ssti_probe", fake_ssti),
            ("nosqli_probe", fake_nosql),
            ("ssrf_probe", fake_ssrf),
            ("smuggling_probe", fake_smuggling),
            ("sqli_validate", fake_sqli),
            ("xss_validate", fake_xss),
        ):
            monkeypatch.setitem(REGISTRY, name, _Fake(fn))

        result = await REGISTRY["exploit_chain"].fn(
            target="https://www.example.com/a?q=1", include_heavy=True
        )

        sqli = [c for c in calls if c[0] == "sqli_validate"]
        xss = [c for c in calls if c[0] == "xss_validate"]
        # Base pass + bypass re-fire per validator (base came back clean).
        assert len(sqli) == 2
        assert len(xss) == 2
        assert any(c[1].get("bypass_vendor") == "cloudflare" for c in sqli)
        assert any(c[1].get("bypass_vendor") == "cloudflare" for c in xss)
        # The chain records the bypass outcomes in per_class.
        classes = result["results"][0]["classes"]
        assert "sql-injection-bypass" in classes
        assert "xss-bypass" in classes
        assert classes["sql-injection-bypass"]["vendor"] == "cloudflare"
        # The coverage ledger got rows from the chain's per-class records.
        rows = {r["class"] for r in engagement.coverage.rows()}
        assert "sql-injection" in rows
        assert "xss-injection" in rows

    @pytest.mark.asyncio
    async def test_no_vendor_no_bypass_refire(self, engagement, monkeypatch) -> None:
        """No waf phase file → base validators fire once, no bypass pass."""
        engagement.approval.backend = PolicyBackend(auto_approve=list(_APPROVED))
        calls: list = []

        async def fake_sqli(**kwargs):
            calls.append(("sqli_validate", kwargs))
            return {"ok": True, "proven": False, "observed": ""}

        async def fake_xss(**kwargs):
            calls.append(("xss_validate", kwargs))
            return {"ok": True, "proven": False, "observed": ""}

        async def fake_ok(**kwargs):
            return {"ok": True, "count": 0, "findings": []}

        class _Fake:
            def __init__(self, fn) -> None:
                self.fn = fn

        for name, fn in (
            ("web_injection_probe", fake_ok),
            ("cmdi_probe", fake_ok),
            ("ssti_probe", fake_ok),
            ("nosqli_probe", fake_ok),
            ("ssrf_probe", fake_ok),
            ("smuggling_probe", fake_ok),
            ("sqli_validate", fake_sqli),
            ("xss_validate", fake_xss),
        ):
            monkeypatch.setitem(REGISTRY, name, _Fake(fn))

        await REGISTRY["exploit_chain"].fn(
            target="https://www.example.com/a?q=1", include_heavy=True
        )
        assert len([c for c in calls if c[0] == "sqli_validate"]) == 1
        assert len([c for c in calls if c[0] == "xss_validate"]) == 1


class TestFindingChains:
    def test_xss_plus_no_csp_upgrade(self) -> None:
        f1 = Finding(asset="https://app.example.com/x", title="Reflected XSS", tags=["xss"])
        f2 = Finding(asset="https://app.example.com", title="Missing Content-Security-Policy header", tags=["csp"])
        chains = find_finding_chains([f1, f2])
        assert any(c.pattern_id == "xss-no-csp" for c in chains)
        chain = next(c for c in chains if c.pattern_id == "xss-no-csp")
        assert chain.upgrade_to == "high"

    def test_ssrf_metadata_upgrade(self) -> None:
        f1 = Finding(asset="https://app.example.com/api", title="SSRF in url parameter", tags=["ssrf"])
        f2 = Finding(asset="https://app.example.com", title="Cloud metadata exposure", tags=["aws", "metadata"])
        chains = find_finding_chains([f1, f2])
        assert any(c.pattern_id == "ssrf-cloud-metadata" for c in chains)

    def test_same_finding_cannot_chain_with_itself(self) -> None:
        f = Finding(asset="https://app.example.com", title="Reflected XSS", tags=["xss", "csp"])
        chains = find_finding_chains([f])
        assert chains == []

    def test_different_assets_do_not_chain(self) -> None:
        f1 = Finding(asset="https://a.example.com", title="Reflected XSS", tags=["xss"])
        f2 = Finding(asset="https://b.example.com", title="Missing Content-Security-Policy", tags=["csp"])
        assert find_finding_chains([f1, f2]) == []


class TestCoverageLedger:
    def test_record_and_summary(self) -> None:
        ledger = CoverageLedger()
        ledger.record("sql-injection", "validated", tool="sqli_validate")
        ledger.record("xss-injection", "detected", tool="xss_validate")
        ledger.record("ssrf", "validated", tool="ssrf_probe")
        summary = ledger.summary()
        assert summary["validated_or_disproven"] == 2
        assert summary["detected"] == 1

    def test_record_upgrades_never_downgrades(self) -> None:
        ledger = CoverageLedger()
        ledger.record("xss-injection", "detected", tool="xss_validate")
        ledger.record("xss-injection", "validated", tool="xss_validate")
        assert ledger.get("xss-injection")["status"] == "validated"

    def test_persists_and_loads(self, tmp_path) -> None:
        path = tmp_path / "coverage.json"
        ledger = CoverageLedger()
        ledger.record("sql-injection", "validated", tool="sqlmap")
        ledger.save(path)
        reloaded = CoverageLedger(path)
        assert reloaded.get("sql-injection")["status"] == "validated"


class TestVerifyOutput:
    def test_nmap_no_host_up_suspicious(self) -> None:
        verdict = verify_output("nmap", ["nmap", "-sV", "host"], 0, "No hosts up")
        assert verdict.status == "suspicious"
        assert "-Pn" in verdict.hint

    def test_nmap_host_up_ok(self) -> None:
        verdict = verify_output("nmap", ["nmap", "-sV", "host"], 0, "Host is up (0.01s latency)")
        assert verdict.status == "ok"

    def test_nuclei_empty_json_suspicious(self) -> None:
        verdict = verify_output("nuclei", ["nuclei", "-u", "x"], 0, "")
        assert verdict.status == "suspicious"

    def test_sqlmap_no_parameter_suspicious(self) -> None:
        verdict = verify_output("sqlmap", ["sqlmap"], 0, "no parameter found")
        assert verdict.status == "suspicious"
        assert "bypass" in verdict.hint

    def test_dalfox_empty_output(self) -> None:
        verdict = verify_output("dalfox", ["dalfox"], 0, "")
        assert verdict.status == "empty"

    def test_unregistered_tool_defaults_ok(self) -> None:
        assert verify_output("dig", ["dig", "x"], 0, "").status == "ok"


class TestJsEscapeNormalization:
    """P2-10: minified-bundle escapes must not hide real endpoints."""

    def test_escaped_slashes_reveal_endpoints(self) -> None:
        from easyhunt.tools.js_analysis import _scan_text

        text = 'const api = "https:\\/\\/app.example.com\\/api\\/users\\?q=";'
        secrets, endpoints = _scan_text(text, "https://cdn.example.com/bundle.js")
        assert any("https://app.example.com/api/users" in e for e in endpoints)

    def test_unicode_slash_normalizes(self) -> None:
        from easyhunt.tools.js_analysis import _normalize_escapes

        assert _normalize_escapes("\\u002Fapi") == "/api"
        assert _normalize_escapes("https:\\/\\/h") == "https://h"

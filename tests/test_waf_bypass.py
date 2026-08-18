"""WAF knowledge base + waf_bypass/fingerprint_waf tools (P0-1).

The fingerprint tables and bypass payload sets are ported data (MIT,
autopentest-ai); the tests pin the behaviour the exploit chain depends on:
vendor aliasing from wafw00f display names, ordered payload sets bounded by
max_payloads, and fingerprint scoring from raw headers/body/status.
"""

from __future__ import annotations

import pytest

from easyhunt.knowledge import waf
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import REGISTRY

load_capabilities()


class TestFingerprint:
    def test_cloudflare_from_headers(self) -> None:
        matches = waf.fingerprint_waf({"cf-ray": "abc123-fra", "server": "cloudflare"}, body="", status_code=403)
        assert matches, "cf-ray header should identify Cloudflare"
        assert matches[0]["waf"] == "cloudflare"
        assert matches[0]["confidence"] >= 37

    def test_akamai_from_server_and_block_page(self) -> None:
        matches = waf.fingerprint_waf(
            {"server": "AkamaiGHost"},
            body="Access Denied\nReference #18.a1b2c3.1690000000.0",
            status_code=403,
        )
        assert matches and matches[0]["waf"] == "akamai"

    def test_modsecurity_from_body_marker(self) -> None:
        matches = waf.fingerprint_waf({}, body="ModSecurity: Request rejected", status_code=406)
        assert matches and matches[0]["waf"] == "modsecurity"

    def test_aws_waf_from_request_id(self) -> None:
        matches = waf.fingerprint_waf({"x-amzn-requestid": "abc-123"}, body="Request blocked", status_code=403)
        assert matches and matches[0]["waf"] == "aws_waf"

    def test_no_signature_returns_empty(self) -> None:
        matches = waf.fingerprint_waf({"server": "nginx"}, body="hello world", status_code=200)
        assert matches == []


class TestBypassPayloads:
    def test_known_vendor_class_returns_ordered_payloads(self) -> None:
        payloads = waf.bypass_payloads("cloudflare", "xss")
        assert len(payloads) >= 6
        # Ordered basic → advanced: all basics before any advanced.
        _LEVEL_RANK = {"basic": 0, "intermediate": 1, "advanced": 2}
        levels = [p["level"] for p in payloads]
        assert levels == sorted(levels, key=lambda level: _LEVEL_RANK[level])

    def test_vendor_aliasing_from_wafw00f_display_names(self) -> None:
        # wafw00f prints these; the chain normalises through vendor_aliases().
        assert waf._normalize_vendor("Cloudflare") == "cloudflare"
        assert waf._normalize_vendor("Amazon Web Services (AWS) WAF") == "aws_waf"
        assert waf._normalize_vendor("F5 BIG-IP") == "f5_big_ip"

    def test_generic_fallback_for_unknown_vendor(self) -> None:
        payloads = waf.bypass_payloads("totally-unknown-waf", "sqli")
        assert payloads, "unknown vendor falls back to the generic table"
        assert "[generic]" in payloads[0]["technique"]

    def test_level_filter(self) -> None:
        basic = waf.bypass_payloads("cloudflare", "xss", level="basic")
        assert basic and all(p["level"] == "basic" for p in basic)

    def test_max_payloads_bound(self) -> None:
        payloads = waf.bypass_payloads("_generic", "sqli", max_payloads=3)
        assert len(payloads) <= 3

    def test_encoding_strategies_apply_to_class(self) -> None:
        encodings = waf.encoding_strategies("xss")
        names = {e["name"] for e in encodings}
        assert "html_entity_encode" in names
        assert "chunked_encoding" in names


class TestWafTools:
    @pytest.mark.asyncio
    async def test_waf_bypass_tool_returns_payloads(self, engagement) -> None:
        result = await REGISTRY["waf_bypass"].fn(vendor="akamai", vuln_class="xss")
        assert result["ok"] is True
        assert result["count"] > 0
        assert all({"payload", "technique", "level"} <= set(p) for p in result["payloads"])

    @pytest.mark.asyncio
    async def test_waf_bypass_tool_unknown_vendor(self, engagement) -> None:
        result = await REGISTRY["waf_bypass"].fn(vendor="nope", vuln_class="xss")
        assert result["ok"] is False
        assert result["error"] == "unknown_vendor"

    @pytest.mark.asyncio
    async def test_fingerprint_waf_tool(self, engagement) -> None:
        result = await REGISTRY["fingerprint_waf"].fn(
            headers={"server": "cloudflare"}, body="", status_code=403
        )
        assert result["primary"] == "cloudflare"

    @pytest.mark.asyncio
    async def test_waf_vendors_lists(self, engagement) -> None:
        result = await REGISTRY["waf_vendors"].fn()
        assert result["count"] == len([v for v in waf.WAF_BYPASSES if v != "_generic"])

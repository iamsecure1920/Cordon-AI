"""gf pattern scan: the pack must load, and a match must stay a candidate.

The whole point of this module is to turn the community gf pattern library into
something a report can trust. Two failure modes matter more than any happy path:

1. **A pattern that does not compile, or a pack that did not load.** A dropped
   ``ssrf`` pack makes an SSRF-shaped estate read as clean — the quietest and
   most expensive lie a scanner can tell. The loader therefore surfaces every
   problem instead of skipping the broken entry.

2. **A regex match being treated as a finding.** A ``?redirect=`` parameter is a
   shape, not a bug. Everything here is a ``sink_candidate`` and names the
   validator that would actually prove or kill it.
"""

from __future__ import annotations

import json

import httpx
import pytest

from cordon.tools import pattern_scan as ps
from cordon.tools.pattern_scan import GF_PATTERNS, load_patterns

HOST = "https://www.example.com"


class TestPackValidity:
    def test_the_pack_loads_with_no_problems(self) -> None:
        assert GF_PATTERNS
        assert ps._LOAD_PROBLEMS == []

    def test_every_class_names_a_validator(self) -> None:
        assert all(p.validator for p in GF_PATTERNS)
        # The validators these point at are real MCP tools, so a renamed tool
        # here would produce a next_step that names nothing.
        known = {
            "xss_validate", "ssrf_probe", "sqli_validate", "ssti_probe",
            "cmdi_probe", "authz_compare", "validate_findings",
            "cloud_asset_discovery", "takeover_verify",
        }
        assert {p.validator for p in GF_PATTERNS} <= known

    def test_a_missing_manifest_is_reported(self, tmp_path) -> None:
        patterns, problems = load_patterns(tmp_path)
        assert patterns == []
        assert problems and "no manifest" in problems[0]

    def test_a_malformed_regex_is_reported_not_skipped(self, tmp_path) -> None:
        (tmp_path / "manifest.json").write_text(
            json.dumps({"patterns": [{"name": "bad", "class": "xss", "severity": "low",
                                      "validator": "xss_validate"}]}),
            encoding="utf-8",
        )
        (tmp_path / "bad.json").write_text(
            json.dumps({"flags": "i", "patterns": ["("]}), encoding="utf-8"
        )
        patterns, problems = load_patterns(tmp_path)
        # The broken entry is dropped and *reported*, never silently absorbed.
        assert patterns == []
        assert any("does not compile" in p for p in problems)

    def test_a_manifest_entry_without_a_file_is_reported(self, tmp_path) -> None:
        (tmp_path / "manifest.json").write_text(
            json.dumps({"patterns": [{"name": "gone", "class": "xss", "severity": "low",
                                      "validator": "xss_validate"}]}),
            encoding="utf-8",
        )
        patterns, problems = load_patterns(tmp_path)
        assert patterns == []
        assert any("missing" in p for p in problems)


def _serve(monkeypatch, routes: dict[str, object]) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        entry = routes.get(request.url.path)
        if entry is None:
            return httpx.Response(404, text="nope")
        if isinstance(entry, tuple):
            body, ctype = entry
        else:
            body, ctype = entry, "text/html"
        return httpx.Response(200, text=body, headers={"content-type": ctype})

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )


class TestPatternScan:
    pytestmark = pytest.mark.asyncio

    async def test_url_parameters_are_classified_without_a_request(
        self, engagement, monkeypatch
    ) -> None:
        requested: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requested.append(request.url.path)
            return httpx.Response(200, text="ok")

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        url = f"{HOST}/login?redirect=https://evil.example.net/x"
        result = await ps.pattern_scan(url, scan_bodies=False)
        assert result["ok"] is True
        # Classification reads the URL string; nothing was fetched.
        assert requested == []
        assert result["classes"]["open-redirect"]["count"] >= 1
        assert result["classes"]["open-redirect"]["validator"] == "validate_findings"

    async def test_a_body_sink_is_found_when_bodies_are_scanned(
        self, engagement, monkeypatch
    ) -> None:
        body = "<script>document.write(location.hash)</script>"
        _serve(monkeypatch, {"/": body})
        result = await ps.pattern_scan(f"{HOST}/", scan_bodies=True)
        assert result["ok"] is True
        assert "xss" in result["classes"]
        assert any(c["from"] == "body" for c in result["classes"]["xss"]["candidates"])

    async def test_a_blocked_response_is_untested_not_clean(
        self, engagement, monkeypatch
    ) -> None:
        _serve(monkeypatch, {"/": "<title>403 Forbidden</title>"})
        result = await ps.pattern_scan(f"{HOST}/", scan_bodies=True)
        assert result["status"] == "PARTIAL"
        assert result["complete"] is False
        assert result["blocked"]

    async def test_no_urls_is_an_error(self, engagement) -> None:
        # An in-scope but non-http target: nothing to classify as a URL.
        result = await ps.pattern_scan("www.example.com")
        assert result["ok"] is False
        assert result["error"] == "no_urls"

    async def test_a_missing_pack_is_untested(self, engagement, monkeypatch) -> None:
        monkeypatch.setattr(ps, "GF_PATTERNS", [])
        monkeypatch.setattr(ps, "_LOAD_PROBLEMS", ["boom"])
        result = await ps.pattern_scan(f"{HOST}/")
        assert result["ok"] is False
        assert result["error"] == "pattern_pack_unavailable"
        assert result["status"] == "UNTESTED"

    async def test_candidates_are_stored_as_tagged_assets(
        self, engagement, monkeypatch
    ) -> None:
        _serve(monkeypatch, {"/": "ok"})
        url = f"{HOST}/users/1042"
        await ps.pattern_scan(url, scan_bodies=False)
        stored = engagement.assets.values("sink_candidate", tag="idor")
        assert url in stored
        # Kind is sink_candidate, not url: a lead to validate, not a target to
        # hand a scanner.
        assert url not in engagement.assets.values("url")

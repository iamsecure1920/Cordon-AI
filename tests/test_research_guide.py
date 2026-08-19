"""Tests for research_guidance — the candidate-to-playbook advisor."""
from __future__ import annotations

import asyncio

from easyhunt.knowledge.coverage import COVERAGE
from easyhunt.tools.research_guide import _normalize_class


class TestNormalizeClass:
    def test_canonical_names(self) -> None:
        assert _normalize_class("sql-injection") == "sql-injection"
        assert _normalize_class("server-side-request-forgery") == "server-side-request-forgery"

    def test_aliases(self) -> None:
        assert _normalize_class("sqli") == "sql-injection"
        assert _normalize_class("xss") == "xss-injection"
        assert _normalize_class("SSRF") == "server-side-request-forgery"
        assert _normalize_class("request smuggling") == "request-smuggling"
        assert _normalize_class("JWT") == "jwt"

    def test_fuzzy_and_unknown(self) -> None:
        assert _normalize_class("sql injection") == "sql-injection"
        assert _normalize_class("  Cross-Site Scripting ") == "xss-injection"
        assert _normalize_class("quantum hacking") is None


class TestGuidance:
    def test_knowledge_playbook(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(REGISTRY["research_guidance"].fn(
            vuln_class="sql injection",
            asset="https://app.example.org/v2/search?q=1",  # in the fixture scope
            evidence="parameter 'q' echoes the value",
            stack="next.js, mysql",
        ))
        assert r["ok"] is True
        assert r["class"] == "sql-injection"
        assert any("sqli_validate" in v for v in r["validators"]["run_next"])
        assert r["validators"]["gf_patterns"]  # gf:sqli
        assert len(r["evidence_checklist"]) >= 5
        assert any("PayloadsAllTheThings" in x for x in r["resources"])
        # brain consulted (empty store -> no learned rows, still present)
        assert isinstance(r["learned"], list)

    def test_technique_index_and_waf_payloads(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        # Seed a WAF tech asset so the advisor pulls vendor payloads.
        from easyhunt.tools.common import store_assets

        store_assets(["Cloudflare"], kind="technology", source="httpx")

        r = asyncio.run(REGISTRY["research_guidance"].fn(vuln_class="xss"))
        assert r["class"] == "xss-injection"
        assert isinstance(r["waf_bypass_payloads"], list)
        assert r["technique_index"] is None or isinstance(r["technique_index"], dict)

    def test_unknown_class(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(REGISTRY["research_guidance"].fn(vuln_class="time travel"))
        assert r["ok"] is False
        assert r["error"] == "unknown_class"
        assert len(r["known"]) >= len(COVERAGE)

    def test_out_of_scope_asset_refused(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(REGISTRY["research_guidance"].fn(
            vuln_class="xss", asset="https://out-of-scope.example.org/",
        ))
        assert r["ok"] is False
        assert r["error"] == "out_of_scope"

    def test_evidence_checklists_are_class_specific(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        sqli = asyncio.run(REGISTRY["research_guidance"].fn(vuln_class="sqli"))
        ssrf = asyncio.run(REGISTRY["research_guidance"].fn(vuln_class="ssrf"))
        assert sqli["evidence_checklist"] != ssrf["evidence_checklist"]
        assert any("DB banner" in e for e in sqli["evidence_checklist"])
        assert any("OOB" in e for e in ssrf["evidence_checklist"])

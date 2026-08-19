"""Tests for research_guidance + guided_validate — the advisor and its dispatch chain."""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from easyhunt.config import Config
from easyhunt.control_plane.context import Engagement, set_engagement
from easyhunt.control_plane.scope import Scope
from easyhunt.knowledge.coverage import COVERAGE
from easyhunt.tools.research_guide import _normalize_class, _validator_names


class _PlainLab(BaseHTTPRequestHandler):
    """A plain 200 page — dispatch target for the read-only web_injection_probe."""

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    do_POST = do_HEAD = do_GET


@pytest.fixture(scope="module")
def lab_url() -> str:
    server = HTTPServer(("127.0.0.1", 0), _PlainLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def dispatch_engagement(lab_url: str, tmp_path_factory: pytest.TempPathFactory):
    """Engagement whose scope covers the lab and approves the dispatched validator."""
    from easyhunt.control_plane.approval import PolicyBackend
    from tests.conftest import scope_dict

    root = tmp_path_factory.mktemp("guided-validate")
    sd = scope_dict()
    sd["in_scope"]["cidrs"].append("127.0.0.1/32")
    sd["in_scope"]["urls"].append(f"{lab_url}/")
    config = Config(
        {
            "workspace": {"root": str(root / "engagements")},
            "approval": {"backend": "deny"},
            "sandbox": {"mode": "none"},
            "memory": {
                "poc_store": str(root / "poc-memory.jsonl"),
                "brain_store": str(root / "neuron-brain.jsonl"),
                "brain_activity": str(root / "brain-activity.jsonl"),
            },
        },
        source=str(root / "config.yaml"),
    )
    eng = Engagement(Scope(sd, source="<test>"), config, workspace=root / "ws")
    eng.approval.backend = PolicyBackend(
        auto_approve=["guided_validate", "web_injection_probe"]
    )
    set_engagement(eng)
    yield eng
    set_engagement(None)


class TestNormalizeClass:
    def test_canonical_names(self) -> None:
        assert _normalize_class("sql-injection") == "sql-injection"
        assert _normalize_class("server-side-request-forgery") == "server-side-request-forgery"

    def test_aliases(self) -> None:
        assert _normalize_class("sqli") == "sql-injection"
        assert _normalize_class("xss") == "xss-injection"
        assert _normalize_class("SSRF") == "server-side-request-forgery"
        assert _normalize_class("request smuggling") == "request-smuggling"
        assert _normalize_class("JWT") == "json-web-token"
        assert _normalize_class("file upload") == "upload-insecure-files"

    def test_fuzzy_and_unknown(self) -> None:
        assert _normalize_class("sql injection") == "sql-injection"
        assert _normalize_class("  Cross-Site Scripting ") == "xss-injection"
        assert _normalize_class("quantum hacking") is None


class TestGuidance:
    def test_knowledge_playbook(self, engagement) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(
            REGISTRY["research_guidance"].fn(
                vuln_class="sql injection",
                asset="https://app.example.org/v2/search?q=1",  # in the fixture scope
                evidence="parameter 'q' echoes the value",
                stack="next.js, mysql",
            )
        )
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

        r = asyncio.run(
            REGISTRY["research_guidance"].fn(
                vuln_class="xss",
                asset="https://out-of-scope.example.org/",
            )
        )
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


class TestValidatorNames:
    """Parsing the coverage matrix's validation strings into tool names."""

    def test_single_with_note(self) -> None:
        # The note contains a comma of its own — must be stripped BEFORE the split.
        assert _validator_names(["xss_validate (dalfox, xsstrike)"]) == ["xss_validate"]

    def test_plain_single(self) -> None:
        assert _validator_names(["sqli_validate (sqlmap)"]) == ["sqli_validate"]

    def test_plus_combination(self) -> None:
        assert _validator_names(["takeover_verify + takeover_confirm (subzy)"]) == [
            "takeover_verify",
            "takeover_confirm",
        ]

    def test_manual_and_none(self) -> None:
        assert _validator_names(["manual — proof requires uploading a file"]) == []
        assert _validator_names(["none — no validator"]) == []
        assert _validator_names(["manual / model-driven — no scanner owns this"]) == []

    def test_dedupe(self) -> None:
        assert _validator_names(["a_probe (x)", "a_probe (y)"]) == ["a_probe"]


class TestGuidedValidate:
    def test_manual_class_dispatches_nothing_and_returns_checklist(
        self, dispatch_engagement, lab_url: str
    ) -> None:
        """Classes with no auto-validator get the evidence checklist, not a fake dispatch."""
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(REGISTRY["guided_validate"].fn(
            vuln_class="file-upload",
            asset=f"{lab_url}/upload",
        ))
        assert r["ok"] is True
        assert r["dispatch"]["ran"] == []
        assert r["dispatch"]["skipped"]
        assert r["evidence_checklist"]

    def test_unknown_class(self, dispatch_engagement, lab_url: str) -> None:
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        r = asyncio.run(REGISTRY["guided_validate"].fn(
            vuln_class="time travel", asset=f"{lab_url}/x",
        ))
        assert r["ok"] is False
        assert r["error"] == "unknown_class"

    def test_out_of_scope_refused(self, dispatch_engagement) -> None:
        """targets_arg=asset puts the scope gate first — out-of-scope assets raise."""
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.errors import OutOfScopeError
        from easyhunt.tools.base import REGISTRY

        with pytest.raises(OutOfScopeError):
            asyncio.run(REGISTRY["guided_validate"].fn(
                vuln_class="xss", asset="https://out-of-scope.example.org/",
            ))

    def test_dispatch_runs_the_named_validator(self, dispatch_engagement, lab_url: str) -> None:
        """open-redirect wires to web_injection_probe — the chain dispatches it."""
        import easyhunt.mcp_server
        import easyhunt.tools.research_guide  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        easyhunt.mcp_server.load_capabilities()

        r = asyncio.run(
            REGISTRY["guided_validate"].fn(
                vuln_class="open redirect",
                asset=f"{lab_url}/page?next=/",
                limit=1,
            )
        )
        assert r["ok"] is True
        ran = r["dispatch"]["ran"]
        assert any(o["tool"] == "web_injection_probe" for o in ran)
        assert all(o["ok"] for o in ran)  # probe ran clean against a plain 200 page

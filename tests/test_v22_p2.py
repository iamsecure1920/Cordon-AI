"""P2 tier — prompt packs (P2-8), Burp handoff (P2-9), code audit (P2-11).

P2-8: the exploit/validation prompt packs are the protocol for LLM-mode
testing of classes no scanner owns. The tests pin the structure the protocol
depends on: every class has a complete pack, every pack's evidence format
covers the "No PoC, no finding" fields, and the universal denies are present.

P2-9: ``burp_send`` is the scope-enforced human handoff. The tests exercise
the failure modes (bad method, batch cap, proxy down) and a real success path
through a local recording proxy, with the proxy config monkeypatched — the
default config points at a Burp that does not exist in CI.

P2-11: ``code_audit`` degrades cleanly with no source, redacts gitleaks
secrets, and renders the deliverable.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cordon.knowledge import prompts
from cordon.mcp_server import load_capabilities
from cordon.tools import burp, code_audit

load_capabilities()

# The decorated module names are the control-plane wrappers (approval backend
# is "deny" in the test config, so any gated call would be refused before the
# body runs). functools.wraps keeps the original function on __wrapped__; the
# tests exercise the body, and the control sequence around it is covered by
# tests/test_decorator.py.
_burp_send = burp.burp_send.__wrapped__
_code_audit = code_audit.code_audit.__wrapped__


# --------------------------------------------------------------------------- #
# P2-8 — prompt packs
# --------------------------------------------------------------------------- #

class TestPromptPacks:
    def test_every_class_has_a_complete_pack(self) -> None:
        required = {
            "pack_type", "phase", "title", "role", "objective",
            "scope", "constraints", "success_criteria", "evidence_format",
        }
        for class_name in prompts.prompt_pack_classes():
            pack = prompts.get_prompt_pack(class_name)
            assert pack is not None, f"{class_name} has no pack"
            missing = required - set(pack)
            assert not missing, f"{class_name} pack missing: {missing}"
            assert pack["scope"], f"{class_name} has an empty scope"
            assert pack["constraints"], f"{class_name} has no constraints"
            assert pack["success_criteria"], f"{class_name} has no success criteria"

    def test_every_pack_evidence_format_covers_the_poc_fields(self) -> None:
        for class_name in prompts.prompt_pack_classes():
            pack = prompts.get_prompt_pack(class_name)
            assert pack is not None
            for field in prompts.EVIDENCE_FIELDS:
                assert field in pack["evidence_format"], (
                    f"{class_name} evidence_format omits {field!r} — a finding "
                    f"that cannot fill it is not reproducible"
                )

    def test_universal_denies_lead_every_constraint_list(self) -> None:
        """The cross-cutting denies must be the first rules of every pack."""
        for class_name in prompts.prompt_pack_classes():
            pack = prompts.get_prompt_pack(class_name)
            constraints = pack["constraints"]
            assert "scope.yaml" in constraints[0], (
                f"{class_name} first constraint is not the scope deny"
            )

    def test_unknown_class_returns_none(self) -> None:
        assert prompts.get_prompt_pack("not-a-class") is None

    def test_lookup_returns_a_copy(self) -> None:
        """Mutating the returned dict must not corrupt the shared table."""
        pack = prompts.get_prompt_pack("sqli")
        pack["title"] = "tampered"
        again = prompts.get_prompt_pack("sqli")
        assert again["title"] != "tampered"

    def test_exploit_pack_differs_from_validate_pack(self) -> None:
        sqli = prompts.get_prompt_pack("sqli")
        authz = prompts.get_prompt_pack("authz")
        assert sqli["pack_type"] == "exploit"
        assert authz["pack_type"] == "validate"


# --------------------------------------------------------------------------- #
# P2-9 — Burp handoff
# --------------------------------------------------------------------------- #

class _RecordingProxy(BaseHTTPRequestHandler):
    """A stand-in for Burp: records the request, answers 200 with a marker."""

    seen: list[dict] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen.append(
            {"method": "GET", "path": self.path, "headers": dict(self.headers)}
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"marker-response")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def recording_proxy():
    """A local proxy that records requests, with its own port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingProxy)
    _RecordingProxy.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


class TestBurpSend:
    async def test_bad_method_refused_before_any_request(self, engagement) -> None:
        result = await _burp_send(
            target="https://example.com/", method="TRACE"
        )
        assert result["ok"] is False
        assert result["error"] == "bad_method"

    async def test_batch_cap_enforced(self, engagement) -> None:
        targets = ",".join(f"https://example.com/{i}" for i in range(11))
        result = await _burp_send(target=targets)
        assert result["ok"] is False
        assert result["error"] == "too_many_targets"

    async def test_proxy_down_is_a_distinct_failure(self, engagement, monkeypatch) -> None:
        # A port we know is closed: bind, learn it, close it.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(burp, "_proxy_config", lambda eng: f"http://127.0.0.1:{port}")
        result = await _burp_send(target="https://example.com/")
        assert result["ok"] is False
        assert result["error"] == "burp_not_running"
        assert "127.0.0.1" in result["message"]

    async def test_request_passes_through_proxy_and_returns_response(
        self, engagement, monkeypatch, recording_proxy
    ) -> None:
        monkeypatch.setattr(burp, "_proxy_config", lambda eng: recording_proxy)
        # http:// targets through an HTTP proxy use absolute-form GET (no
        # CONNECT tunnel), which the recording stub can serve.
        result = await _burp_send(
            target="http://example.com/a,http://example.com/b",
            method="GET",
        )
        assert result["ok"] is True
        assert result["forwarded"] == 2
        for item in result["results"]:
            assert item["ok"] is True
            assert item["status_code"] == 200
            assert "marker-response" in item["body"]
        # The proxy recorded both requests — the traffic actually went through
        # it. HTTP proxies receive absolute-form request targets.
        assert len(_RecordingProxy.seen) == 2
        assert {r["path"] for r in _RecordingProxy.seen} == {
            "http://example.com/a", "http://example.com/b"
        }
        # http.server lowercases header names; the tagged UA must be present.
        assert all(
            any(k.lower() == "user-agent" for k in r["headers"])
            for r in _RecordingProxy.seen
        )

    async def test_bad_target_in_list_is_reported_per_item(self, engagement, monkeypatch, recording_proxy) -> None:
        monkeypatch.setattr(burp, "_proxy_config", lambda eng: recording_proxy)
        result = await _burp_send(target="http://example.com/ok,not-a-url")
        assert result["ok"] is True
        assert result["forwarded"] == 1
        failed = [r for r in result["results"] if not r["ok"]]
        assert len(failed) == 1
        assert failed[0]["error"] == "bad_target"


# --------------------------------------------------------------------------- #
# P2-11 — code audit
# --------------------------------------------------------------------------- #

class TestCodeAudit:
    async def test_no_source_degrades_cleanly(self, engagement) -> None:
        result = await _code_audit(path="does-not-exist")
        assert result["ok"] is True
        assert result["count"] == 0
        assert "source_fetch" in result["message"]

    def test_gitleaks_parser_redacts_and_filters_noise(self) -> None:
        payload = json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS Access Token",
                    "File": "src/config.py",
                    "Line": 12,
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Entropy": 3.9,
                    "StartLine": 12,
                    "EndLine": 12,
                    "Tags": ["AWS"],
                },
                {
                    "RuleID": "generic-api-key",
                    "Description": "API key",
                    "File": "frontend/node_modules/pkg/index.js",
                    "Line": 1,
                    "Secret": "deadbeef",
                    "Match": "deadbeef",
                },
            ]
        )
        records = code_audit._parse_gitleaks(payload)
        assert len(records) == 1, "node_modules noise must be filtered"
        record = records[0]
        assert record["file"] == "src/config.py"
        assert record["secret"] == "[redacted]"
        assert record["match"] == "[redacted]"
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(records)
        assert record["rule"] == "aws-access-token"

    def test_gitleaks_parser_tolerates_junk(self) -> None:
        assert code_audit._parse_gitleaks("not json") == []
        assert code_audit._parse_gitleaks(json.dumps({"results": []})) == []

    def test_surface_implications_derive_from_hits(self) -> None:
        records = [
            {"cwe": "CWE-89", "path": "api/search.py"},
            {"cwe": "CWE-89", "path": "api/search.py"},
            {"cwe": "CWE-79", "path": "web/render.py"},
        ]
        implications = code_audit._surface_implications(records)
        assert any("CWE-89" in i for i in implications)
        assert any("api/" in i for i in implications)
        assert code_audit._surface_implications([])  # graceful empty

    def test_markdown_renders_sections_and_stays_redacted(self) -> None:
        md = code_audit._render_markdown(
            source="/ws/source/repo",
            semgrep=[
                {
                    "message": "SQL query built from string",
                    "check_id": "python.lang.security.audit.dangerous-sql",
                    "path": "api/search.py",
                    "line": 42,
                    "end_line": 42,
                    "severity": "ERROR",
                    "snippet": "cursor.execute(user_input)",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021",
                    "confidence": "HIGH",
                    "references": [],
                    "fix": None,
                }
            ],
            gitleaks=[
                {
                    "file": "src/config.py",
                    "line": 12,
                    "rule": "aws-access-token",
                    "description": "AWS Access Token",
                }
            ],
            implications=["2 finding(s) tagged CWE-89"],
        )
        assert "# Code audit deliverable" in md
        assert "SQL query built from string" in md
        assert "api/search.py:42" in md
        assert "aws-access-token" in md
        assert "redacted" in md.lower()

    def test_empty_audit_renders_honestly(self) -> None:
        md = code_audit._render_markdown(
            source="/ws/source/repo", semgrep=[], gitleaks=[], implications=[]
        )
        assert "_No findings at the configured severity._" in md
        assert "_No secret-pattern hits._" in md

"""Tests for forbidden_bypass / forbidden_candidates (unKover 403-bypass)."""

from __future__ import annotations

import asyncio
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cordon.config import Config
from cordon.control_plane.context import Engagement, set_engagement
from cordon.control_plane.scope import Scope
from cordon.knowledge.findings import Severity
from cordon.tools.forbidden import _escalate

UNKOVER = shutil.which("unkover")


class _ForbiddenLab(BaseHTTPRequestHandler):
    """403 lab:

    * ``/open``    — always 200 (preflight-refusal case: not a 403)
    * ``/locked``  — always 403, no bypass path (clean-pass case)
    * anything else (e.g. ``/admin``) — 403 unless X-Forwarded-For /
      X-Original-URL / POST / ``/./``, then 200 (bypass case)
    """

    def log_message(self, *args: object) -> None:  # keep test output clean
        pass

    def _go(self) -> None:
        # containment, not startswith: unKover's path_normalization rewrites
        # /locked -> /./locked, which must STILL be 403 on the locked path.
        if "/open" in self.path:
            self._reply(200, b"open page")
            return
        if "/locked" in self.path:
            self._reply(403, b"forbidden forever")
            return
        h = self.headers
        bypass = (
            h.get("X-Forwarded-For") or h.get("X-Original-URL") or self.command in ("POST", "PUT")
        )
        self._reply(200 if bypass else 403, b"secret dashboard content" if bypass else b"forbidden")

    def _reply(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _go


@pytest.fixture(scope="module")
def lab_url() -> str:
    server = HTTPServer(("127.0.0.1", 0), _ForbiddenLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def engagement(lab_url: str, tmp_path_factory: pytest.TempPathFactory):
    """Engagement whose scope includes the 403 lab (module-scoped, like lab_url)."""
    from cordon.control_plane.approval import PolicyBackend
    from tests.conftest import scope_dict

    root = tmp_path_factory.mktemp("forbidden")
    sd = scope_dict()
    sd["in_scope"]["cidrs"].append("127.0.0.1/32")
    sd["in_scope"]["urls"].append(f"{lab_url}/")
    # Redirect the brain/activity stores to tmp — tests must never write the
    # real home-dir memory.
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

    eng = Engagement(
        Scope(sd, source="<test>"),
        config,
        workspace=root / "ws",
    )
    eng.approval.backend = PolicyBackend(auto_approve=["forbidden_bypass", "forbidden_chain"])
    set_engagement(eng)
    yield eng
    set_engagement(None)


class TestEscalation:
    def test_admin_path_with_authz_technique_is_high(self) -> None:
        assert _escalate("https://x.com/admin/users", "ip_header_spoof") is Severity.HIGH
        assert _escalate("https://x.com/internal/api/v1/x", "header_override") is Severity.HIGH

    def test_non_admin_stays_medium(self) -> None:
        assert _escalate("https://x.com/products", "ip_header_spoof") is Severity.MEDIUM

    def test_method_quirk_is_medium_even_on_admin(self) -> None:
        assert _escalate("https://x.com/admin", "method_tampering") is Severity.MEDIUM


class TestParse:
    """Parsing of unKover's JSON contract — no binary required."""

    def test_bypass_json(self) -> None:
        from cordon.tools.forbidden import _parse_unkover_output

        out = {
            "meta": {"tool": "unkover"},
            "bypass": True,
            "target": "https://x.com/admin",
            "poc": "curl -i -H 'X-Forwarded-For: 127.0.0.1' 'https://x.com/admin'",
            "findings": [
                {
                    "technique": "ip_header_spoof",
                    "request": {"header": "X-Forwarded-For", "value": "127.0.0.1"},
                    "result": {"status": 200, "size": 24},
                }
            ],
            "baseline": {"status": 403, "size": 9},
        }
        parsed, error = _parse_unkover_output(json.dumps(out))
        assert error is None
        assert parsed["bypass"] is True
        assert parsed["findings"][0]["technique"] == "ip_header_spoof"
        assert parsed["poc"].startswith("curl")

    def test_clean_json(self) -> None:
        from cordon.tools.forbidden import _parse_unkover_output

        parsed, error = _parse_unkover_output(
            json.dumps({"bypass": False, "findings": [], "baseline": {"status": 403, "size": 9}})
        )
        assert error is None
        assert parsed["bypass"] is False

    def test_error_json(self) -> None:
        from cordon.tools.forbidden import _parse_unkover_output

        parsed, error = _parse_unkover_output(
            json.dumps({"error": "target returned 301, expected 403"})
        )
        assert parsed is None
        assert error == "not_forbidden"
        assert parsed is None and error == "not_forbidden"

    def test_garbage_output(self) -> None:
        from cordon.tools.forbidden import _parse_unkover_output

        parsed, error = _parse_unkover_output("not json at all\n")
        assert parsed is None
        assert error == "unparseable_output"


@pytest.mark.skipif(not UNKOVER, reason="unkover not installed")
class TestLiveBypass:
    def test_finds_bypass_and_files_finding(self, engagement, lab_url: str) -> None:
        import cordon.tools.forbidden  # noqa: F401
        from cordon.tools.base import REGISTRY

        result = asyncio.run(REGISTRY["forbidden_bypass"].fn(url=f"{lab_url}/admin"))
        assert result["ok"] is True
        assert result["bypass"] is True
        assert result["technique"] == "ip_header_spoof"
        assert result["poc"].startswith("curl")
        findings = engagement.findings.all()
        assert len(findings) == 1
        f = findings[0]
        assert f.severity is Severity.HIGH  # admin path + authz-relevant technique
        assert f.status.value == "needs_manual_review"
        assert "X-Forwarded-For" in str(f.extra.get("poc"))

    def test_not_forbidden_is_refused(self, engagement, lab_url: str) -> None:
        import cordon.tools.forbidden  # noqa: F401
        from cordon.tools.base import REGISTRY

        # A URL that is NOT 403 must be refused before any bypass attempt.
        before = len(engagement.findings.all())
        result = asyncio.run(REGISTRY["forbidden_bypass"].fn(url=f"{lab_url}/open"))
        assert result["ok"] is False
        assert result["error"] == "not_forbidden"
        assert len(engagement.findings.all()) == before  # nothing filed

    def test_clean_pass_files_nothing(self, engagement, lab_url: str) -> None:
        import cordon.tools.forbidden  # noqa: F401
        from cordon.tools.base import REGISTRY

        # A genuinely enforced 403 survives all 12 techniques: no new finding,
        # and the brain records a clean lesson.
        before = len(engagement.findings.all())
        result = asyncio.run(REGISTRY["forbidden_bypass"].fn(url=f"{lab_url}/locked"))
        assert result["ok"] is True
        assert result["bypass"] is False
        assert len(engagement.findings.all()) == before  # nothing new filed
        lessons = [
            s
            for s in engagement.brain._synapses.values()
            if s.context.startswith("access-control-bypass")
        ]
        assert lessons and lessons[0].clean >= 1

    def test_candidates_precheck(self, engagement, lab_url: str) -> None:
        import cordon.tools.forbidden  # noqa: F401
        from cordon.tools.base import REGISTRY

        result = asyncio.run(
            REGISTRY["forbidden_candidates"].fn(urls=[f"{lab_url}/admin", f"{lab_url}/open"])
        )
        assert result["checked"] == 2
        assert len(result["candidates"]) == 1
        assert result["candidates"][0]["status"] == 403


@pytest.mark.skipif(not UNKOVER, reason="unkover not installed")
class TestForbiddenChain:
    def test_chain_discovers_and_bypasses_403(self, engagement, lab_url: str) -> None:
        """The auto-chain: pre-check finds the 403, then bypasses it end-to-end."""
        import cordon.tools.forbidden  # noqa: F401
        from cordon.tools.base import REGISTRY

        result = asyncio.run(
            REGISTRY["forbidden_chain"].fn(
                urls=[f"{lab_url}/admin", f"{lab_url}/open", f"{lab_url}/locked"]
            )
        )
        assert result["ok"] is True
        assert result["checked"] == 3
        assert result["candidates"] == 2  # /admin and /locked are 403
        assert result["bypassed"] == 1  # /admin bypasses; /locked holds
        by_url = {r["url"]: r for r in result["results"]}
        assert by_url[f"{lab_url}/admin"]["bypass"] is True
        assert by_url[f"{lab_url}/locked"]["bypass"] is False
        # The bypass filed a finding through forbidden_bypass.
        assert any(f.asset == f"{lab_url}/admin" for f in engagement.findings.all())

    def test_chain_empty_input_refused(self, engagement) -> None:
        """An empty target list is refused by the scope gate, never silently passed."""
        import cordon.tools.forbidden  # noqa: F401
        from cordon.errors import CordonError
        from cordon.tools.base import REGISTRY

        with pytest.raises(CordonError):
            asyncio.run(REGISTRY["forbidden_chain"].fn(urls=[]))

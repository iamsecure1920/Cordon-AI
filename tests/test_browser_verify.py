"""Tests for browser_verify (Playwright-driven reflection/execution proof)."""

from __future__ import annotations

import asyncio
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from cordon.config import Config
from cordon.control_plane.context import Engagement, set_engagement
from cordon.control_plane.scope import Scope
from cordon.knowledge.findings import Severity
from cordon.tools.browser_verify import (
    Reflection,
    build_target_url,
    classify_reflection,
    reflection_snippet,
)

CHROME = (
    shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
)


def _playwright_ok() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


HAVE_BROWSER = _playwright_ok() and bool(CHROME)


class _ReflectLab(BaseHTTPRequestHandler):
    """Reflects ``?q=`` into the page body — unescaped (XSS-able)."""

    def log_message(self, *args: object) -> None:
        pass

    def _reply(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = f"<html><head><title>lab</title></head><body><h1>Search: {q}</h1></body></html>"
        self._reply(200, body.encode())

    do_POST = do_GET


@pytest.fixture(scope="module")
def lab_url() -> str:
    server = HTTPServer(("127.0.0.1", 0), _ReflectLab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def engagement(lab_url: str, tmp_path_factory: pytest.TempPathFactory):
    from cordon.control_plane.approval import PolicyBackend
    from tests.conftest import scope_dict

    root = tmp_path_factory.mktemp("browser-verify")
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
    eng.approval.backend = PolicyBackend(auto_approve=["browser_verify"])
    set_engagement(eng)
    yield eng
    set_engagement(None)


class TestBuildTargetUrl:
    def test_injects_param(self) -> None:
        out = build_target_url("https://x.com/search?foo=1", "q", "<svg onload=alert(1)>")
        assert out.startswith("https://x.com/search?foo=1&q=")
        assert parse_qs(urlsplit(out).query)["q"][0] == "<svg onload=alert(1)>"

    def test_replaces_existing_param(self) -> None:
        out = build_target_url("https://x.com/search?q=old&foo=1", "q", "new")
        qs = parse_qs(urlsplit(out).query)
        assert qs["q"] == ["new"]
        assert qs["foo"] == ["1"]

    def test_no_param_returns_unchanged(self) -> None:
        url = "https://x.com/page"
        assert build_target_url(url, "", "x") == url


class TestClassifyReflection:
    def test_html_significant_raw(self) -> None:
        assert (
            classify_reflection("<h1>echo <script>a</script></h1>", "<script>a</script>")
            == Reflection.RAW
        )

    def test_plain_echo_is_not_raw(self) -> None:
        # "hello-world" reflected verbatim is PLAIN — interesting, not injectable.
        assert (
            classify_reflection("<h1>Search: hello-world</h1>", "hello-world") == Reflection.PLAIN
        )

    def test_escaped(self) -> None:
        assert (
            classify_reflection(
                "<h1>Search: &lt;script&gt;a&lt;/script&gt;</h1>", "<script>a</script>"
            )
            == Reflection.ESCAPED
        )

    def test_absent(self) -> None:
        assert classify_reflection("<h1>nope</h1>", "<script>a</script>") == Reflection.NONE

    def test_empty_payload(self) -> None:
        assert classify_reflection("<h1>x</h1>", "") == Reflection.NONE


class TestSnippet:
    def test_windows_around_needle(self) -> None:
        doc = "A" * 300 + "<b>needle</b>" + "B" * 300
        snip = reflection_snippet(doc, "needle")
        assert "needle" in snip
        assert len(snip) <= 2 * 200 + len("needle") + 8


@pytest.mark.skipif(not HAVE_BROWSER, reason="playwright or Chrome unavailable")
class TestLiveBrowser:
    def test_execution_files_high_finding(self, engagement, lab_url: str) -> None:
        """An executed payload is the PoC — HIGH finding with screenshot evidence."""
        import cordon.tools.browser_verify  # noqa: F401
        from cordon.tools.base import REGISTRY

        result = asyncio.run(
            REGISTRY["browser_verify"].fn(
                url=f"{lab_url}/", param="q", payload='<svg onload=alert("xvuln")>'
            )
        )
        assert result["ok"] is True
        assert result["executed"] is True
        assert result["count"] >= 1
        findings = engagement.findings.all()
        xss = [f for f in findings if "XSS" in f.title]
        assert xss, "executed payload must file an XSS finding"
        assert xss[0].severity is Severity.HIGH
        assert any(ev.kind == "screenshot" for ev in xss[0].evidence)

    def test_plain_echo_files_nothing(self, engagement, lab_url: str) -> None:
        """A plain token echoed back is NOT a finding (false-positive guard)."""
        import cordon.tools.browser_verify  # noqa: F401
        from cordon.tools.base import REGISTRY

        before = len(engagement.findings.all())
        result = asyncio.run(
            REGISTRY["browser_verify"].fn(url=f"{lab_url}/", param="q", payload="hello-world")
        )
        assert result["ok"] is True
        assert result["reflection"] == Reflection.PLAIN
        assert result["executed"] is False
        assert result["count"] == 0
        assert len(engagement.findings.all()) == before

"""End-to-end run against a lab target on loopback that this test owns.

Starts a deliberately misconfigured HTTP server, authorizes it explicitly in a
scope file, and drives the real flow: load scope → probe → scan → triage →
validate → report. Real binaries (httpx, nuclei) run if they are installed;
where they are not, the test asserts the graceful-degradation path instead.

The server binds 127.0.0.1 only, and the scope names 127.0.0.0/8 explicitly —
which is the one way EasyHunt permits a reserved address, precisely so a lab can
exist without weakening the rule for real engagements.
"""

from __future__ import annotations

import functools
import http.server
import shutil
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from easyhunt.config import Config
from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.context import Engagement, set_engagement
from easyhunt.control_plane.scope import Scope
from easyhunt.knowledge.findings import Status
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import REGISTRY

pytestmark = pytest.mark.e2e

# The full tool surface, exactly as the MCP server loads it.
load_capabilities()


def _real_httpx() -> bool:
    """ProjectDiscovery's httpx, not the Python library's CLI of the same name."""
    from easyhunt.tools.common import verify_identity

    return shutil.which("httpx") is not None and verify_identity("httpx")[0]

VULNERABLE_FILES = {
    ".env": "APP_ENV=production\nDB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n",
    ".git/config": "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/example/app.git\n",
    "index.html": "<html><title>Lab target</title><body>EasyHunt e2e lab</body></html>",
    "app.js": 'const API="/api/v2/internal";const KEY="AIzaSyD-1234567890abcdefghijklmnopqrstu";\n',
}


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # noqa: ANN401
        """Keep the test output readable."""

    def guess_type(self, path: str) -> str:
        # Serve dotfiles as plain text, the way a misconfigured server would.
        if path.endswith((".env", "config")):
            return "text/plain"
        return super().guess_type(path)


@pytest.fixture(scope="module")
def lab() -> Any:
    """A deliberately misconfigured web server on loopback."""
    root = Path(__file__).parent / "_lab_root"
    root.mkdir(exist_ok=True)
    for name, content in VULNERABLE_FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    # directory= is an __init__ kwarg, not a class attribute — setting it on the
    # class is silently overwritten and the server ends up serving the cwd.
    handler = functools.partial(QuietHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield {"port": port, "url": f"http://127.0.0.1:{port}", "root": root}

    server.shutdown()
    server.server_close()
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def lab_engagement(lab, tmp_path) -> Any:
    """An engagement authorized for the loopback lab and nothing else."""
    scope_data = {
        "version": 1,
        "engagement": {
            "name": "e2e-lab",
            # This is an asset the test process itself created and owns.
            "authorization": "owned",
            "fetched_at": datetime.now(UTC).isoformat(),
            "researcher_handle": "e2e",
        },
        # Loopback is reserved; naming the CIDR explicitly is the only way
        # EasyHunt will permit it.
        "in_scope": {"cidrs": ["127.0.0.0/8"]},
        "out_of_scope": {"domains": ["example.com"]},
        "rules": {"max_rps": 50, "max_concurrency": 5, "allow_aggressive": True,
                  "allow_exploitation": True},
        "budget": {"llm_usd": 0.0, "wall_clock_minutes": 10, "max_requests": 100_000,
                   "max_tool_seconds": 600},
    }
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")

    repo = Path(__file__).resolve().parents[1]
    config = Config(
        {
            "workspace": {"root": str(tmp_path / "engagements")},
            "sandbox": {"mode": "none"},
            "approval": {"backend": "deny"},
            "rules": {"dirs": [str(repo / "rules")]},
            "memory": {"poc_store": str(tmp_path / "memory.jsonl")},
            "engines": {"nuclei": {"templates_dir": str(repo / "rules" / "nuclei")}},
        },
        source=str(tmp_path / "config.yaml"),
    )
    engagement = Engagement(Scope.load(scope_file), config, workspace=tmp_path / "ws")
    set_engagement(engagement)

    from easyhunt.plugins.loader import load_all

    load_all([repo / "rules"], import_python=False)

    yield engagement
    set_engagement(None)


class TestEndToEnd:
    async def test_scope_authorizes_the_lab_and_nothing_else(self, lab_engagement, lab) -> None:
        scope = lab_engagement.scope
        assert scope.check(lab["url"]).in_scope
        assert scope.check("127.0.0.1").in_scope
        # The rest of the internet is still refused.
        assert not scope.check("example.com").in_scope
        assert not scope.check("169.254.169.254").in_scope
        assert not scope.check("8.8.8.8").in_scope

    @pytest.mark.skipif(
        not _real_httpx(), reason="ProjectDiscovery httpx not on PATH (name collision or absent)"
    )
    async def test_http_probe_finds_the_service(self, lab_engagement, lab) -> None:
        result = await REGISTRY["http_probe"].fn(target=lab["url"])
        assert result["live"] >= 1
        assert any("Lab target" in str(s.get("title")) for s in result["services"])

    async def test_http_probe_degrades_cleanly_when_the_tool_is_wrong(
        self, lab_engagement, lab
    ) -> None:
        # Whether or not the right httpx is installed, the wrapper must return a
        # well-formed result rather than raising — a missing or shadowed binary is
        # a coverage gap to report, not a crash.
        result = await REGISTRY["http_probe"].fn(target=lab["url"])
        assert result["ok"] is True
        assert isinstance(result["services"], list)

    @pytest.mark.skipif(not shutil.which("nuclei"), reason="nuclei not installed")
    async def test_nuclei_finds_the_exposed_git_config(self, lab_engagement, lab) -> None:
        lab_engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        result = await REGISTRY["nuclei_scan"].fn(
            target=lab["url"],
            templates=[str(Path(__file__).resolve().parents[1] / "rules" / "nuclei")],
            severity="info,low,medium,high,critical",
            wait_seconds=180,
        )
        assert result.get("completed"), f"scan did not finish: {result}"
        rules = {f["rule_id"] for f in result.get("findings", [])}
        assert "easyhunt-exposed-git-config" in rules, f"got {rules}"

        finding = next(
            f for f in lab_engagement.findings.all() if f.rule_id == "easyhunt-exposed-git-config"
        )
        # A scanner hit is a candidate, never a confirmed finding.
        assert finding.status is Status.CANDIDATE
        assert finding.poc is None

    async def test_js_analysis_extracts_an_endpoint_and_a_key(self, lab_engagement, lab) -> None:
        result = await REGISTRY["js_analyze"].fn(target=f"{lab['url']}/app.js")
        assert result["ok"]
        assert "/api/v2/internal" in result["endpoints"]
        assert any(s["type"] == "google-api-key" for s in result["secrets"])
        # The key must be masked everywhere it appears — including the
        # surrounding-source context, which is where it used to leak through.
        assert all(
            "AIzaSyD-1234567890abcdefghijklmnopqrstu" not in str(s) for s in result["secrets"]
        )
        stored = [f for f in lab_engagement.findings.all() if f.rule_id == "js.google-api-key"]
        assert stored and all(
            "AIzaSyD-1234567890abcdefghijklmnopqrstu" not in e.excerpt
            for f in stored
            for e in f.evidence
        )

    async def test_validation_confirms_a_real_exposure(self, lab_engagement, lab) -> None:
        from easyhunt.knowledge.findings import Finding, Severity

        finding = lab_engagement.findings.add(
            Finding(
                asset=f"{lab['url']}/.env",
                title="Exposed .env file",
                severity=Severity.HIGH,
                source_tool="e2e",
                rule_id="exposure.env",
                tags=["exposure"],
            )
        )
        lab_engagement.approval.backend = PolicyBackend(auto_approve=["validate_findings"])

        result = await REGISTRY["validate_findings"].fn(finding_ids=[finding.id])
        assert result["confirmed"] == 1
        assert finding.status is Status.CONFIRMED
        assert finding.poc.is_reproducible()
        assert "curl" in finding.poc.reproduction

    async def test_validation_refuses_to_confirm_a_missing_file(self, lab_engagement, lab) -> None:
        from easyhunt.knowledge.findings import Finding, Severity

        finding = lab_engagement.findings.add(
            Finding(
                asset=f"{lab['url']}/does-not-exist.env",
                title="Exposed .env file",
                severity=Severity.HIGH,
                tags=["exposure"],
            )
        )
        lab_engagement.approval.backend = PolicyBackend(auto_approve=["validate_findings"])

        result = await REGISTRY["validate_findings"].fn(finding_ids=[finding.id])
        assert result["confirmed"] == 0
        assert finding.status is Status.NEEDS_MANUAL_REVIEW

    async def test_out_of_scope_target_is_refused_mid_run(self, lab_engagement) -> None:
        from easyhunt.errors import OutOfScopeError

        with pytest.raises(OutOfScopeError):
            await REGISTRY["http_probe"].fn(target="http://example.com/")

    async def test_full_flow_produces_a_complete_report(self, lab_engagement, lab) -> None:
        import easyhunt.tools.report_tools  # noqa: F401
        from easyhunt.knowledge.findings import Finding, Severity

        finding = lab_engagement.findings.add(
            Finding(
                asset=f"{lab['url']}/.env",
                # Deliberately not "…with credentials": a title mentioning
                # credentials classifies as a secrets finding, which routes to a
                # human rather than to automatic validation.
                title="Exposed .env configuration file",
                severity=Severity.CRITICAL,
                source_tool="nuclei",
                rule_id="exposed-env-file",
                how_found="Nuclei template 'exposed-env-file' matched",
                tags=["exposure"],
            )
        )
        lab_engagement.discovered("dangling_cname", "127.0.0.1", source="dns_resolve")
        lab_engagement.approval.backend = PolicyBackend(auto_approve=["validate_findings"])
        await REGISTRY["validate_findings"].fn(finding_ids=[finding.id])

        result = await REGISTRY["report_generate"].fn()
        assert result["ok"] and result["confirmed"] >= 1

        report = Path(result["reports"]["md"]).read_text()
        assert "## Confirmed findings" in report
        assert "Exposed .env configuration file" in report
        assert "curl" in report
        assert lab_engagement.scope.fingerprint() in report
        assert "Hash chain: intact" in report

        for artifact in ("md", "csv", "json", "taskgraph"):
            assert Path(result["reports"][artifact]).exists()

        summary = lab_engagement.finish()
        assert summary["audit"]["chain_ok"]
        # A confirmed finding's method is carried into cross-engagement memory.
        assert summary["memory"]["techniques_remembered"] >= 1

    async def test_audit_log_records_every_attempt(self, lab_engagement, lab) -> None:
        from easyhunt.errors import OutOfScopeError

        await REGISTRY["js_analyze"].fn(target=f"{lab['url']}/app.js")
        with pytest.raises(OutOfScopeError):
            await REGISTRY["js_analyze"].fn(target="http://example.com/app.js")

        records = [r for r in lab_engagement.audit.read_all() if r["event"] == "tool_call"]
        outcomes = {r["outcome"] for r in records}
        assert "ok" in outcomes and "refused" in outcomes
        assert lab_engagement.audit.verify()[0]

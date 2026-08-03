"""Engine tier: BBOT normalization/scope enforcement and Nuclei parsing/execution.

The Nuclei tests run a stub binary that emits recorded JSONL, so the wrapper's
argument construction, scope re-checking, and parsing are all exercised without
sending a packet anywhere.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.sanitize import sanitize_argv
from easyhunt.engines import osmedeus_engine, strix_engine  # noqa: F401 — registers the tools
from easyhunt.engines.bbot_engine import PRESET_MODES, _store_event, normalize_event
from easyhunt.engines.nuclei_engine import DENIED_TAGS, parse_nuclei_results
from easyhunt.engines.nuclei_engine import SPEC as NUCLEI_SPEC
from easyhunt.errors import SanitizeError, ToolUnavailable
from easyhunt.knowledge.findings import Severity, Status
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import resolve_binary, verify_identity

NUCLEI_RESULT = {
    "template-id": "exposed-git-config",
    "template": "custom/exposed-git-config.yaml",
    "info": {
        "name": "Exposed .git/config",
        "severity": "medium",
        "description": "The .git directory is served.",
        "remediation": "Block dotted paths.",
        "tags": ["exposure", "git"],
        "reference": ["https://example.org/ref"],
        "classification": {"cvss-score": 5.3, "cvss-metrics": "CVSS:3.1/AV:N/AC:L"},
    },
    "matched-at": "https://www.example.com/.git/config",
    "host": "www.example.com",
    "type": "http",
    "request": "GET /.git/config HTTP/1.1",
    "response": "HTTP/1.1 200 OK\n\n[core]\nrepositoryformatversion = 0",
    "extracted-results": ["https://github.com/org/repo.git"],
    "curl-command": "curl -X GET https://www.example.com/.git/config",
}


@pytest.fixture
def fake_nuclei(tmp_path: Path, monkeypatch) -> Path:
    """A stub 'nuclei' that prints one finding and one out-of-scope finding."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    off_scope = {**NUCLEI_RESULT, "matched-at": "https://evil.example.net/.git/config"}
    # Written to a file and cat'd rather than echo'd: dash's echo interprets
    # backslash escapes, which would split the JSON across lines.
    payload = tmp_path / "nuclei-output.jsonl"
    payload.write_text(
        json.dumps(NUCLEI_RESULT) + "\n"
        + json.dumps(off_scope) + "\n"
        + "[INF] banner noise that is not JSON\n"
    )
    script = bin_dir / "nuclei"
    # The `-version` branch matters: nuclei declares identity_marker="nuclei
    # engine" because PyPI publishes an unrelated "nuclei" package, and
    # resolve_binary refuses any binary of that name which cannot identify
    # itself. A stub that does not answer -version the way the real tool does is
    # exactly the impostor the marker exists to reject, so without this the
    # wrapper correctly declines to run it and the argv file is never written.
    script.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *-version*) echo "[INF] Nuclei Engine Version: v3.7.1"; exit 0 ;;\n'
        "esac\n"
        f'printf "%s\\n" "$*" > "{tmp_path}/nuclei-argv.txt"\n'
        f'cat "{payload}"\n'
        "exit 0\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    # resolve_binary is lru_cached and guarded_run only consults it for specs
    # that declare an identity_marker. nuclei gained one, so a path cached
    # earlier in the session — from the real PATH — would be returned here and
    # this stub would never run. Same clearing the resolution tests already do.
    resolve_binary.cache_clear()
    verify_identity.cache_clear()
    return tmp_path


class TestBbotNormalization:
    def test_event_flattening(self) -> None:
        event = SimpleNamespace(
            type="DNS_NAME",
            data="api.example.com",
            host="api.example.com",
            module="crt",
            tags=["subdomain", "in-scope"],
            scope_distance=0,
            id="abc",
        )
        record = normalize_event(event)
        assert record["type"] == "DNS_NAME"
        assert record["tags"] == ["in-scope", "subdomain"]

    def test_in_scope_event_becomes_an_asset(self, engagement) -> None:
        record = {
            "type": "DNS_NAME", "data": "api.example.com", "host": "api.example.com",
            "module": "crt", "tags": [], "scope_distance": 0, "id": "1",
        }
        assert _store_event(engagement, record)["stored"] == "asset"
        assert "api.example.com" in engagement.assets.values("subdomain")

    def test_out_of_scope_event_is_dropped_and_audited(self, engagement) -> None:
        record = {
            "type": "DNS_NAME", "data": "someone-else.net", "host": "someone-else.net",
            "module": "crt", "tags": [], "scope_distance": 1, "id": "2",
        }
        assert _store_event(engagement, record) is None
        assert len(engagement.assets) == 0
        drops = [r for r in engagement.audit.read_all() if r["event"] == "event_dropped"]
        assert drops and drops[-1]["reason"] == "not_in_allowlist"

    def test_denylisted_event_is_dropped(self, engagement) -> None:
        record = {
            "type": "DNS_NAME", "data": "blog.example.com", "host": "blog.example.com",
            "module": "crt", "tags": [], "scope_distance": 0, "id": "3",
        }
        assert _store_event(engagement, record) is None

    def test_vulnerability_event_becomes_a_candidate_finding(self, engagement) -> None:
        record = {
            "type": "VULNERABILITY",
            "data": {"description": "Exposed admin panel", "severity": "HIGH"},
            "host": "admin.example.com", "module": "httpx", "tags": [], "scope_distance": 0, "id": "4",
        }
        assert _store_event(engagement, record)["stored"] == "finding"
        finding = engagement.findings.all()[0]
        assert finding.severity is Severity.HIGH
        # A scanner event is never born confirmed.
        assert finding.status is Status.CANDIDATE

    def test_baddns_event_is_routed_to_the_takeover_flow(self, engagement) -> None:
        record = {
            "type": "FINDING",
            "data": {"description": "Dangling CNAME to unclaimed S3 bucket"},
            "host": "cdn.example.com", "module": "baddns", "tags": ["takeover"],
            "scope_distance": 0, "id": "5",
        }
        _store_event(engagement, record)
        finding = engagement.findings.all()[0]
        assert finding.phase == "takeover"
        assert "takeover-candidate" in finding.tags

    def test_unknown_event_types_are_ignored(self, engagement) -> None:
        record = {
            "type": "SOMETHING_NEW", "data": "x", "host": "www.example.com",
            "module": "m", "tags": [], "scope_distance": 0, "id": "6",
        }
        assert _store_event(engagement, record) is None


class TestBbotPresetGating:
    async def test_aggressive_preset_cannot_be_run_through_the_passive_tool(self, engagement) -> None:
        with pytest.raises(ToolUnavailable, match="bbot_scan_active"):
            await REGISTRY["bbot_scan"].fn(target="www.example.com", preset="spider")

    async def test_unknown_preset_is_refused(self, engagement) -> None:
        with pytest.raises(ToolUnavailable, match="unknown BBOT preset"):
            await REGISTRY["bbot_scan"].fn(target="www.example.com", preset="hack-everything")

    def test_every_exposed_preset_declares_a_mode(self) -> None:
        assert all(mode in {"passive", "aggressive"} for mode in PRESET_MODES.values())


class TestNucleiParsing:
    def test_parses_jsonl_into_candidates(self) -> None:
        findings = parse_nuclei_results(json.dumps(NUCLEI_RESULT))
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "exposed-git-config"
        assert finding.severity is Severity.MEDIUM
        assert finding.cvss == 5.3
        assert finding.status is Status.CANDIDATE
        assert finding.confidence < 0.95
        assert "Nuclei template" in finding.how_found

    def test_request_and_response_become_evidence(self) -> None:
        finding = parse_nuclei_results(json.dumps(NUCLEI_RESULT))[0]
        kinds = {e.kind for e in finding.evidence}
        assert {"request", "response", "log"} <= kinds

    def test_banner_noise_is_skipped(self) -> None:
        text = "[INF] Templates loaded\n" + json.dumps(NUCLEI_RESULT) + "\nnot json\n"
        assert len(parse_nuclei_results(text)) == 1

    def test_empty_output_yields_nothing(self) -> None:
        assert parse_nuclei_results("") == []


class TestNucleiArgumentPolicy:
    def test_rate_limit_ceiling_is_enforced(self) -> None:
        with pytest.raises(SanitizeError, match="exceeds the ceiling"):
            sanitize_argv("nuclei", ["-rate-limit", "5000"], policy=NUCLEI_SPEC.arg_policy)

    def test_itags_is_not_on_the_allowlist(self) -> None:
        # -itags would re-enable the dos/fuzz/intrusive templates we exclude.
        with pytest.raises(SanitizeError):
            sanitize_argv("nuclei", ["-itags", "dos"], policy=NUCLEI_SPEC.arg_policy)

    def test_disruptive_tags_are_denied_as_values(self) -> None:
        with pytest.raises(SanitizeError, match="denied"):
            sanitize_argv("nuclei", ["-tags", "cve,dos"], policy=NUCLEI_SPEC.arg_policy)

    def test_normal_invocation_passes(self) -> None:
        argv = ["-l", "targets.txt", "-jsonl", "-silent", "-severity", "high,critical", "-c", "10"]
        assert sanitize_argv("nuclei", argv, policy=NUCLEI_SPEC.arg_policy) == argv


class TestNucleiExecution:
    async def test_scan_runs_parses_and_stores(self, engagement, fake_nuclei) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        result = await REGISTRY["nuclei_scan"].fn(
            target="https://www.example.com", wait_seconds=30
        )
        assert result["completed"] is True
        assert result["count"] == 1, "the out-of-scope result must not be counted"
        assert result["by_severity"] == {"medium": 1}
        assert engagement.findings.all()[0].rule_id == "exposed-git-config"

    async def test_out_of_scope_result_is_dropped_and_audited(self, engagement, fake_nuclei) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        await REGISTRY["nuclei_scan"].fn(target="https://www.example.com", wait_seconds=30)
        drops = [r for r in engagement.audit.read_all() if r["event"] == "finding_dropped"]
        assert drops and "evil.example.net" in drops[0]["asset"]

    async def test_rate_limit_comes_from_scope_not_the_caller(self, engagement, fake_nuclei) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        await REGISTRY["nuclei_scan"].fn(target="https://www.example.com", wait_seconds=30)
        argv = (fake_nuclei / "nuclei-argv.txt").read_text()
        assert "-rate-limit 5" in argv  # scope fixture sets max_rps: 5
        assert "-etags" in argv and "dos" in argv

    async def test_disruptive_tags_refused_before_launch(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        with pytest.raises(ToolUnavailable, match="disruptive"):
            await REGISTRY["nuclei_scan"].fn(target="https://www.example.com", tags="cve,dos")

    async def test_custom_rules_directory_is_included(self, engagement, fake_nuclei) -> None:
        from easyhunt.plugins.loader import load_all

        load_all([Path(__file__).resolve().parents[1] / "rules"], import_python=False)
        engagement.approval.backend = PolicyBackend(auto_approve=["nuclei_scan"])
        await REGISTRY["nuclei_scan"].fn(target="https://www.example.com", wait_seconds=30)
        assert "rules/nuclei" in (fake_nuclei / "nuclei-argv.txt").read_text()

    async def test_scan_requires_approval(self, engagement, fake_nuclei) -> None:
        from easyhunt.errors import ApprovalDenied

        with pytest.raises(ApprovalDenied):
            await REGISTRY["nuclei_scan"].fn(target="https://www.example.com")

    def test_denied_tags_are_a_closed_set(self) -> None:
        assert {"dos", "fuzz", "intrusive"} <= DENIED_TAGS


class TestOptionalEngines:
    async def test_osmedeus_disabled_by_default(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["osmedeus_flow"])
        with pytest.raises(ToolUnavailable, match="disabled"):
            await REGISTRY["osmedeus_flow"].fn(target="www.example.com")

    async def test_strix_disabled_by_default(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["strix_deep"])
        with pytest.raises(ToolUnavailable, match="disabled"):
            await REGISTRY["strix_deep"].fn(target="https://www.example.com")

    async def test_strix_refuses_to_run_outside_the_sandbox(self, engagement) -> None:
        engagement.config.data["engines"]["strix"]["enabled"] = True
        engagement.approval.backend = PolicyBackend(auto_approve=["strix_deep"])
        # The engagement fixture uses sandbox.mode: none.
        with pytest.raises(ToolUnavailable, match="container sandbox"):
            await REGISTRY["strix_deep"].fn(target="https://www.example.com")

    async def test_strix_is_exploit_mode(self) -> None:
        assert REGISTRY["strix_deep"].mode == "exploit"

"""Tests for the live engagement dashboard (cordon/tools/dashboard.py)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from cordon.tools.dashboard import (
    _canonical_phase,
    _collect_assets_detailed,
    _collect_coverage,
    _collect_false_positives,
    _collect_findings,
    _collect_used_tools,
    _phase_status,
    _render_html,
    collect_state,
)


def _make_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "engagements" / "lab_20260101-000000"
    (ws / "reports").mkdir(parents=True)
    (ws / "reports" / "report.md").write_text("# report", encoding="utf-8")

    status = [
        {"phase": "probe", "state": "start", "tool": "http_probe", "at": "t1"},
        {"phase": "probe", "state": "ok", "tool": "http_probe", "seconds": 2.5,
         "findings": 0, "input": "argument", "at": "t2"},
        {"phase": "scan", "state": "start", "tool": "nuclei_scan", "at": "t3"},
        {"phase": "report", "state": "start", "tool": "report_generate", "at": "t4"},
        {"phase": "report", "state": "ok", "tool": "report_generate", "seconds": 3.1,
         "findings": 0, "at": "t5"},
    ]
    (ws / "status.jsonl").write_text(
        "\n".join(json.dumps(s) for s in status), encoding="utf-8"
    )

    findings = {
        "generated_at": "now",
        "stats": {"total": 2},
        "findings": [
            {"id": "a", "title": "SQLi candidate", "asset": "https://x.example.com",
             "severity": "high", "status": "candidate", "phase": "exploit",
             "source_tool": "sqlmap", "confidence": 0.9, "cvss": 8.1,
             "evidence": [{"kind": "log", "description": "hit"}]},
            {"id": "b", "title": "TLS hygiene", "asset": "https://x.example.com",
             "severity": "low", "status": "needs_manual_review", "phase": "http_probe",
             "source_tool": "testssl", "confidence": 0.4, "cvss": None,
             "evidence": []},
        ],
    }
    (ws / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    assets = [
        {"value": "x.example.com", "kind": "subdomain", "host": "x.example.com"},
        {"value": "https://x.example.com", "kind": "url", "status": 200},
    ]
    (ws / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    return ws


class TestPhaseStatus:
    def test_maps_audit_slugs_to_pipeline_labels(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        status = _phase_status(ws)
        assert status["probe"]["state"] == "ok"
        assert status["probe"]["seconds"] == 2.5
        assert status["scan"]["state"] == "running"
        assert status["report"]["state"] == "ok"
        # untouched phases stay pending
        assert status["exploit"]["state"] == "pending"
        # the full canonical pipeline is present
        assert list(status) == [
            "recon", "resolve", "probe", "waf", "tls", "cors", "endpoints",
            "js", "auth", "takeover", "scan", "exploit", "plan", "report",
        ]

    def test_canonical_phase(self) -> None:
        assert _canonical_phase("http_probe") == "probe"
        assert _canonical_phase("js_analysis") == "js"
        assert _canonical_phase("scan") == "scan"


class TestCollectFindings:
    def test_sorts_by_severity_and_counts(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        out = _collect_findings(ws)
        assert out["total"] == 2
        assert out["by_severity"] == {"high": 1, "low": 1}
        assert out["by_status"] == {"candidate": 1, "needs_manual_review": 1}
        # high sorts before low
        assert out["findings"][0]["severity"] == "high"
        # canonical phase mapping applied to findings too
        assert out["findings"][1]["phase"] == "probe"


class TestCollectState:
    def test_full_blob(self, tmp_path: Path) -> None:
        root = tmp_path
        _make_workspace(root)
        state = collect_state(root)
        assert state["workspace_name"].endswith("lab_20260101-000000")
        assert state["running_phase"] == "scan"
        assert state["findings"]["total"] == 2
        assert "subdomain" in state["assets"]
        assert "reports/report.md" in state["reports"]

    def test_no_workspace(self, tmp_path: Path) -> None:
        state = collect_state(tmp_path)
        assert state["workspace"] is None


class TestRenderHtml:
    def test_page_embeds_state_and_renders(self, tmp_path: Path) -> None:
        root = tmp_path
        _make_workspace(root)
        html = _render_html(collect_state(root))
        assert "<title>Cordon" in html
        assert "window.__live__ = false;" in html  # static mode does not poll
        embedded = re.search(
            r'<script id="boot-state" type="application/json">(.*?)</script>',
            html, re.S,
        )
        assert embedded is not None
        state = json.loads(embedded.group(1))
        assert state["findings"]["total"] == 2


class TestCollectAssetsDetailed:
    def test_groups_by_kind_with_fields(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        out = _collect_assets_detailed(ws)
        assert out["counts"] == {"subdomain": 1, "url": 1}
        assert out["items"]["subdomain"][0]["value"] == "x.example.com"
        assert out["items"]["subdomain"][0]["host"] == "x.example.com"
        # url item carries no host and survives the flatten
        assert out["items"]["url"][0]["value"] == "https://x.example.com"
        assert out["items"]["url"][0]["host"] is None


class TestCollectCoverage:
    def test_parses_ledger_rows(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        (ws / "coverage.json").write_text(json.dumps({"rows": [
            {"class": "sql-injection", "status": "validated", "tool": "sqli_validate"},
            {"class": "xxe", "status": "not_attempted", "tool": ""},
        ]}), encoding="utf-8")
        out = _collect_coverage(ws)
        assert out["total"] == 2
        assert out["by_status"] == {"validated": 1, "not_attempted": 1}
        assert out["rows"][0]["class"] == "sql-injection"


class TestCollectUsedTools:
    def test_derives_tool_usage_from_audit(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        audit = [
            {"event": "tool_call", "tool": "sqlmap", "phase": "exploit",
             "outcome": "ok", "findings": 2, "ts": "2026-01-01T00:00:01"},
            {"event": "tool_call", "tool": "sqlmap", "phase": "exploit",
             "outcome": "error", "findings": 0, "ts": "2026-01-01T00:00:02"},
            {"event": "tool_call", "tool": "dalfox", "phase": "http_probe",
             "outcome": "ok", "findings": 0, "ts": "2026-01-01T00:00:03"},
            {"event": "engagement_start", "tool": None},  # not a tool call
        ]
        (ws / "audit.jsonl").write_text(
            "\n".join(json.dumps(a) for a in audit), encoding="utf-8")
        tools = _collect_used_tools(ws)
        by_name = {t["tool"]: t for t in tools}
        assert by_name["sqlmap"]["calls"] == 2
        assert by_name["sqlmap"]["errors"] == 1
        assert by_name["sqlmap"]["findings"] == 2
        assert by_name["sqlmap"]["phases"] == ["exploit"]
        assert by_name["dalfox"]["phases"] == ["probe"]  # canonical slug
        # most-called first
        assert tools[0]["tool"] == "sqlmap"


class TestCollectFalsePositives:
    def test_finds_dismissed_findings_and_brain_lessons(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        # mark one finding dismissed with a triage note
        data = json.loads((ws / "findings.json").read_text(encoding="utf-8"))
        data["findings"][0]["status"] = "false_positive"
        data["findings"][0]["triage_notes"] = {"reason": "matched inside cookie"}
        (ws / "findings.json").write_text(json.dumps(data), encoding="utf-8")
        out = _collect_false_positives(ws, tmp_path)
        assert len(out) == 1
        assert out[0]["status"] == "false_positive"
        assert "cookie" in out[0]["reason"]


class TestWorkspaceSwitching:
    def test_pins_workspace_by_name(self, tmp_path: Path) -> None:
        ws = _make_workspace(tmp_path)
        other = tmp_path / "engagements" / "older_20251231-000000"
        other.mkdir(parents=True)
        (other / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
        state = collect_state(tmp_path, workspace="older_20251231-000000")
        assert state["workspace_name"] == "older_20251231-000000"
        assert state["findings"]["total"] == 0
        assert ws.name in {w["name"] for w in state["workspaces"]}

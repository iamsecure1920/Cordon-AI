"""Tests for the live engagement dashboard (easyhunt/tools/dashboard.py)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from easyhunt.tools.dashboard import (
    _canonical_phase,
    _collect_findings,
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
        assert "<title>EasyHunt" in html
        assert "window.__live__ = false;" in html  # static mode does not poll
        embedded = re.search(
            r'<script id="boot-state" type="application/json">(.*?)</script>',
            html, re.S,
        )
        assert embedded is not None
        state = json.loads(embedded.group(1))
        assert state["findings"]["total"] == 2

"""Coverage matrix: every bug class grades itself auto / detect-only / manual.

The completeness question a client asks. Each row must name how the class is
found, confirmed, and bypassed, and its references (payload lists, gf packs,
technique classes) must point at things that actually exist — a coverage table
that names a payload list or technique that is not there is a false promise.
"""

from __future__ import annotations

import json
from pathlib import Path

from cordon.mcp_server import load_capabilities
from cordon.tools.base import REGISTRY

load_capabilities()

ROOT = Path(__file__).resolve().parent.parent

KEY_CLASSES = {
    "sql-injection", "xss-injection", "server-side-request-forgery",
    "server-side-template-injection", "command-injection", "nosql-injection",
    "request-smuggling", "subdomain-takeover", "cors-misconfiguration",
    "json-web-token", "graphql-injection", "web-sockets", "secrets",
    "insecure-direct-object-references", "business-logic-errors",
    "xxe-injection", "crlf-injection", "file-inclusion", "open-redirect",
    "http-parameter-pollution", "upload-insecure-files",
    "insecure-deserialization", "cross-site-request-forgery",
    "web-cache-deception", "race-condition", "mass-assignment",
}

VALID_STATUSES = {"auto", "detect-only", "manual"}


class TestCoverageIndex:
    def _index(self):
        from cordon.knowledge.coverage import load_coverage

        return load_coverage()

    def test_every_key_class_is_present(self) -> None:
        index = self._index()
        present = {r["class"] for r in index.all()}
        missing = KEY_CLASSES - present
        assert missing == set(), f"coverage row missing for: {missing}"

    def test_status_is_one_of_three_honest_grades(self) -> None:
        index = self._index()
        for row in index.all():
            assert row["status"] in VALID_STATUSES, row["class"]
            assert row["detection"] and row["validation"], row["class"]

    def test_gaps_name_every_non_auto_class(self) -> None:
        index = self._index()
        gaps = index.gaps()
        auto = index.by_status("auto")
        assert {r["status"] for r in gaps} <= {"detect-only", "manual"}
        assert len(gaps) + len(auto) == len(index.all())

    def test_summary_counts_by_status(self) -> None:
        index = self._index()
        summary = index.summary()
        assert set(summary) <= VALID_STATUSES
        assert sum(summary.values()) == len(index.all())
        assert summary["auto"] > 0, "at least the proven validators must be auto"

    def test_get_returns_one_row(self) -> None:
        index = self._index()
        assert index.get("sql-injection")["validation"] == "sqli_validate (sqlmap)"
        # The native web_injection_probe promoted the no-scanner classes to auto.
        assert index.get("xxe-injection")["status"] == "auto"
        assert index.get("xxe-injection")["validation"] == "web_injection_probe (xxe)"
        assert index.get("http-parameter-pollution")["status"] == "auto"
        assert index.get("http-parameter-pollution")["validation"] == "web_injection_probe (hpp)"
        assert index.get("business-logic-errors")["status"] == "manual"


class TestCoverageReferences:
    """A coverage row must not point at things that do not exist."""

    def _index(self):
        from cordon.knowledge.coverage import load_coverage

        return load_coverage()

    def test_bypass_techniques_exist_in_the_technique_index(self) -> None:
        from cordon.knowledge.techniques import load_index

        tech = load_index()
        if not tech.available:
            return  # technique index is fetched, not required for this test
        for row in self._index().all():
            assert tech.get(row["bypass"]) is not None, (
                f"{row['class']} bypass {row['bypass']!r} not in the technique index"
            )

    def test_gf_packs_exist(self) -> None:
        packs = {p.stem for p in (ROOT / "rules" / "gf").glob("*.json") if p.stem != "manifest"}
        for row in self._index().all():
            for pack in row.get("gf", []):
                assert pack in packs, f"{row['class']} references missing gf pack {pack!r}"

    def test_auto_validators_are_registered_tools(self) -> None:
        """A row claiming a validator owns it must point at a real MCP tool.

        The native web_injection_probe promoted XXE/CRLF/LFI/open-redirect from
        detect-only to auto. If the tool is not registered, that promotion is a
        false promise — the exact lie this suite exists to catch.
        """
        import re

        for row in self._index().all():
            if row["status"] != "auto":
                continue
            named = re.findall(r"[a-z][a-z0-9_]+", row["validation"])
            registered = [t for t in named if t in REGISTRY]
            assert registered, (
                f"{row['class']} claims auto validation by {row['validation']!r}, "
                f"which names no registered tool"
            )

    def test_payloads_exist_in_the_manifest(self) -> None:
        manifest = ROOT / "payloads" / "manifest.json"
        if not manifest.is_file():
            return  # payload store is fetched, not redistributed
        names = {f["name"] for f in json.loads(manifest.read_text())["files"]}
        for row in self._index().all():
            for name in row.get("payloads", []):
                assert name in names, f"{row['class']} references missing payload {name!r}"


class TestCoverageReportTool:
    async def test_tool_is_free_and_targetless(self) -> None:
        spec = REGISTRY["coverage_report"]
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

    async def test_class_name_returns_a_row(self, engagement) -> None:
        result = await REGISTRY["coverage_report"].fn(class_name="sql-injection")
        assert result["ok"] is True
        assert result["coverage"]["class"] == "sql-injection"

    async def test_gaps_only_names_non_auto_classes(self, engagement) -> None:
        result = await REGISTRY["coverage_report"].fn(gaps_only=True)
        assert result["ok"] is True
        assert all(g["status"] != "auto" for g in result["gaps"])

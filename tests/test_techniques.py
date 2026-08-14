"""The technique index: PayloadsAllTheThings as queryable methodology.

The WSTG index answers *what to check*; this answers *how* — which EasyHunt
tools test a bug class, which vetted payload lists and gf pattern packs belong
to it. Built by ``scripts/fetch_pat.py`` from a pinned PAT commit (MIT), with
attribution on every record. The tests below are split: retrieval behaviour
(skip when the index is not built on a machine) and wiring integrity (always
run — the index must not point at payload lists or pattern packs that do not
exist).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import REGISTRY

# Register every capability tool once, so REGISTRY["technique_lookup"] exists.
load_capabilities()

ROOT = Path(__file__).resolve().parent.parent


class TestTechniqueIndex:
    def _index(self):
        from easyhunt.knowledge.techniques import load_index

        index = load_index()
        if not index.available:
            pytest.skip("technique index not built on this machine")
        return index

    def test_index_is_built_and_attributed(self) -> None:
        index = self._index()
        assert index.source["license"] == "MIT"
        assert "PayloadsAllTheThings" in index.source["attribution"]
        assert len(index.source["commit"]) == 40, "source must be pinned"

    def test_known_classes_resolve(self) -> None:
        index = self._index()
        for class_name in (
            "sql-injection",
            "open-redirect",
            "insecure-direct-object-references",
            "server-side-template-injection",
        ):
            tech = index.get(class_name)
            assert tech is not None, f"{class_name} missing"
            assert tech["title"] and tech["class"]
            assert tech["phase"]

    def test_wiring_names_real_tools(self) -> None:
        index = self._index()
        sql = index.get("sql-injection")
        assert "sqli_validate" in sql["tools"]
        ssti = index.get("server-side-template-injection")
        assert "ssti_probe" in ssti["tools"]

    def test_search_ranks_the_obvious_answer_first(self) -> None:
        index = self._index()
        assert index.search("server side request forgery")[0]["class"] == (
            "server-side-request-forgery"
        )
        assert index.search("sql injection")[0]["class"] == "sql-injection"

    def test_search_matches_acronyms_via_keywords(self) -> None:
        index = self._index()
        # A planner says "IDOR", not "insecure direct object reference". The
        # keywords field is what bridges that gap.
        assert index.search("idor")[0]["class"] == "insecure-direct-object-references"
        assert index.search("ssti")[0]["class"] == "server-side-template-injection"
        assert index.search("jwt forgery")[0]["class"] == "json-web-token"

    def test_stack_hints_map_to_classes(self) -> None:
        index = self._index()
        matches = index.for_stack(["Rails", "MongoDB"])
        classes = {m["class"] for m in matches}
        assert "mass-assignment" in classes
        assert "nosql-injection" in classes

    def test_unknown_stack_returns_nothing_rather_than_everything(self) -> None:
        index = self._index()
        assert index.for_stack(["CompletelyUnknownTech"]) == []

    def test_for_tool_lists_every_consumer(self) -> None:
        index = self._index()
        matches = index.for_tool("sqli_validate")
        assert "sql-injection" in {m["class"] for m in matches}

    def test_dos_is_marked_not_testable(self) -> None:
        index = self._index()
        dos = index.get("denial-of-service")
        assert dos is not None
        assert "not tested" in dos.get("note", "")

    def test_cheatsheets_are_indexed_with_a_kind(self) -> None:
        index = self._index()
        sheets = [t for t in index.techniques if t.get("kind") == "cheatsheet"]
        assert sheets, "the Methodology and Resources cheatsheets should be indexed"
        aws = index.get("cloud-aws-pentest")
        assert aws is not None and aws["kind"] == "cheatsheet"
        assert "cloud_audit" in aws["tools"]

    def test_post_exploitation_cheatsheets_have_no_tool(self) -> None:
        index = self._index()
        for class_name in ("windows-privilege-escalation", "active-directory-attack"):
            tech = index.get(class_name)
            assert tech is not None, f"{class_name} missing"
            assert tech["phase"] == "post_exploitation"
            # EasyHunt has no C2/host-agent tooling; pretending otherwise would
            # be a lie in the index.
            assert tech["tools"] == []


class TestWiringIntegrity:
    """The index is only as trustworthy as its references. These run always."""

    def _index(self):
        from easyhunt.knowledge.techniques import load_index

        index = load_index()
        if not index.available:
            pytest.skip("technique index not built on this machine")
        return index

    def test_gf_references_exist(self) -> None:
        gf_dir = ROOT / "rules" / "gf"
        packs = {p.stem for p in gf_dir.glob("*.json") if p.stem != "manifest"}
        for tech in self._index().techniques:
            for pack in tech.get("gf", []):
                assert pack in packs, (
                    f"{tech['class']} references missing gf pack {pack!r}"
                )

    def test_payload_references_exist_in_manifest(self) -> None:
        manifest = ROOT / "payloads" / "manifest.json"
        if not manifest.is_file():
            pytest.skip("payload store not built on this machine")
        names = {f["name"] for f in json.loads(manifest.read_text())["files"]}
        for tech in self._index().techniques:
            for name in tech.get("payloads", []):
                assert name in names, (
                    f"{tech['class']} references missing payload list {name!r}"
                )


class TestTechniqueLookupTool:
    async def test_tool_reports_a_missing_index(self, engagement, monkeypatch) -> None:
        from easyhunt.knowledge import techniques

        monkeypatch.setattr(
            techniques, "load_index", lambda *a, **k: techniques.TechniqueIndex({})
        )
        result = await REGISTRY["technique_lookup"].fn(query="xss")
        assert result["ok"] is False
        assert "fetch_pat.py --fetch" in result["message"]

    async def test_tool_is_free_and_targetless(self) -> None:
        spec = REGISTRY["technique_lookup"]
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

    async def test_class_name_returns_full_record(self, engagement) -> None:
        spec = REGISTRY["technique_lookup"]
        result = await spec.fn(class_name="sql-injection")
        if result.get("error") == "index_not_built":
            pytest.skip("technique index not built on this machine")
        assert result["ok"] is True
        assert result["technique"]["class"] == "sql-injection"
        assert result["attribution"]["license"] == "MIT"


class TestHuntPlanEnrichment:
    """hunt_plan attaches the technique wiring (tool + payload + gf) so a plan
    names the "how", not just the "what"."""

    def _enrich(self, proposal: dict) -> dict:
        from easyhunt.knowledge.techniques import load_index
        from easyhunt.tools import hunt_plan

        if not load_index().available:
            pytest.skip("technique index not built on this machine")
        return hunt_plan._enrich([proposal])[0]

    def test_idor_proposal_names_its_tool_and_pattern(self) -> None:
        out = self._enrich(
            {"category": "IDOR", "title": "swap the order id in the basket", "observation": "x"}
        )
        tech = out["technique"]
        assert tech["class"] == "insecure-direct-object-references"
        assert "authz_compare" in tech["tools"]
        assert "idor" in tech["gf"]

    def test_unmatched_proposal_is_left_untouched(self) -> None:
        proposal = {"category": "nonsense class", "title": "zzz", "observation": "x"}
        assert "technique" not in self._enrich(proposal)

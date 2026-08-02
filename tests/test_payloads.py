"""Payload store: tier enforcement, name resolution, and catalog exposure.

The property that matters most is ``test_quarantine_is_absolute``. Tier C files
hold real RCE (``exec master..xp_cmdshell``) and hardcoded callbacks to
third-party infrastructure. No configuration, and no caller opt-in, may reach
them.
"""

from __future__ import annotations

import json

import pytest

from easyhunt.config import Config
from easyhunt.knowledge.payloads import PayloadError, PayloadStore, store_from_config
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import REGISTRY

load_capabilities()

MANIFEST = {
    "files": [
        {"name": "safe.txt", "tier": "A", "kind": "wordlist", "lines": 10,
         "sha256": "x", "get_only": False, "reasons": []},
        {"name": "stateful.txt", "tier": "A", "kind": "wordlist", "lines": 20,
         "sha256": "x", "get_only": True, "reasons": ["state-changing paths"]},
        {"name": "inject.txt", "tier": "B", "kind": "injection", "lines": 30,
         "sha256": "x", "get_only": False, "reasons": []},
        {"name": "nasty.txt", "tier": "C", "kind": "injection", "lines": 40,
         "sha256": "x", "get_only": False, "reasons": ["2 destructive/RCE statement(s)"]},
    ]
}

ALIASES = {
    "safe": {"file": "safe.txt", "tools": ["ffuf"], "purpose": "safe list"},
    "stateful": {"file": "stateful.txt", "tools": ["ffuf"], "purpose": "has /shutdown"},
    "inject": {"file": "inject.txt", "tools": ["dalfox"], "purpose": "injection"},
    "nasty": {"file": "nasty.txt", "tools": ["ffuf"], "purpose": "quarantined"},
    "dangling": {"file": "absent.txt", "tools": ["ffuf"], "purpose": "not in manifest"},
}


@pytest.fixture
def store(tmp_path) -> PayloadStore:
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    for tier, name in (("A", "safe.txt"), ("A", "stateful.txt"),
                       ("B", "inject.txt"), ("_quarantine", "nasty.txt")):
        directory = tmp_path / tier
        directory.mkdir(exist_ok=True)
        (directory / name).write_text("payload\n")
    return PayloadStore(tmp_path, ALIASES)


class TestTierEnforcement:
    def test_tier_a_resolves(self, store: PayloadStore) -> None:
        entry = store.resolve("safe")
        assert entry.tier == "A"
        assert entry.path.is_file()

    def test_tier_b_needs_explicit_opt_in(self, store: PayloadStore) -> None:
        # Injection payloads are not discovery wordlists; content_discovery must
        # not be able to reach them by naming one.
        with pytest.raises(PayloadError, match="not a discovery wordlist"):
            store.resolve("inject")
        assert store.resolve("inject", allow_tier_b=True).tier == "B"

    def test_quarantine_is_absolute(self, store: PayloadStore) -> None:
        # Not reachable by any caller, with or without opt-in. Tier C holds
        # genuine RCE and third-party callbacks.
        with pytest.raises(PayloadError, match="QUARANTINED"):
            store.resolve("nasty")
        with pytest.raises(PayloadError, match="QUARANTINED"):
            store.resolve("nasty", allow_tier_b=True)

    def test_quarantine_error_says_why(self, store: PayloadStore) -> None:
        with pytest.raises(PayloadError, match="destructive/RCE"):
            store.resolve("nasty")

    def test_unknown_name_lists_alternatives(self, store: PayloadStore) -> None:
        with pytest.raises(PayloadError, match="unknown payload list"):
            store.resolve("no-such-list")

    def test_manifest_miss_is_reported(self, store: PayloadStore) -> None:
        # An alias pointing at a file that was never vetted must fail closed,
        # not fall through to an unvetted read.
        with pytest.raises(PayloadError, match="not in the payload manifest"):
            store.resolve("dangling")

    def test_get_only_is_carried_through(self, store: PayloadStore) -> None:
        # Lists holding /shutdown, /restart are safe to GET and destructive to
        # POST. The flag has to survive resolution for the caller to honour it.
        assert store.resolve("stateful").get_only is True
        assert store.resolve("safe").get_only is False


class TestCatalog:
    def test_catalog_hides_quarantine(self, store: PayloadStore) -> None:
        assert "nasty" not in {item["name"] for item in store.catalog()}

    def test_catalog_filters_by_tool(self, store: PayloadStore) -> None:
        assert {i["name"] for i in store.catalog(tool="dalfox")} == {"inject"}

    def test_unbuilt_store_is_a_state_not_an_error(self, tmp_path) -> None:
        empty = PayloadStore(tmp_path, ALIASES)
        assert empty.available is False
        # Reports absence rather than substituting a different wordlist: swapping
        # in a list the operator did not pick changes the impact on the target.
        with pytest.raises(PayloadError, match="has not been built"):
            empty.resolve("safe")


class TestShippedConfig:
    def test_every_alias_is_tier_a(self) -> None:
        # config.yaml maps only discovery wordlists. If a tier B or C file ever
        # gets aliased there, this fails before anything fires it at a target.
        configured = store_from_config(Config.load())
        if not configured.available:
            pytest.skip("payload store not built on this machine")
        for item in configured.catalog():
            assert item["tier"] == "A", f"{item['name']} is tier {item['tier']}"

    def test_aliases_resolve_to_real_files(self) -> None:
        configured = store_from_config(Config.load())
        if not configured.available:
            pytest.skip("payload store not built on this machine")
        for item in configured.catalog():
            assert configured.resolve(item["name"]).path.is_file()


class TestCatalogTool:
    async def test_catalog_tool_is_free_and_targetless(self) -> None:
        spec = REGISTRY["payload_catalog"]
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

    async def test_catalog_tool_lists_names(self, engagement, tmp_path) -> None:
        # The fixture config carries no payloads section, so point it at a
        # purpose-built store rather than at whatever this machine happens to
        # have fetched — the test should not depend on that.
        (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
        (tmp_path / "A").mkdir()
        (tmp_path / "A" / "safe.txt").write_text("payload\n")
        engagement.config.data["payloads"] = {
            "store": str(tmp_path),
            "lists": {"safe": ALIASES["safe"]},
        }

        result = await REGISTRY["payload_catalog"].fn()
        assert result["ok"] is True
        assert [item["name"] for item in result["lists"]] == ["safe"]

    async def test_catalog_tool_reports_an_unbuilt_store(self, engagement, tmp_path) -> None:
        # Absence must be legible, not an empty list that reads as "nothing here".
        engagement.config.data["payloads"] = {
            "store": str(tmp_path / "never-fetched"), "lists": ALIASES,
        }
        result = await REGISTRY["payload_catalog"].fn()
        assert result["ok"] is False
        assert result["error"] == "store_not_built"
        assert "vet_payloads.py --fetch" in result["message"]


class TestJobStatus:
    """Long scans hand back a job_id; something has to be able to read it.

    nuclei_scan, bbot_scan and osmedeus_flow cap their internal wait at 300s and
    return {"completed": false, "job_id": ...}. Before job_status existed no
    registered tool could fetch that result, so any scan over five minutes
    finished into a job nothing could reach.
    """

    async def test_registered_and_free(self) -> None:
        spec = REGISTRY["job_status"]
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

    async def test_lists_jobs_without_an_id(self, engagement) -> None:
        result = await REGISTRY["job_status"].fn()
        assert result["ok"] is True
        assert isinstance(result["jobs"], list)

    async def test_unknown_job_is_an_error_not_a_silent_empty(self, engagement) -> None:
        from easyhunt.errors import EasyHuntError

        with pytest.raises(EasyHuntError):
            await REGISTRY["job_status"].fn(job_id="nuclei_scan-9999")

    async def test_finished_job_returns_its_result(self, engagement) -> None:
        async def work(job):
            return {"count": 3, "findings": []}

        job = engagement.jobs.launch(work, tool="nuclei_scan", phase="vuln_scan", targets=[])
        result = await REGISTRY["job_status"].fn(job_id=job.id, wait_seconds=10.0)
        assert result["completed"] is True
        assert result["count"] == 3


class TestWstgIndex:
    """Methodology as queryable data — the gap a live engagement exposed.

    On a mature estate nuclei came back clean and the next move was improvisation.
    The WSTG names 115 tests by phase; retrieval turns "what now" into a query.
    """

    def test_index_is_built_and_attributed(self) -> None:
        from easyhunt.knowledge.wstg import load_index

        index = load_index()
        if not index.available:
            pytest.skip("WSTG index not built on this machine")
        # CC BY-SA 4.0 obliges attribution wherever the text travels.
        assert index.source["license"] == "CC BY-SA 4.0"
        assert "OWASP" in index.source["attribution"]
        assert len(index.source["commit"]) == 40, "source must be pinned"

    def test_known_tests_resolve(self) -> None:
        from easyhunt.knowledge.wstg import load_index

        index = load_index()
        if not index.available:
            pytest.skip("WSTG index not built")
        for wstg_id in ("WSTG-INPV-05", "WSTG-INPV-19", "WSTG-ATHZ-04"):
            test = index.get(wstg_id)
            assert test is not None, f"{wstg_id} missing"
            assert test["title"] and test["objectives"]

    def test_search_ranks_the_obvious_answer_first(self) -> None:
        from easyhunt.knowledge.wstg import load_index

        index = load_index()
        if not index.available:
            pytest.skip("WSTG index not built")
        assert index.search("server side request forgery")[0]["id"] == "WSTG-INPV-19"
        assert index.search("insecure direct object reference")[0]["id"] == "WSTG-ATHZ-04"

    def test_stack_hints_map_to_categories(self) -> None:
        from easyhunt.knowledge.wstg import load_index

        index = load_index()
        if not index.available:
            pytest.skip("WSTG index not built")
        # The stack actually observed on a real engagement.
        matches = index.for_stack(["Java", "Akamai", "SAML", "OAuth", "API"])
        categories = {m["category"] for m in matches}
        assert {"ATHZ", "ATHN"} & categories, "auth tests should surface for SAML/OAuth"

    def test_unknown_stack_returns_nothing_rather_than_everything(self) -> None:
        from easyhunt.knowledge.wstg import load_index

        index = load_index()
        if not index.available:
            pytest.skip("WSTG index not built")
        # Returning all 115 for an unrecognised stack would be noise pretending
        # to be guidance.
        assert index.for_stack(["CompletelyUnknownTech"]) == []

    async def test_tool_reports_a_missing_index(self, engagement, monkeypatch) -> None:
        from easyhunt.knowledge import wstg

        monkeypatch.setattr(wstg, "load_index", lambda *a, **k: wstg.WstgIndex({}))
        result = await REGISTRY["wstg_lookup"].fn(query="xss")
        assert result["ok"] is False
        assert "fetch_wstg.py --fetch" in result["message"]

    async def test_tool_is_free_and_targetless(self) -> None:
        spec = REGISTRY["wstg_lookup"]
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

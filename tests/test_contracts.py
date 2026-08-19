"""Smart-contract analysis: argument safety, tool identity, honest absence.

The sharpest test is ``test_forge_cannot_broadcast``. Foundry is the PoC engine,
and the difference between security research and theft is whether the exploit
runs against a local fork or against mainnet. That must be unreachable, not
discouraged.
"""

from __future__ import annotations

import pytest

from cordon.control_plane.sanitize import sanitize_argv
from cordon.errors import SanitizeError
from cordon.mcp_server import load_capabilities
from cordon.tools.base import REGISTRY
from cordon.tools.common import CATALOG

load_capabilities()


class TestForgeSafety:
    """Foundry can send real transactions. It must not be able to here."""

    @pytest.mark.parametrize(
        "flag",
        ["--broadcast", "--private-key", "--unlocked", "--mnemonic",
         "--ledger", "--trezor", "--keystore", "--rpc-url"],
    )
    def test_forge_cannot_broadcast(self, flag: str) -> None:
        spec = CATALOG["forge"]
        with pytest.raises(SanitizeError):
            sanitize_argv("forge", ["test", flag, "x"], policy=spec.arg_policy)

    @pytest.mark.parametrize("sub", ["script", "create", "send"])
    def test_state_changing_subcommands_are_denied(self, sub: str) -> None:
        # `forge script`/`create` and `cast send` deploy or transact for real.
        spec = CATALOG["forge"]
        with pytest.raises(SanitizeError):
            sanitize_argv("forge", [sub], policy=spec.arg_policy)

    def test_fork_url_must_be_local(self) -> None:
        # Immunefi and every other platform require testing on a local fork.
        spec = CATALOG["forge"]
        sanitize_argv(
            "forge", ["test", "--fork-url", "http://127.0.0.1:8545"], policy=spec.arg_policy
        )
        with pytest.raises(SanitizeError):
            sanitize_argv(
                "forge", ["test", "--fork-url", "https://mainnet.infura.io/v3/k"],
                policy=spec.arg_policy,
            )

    def test_running_tests_still_works(self) -> None:
        spec = CATALOG["forge"]
        sanitize_argv(
            "forge",
            ["test", "--match-test", "testExploit", "-vvvv", "--json"],
            policy=spec.arg_policy,
        )


class TestToolIdentity:
    def test_medusa_requires_identity_verification(self) -> None:
        # Kali ships /usr/bin/medusa: a password brute-forcer with the same name
        # as Trail of Bits' contract fuzzer. Running the wrong one launches
        # credential attacks at a host instead of fuzzing a contract.
        assert CATALOG["medusa"].identity_marker == "medusa version"

    def test_contract_tools_are_catalogued(self) -> None:
        for name in ("slither", "aderyn", "forge", "medusa"):
            assert name in CATALOG, f"{name} missing from the catalog"

    def test_licenses_recorded(self) -> None:
        # Slither and medusa are AGPL — it matters if anyone redistributes.
        assert CATALOG["slither"].license.startswith("AGPL")
        assert CATALOG["medusa"].license.startswith("AGPL")


class TestAnalysisHonesty:
    async def test_static_scan_is_passive_and_free(self) -> None:
        spec = REGISTRY["contract_static_scan"]
        # Source analysis contacts nothing and costs no budget.
        assert spec.mode == "passive"
        assert spec.estimated_requests == 0

    async def test_missing_repo_is_reported_not_guessed(self, engagement) -> None:
        result = await REGISTRY["contract_static_scan"].fn(repo="does-not-exist")
        assert result["ok"] is False
        assert result["error"] == "repo_not_found"

    async def test_absent_slither_means_unanalysed(self, engagement, monkeypatch) -> None:
        # The failure this codebase keeps producing: a tool that did not run,
        # reported as a clean result.
        from cordon.tools import common

        (engagement.workspace / "repo").mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(common, "installed", lambda name: name != "slither")
        result = await REGISTRY["contract_static_scan"].fn(repo="repo")
        assert result["ok"] is False
        assert "UNANALYSED, not clean" in result["message"]

    async def test_toolchain_reports_absence_per_tool(self, engagement) -> None:
        result = await REGISTRY["contract_toolchain"].fn()
        assert result["ok"] is True
        assert set(result["tools"]) == {"slither", "aderyn", "forge", "medusa"}
        assert "NOT performed" in result["note"]

    def test_detector_hits_never_exceed_high(self) -> None:
        # Slither's "High" means high impact *if real*, not high confidence.
        # CRITICAL requires a reproducible PoC, which static analysis cannot give.
        from cordon.knowledge.findings import Severity
        from cordon.tools.contracts import _IMPACT

        assert Severity.CRITICAL not in _IMPACT.values()
        assert _IMPACT["High"] is Severity.HIGH

    def test_priority_detectors_cover_what_pays(self) -> None:
        from cordon.tools.contracts import _PRIORITY

        # The classes that actually earn bounties: access control, reentrancy
        # including read-only, arbitrary calls, delegatecall, precision.
        for check in ("reentrancy-eth", "arbitrary-send-eth", "controlled-delegatecall",
                      "unprotected-upgrade", "divide-before-multiply"):
            assert check in _PRIORITY

"""The decorator, not the tool body, is what enforces the control plane.

Every test here uses a tool whose body would happily do the wrong thing if it
were ever reached. Reaching it is the failure condition.
"""

from __future__ import annotations

import asyncio

import pytest

from cordon.control_plane.approval import PolicyBackend
from cordon.errors import ApprovalDenied, BudgetExceeded, OutOfScopeError, SanitizeError
from cordon.tools.base import REGISTRY, cordon_tool, registered_tools

TOUCHED: list[str] = []


@cordon_tool(phase="recon", mode="passive", targets_arg="target", name="t_passive")
async def _passive(target: str, note: str = "") -> dict:
    """A passive probe."""
    TOUCHED.append(target)
    return {"ok": True, "hosts": [target], "note": note}


@cordon_tool(phase="vuln_scan", mode="aggressive", targets_arg="target", name="t_aggressive")
async def _aggressive(target: str) -> dict:
    """An aggressive scan."""
    TOUCHED.append(target)
    return {"ok": True}


@cordon_tool(phase="exploit", mode="exploit", targets_arg="target", name="t_exploit")
async def _exploit(target: str) -> dict:
    """An exploitation attempt."""
    TOUCHED.append(target)
    return {"ok": True}


@cordon_tool(phase="recon", mode="passive", targets_arg="target", name="t_big")
async def _big(target: str) -> dict:
    """Returns far more than an MCP response should carry."""
    return {"ok": True, "findings": [{"host": f"h{i}.example.com", "blob": "x" * 500} for i in range(5000)]}


@cordon_tool(phase="recon", mode="passive", targets_arg=None, name="t_untargeted")
async def _untargeted() -> dict:
    """A tool that touches no specific target."""
    return {"ok": True}


@cordon_tool(phase="recon", mode="passive", targets_arg="target", name="t_raises")
async def _raises(target: str) -> dict:
    """A tool whose body fails."""
    raise RuntimeError("upstream tool exploded")


@pytest.fixture(autouse=True)
def _clear() -> None:
    TOUCHED.clear()


def last_call(engagement) -> dict:
    calls = [r for r in engagement.audit.read_all() if r["event"] == "tool_call"]
    return calls[-1]


class TestScopeEnforcement:
    async def test_out_of_scope_refused_before_the_body_runs(self, engagement) -> None:
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target="notmine.example.net")
        assert TOUCHED == []

    async def test_denylisted_target_refused(self, engagement) -> None:
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target="blog.example.com")
        assert TOUCHED == []

    async def test_in_scope_target_runs(self, engagement) -> None:
        result = await REGISTRY["t_passive"].fn(target="www.example.com")
        assert result["hosts"] == ["www.example.com"]

    async def test_one_bad_target_refuses_the_whole_batch(self, engagement) -> None:
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target=["www.example.com", "evil.example.net"])
        assert TOUCHED == []

    async def test_comma_separated_targets_are_each_checked(self, engagement) -> None:
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target="a.example.com, blog.example.com")

    async def test_missing_target_is_refused(self, engagement) -> None:
        with pytest.raises(Exception, match="no target supplied"):
            await REGISTRY["t_passive"].fn(target="")

    async def test_untargeted_tool_needs_no_scope_check(self, engagement) -> None:
        assert (await REGISTRY["t_untargeted"].fn())["ok"]


class TestSanitizeEnforcement:
    async def test_injection_in_a_non_target_argument_is_refused(self, engagement) -> None:
        with pytest.raises(SanitizeError):
            await REGISTRY["t_passive"].fn(target="www.example.com", note="ok; rm -rf /")
        assert TOUCHED == []


class TestApprovalEnforcement:
    async def test_aggressive_blocked_without_approval(self, engagement) -> None:
        with pytest.raises(ApprovalDenied):
            await REGISTRY["t_aggressive"].fn(target="www.example.com")
        assert TOUCHED == []

    async def test_exploit_blocked_without_approval(self, engagement) -> None:
        with pytest.raises(ApprovalDenied):
            await REGISTRY["t_exploit"].fn(target="www.example.com")
        assert TOUCHED == []

    async def test_aggressive_runs_once_approved(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["t_aggressive"])
        assert (await REGISTRY["t_aggressive"].fn(target="www.example.com"))["ok"]
        assert TOUCHED == ["www.example.com"]

    async def test_scope_is_checked_before_approval(self, engagement) -> None:
        # An approved tool still cannot reach an out-of-scope host.
        engagement.approval.backend = PolicyBackend(auto_approve=["t_aggressive"])
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_aggressive"].fn(target="blog.example.com")


class TestBudgetEnforcement:
    async def test_exhausted_budget_stops_new_work(self, engagement) -> None:
        # Ceilings are opt-in since the default flipped to enforce: false;
        # this test exercises the ceiling, so it must ask for one.
        engagement.budget.limits.enforce = True
        engagement.budget.charge_tool(seconds=0, requests=engagement.budget.limits.max_requests)
        with pytest.raises(BudgetExceeded):
            await REGISTRY["t_passive"].fn(target="www.example.com")
        assert TOUCHED == []


class TestRateLimit:
    async def test_calls_are_serialized_by_the_concurrency_ceiling(self, engagement) -> None:
        # scope fixture sets max_concurrency=3.
        await asyncio.gather(
            *(REGISTRY["t_passive"].fn(target=f"h{i}.example.com") for i in range(6))
        )
        assert engagement.limiter.stats()["peak_in_flight"] <= 3


class TestAuditing:
    async def test_success_is_audited(self, engagement) -> None:
        await REGISTRY["t_passive"].fn(target="www.example.com")
        record = last_call(engagement)
        assert record["outcome"] == "ok"
        assert record["tool"] == "t_passive"
        assert record["scope_verdicts"][0]["in_scope"]

    async def test_refusal_is_audited_with_its_reason(self, engagement) -> None:
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target="blog.example.com")
        record = last_call(engagement)
        assert record["outcome"] == "refused"
        assert record["error_code"] == "out_of_scope"

    async def test_approval_refusal_is_audited(self, engagement) -> None:
        with pytest.raises(ApprovalDenied):
            await REGISTRY["t_aggressive"].fn(target="www.example.com")
        assert last_call(engagement)["error_code"] == "approval_denied"

    async def test_body_failure_is_audited_as_error(self, engagement) -> None:
        with pytest.raises(RuntimeError):
            await REGISTRY["t_raises"].fn(target="www.example.com")
        record = last_call(engagement)
        assert record["outcome"] == "error"
        assert record["error_code"] == "RuntimeError"

    async def test_audit_chain_survives_a_mix_of_outcomes(self, engagement) -> None:
        await REGISTRY["t_passive"].fn(target="a.example.com")
        with pytest.raises(OutOfScopeError):
            await REGISTRY["t_passive"].fn(target="nope.example.net")
        await REGISTRY["t_passive"].fn(target="b.example.com")
        assert engagement.audit.verify()[0]


class TestPayloadCapping:
    async def test_large_result_is_capped(self, engagement) -> None:
        result = await REGISTRY["t_big"].fn(target="www.example.com")
        assert result.get("truncated")
        assert len(result["findings"]) < 5000
        assert "fetch_slice" in result["_truncated"]["hint"]


class TestRegistry:
    def test_tools_are_discoverable_by_phase_and_mode(self) -> None:
        assert any(t.name == "t_passive" for t in registered_tools(phase="recon"))
        assert all(t.mode == "aggressive" for t in registered_tools(mode="aggressive"))

    def test_definition_is_stable_and_hashable(self) -> None:
        first = REGISTRY["t_passive"].definition()
        assert first == REGISTRY["t_passive"].definition()
        assert [p["name"] for p in first["params"]] == ["target", "note"]

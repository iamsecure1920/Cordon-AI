"""Rate limiter, approval gate, audit log, and budget ceilings."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from easyhunt.control_plane.approval import (
    ApprovalGate,
    ApprovalRequest,
    Decision,
    DenyBackend,
    ElicitationBackend,
    PendingBackend,
    PolicyBackend,
    build_backend,
)
from easyhunt.control_plane.audit import AuditLog, redact
from easyhunt.control_plane.budget import Budget, BudgetLimits
from easyhunt.control_plane.ratelimit import RateLimiter, TokenBucket
from easyhunt.control_plane.scope import Scope
from easyhunt.errors import ApprovalDenied, ApprovalRequired, BudgetExceeded

from .conftest import scope_dict


def request(tool: str = "nuclei_scan", mode: str = "aggressive") -> ApprovalRequest:
    return ApprovalRequest(
        tool=tool,
        phase="vuln_scan",
        mode=mode,
        targets=["example.com"],
        command="nuclei -u https://example.com",
        rationale="test",
    )


class TestRateLimit:
    async def test_bucket_caps_throughput(self) -> None:
        bucket = TokenBucket(rate=20, capacity=1)
        started = time.monotonic()
        for _ in range(6):
            await bucket.acquire()
        # 1 burst token + 5 refills at 20/s ≈ 0.25s. Generous lower bound to stay
        # stable on a loaded CI box while still failing if the cap is ignored.
        assert time.monotonic() - started >= 0.15

    async def test_burst_then_throttle(self) -> None:
        bucket = TokenBucket(rate=5, capacity=5)
        assert all(bucket.try_acquire() for _ in range(5))
        assert not bucket.try_acquire()

    async def test_concurrency_ceiling_is_respected(self) -> None:
        limiter = RateLimiter(rps=1000, concurrency=2)
        peak = 0
        live = 0

        async def worker() -> None:
            nonlocal peak, live
            async with limiter.slot(host="example.com"):
                live += 1
                peak = max(peak, live)
                await asyncio.sleep(0.02)
                live -= 1

        await asyncio.gather(*(worker() for _ in range(10)))
        assert peak <= 2

    async def test_per_host_buckets_are_independent(self) -> None:
        limiter = RateLimiter(rps=1000, concurrency=10, per_host_rps=1000)
        await limiter.acquire(host="a.example.com")
        await limiter.acquire(host="b.example.com")
        assert limiter.stats()["tracked_hosts"] == 2

    def test_limits_come_from_scope(self) -> None:
        limiter = RateLimiter.from_scope(Scope(scope_dict(), source="<test>"))
        assert (limiter.rps, limiter.concurrency) == (5.0, 3)


class TestApproval:
    async def test_aggressive_blocked_without_approval(self) -> None:
        gate = ApprovalGate(DenyBackend())
        with pytest.raises(ApprovalDenied):
            await gate.require(request())

    async def test_policy_allowlist_grants(self) -> None:
        gate = ApprovalGate(PolicyBackend(auto_approve=["nuclei_scan"]))
        assert (await gate.require(request())).accepted

    async def test_policy_default_is_refusal(self) -> None:
        gate = ApprovalGate(PolicyBackend(auto_approve=["something_else"]))
        with pytest.raises(ApprovalDenied):
            await gate.require(request())

    async def test_scope_rules_refuse_before_asking_a_human(self) -> None:
        data = scope_dict()
        data["rules"] = {**data["rules"], "allow_exploitation": False}
        gate = ApprovalGate(
            PolicyBackend(auto_approve=["sqlmap_scan"]), scope=Scope(data, source="<test>")
        )
        # Even an auto-approve entry cannot authorize what the program forbids.
        with pytest.raises(ApprovalDenied, match="forbid exploitation"):
            await gate.require(request("sqlmap_scan", mode="exploit"))

    async def test_elicitation_accept(self) -> None:
        class FakeAccepted:
            action = "accept"

            class data:  # noqa: N801
                approve = True
                note = "go ahead"
                remember_for_this_target = False

        class FakeCtx:
            async def elicit(self, message, response_type):  # noqa: ANN001, ARG002
                return FakeAccepted()

        gate = ApprovalGate(ElicitationBackend(timeout=5))
        decision = await gate.require(request(), FakeCtx())
        assert decision.accepted and decision.approver == "human"

    async def test_elicitation_decline(self) -> None:
        class FakeDeclined:
            action = "decline"

        class FakeCtx:
            async def elicit(self, message, response_type):  # noqa: ANN001, ARG002
                return FakeDeclined()

        gate = ApprovalGate(ElicitationBackend(timeout=5))
        with pytest.raises(ApprovalDenied):
            await gate.require(request(), FakeCtx())

    async def test_elicitation_failure_falls_back_closed(self) -> None:
        class BrokenCtx:
            async def elicit(self, message, response_type):  # noqa: ANN001, ARG002
                raise RuntimeError("client has no elicitation support")

        # Falls through to the pending backend, which parks rather than proceeds.
        gate = ApprovalGate(ElicitationBackend(timeout=0.2))
        with pytest.raises((ApprovalDenied, ApprovalRequired)):
            await gate.require(request(), BrokenCtx())

    async def test_pending_backend_round_trip(self) -> None:
        backend = PendingBackend(timeout=5, block=True)
        gate = ApprovalGate(backend)
        task = asyncio.create_task(gate.require(request()))
        await asyncio.sleep(0.05)
        pending = gate.pending()
        assert len(pending) == 1
        assert gate.respond(pending[0]["token"], "accept", note="ok")
        assert (await task).accepted

    async def test_remembered_approval_is_reused(self) -> None:
        calls = 0

        class CountingBackend:
            name = "counting"

            async def ask(self, req, ctx):  # noqa: ANN001, ARG002
                nonlocal calls
                calls += 1
                from easyhunt.control_plane.approval import ApprovalDecision

                return ApprovalDecision(Decision.ACCEPT, approver="human", remember=True)

        gate = ApprovalGate(CountingBackend(), remember_ttl=60)
        await gate.require(request())
        await gate.require(request())
        assert calls == 1

    def test_unknown_backend_name_fails_closed(self) -> None:
        assert build_backend({"backend": "yolo"}).name == "deny"


class TestAudit:
    def test_every_attempt_is_written_including_refusals(self, tmp_path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.tool_call(
            tool="nuclei_scan", phase="vuln_scan", mode="aggressive",
            targets=["blog.example.com"], outcome="refused", error_code="out_of_scope",
        )
        log.tool_call(
            tool="httpx_probe", phase="recon", mode="passive",
            targets=["example.com"], outcome="ok", exit_code=0,
        )
        records = log.read_all()
        assert [r["outcome"] for r in records] == ["refused", "ok"]

    def test_hash_chain_detects_tampering(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.record("tool_call", tool=f"t{i}")
        assert log.verify()[0]

        lines = path.read_text().splitlines()
        record = json.loads(lines[1])
        record["tool"] = "tampered"
        lines[1] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n")

        ok, message = AuditLog(path).verify()
        assert not ok and "tampered" in message

    def test_chain_detects_deletion(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        for i in range(4):
            log.record("tool_call", tool=f"t{i}")
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        assert not AuditLog(path).verify()[0]

    def test_resumes_an_existing_chain(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        AuditLog(path).record("engagement_start")
        AuditLog(path).record("tool_call", tool="x")
        assert AuditLog(path).verify()[0]

    def test_secrets_are_redacted_before_they_land(self, tmp_path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.record(
            "tool_call",
            args={"api_key": "super-secret", "url": "https://x/?token=abcdef123456"},
            note="AKIAIOSFODNN7EXAMPLE",
        )
        written = (tmp_path / "audit.jsonl").read_text()
        assert "super-secret" not in written
        assert "AKIAIOSFODNN7EXAMPLE" not in written
        assert "<redacted" in written

    def test_redact_handles_nesting(self) -> None:
        out = redact({"a": [{"password": "hunter2"}, "ghp_" + "a" * 30]})
        assert out["a"][0]["password"] == "<redacted>"
        assert "<redacted:github-token>" in out["a"][1]


class TestBudget:
    def test_llm_ceiling_aborts(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(llm_usd=0.10), path=tmp_path / "b.json")
        budget.charge_llm(usd=0.09, prompt_tokens=100, completion_tokens=50, phase="triage", tier="t0")
        budget.check()
        budget.charge_llm(usd=0.02, phase="triage", tier="t0")
        with pytest.raises(BudgetExceeded, match="llm_usd"):
            budget.check()

    def test_preflight_refuses_work_it_cannot_afford(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(max_requests=100), path=tmp_path / "b.json")
        budget.charge_tool(seconds=1, requests=95)
        with pytest.raises(BudgetExceeded, match="requests"):
            budget.check(need_requests=50)

    def test_wall_clock_ceiling(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(wall_clock_minutes=0.0001), path=tmp_path / "b.json")
        time.sleep(0.02)
        with pytest.raises(BudgetExceeded, match="wall_clock"):
            budget.check()

    def test_ledger_survives_a_resume(self, tmp_path) -> None:
        path = tmp_path / "b.json"
        first = Budget(BudgetLimits(llm_usd=1.0), path=path)
        first.charge_llm(usd=0.4, phase="recon", tier="t0")
        resumed = Budget(BudgetLimits(llm_usd=1.0), path=path)
        assert resumed.ledger.llm_usd == pytest.approx(0.4)

    def test_phase_token_allowance(self, tmp_path) -> None:
        budget = Budget(
            BudgetLimits(phase_token_budget={"triage": 1000}), path=tmp_path / "b.json"
        )
        budget.charge_llm(usd=0.0, prompt_tokens=600, completion_tokens=100, phase="triage", tier="t0")
        assert budget.phase_tokens_remaining("triage") == 300
        assert budget.phase_tokens_remaining("recon") is None

    def test_cost_summary_breaks_down_by_phase_and_tier(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(), path=tmp_path / "b.json")
        budget.charge_llm(usd=0.01, phase="triage", tier="t0")
        budget.charge_llm(usd=0.20, phase="report", tier="t2")
        summary = budget.cost_summary()
        assert summary["by_tier_usd"] == {"t0": 0.01, "t2": 0.2}
        assert list(summary["by_phase_usd"]) == ["report", "triage"]


class TestEngagementWiring:
    def test_engagement_records_its_own_start(self, engagement) -> None:
        records = engagement.audit.read_all()
        assert records[0]["event"] == "engagement_start"
        assert records[0]["scope_fingerprint"] == engagement.scope.fingerprint()

    def test_workspace_layout(self, engagement) -> None:
        for sub in ("raw", "evidence", "poc", "reports"):
            assert (engagement.workspace / sub).is_dir()

    def test_finish_writes_artifacts(self, engagement) -> None:
        summary = engagement.finish()
        assert (engagement.workspace / "findings.json").exists()
        assert summary["audit"]["chain_ok"]

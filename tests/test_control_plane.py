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

    async def test_nested_slot_does_not_deadlock(self) -> None:
        # A tool body pacing its own requests calls slot() inside the wrapper's
        # slot (exploit_chain → web_injection_probe → per-request probe). With
        # the concurrency ceiling exhausted, re-acquiring the semaphore waits on
        # a slot the same call holds — a 3-deep nesting under concurrency=2 hung
        # the exploit phase for twenty minutes against a live target. A nested
        # slot must take the rate tokens and skip the semaphore.
        limiter = RateLimiter(rps=1000, concurrency=2)

        async def nested() -> None:
            async with limiter.slot(host="example.com"):
                # Simulate the wrapper's slot: hold it while the body runs.
                async with limiter.slot(host="example.com"):
                    await asyncio.sleep(0.01)

        await asyncio.wait_for(nested(), timeout=5)

    async def test_nested_slot_skips_the_semaphore_but_paces_tokens(self) -> None:
        # The outer slot is one in-flight call; nested slots are its own pacing,
        # not new calls. Peak in-flight must stay 1, proving the semaphore was
        # not double-counted.
        limiter = RateLimiter(rps=1000, concurrency=2)

        async def nested() -> None:
            async with limiter.slot(host="example.com"):
                async with limiter.slot(host="example.com"):
                    await asyncio.sleep(0.01)

        await nested()
        assert limiter.stats()["peak_in_flight"] == 1

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

    def test_account_credentials_are_redacted(self, tmp_path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.record(
            "tool_call",
            args={
                "username": "alice",
                "email": "alice@example.com",
                "password": "hunter2",
                "username_field": "username",
            },
        )
        written = (tmp_path / "audit.jsonl").read_text()
        # The test account's login pair is a credential; the field *name* is not.
        assert "alice@example.com" not in written
        assert "\"username\": \"alice\"" not in written
        assert "hunter2" not in written
        assert "username_field" in written


class TestBudget:
    def test_llm_ceiling_aborts(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(enforce=True, llm_usd=0.10), path=tmp_path / "b.json")
        budget.charge_llm(usd=0.09, prompt_tokens=100, completion_tokens=50, phase="triage", tier="t0")
        budget.check()
        budget.charge_llm(usd=0.02, phase="triage", tier="t0")
        with pytest.raises(BudgetExceeded, match="llm_usd"):
            budget.check()

    def test_preflight_refuses_work_it_cannot_afford(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(enforce=True, max_requests=100), path=tmp_path / "b.json")
        budget.charge_tool(seconds=1, requests=95)
        with pytest.raises(BudgetExceeded, match="requests"):
            budget.check(need_requests=50)

    def test_wall_clock_ceiling(self, tmp_path) -> None:
        budget = Budget(BudgetLimits(enforce=True, wall_clock_minutes=0.0001), path=tmp_path / "b.json")
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

    def test_enforce_false_disables_every_ceiling(self, tmp_path) -> None:
        # Operator decision: no ceilings. check() must never raise and
        # remaining() must report unlimited, no matter how much is spent.
        budget = Budget(BudgetLimits(enforce=False, max_requests=10), path=tmp_path / "b.json")
        budget.charge_tool(seconds=1, requests=9999)
        assert budget.exhausted() is None
        budget.check(need_requests=10**12)
        assert budget.remaining()["requests"] == float("inf")
        assert budget.remaining()["wall_clock_seconds"] == float("inf")

    def test_enforce_defaults_to_false(self) -> None:
        # A scope that says nothing about budget gets no ceilings: the control
        # truncates coverage rather than protecting the target, so opting in is
        # explicit. The numbers alone must not enable it — a stale ceiling left
        # in a copied scope file would otherwise stop a run nobody expected to
        # be capped.
        assert BudgetLimits.from_dict({}).enforce is False
        assert BudgetLimits.from_dict({"llm_usd": 1.0, "max_requests": 10}).enforce is False
        assert BudgetLimits.from_dict({"enforce": True}).enforce is True


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


class TestAssetStorePersistsAcrossProcesses:
    """The store was write-only, and the pipeline runs a process per phase.

    Every phase called `assets.save()`; nothing ever loaded it back. Inside one
    process that is invisible — the store is still in memory. Across processes,
    which is how `hunt.sh` runs, every phase started blind. Ten tools each
    deduplicated their own output correctly and none of it reached the next
    stage: a full run left 52 assets, all of one kind, because the driver had
    handed every phase the same hostname.
    """

    def test_load_repopulates_what_save_wrote(self, tmp_path) -> None:
        from easyhunt.knowledge.findings import Asset, AssetStore

        first = AssetStore()
        first.add(Asset(value="a.example.com", kind="subdomain", source="subfinder"))
        first.add(Asset(value="b.example.com", kind="subdomain", source="amass"))
        first.save(tmp_path / "assets.json")

        second = AssetStore()
        assert second.load(tmp_path / "assets.json") == 2
        assert second.values("subdomain") == ["a.example.com", "b.example.com"]

    def test_load_merges_rather_than_replaces(self, tmp_path) -> None:
        """A resumed run keeps what it already knew."""
        from easyhunt.knowledge.findings import Asset, AssetStore

        saved = AssetStore()
        saved.add(Asset(value="a.example.com", kind="subdomain", source="subfinder"))
        saved.save(tmp_path / "assets.json")

        live = AssetStore()
        live.add(Asset(value="c.example.com", kind="subdomain", source="live"))
        live.load(tmp_path / "assets.json")
        assert live.values("subdomain") == ["a.example.com", "c.example.com"]

    def test_the_same_host_from_two_tools_is_stored_once(self, tmp_path) -> None:
        """Dedupe is the whole reason several enumerators can run together."""
        from easyhunt.knowledge.findings import Asset, AssetStore

        store = AssetStore()
        store.add(Asset(value="a.example.com", kind="subdomain", source="subfinder"))
        store.add(Asset(value="a.example.com", kind="subdomain", source="amass"))
        assert len(store.values("subdomain")) == 1

    def test_a_missing_file_is_not_an_error(self, tmp_path) -> None:
        from easyhunt.knowledge.findings import AssetStore

        assert AssetStore().load(tmp_path / "nope.json") == 0

    def test_an_engagement_resuming_a_workspace_inherits_its_assets(
        self, scope, config, tmp_path
    ) -> None:
        from easyhunt.control_plane.context import Engagement
        from easyhunt.knowledge.findings import Asset

        first = Engagement(scope, config, workspace=tmp_path / "ws")
        first.assets.add(Asset(value="a.example.com", kind="subdomain", source="recon"))
        first.assets.save(first.workspace / "assets.json")

        resumed = Engagement(scope, config, workspace=tmp_path / "ws")
        assert resumed.assets.values("subdomain") == ["a.example.com"]


class TestEmptyIsNotTheSameAsFiltered:
    """An empty result and a fully-filtered one had the same shape.

    Measured live: subfinder returned one host, the scope filter dropped it as
    out of scope, and the phase reported `subdomains: []` with no message —
    indistinguishable from "no subdomains exist". The fixes are opposite:
    nothing found means look elsewhere; everything filtered means the scope is
    narrower than the seed, usually because a HOST was passed where a registrable
    domain was wanted.
    """

    def _runs(self, found: int):
        from easyhunt.tools.common import ToolRun

        return [ToolRun(tool="subfinder", ran=True, values=[f"h{i}.example.com" for i in range(found)])]

    def test_everything_filtered_says_so(self) -> None:
        from easyhunt.tools.common import grouped_result

        r = grouped_result(kind="subdomains", runs=self._runs(3), values=[], dropped=3)
        assert r["complete"] is False
        assert "out of scope" in r["message"]
        assert "scope mismatch" in r["message"]

    def test_genuinely_empty_says_something_different(self) -> None:
        from easyhunt.tools.common import grouped_result

        r = grouped_result(kind="subdomains", runs=self._runs(0), values=[], dropped=0)
        assert "No results from any source" in r["message"]
        assert r.get("complete") is not False

    def test_a_normal_result_carries_no_alarm(self) -> None:
        from easyhunt.tools.common import grouped_result

        r = grouped_result(
            kind="subdomains", runs=self._runs(2), values=["a.example.com"], dropped=1
        )
        assert "message" not in r
        assert r["count"] == 1
        assert r["dropped_out_of_scope"] == 1


class TestLiveAndArchivedUrlsAreNotTheSameInput:
    """Both are kind "url"; only one is a scan target.

    `http_probe` stores confirmed-live URLs and `endpoint_discovery` stores
    archived ones, both as kind "url". A phase asking for "url" therefore got
    both — and feeding nuclei 2,736 archived URLs produced a request for 7,393
    templates across 500 targets: 7.7 million requests, 215 hours at the
    engagement's ceiling. The sizing gate refused it, correctly, but the ask was
    nonsense before it ever reached the gate.
    """

    def _store(self):
        from easyhunt.knowledge.findings import Asset, AssetStore

        s = AssetStore()
        s.add(Asset(value="https://live.example.com/", kind="url",
                    source="httpx", tags=["live"]))
        s.add(Asset(value="https://old.example.com/a?x=1", kind="url",
                    source="archives", tags=["archived"]))
        s.add(Asset(value="https://old.example.com/b", kind="url",
                    source="ffuf", tags=["brute-forced"]))
        return s

    def test_untagged_query_returns_everything(self) -> None:
        assert len(self._store().values("url")) == 3

    def test_live_tag_returns_only_confirmed_hosts(self) -> None:
        assert self._store().values("url", tag="live") == ["https://live.example.com/"]

    def test_a_tag_nothing_carries_returns_nothing(self) -> None:
        assert self._store().values("url", tag="nonexistent") == []


class TestHuntPlanSurfaceGrouping:
    """2,747 URLs is not a surface anyone can reason about; 19 is.

    Scanners cover known CVEs. What they do not do is notice that a path ends
    in a six-digit number, or that a parameter is named `redirect_uri`. This
    grouping is the difference between a dump and a short list of things to
    actually try — measured on a live run, 2,747 URLs reduced to 19 object
    reference candidates.
    """

    def _group(self, urls):
        from easyhunt.tools.hunt_plan import _interesting

        return _interesting(urls)

    def test_numeric_path_segments_are_object_references(self) -> None:
        g = self._group(["https://x.example.com/event/43691/", "https://x.example.com/about"])
        assert g["object_reference_candidates"] == ["https://x.example.com/event/43691/"]

    def test_uuids_are_object_references(self) -> None:
        g = self._group(["https://x.example.com/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301"])
        assert len(g["object_reference_candidates"]) == 1

    def test_id_parameters_are_object_references(self) -> None:
        g = self._group(["https://x.example.com/p?user_id=7", "https://x.example.com/p?q=hello"])
        assert g["object_reference_candidates"] == ["https://x.example.com/p?user_id=7"]

    def test_url_taking_parameters_are_sinks(self) -> None:
        g = self._group([
            "https://x.example.com/go?redirect_uri=https://y.example.com",
            "https://x.example.com/f?file=notes.txt",
            "https://x.example.com/plain?q=1",
        ])
        assert len(g["server_side_sink_candidates"]) == 2

    def test_parameter_vocabulary_is_collected_and_deduplicated(self) -> None:
        g = self._group([
            "https://x.example.com/a?page=1&sort=asc",
            "https://x.example.com/b?page=2&filter=x",
        ])
        assert g["distinct_parameter_names"] == ["filter", "page", "sort"]

    def test_an_ordinary_page_produces_no_candidates(self) -> None:
        """The control: this must not flag everything."""
        g = self._group(["https://x.example.com/", "https://x.example.com/about-us"])
        assert not g["object_reference_candidates"]
        assert not g["server_side_sink_candidates"]


class TestApprovalPolicyContradiction:
    """A tool in both auto_approve and auto_deny.

    Deny wins because deny is checked first — but that is an accident of
    ordering, not a decision anybody made, and an operator reading the config
    cannot tell which list is in force. Resolve toward safety, and say so.
    """

    def test_a_tool_in_both_lists_is_denied(self) -> None:
        from easyhunt.control_plane.approval import PolicyBackend

        backend = PolicyBackend(auto_approve=["ssrf_probe", "nuclei_scan"],
                                auto_deny=["ssrf_probe"])
        assert "ssrf_probe" not in backend.auto_approve
        assert "ssrf_probe" in backend.auto_deny
        # The uncontested entry is untouched.
        assert "nuclei_scan" in backend.auto_approve

    def test_the_contradiction_is_logged(self, caplog) -> None:
        import logging

        from easyhunt.control_plane.approval import PolicyBackend

        with caplog.at_level(logging.WARNING, logger="easyhunt.approval"):
            PolicyBackend(auto_approve=["port_scan"], auto_deny=["port_scan"])
        # Silently picking one is how a config stops describing what runs.
        assert "port_scan" in caplog.text
        assert "DENIED" in caplog.text

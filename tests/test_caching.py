"""Prompt caching: breakpoints on the stable prefix, and honest accounting."""

from __future__ import annotations

import json
from typing import Any

import pytest

from easyhunt.llm.openrouter import (
    MIN_CACHEABLE_CHARS,
    LLMClient,
    build_messages,
    needs_explicit_cache_control,
)

LONG_STABLE = "Triage rubric. " * 400  # comfortably past the write threshold


class TestProviderDetection:
    @pytest.mark.parametrize(
        "model", ["anthropic/claude-sonnet-4.5", "google/gemini-2.0-flash-001", "gemini-pro"]
    )
    def test_explicit_cache_providers(self, model: str) -> None:
        assert needs_explicit_cache_control(model)

    @pytest.mark.parametrize("model", ["openai/gpt-5", "deepseek/deepseek-chat", "x-ai/grok-2"])
    def test_automatic_cache_providers_need_no_marker(self, model: str) -> None:
        # These cache automatically; a marker would be noise.
        assert not needs_explicit_cache_control(model)


class TestMessageBuilder:
    def test_marks_the_stable_prefix(self) -> None:
        messages = build_messages(
            system="You are an analyst.",
            stable=LONG_STABLE,
            volatile="FINDINGS: [...]",
            model="anthropic/claude-sonnet-4.5",
        )
        system = messages[0]["content"]
        assert isinstance(system, list)
        assert system[0]["cache_control"] == {"type": "ephemeral"}

    def test_volatile_data_goes_last(self) -> None:
        messages = build_messages(
            system="sys", stable=LONG_STABLE, volatile="BATCH 7",
            model="anthropic/claude-sonnet-4.5",
        )
        # The cached prefix must precede the part that changes every call,
        # otherwise the prefix is never byte-identical and nothing caches.
        assert messages[-1]["role"] == "user"
        assert messages[-1]["content"] == "BATCH 7"

    def test_short_prefixes_are_not_marked(self) -> None:
        # Below the threshold a cache write costs more than the reads save.
        messages = build_messages(
            system="short", stable="also short", volatile="x",
            model="anthropic/claude-sonnet-4.5",
        )
        assert isinstance(messages[0]["content"], str)

    def test_threshold_is_documented(self) -> None:
        assert MIN_CACHEABLE_CHARS >= 1000

    def test_auto_caching_providers_get_plain_messages(self) -> None:
        messages = build_messages(
            system="sys", stable=LONG_STABLE, volatile="data", model="openai/gpt-5"
        )
        assert isinstance(messages[0]["content"], str)

    def test_force_cache_overrides_detection(self) -> None:
        messages = build_messages(
            system="sys", stable=LONG_STABLE, volatile="d", model="openai/gpt-5", force_cache=True
        )
        assert isinstance(messages[0]["content"], list)

    def test_prefix_is_identical_across_calls(self) -> None:
        # The property the whole technique depends on.
        first = build_messages(
            system="sys", stable=LONG_STABLE, volatile="batch 1",
            model="anthropic/claude-sonnet-4.5",
        )
        second = build_messages(
            system="sys", stable=LONG_STABLE, volatile="batch 2",
            model="anthropic/claude-sonnet-4.5",
        )
        assert first[0] == second[0]
        assert first[1] != second[1]


class FakeUsage:
    def __init__(self, cached: int = 0, *, as_dict: bool = False, top_level: bool = False) -> None:
        self.prompt_tokens = 1000
        self.completion_tokens = 50
        self.cost = 0.0
        self.cache_discount = 0.004 if cached else 0.0
        if top_level:
            self.cache_read_input_tokens = cached
        elif as_dict:
            self.prompt_tokens_details = {"cached_tokens": cached}
        else:
            self.prompt_tokens_details = type("D", (), {"cached_tokens": cached})()


class FakeCompletion:
    def __init__(self, usage: Any) -> None:
        self.model = "anthropic/claude-sonnet-4.5"
        self.usage = usage
        message = type("M", (), {"content": "ok"})()
        self.choices = [type("C", (), {"message": message})()]


class FakeOpenAI:
    def __init__(self, usage: Any) -> None:
        self.calls: list[dict[str, Any]] = []
        owner = self

        class Completions:
            async def create(self, **kwargs: Any) -> FakeCompletion:
                owner.calls.append(kwargs)
                return FakeCompletion(usage)

        self.chat = type("Chat", (), {"completions": Completions()})()


@pytest.fixture
def client(engagement, monkeypatch) -> LLMClient:
    engagement.config.data["llm"]["tiers"] = {
        "t1": {"model": "anthropic/claude-3.5-haiku", "max_price": {"prompt": 2, "completion": 6}}
    }
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    return LLMClient(engagement)


class TestCacheAccounting:
    @pytest.mark.parametrize("shape", ["object", "dict", "top_level"])
    async def test_reads_cached_tokens_in_every_shape(self, client, shape) -> None:
        usage = FakeUsage(
            800, as_dict=(shape == "dict"), top_level=(shape == "top_level")
        )
        client._client = FakeOpenAI(usage)
        response = await client.complete([{"role": "user", "content": "x"}], tier="t1")
        assert response.cached_tokens == 800

    async def test_hit_rate(self, client) -> None:
        client._client = FakeOpenAI(FakeUsage(750))
        response = await client.complete([{"role": "user", "content": "x"}], tier="t1")
        assert response.cache_hit_rate == pytest.approx(0.75)

    async def test_cache_hits_reduce_the_estimated_cost(self, client) -> None:
        client._client = FakeOpenAI(FakeUsage(0))
        uncached = await client.complete([{"role": "user", "content": "x"}], tier="t1")

        client._client = FakeOpenAI(FakeUsage(900))
        cached = await client.complete([{"role": "user", "content": "x"}], tier="t1")

        # A cache hit must not be charged at the full prompt rate, or the budget
        # will stop a run that is actually well within its ceiling.
        assert cached.usd < uncached.usd

    async def test_no_usage_details_is_safe(self, client) -> None:
        client._client = FakeOpenAI(type("U", (), {"prompt_tokens": 10, "completion_tokens": 1, "cost": 0.001})())
        response = await client.complete([{"role": "user", "content": "x"}], tier="t1")
        assert response.cached_tokens == 0

    async def test_audit_records_cache_stats(self, engagement, client) -> None:
        client._client = FakeOpenAI(FakeUsage(600))
        await client.complete([{"role": "user", "content": "x"}], tier="t1", phase="triage")
        record = [r for r in engagement.audit.read_all() if r["event"] == "llm_call"][-1]
        assert record["cached_tokens"] == 600
        assert record["cache_discount"] > 0

    async def test_client_summary_totals_savings(self, client) -> None:
        client._client = FakeOpenAI(FakeUsage(500))
        for _ in range(3):
            await client.complete([{"role": "user", "content": "x"}], tier="t1")
        summary = client.summary()
        assert summary["cached_prompt_tokens"] == 1500
        assert summary["cache_savings_usd"] > 0


class TestTriageUsesCaching:
    async def test_triage_puts_instructions_in_the_cacheable_prefix(self, engagement) -> None:
        from easyhunt.knowledge.findings import Finding, Severity
        from easyhunt.llm.triage import Taskflow, run_taskflow

        sent: list[Any] = []

        class RecordingClient:
            enabled = True
            tiers = {"t1": type("T", (), {"model": "anthropic/claude-sonnet-4.5"})()}

            async def complete(self, messages, **kwargs: Any):
                sent.append(messages)

                class Response:
                    text = "[]"
                    model = "stub"

                    def json(self, default=None):  # noqa: ANN001
                        return []

                return Response()

        finding = engagement.findings.add(
            Finding(asset="https://www.example.com/x", title="Candidate", severity=Severity.HIGH)
        )
        flow = Taskflow.from_dict(
            {
                "name": "cache-test",
                "canaries": 0,
                # A realistic triage prompt: long enough that caching it pays.
                "steps": [{"name": "falsifier", "tier": "t1", "prompt": "Falsify this finding. " * 200}],
            },
            source="<test>",
        )
        await run_taskflow(RecordingClient(), flow, [finding], engagement=engagement)

        assert sent, "the step should have issued a call"
        system = sent[0][0]["content"]
        # The step's instructions repeat across every batch, so they belong in
        # the cached prefix while only the findings vary.
        assert isinstance(system, list)
        assert system[0]["cache_control"] == {"type": "ephemeral"}
        assert "FINDINGS:" in sent[0][-1]["content"]
        assert "FINDINGS:" not in json.dumps(system)

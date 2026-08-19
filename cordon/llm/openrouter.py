"""OpenRouter client: three-tier routing, fallbacks, price ceilings, accounting.

The economics of an agentic scanner are decided here. A run that sends raw tool
output to a strong model burns its whole budget summarizing 404s; a run that
routes properly spends most of its tokens on a free model and reserves the
expensive one for exploit reasoning and the report.

Four controls, all of which have to be in place for a run to be safe to leave
alone:

* **Tiers.** T0 dedupes/classifies/summarizes in bulk. T1 correlates and triages.
  T2 reasons about exploitation and writes the report. Slugs come from config —
  never hardcoded, because model names change and a hardcoded slug is an outage.
* **``models[]`` fallback.** Billed only for the one that runs, with
  ``openrouter/auto`` last so a renamed slug degrades instead of failing.
* **``max_price``.** A hard USD-per-million ceiling per tier. The request fails
  rather than silently routing to an expensive provider.
* **Budget integration.** Every call is pre-checked against the engagement's USD
  ceiling and charged after, so a loop cannot outrun the budget between calls.

Free tiers have per-minute and per-day caps that change without notice. On a rate
limit the client backs off and then *demotes* to a cheaper tier rather than
failing the phase — a triage pass that completes on a weaker model beats one that
does not complete.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
from dataclasses import dataclass, field
from typing import Any

from cordon.errors import LLMError

log = logging.getLogger("cordon.llm")

__all__ = ["LLMClient", "LLMResponse", "TierConfig"]

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

# Fallback pricing (USD per million tokens) used only when a response omits
# usage costs. Deliberately pessimistic: over-estimating spend stops a run early,
# under-estimating it lets a run overspend.
_ASSUMED_PRICE = {"t0": (0.5, 1.5), "t1": (3.0, 9.0), "t2": (12.0, 36.0)}


@dataclass
class TierConfig:
    """One routing tier."""

    name: str
    model: str
    fallbacks: list[str] = field(default_factory=list)
    max_price: dict[str, float] = field(default_factory=dict)
    provider_sort: str = "price"
    max_output_tokens: int = 4096

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any] | None) -> TierConfig:
        data = data or {}
        fallbacks = [str(f) for f in (data.get("fallbacks") or [])]
        # A renamed slug should degrade, not break the run.
        if "openrouter/auto" not in fallbacks:
            fallbacks.append("openrouter/auto")
        return cls(
            name=name,
            model=str(data.get("model") or "openrouter/auto"),
            fallbacks=fallbacks,
            max_price=dict(data.get("max_price") or {}),
            provider_sort=str(data.get("provider_sort") or "price"),
            max_output_tokens=int(data.get("max_output_tokens") or 4096),
        )


@dataclass
class LLMResponse:
    text: str
    model: str
    tier: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    fallback_used: str | None = None
    demoted_from: str | None = None
    #: Prompt tokens served from cache. On a triage run over one findings set,
    #: this should be most of the prompt after the first call.
    cached_tokens: int = 0
    #: USD saved by those cache hits, as reported by the provider.
    cache_discount: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def cache_hit_rate(self) -> float:
        return self.cached_tokens / self.prompt_tokens if self.prompt_tokens else 0.0

    def json(self, *, default: Any = None) -> Any:
        """Parse the response as JSON, tolerating fenced code blocks.

        Models wrap JSON in ``` fences often enough that failing on it would mean
        losing a paid call to a formatting detail.
        """
        text = self.text.strip()
        fence = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
        if fence:
            text = fence.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Last resort: the first balanced object or array in the text.
            match = re.search(r"[\[{].*[\]}]", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        return default


# Providers that need an explicit cache_control breakpoint. OpenAI, DeepSeek,
# Grok, and Groq cache automatically and ignore the marker; Anthropic and Gemini
# only cache what you mark, so omitting it means paying full price every call.
_EXPLICIT_CACHE_PREFIXES = ("anthropic/", "google/gemini", "gemini")

# Below this, a cache write costs more than the reads save. Anthropic's minimum
# cacheable prefix is ~1024 tokens for most models; 3000 characters is a
# conservative stand-in that avoids paying the write premium on short prompts.
MIN_CACHEABLE_CHARS = 3000


def _cached_tokens(usage: Any) -> int:
    """Cached prompt tokens, wherever this provider chose to report them.

    OpenAI-compatible responses put it in ``prompt_tokens_details.cached_tokens``,
    but that field is sometimes an object and sometimes a dict, and some
    providers report ``cache_read_input_tokens`` at the top level instead.
    """
    if usage is None:
        return 0

    details = getattr(usage, "prompt_tokens_details", None)
    if isinstance(details, dict):
        value = details.get("cached_tokens")
    elif details is not None:
        value = getattr(details, "cached_tokens", None)
    else:
        value = None

    if value is None:
        value = getattr(usage, "cache_read_input_tokens", None)

    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def needs_explicit_cache_control(model: str) -> bool:
    """Whether this model requires cache_control markers to cache at all."""
    lowered = (model or "").lower()
    return any(lowered.startswith(prefix) for prefix in _EXPLICIT_CACHE_PREFIXES)


def build_messages(
    *,
    system: str,
    stable: str = "",
    volatile: str = "",
    model: str = "",
    force_cache: bool | None = None,
) -> list[dict[str, Any]]:
    """Assemble messages with the cacheable prefix marked.

    Caching only pays when the prefix is byte-identical across calls, so the
    ordering is the whole technique: **system prompt and stable instructions
    first, volatile data last**. Triage sends the same instructions with
    different findings twenty times in a phase — with the split, nineteen of
    those calls read the instructions from cache.

    ``stable`` is content repeated across calls (schemas, rubrics, methodology).
    ``volatile`` is the payload that differs each time. The breakpoint goes at
    the end of the stable section.
    """
    explicit = needs_explicit_cache_control(model) if force_cache is None else force_cache
    prefix = f"{system}\n\n{stable}".strip() if stable else system.strip()
    worth_caching = explicit and len(prefix) >= MIN_CACHEABLE_CHARS

    if not worth_caching:
        messages: list[dict[str, Any]] = [{"role": "system", "content": prefix}]
        if volatile:
            messages.append({"role": "user", "content": volatile})
        return messages

    # Content-block form, with the breakpoint on the final stable block.
    return [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": prefix,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        },
        {"role": "user", "content": volatile or "Proceed."},
    ]


class LLMClient:
    """Async OpenRouter client wired to the engagement's budget and audit log."""

    def __init__(self, engagement: Any) -> None:
        self.engagement = engagement
        config = engagement.config
        self.base_url = str(config.get("llm.base_url", DEFAULT_BASE_URL))
        self.api_key = os.environ.get(str(config.get("llm.api_key_env", "OPENROUTER_API_KEY")), "")
        self.max_retries = int(config.get("llm.max_retries", 4))
        self.demote_on_ratelimit = bool(config.get("llm.demote_on_ratelimit", True))
        self.referer = str(config.get("llm.referer", "https://github.com/iamsecure1920/Cordon-AI"))
        self.title = str(config.get("llm.title", "Cordon AI"))

        tiers = config.section("llm.tiers")
        self.tiers = {name: TierConfig.from_dict(name, tiers.get(name)) for name in ("t0", "t1", "t2")}
        self._client: Any = None
        self.calls = 0
        self.cached_tokens = 0
        self.cache_savings = 0.0

    # -- availability ------------------------------------------------------- #

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise LLMError(
                "no OpenRouter API key. Set $OPENROUTER_API_KEY, or run with LLM "
                "features disabled — passive recon and rule-based detection do not "
                "need a model.",
                code="llm_no_key",
            )
        try:
            from openai import AsyncOpenAI  # noqa: PLC0415
        except ImportError as exc:
            raise LLMError(
                "the 'openai' package is required for the OpenRouter client "
                "(pip install 'cordon-ai[llm]')",
                code="llm_missing_dependency",
            ) from exc

        self._client = AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            default_headers={"HTTP-Referer": self.referer, "X-Title": self.title},
            max_retries=0,  # retries and backoff are handled here, with demotion
        )
        return self._client

    # -- the call ----------------------------------------------------------- #

    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        tier: str = "t0",
        phase: str = "unknown",
        purpose: str = "",
        max_tokens: int | None = None,
        temperature: float = 0.2,
        json_mode: bool = False,
    ) -> LLMResponse:
        """One chat completion, budgeted, routed, retried, and accounted for.

        Messages should be ordered stable-first: the system prompt and any fixed
        instructions at the top, volatile findings data at the end. That is what
        makes prompt caching effective across a phase's many similar calls.
        """
        tier_config = self.tiers.get(tier) or self.tiers["t0"]
        client = self._ensure_client()
        budget = self.engagement.budget

        estimated = self._estimate_cost(messages, tier_config, max_tokens)
        budget.check(need_usd=estimated)

        remaining = budget.phase_tokens_remaining(phase)
        if remaining is not None and remaining <= 0:
            raise LLMError(
                f"phase '{phase}' has exhausted its token allowance; summarize what "
                "you have and move on",
                code="phase_budget_exhausted",
                phase=phase,
            )

        # Strongest first, then progressively cheaper tiers on rate limiting.
        ladder = ["t2", "t1", "t0"]
        order = [tier_config]
        if self.demote_on_ratelimit and tier_config.name in ladder:
            cheaper = ladder[ladder.index(tier_config.name) + 1 :]
            order += [self.tiers[name] for name in cheaper if name in self.tiers]

        last_error: Exception | None = None
        for attempt_tier in order:
            for attempt in range(self.max_retries):
                try:
                    response = await self._request(
                        client, messages, attempt_tier, max_tokens, temperature, json_mode
                    )
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    status = getattr(exc, "status_code", None)
                    message = str(exc).lower()
                    rate_limited = status == 429 or "rate" in message and "limit" in message

                    if status in {400, 401, 403} and not rate_limited:
                        raise LLMError(
                            f"OpenRouter rejected the request: {exc}", code="llm_rejected",
                            tier=attempt_tier.name, model=attempt_tier.model,
                        ) from exc

                    if attempt == self.max_retries - 1:
                        break
                    # Exponential backoff with jitter, so parallel triage calls
                    # do not retry in lockstep and re-trigger the limit.
                    delay = min(30.0, (2**attempt) + random.random())  # noqa: S311
                    log.warning(
                        "%s on %s (attempt %d/%d), retrying in %.1fs",
                        type(exc).__name__, attempt_tier.model, attempt + 1, self.max_retries, delay,
                    )
                    await asyncio.sleep(delay)
                    continue

                if attempt_tier is not tier_config:
                    response.demoted_from = tier_config.name
                    log.warning(
                        "demoted %s → %s after rate limiting", tier_config.name, attempt_tier.name
                    )

                budget.charge_llm(
                    usd=response.usd,
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    phase=phase,
                    tier=response.tier,
                )
                self.engagement.audit.llm_call(
                    tier=response.tier,
                    model=response.model,
                    phase=phase,
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    usd=response.usd,
                    purpose=purpose,
                    fallback_used=response.fallback_used,
                    cached_tokens=response.cached_tokens,
                    cache_discount=response.cache_discount,
                )
                self.calls += 1
                self.cached_tokens += response.cached_tokens
                self.cache_savings += response.cache_discount
                return response

        raise LLMError(
            f"all tiers and retries exhausted: {last_error}",
            code="llm_unavailable",
            tier=tier,
        )

    async def _request(
        self,
        client: Any,
        messages: list[dict[str, str]],
        tier: TierConfig,
        max_tokens: int | None,
        temperature: float,
        json_mode: bool,
    ) -> LLMResponse:
        extra_body: dict[str, Any] = {
            # Billed only for the model that actually runs.
            "models": tier.fallbacks,
            "provider": {"sort": tier.provider_sort},
            # Report usage accounting so spend is measured, not estimated.
            "usage": {"include": True},
        }
        if tier.max_price:
            # The request fails rather than overspending.
            extra_body["provider"]["max_price"] = tier.max_price

        kwargs: dict[str, Any] = {
            "model": tier.model,
            "messages": messages,
            "max_tokens": max_tokens or tier.max_output_tokens,
            "temperature": temperature,
            "extra_body": extra_body,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        completion = await client.chat.completions.create(**kwargs)

        usage = getattr(completion, "usage", None)
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        usd = float(getattr(usage, "cost", 0.0) or 0.0)

        # Cache accounting — without it the caching work is unverifiable.
        cached_tokens = _cached_tokens(usage)
        cache_discount = float(getattr(usage, "cache_discount", 0.0) or 0.0)

        if not usd:
            usd = self._price(tier.name, prompt_tokens, completion_tokens)
            # Cached prompt tokens are heavily discounted; reflect that in the
            # estimate so the budget is not charged full price for a cache hit.
            if cached_tokens:
                prompt_rate, _ = _ASSUMED_PRICE.get(tier.name, _ASSUMED_PRICE["t1"])
                usd = max(0.0, usd - (cached_tokens * prompt_rate * 0.9) / 1_000_000)

        model_used = str(getattr(completion, "model", tier.model))
        choice = completion.choices[0] if completion.choices else None
        text = (getattr(choice.message, "content", "") if choice else "") or ""

        return LLMResponse(
            text=text,
            model=model_used,
            tier=tier.name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            usd=usd,
            cached_tokens=cached_tokens,
            cache_discount=cache_discount,
            fallback_used=model_used if model_used != tier.model else None,
        )

    # -- costing ------------------------------------------------------------ #

    @staticmethod
    def _price(tier: str, prompt_tokens: int, completion_tokens: int) -> float:
        prompt_rate, completion_rate = _ASSUMED_PRICE.get(tier, _ASSUMED_PRICE["t1"])
        return (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1_000_000

    def _estimate_cost(
        self, messages: list[dict[str, str]], tier: TierConfig, max_tokens: int | None
    ) -> float:
        """Rough pre-flight estimate, ~4 characters per token."""
        characters = sum(len(str(m.get("content", ""))) for m in messages)
        prompt_tokens = characters // 4
        completion_tokens = max_tokens or tier.max_output_tokens
        ceiling = tier.max_price
        if ceiling:
            return (
                prompt_tokens * float(ceiling.get("prompt", 0))
                + completion_tokens * float(ceiling.get("completion", 0))
            ) / 1_000_000
        return self._price(tier.name, prompt_tokens, completion_tokens)

    # -- diagnostics -------------------------------------------------------- #

    async def probe(self) -> dict[str, Any]:
        """Check which configured model slugs actually exist right now.

        Model names get renamed and retired. ``cordon doctor`` runs this so a
        run does not discover a dead slug halfway through the report phase.
        """
        if not self.api_key:
            return {"ok": False, "reason": "no API key set", "tiers": {}}
        try:
            import httpx  # noqa: PLC0415

            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                response.raise_for_status()
                available = {
                    str(m.get("id"))
                    for m in (response.json().get("data") or [])
                    if isinstance(m, dict)
                }
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": f"could not reach OpenRouter: {exc}", "tiers": {}}

        report: dict[str, Any] = {}
        for name, tier in self.tiers.items():
            chain = [tier.model, *tier.fallbacks]
            report[name] = {
                "model": tier.model,
                "model_available": tier.model in available,
                "fallbacks_available": [f for f in chain[1:] if f in available or f == "openrouter/auto"],
                "dead_slugs": [
                    f for f in chain if f not in available and f != "openrouter/auto"
                ],
            }
        return {"ok": True, "models_listed": len(available), "tiers": report}

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "calls": self.calls,
            "cached_prompt_tokens": self.cached_tokens,
            "cache_savings_usd": round(self.cache_savings, 6),
            "tiers": {
                name: {"model": t.model, "fallbacks": t.fallbacks, "max_price": t.max_price}
                for name, t in self.tiers.items()
            },
        }

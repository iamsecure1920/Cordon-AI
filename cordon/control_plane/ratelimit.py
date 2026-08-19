"""Rate limiting and concurrency control.

A token bucket capped at ``scope.rules.max_rps`` plus a concurrency semaphore at
``scope.rules.max_concurrency``. Both apply to the engine tier as well as to
atomic wrappers — a BBOT or Nuclei run is not exempt just because it manages its
own internal parallelism, so engines additionally receive the ceiling as a native
flag (``-rate-limit``, ``web.requests_per_second``) and are charged here for the
launch itself.

Per-host buckets exist because a program's published rate limit is usually
per-asset, and a global-only limiter would let 20 subdomains share one budget
while a single host absorbs it all.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from cordon.errors import RateLimited

__all__ = ["RateLimiter", "TokenBucket"]


class TokenBucket:
    """Classic token bucket. ``rate`` tokens/second, bursting up to ``capacity``."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(rate, 1.0))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self.granted = 0
        #: Tokens actually charged, as distinct from calls admitted. The gap
        #: between the two is the whole point of costing a call by its requests.
        self.charged = 0.0
        #: Charged but not enforceable — see :meth:`acquire`. Non-zero means the
        #: ceiling did not actually bind for at least one call.
        self.unenforced = 0.0
        self.total_wait = 0.0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    @property
    def tokens(self) -> float:
        self._refill()
        return self._tokens

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Non-blocking attempt. Used by callers that prefer to skip over waiting."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            self.granted += 1
            self.charged += tokens
            return True
        return False

    async def acquire(self, tokens: float = 1.0) -> float:
        """Block until the charge can be made. Returns seconds spent waiting.

        Costs larger than ``capacity`` are charged in full and allowed to drive
        the bucket **negative**, rather than being clamped down to what fits.

        The clamp this replaces was the more dangerous of the two options. A tool
        declaring 8,283 requests was charged ``capacity`` — typically 5 — and the
        limiter then reported a compliant engagement while the traffic ran three
        orders of magnitude past the published ceiling. Truncating the price of
        something does not make it cheaper; it only stops you seeing the bill.

        Raising ``capacity`` instead is not the fix either: a bucket starts full,
        so a capacity big enough to hold the largest cost would hand out that
        many free tokens on the very first call, and the ceiling would mean
        nothing at t=0. Burst stays small; debt makes the cost honest.

        What this guarantees is *amortized* compliance. A subprocess's own
        request loop is beyond reach — what the limiter can enforce is that the
        engagement issues no more work than ``rate`` allows over time. A call
        that spends 8,283 requests proceeds once a burst is on hand, and the
        engagement then waits out the debt before issuing the next one.
        """
        tokens = max(0.0, float(tokens))
        # Enough on hand to start; the full cost is recorded either way.
        threshold = min(tokens, self.capacity)
        waited = 0.0
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= threshold:
                    self.granted += 1
                    self.charged += tokens
                    # Debt is bounded at one burst. Beyond that the arrears are
                    # recorded but not enforced, and the two are deliberately
                    # different numbers.
                    #
                    # Enforcing unbounded debt is defensible in theory and wrong
                    # in practice: the charge is taken up front, when the call's
                    # duration is unknown, so a tool that spends 2,000 requests
                    # politely over fifteen minutes is billed as though it sent
                    # them all at once and blocks the engagement for the next
                    # four hundred seconds. That penalises compliant tools.
                    #
                    # So enforcement stays bounded and the *accounting* stays
                    # exact: `charged` is the true figure, `unenforced` is what
                    # the ceiling could not claw back, and a report that shows a
                    # non-zero `unenforced` is telling the operator the ceiling
                    # was a wish for that call. The egregious case never reaches
                    # here — RateLimiter refuses it outright.
                    floor = -self.capacity
                    after = self._tokens - tokens
                    if after < floor:
                        self.unenforced += floor - after
                        after = floor
                    self._tokens = after
                    self.total_wait += waited
                    return waited
                deficit = threshold - self._tokens
                delay = deficit / self.rate
            await asyncio.sleep(delay)
            waited += delay

    @property
    def debt(self) -> float:
        """Tokens owed — how far past its allowance this bucket has been charged."""
        self._refill()
        return max(0.0, -self._tokens)


@dataclass
class RateLimiter:
    """Global + per-host token buckets, plus a concurrency ceiling."""

    rps: float = 5.0
    concurrency: int = 5
    per_host_rps: float | None = None
    burst: float | None = None
    #: Refuse a single call whose declared cost would take longer than this to
    #: pay for at ``rps``. One hour, not fifteen minutes: with debt enforcement
    #: bounded there is no stall to prevent, so this guards only against a
    #: declaration that no engagement could honour. Fifteen minutes refused
    #: ssrf_probe (8,283 requests) on any program publishing under 10 rps, which
    #: is a real judgement about that tool rather than a rate-limiter concern —
    #: and one already recorded in its risk_notes.
    max_wait_seconds: float = 3600.0

    _global: TokenBucket = field(init=False)
    _hosts: dict[str, TokenBucket] = field(init=False, default_factory=dict)
    _sem: asyncio.Semaphore = field(init=False)
    #: Task ids currently holding the concurrency semaphore. A tool body that
    #: paces its own requests calls ``slot()`` *inside* the wrapper's slot —
    #: exploit_chain → web_injection_probe → per-request probe. Acquiring the
    #: semaphore again would deadlock once the ceiling is exhausted (a 3-deep
    #: nesting under max_concurrency=2), and it would double-count one tool call
    #: as two in-flight. Nested slots take the rate tokens and skip the
    #: semaphore; the outer slot still bounds the call's concurrency.
    _sem_holders: set[int] = field(init=False, default_factory=set)
    _peak_in_flight: int = field(init=False, default=0)
    _in_flight: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.rps = max(float(self.rps), 0.01)
        self.concurrency = max(int(self.concurrency), 1)
        self._global = TokenBucket(self.rps, self.burst or max(self.rps, 1.0))
        self._sem = asyncio.Semaphore(self.concurrency)

    @classmethod
    def from_scope(cls, scope: Any) -> RateLimiter:
        rules = scope.rules
        return cls(
            rps=rules.max_rps,
            concurrency=rules.max_concurrency,
            # Default per-host to the global ceiling: never faster, often slower.
            per_host_rps=rules.max_rps,
        )

    def _bucket_for(self, host: str | None) -> TokenBucket | None:
        if not host or self.per_host_rps is None:
            return None
        bucket = self._hosts.get(host)
        if bucket is None:
            bucket = TokenBucket(self.per_host_rps, max(self.per_host_rps, 1.0))
            self._hosts[host] = bucket
        return bucket

    def affordable(self, cost: float) -> float:
        """Seconds this cost implies at the engagement's ceiling."""
        return max(0.0, float(cost)) / self.rps

    def _refuse_if_unaffordable(self, cost: float, tool: str | None) -> None:
        """Refuse loudly rather than stall for hours.

        Debt accounting means no cost is impossible — every cost is merely slow.
        That removes the deadlock the old clamp was avoiding, and introduces a
        subtler failure: a tool declaring 8,283 requests against a 5 rps program
        implies a 28-minute wait before the *next* call can be issued. Silently
        absorbing that is not rate limiting, it is a hang with a good excuse.

        A program publishing a ceiling this tool cannot respect is a fact the
        operator needs at the point of the call, in the words of the numbers
        involved — not one to discover from a stalled engagement.
        """
        implied = self.affordable(cost)
        if implied <= self.max_wait_seconds:
            return
        raise RateLimited(
            f"{tool or 'this tool'} declares {int(cost)} requests, which needs "
            f"{implied / 60:.0f} minutes at the engagement's {self.rps:g} rps ceiling "
            f"(limit {self.max_wait_seconds / 60:.0f} minutes). It cannot be run "
            "compliantly against this program. Narrow the target, pick a tool that "
            "sends less, or raise max_rps only if the program's policy permits it.",
            tool=tool,
            cost=int(cost),
            implied_wait_seconds=round(implied, 1),
            rps_ceiling=self.rps,
        )

    async def acquire(
        self, *, host: str | None = None, cost: float = 1.0, tool: str | None = None
    ) -> float:
        """Charge ``cost`` units of work. Returns total seconds spent waiting."""
        self._refuse_if_unaffordable(cost, tool)
        waited = await self._global.acquire(cost)
        bucket = self._bucket_for(host)
        if bucket is not None:
            waited += await bucket.acquire(cost)
        return waited

    @asynccontextmanager
    async def slot(
        self, *, host: str | None = None, cost: float = 1.0, tool: str | None = None
    ) -> AsyncIterator[float]:
        """Acquire a concurrency slot *and* rate-limit tokens for one call.

        ``cost`` is the number of requests the call is expected to make, not the
        number of calls. Charging one token per invocation — which is what every
        caller did before this parameter was wired up — priced a 8,283-request
        SSRF sweep identically to a single ``dig``.

        Yields the time spent waiting so the audit line can record throttling.
        """
        # Refuse before taking the concurrency slot: an unaffordable call should
        # not occupy a slot other work could use while it fails.
        self._refuse_if_unaffordable(cost, tool)
        task = asyncio.current_task()
        task_id = id(task) if task is not None else None
        # Re-entrant slot: this call is already inside a concurrency slot held
        # by the same task (a tool body pacing its own requests). Taking the
        # semaphore again deadlocks once the ceiling is exhausted — the wrapper
        # holds the slot for the whole call, so the body's nested acquisition
        # waits on a slot its own call will not release until it finishes.
        if task_id is not None and task_id in self._sem_holders:
            waited = await self.acquire(host=host, cost=cost, tool=tool)
            yield waited
            return
        async with self._sem:
            if task_id is not None:
                self._sem_holders.add(task_id)
            self._in_flight += 1
            self._peak_in_flight = max(self._peak_in_flight, self._in_flight)
            try:
                waited = await self.acquire(host=host, cost=cost, tool=tool)
                yield waited
            finally:
                self._in_flight -= 1
                if task_id is not None:
                    self._sem_holders.discard(task_id)

    def stats(self) -> dict[str, Any]:
        return {
            "rps_ceiling": self.rps,
            "concurrency_ceiling": self.concurrency,
            "per_host_rps": self.per_host_rps,
            # Calls admitted. NOT requests — a call may declare thousands.
            "calls_granted": self._global.granted,
            "requests_charged": round(self._global.charged, 1),
            # Outstanding debt: requests already charged that the ceiling has not
            # yet paid off. Non-zero means the next call will wait, and a report
            # that omitted it would imply the engagement was idle by choice.
            "requests_owed": round(self._global.debt, 1),
            # Charged but beyond what the bucket could hold against. Non-zero
            # means the published ceiling did not bind for at least one call,
            # and a report claiming compliance without saying so would be wrong.
            "requests_unenforced": round(self._global.unenforced, 1),
            "total_wait_seconds": round(self._global.total_wait, 3),
            "peak_in_flight": self._peak_in_flight,
            "tracked_hosts": len(self._hosts),
        }

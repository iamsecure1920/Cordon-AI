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
            return True
        return False

    async def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds spent waiting."""
        if tokens > self.capacity:
            # Asking for more than the bucket can ever hold would deadlock;
            # clamp so a large batch call degrades to "as fast as allowed".
            tokens = self.capacity
        waited = 0.0
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    self.granted += 1
                    self.total_wait += waited
                    return waited
                deficit = tokens - self._tokens
                delay = deficit / self.rate
            await asyncio.sleep(delay)
            waited += delay


@dataclass
class RateLimiter:
    """Global + per-host token buckets, plus a concurrency ceiling."""

    rps: float = 5.0
    concurrency: int = 5
    per_host_rps: float | None = None
    burst: float | None = None

    _global: TokenBucket = field(init=False)
    _hosts: dict[str, TokenBucket] = field(init=False, default_factory=dict)
    _sem: asyncio.Semaphore = field(init=False)
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

    async def acquire(self, *, host: str | None = None, cost: float = 1.0) -> float:
        """Charge one unit of work. Returns total seconds spent waiting."""
        waited = await self._global.acquire(cost)
        bucket = self._bucket_for(host)
        if bucket is not None:
            waited += await bucket.acquire(cost)
        return waited

    @asynccontextmanager
    async def slot(self, *, host: str | None = None, cost: float = 1.0) -> AsyncIterator[float]:
        """Acquire a concurrency slot *and* rate-limit tokens for one call.

        Yields the time spent waiting so the audit line can record throttling.
        """
        async with self._sem:
            self._in_flight += 1
            self._peak_in_flight = max(self._peak_in_flight, self._in_flight)
            try:
                waited = await self.acquire(host=host, cost=cost)
                yield waited
            finally:
                self._in_flight -= 1

    def stats(self) -> dict[str, Any]:
        return {
            "rps_ceiling": self.rps,
            "concurrency_ceiling": self.concurrency,
            "per_host_rps": self.per_host_rps,
            "requests_granted": self._global.granted,
            "total_wait_seconds": round(self._global.total_wait, 3),
            "peak_in_flight": self._peak_in_flight,
            "tracked_hosts": len(self._hosts),
        }

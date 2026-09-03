"""The single network chokepoint every scope-enforcing HTTP request passes through.

One gate, one sequence, no exceptions:

    scope → sanitize defaults → rate-limit → request → audit

Every network action that enforces program scope — direct probes, validators,
crawlers, fuzzers — must route through :func:`http_request`. A request that
does not flow through this function is a request the scope engine never saw,
and the engagement's only audit answer for it is "we don't know".

History: the codebase accumulated several direct ``httpx`` call sites that
bypassed parts of the chain. ``forbidden_candidates`` sent HEAD requests with
no limiter token and no scope check; ``burp_send`` sent scope-checked targets
but no rate tokens. This module exists so the next HTTP call site has exactly
one correct thing to do.

The gate does **not** replace the :func:`~cordon.tools.base.cordon_tool`
decorator — it complements it. The decorator guards the *tool*; this guards
the *request*. Both must be passed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from cordon.control_plane.context import get_engagement
from cordon.errors import OutOfScopeError
from cordon.util.parse import host_of

__all__ = ["HttpGate", "HttpRequest", "http_request", "request_text"]


@dataclass
class HttpRequest:
    """One request to send through the gate.

    ``url`` is the only required field. The engagement's tagged user-agent and
    any program-mandated attribution headers are always applied on top of
    caller headers.
    """

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None
    content: str | None = None
    json: Any = None
    follow_redirects: bool = True
    timeout: float = 15.0
    #: Caller-supplied kwargs for httpx.AsyncClient.request (e.g. ``verify``
    #: for a deliberate proxy handoff). Everything not named above.
    extra: dict[str, Any] = field(default_factory=dict)
    #: Caller-supplied kwargs for httpx.AsyncClient itself (e.g. ``proxy``).
    #: Kept separate from ``extra`` because proxy/mounts/etc. configure the
    #: client, not the request.
    client_kwargs: dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return host_of(self.url)


class HttpGate:
    """Scope-check, rate-limit, and audit every request made to in-scope assets."""

    def __init__(self, engagement: Any = None) -> None:
        self.engagement = engagement or get_engagement()

    def _check_scope(self, request: HttpRequest) -> None:
        verdict = self.engagement.scope.check(request.url)
        if not verdict.in_scope:
            # Fail closed, exactly like the decorator: one out-of-scope URL
            # refuses the request, and the refusal is audited.
            raise OutOfScopeError(
                f"request refused: {request.url} ({verdict.reason})",
                **verdict.to_dict(),
            )

    def _base_headers(self) -> dict[str, str]:
        rules = self.engagement.scope.rules
        return {"User-Agent": rules.user_agent, **dict.fromkeys(rules.required_headers, "")}

    def _required_headers(self) -> dict[str, str]:
        """Program-mandated attribution headers, parsed from 'Name: value'."""
        out: dict[str, str] = {}
        for entry in self.engagement.scope.rules.required_headers:
            name, _, value = entry.partition(":")
            if name.strip():
                out[name.strip()] = value.strip()
        return out

    async def request(self, request: HttpRequest) -> httpx.Response:
        """Send one request through scope, rate limit, and audit."""
        self._check_scope(request)
        headers = {**self._base_headers(), **self._required_headers(), **request.headers}

        started = time.monotonic()
        outcome = "ok"
        status_code: int | None = None
        error: str | None = None
        try:
            async with self.engagement.limiter.slot(host=request.host, cost=1.0):
                async with httpx.AsyncClient(
                    timeout=request.timeout,
                    follow_redirects=request.follow_redirects,
                    headers=headers,
                    **request.client_kwargs,
                ) as client:
                    response = await client.request(
                        request.method,
                        request.url,
                        params=request.params,
                        data=request.data,
                        content=request.content,
                        json=request.json,
                        **request.extra,
                    )
            status_code = response.status_code
            return response
        except OutOfScopeError:
            raise
        except httpx.HTTPError as exc:
            outcome = "error"
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            self.engagement.audit.record(
                "http_request",
                url=request.url,
                method=request.method,
                outcome=outcome,
                status=status_code,
                duration_ms=duration_ms,
                error=error,
            )


async def http_request(request: HttpRequest) -> httpx.Response:
    """The gate: send ``request`` through scope, rate limit, and audit."""
    return await HttpGate().request(request)


async def request_text(request: HttpRequest, *, limit: int = 4 * 1024 * 1024) -> str:
    """The gate, returning response text (capped) instead of the raw response."""
    response = await http_request(request)
    return response.text[:limit]

"""Burp handoff: send requests through the operator's Burp proxy.

The classes no scanner owns — IDOR, business logic, race conditions, cache
poisoning — end in a human reading a request in Burp and deciding. This tool is
the bridge: it sends one HTTP request *through* the local Burp proxy per target,
so the traffic lands in Burp's Proxy history where the human (or a Repeater
session) can take it over. The agent gets the responses back; the human gets the
artifacts.

Deliberately a handoff, not a scanner:

* Requests pass through Burp and go nowhere else. The proxy is a local loopback
  listener, and the responses are returned to the caller as evidence.
* Every ``target`` is scope-checked exactly like any other tool — the
  decorator's scope gate runs on the list before anything is sent, so a request
  cannot be forwarded to an out-of-scope host because the caller "was just
  testing Burp".
* The tool is approval-gated (``aggressive``): it sends live requests, and
  approving a handoff is approving those requests. Its declared cost is
  derived from its own cap — one request per target, at most
  ``BURP_HANDOFF_MAX_TARGETS`` per call — the same pattern the other gated
  tools use (``oob_listener`` derives its number from its poll interval).
* Burp not running is a clean, distinct failure. The point of the tool is
  human handoff; a missing proxy means "no human", not "target down", and the
  two must not look the same.

The proxy URL is operator configuration (``tools.burp.proxy_url`` in
config.yaml, default ``http://127.0.0.1:8080``), never a caller-supplied
argument: the proxy is infrastructure the operator chose, and keeping it out of
the call prevents an agent from redirecting traffic to an arbitrary listener.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from easyhunt.control_plane.context import get_engagement
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import split_targets

log = logging.getLogger("easyhunt.tools.burp")

__all__ = ["burp_send"]

#: A handoff is a bounded batch: one request per target, at most this many per
#: call. The declared cost derives from this cap (the oob_listener pattern), so
#: the rate limiter is charged what the wrapper itself allows, not a floor of 1.
BURP_HANDOFF_MAX_TARGETS = 10
BURP_ESTIMATED_REQUESTS = BURP_HANDOFF_MAX_TARGETS

#: Methods the handoff will forward. Anything else is refused before a request
#: is built — the tool is a human's probe, not a fuzzer's carrier.
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

#: Proxy configuration is a URL; validate its shape so a typo in config.yaml
#: fails with a readable message instead of an httpx parse error.
_PROXY_URL = re.compile(r"https?://[A-Za-z0-9._:\[\]-]{1,255}")


def _proxy_config(engagement: Any) -> str:
    proxy = str(engagement.config.get("tools.burp.proxy_url", "http://127.0.0.1:8080"))
    if not _PROXY_URL.fullmatch(proxy):
        raise ValueError(
            f"config tools.burp.proxy_url is not an http(s) URL: {proxy!r}"
        )
    if urlsplit(proxy).scheme not in {"http", "https"} or not urlsplit(proxy).hostname:
        raise ValueError(f"config tools.burp.proxy_url is not an http(s) URL: {proxy!r}")
    return proxy


@easyhunt_tool(
    phase="exploit",
    mode="aggressive",
    targets_arg="target",
    timeout=120,
    name="burp_send",
    tags={"handoff", "manual"},
    estimated_requests=BURP_ESTIMATED_REQUESTS,
    risk_notes=[
        "Sends one HTTP request per target through the operator's local Burp proxy.",
        "Requests appear in Burp's Proxy history for human follow-up.",
        "Nothing is fuzzed or automated — exactly one request per target, "
        f"bounded to {BURP_HANDOFF_MAX_TARGETS} targets per call.",
    ],
    rationale=(
        "Hand requests to the human reviewer through Burp: every target is "
        "scope-checked, forwarded through the operator's local proxy so the "
        "traffic lands in Burp history, and the responses are returned. For "
        "the classes no scanner owns (IDOR, business logic, race conditions)."
    ),
    text_args=("body",),
)
async def burp_send(
    target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    """Send one HTTP request per target through the operator's Burp proxy.

    ``target`` is one or more comma-separated URLs (at most
    ``BURP_HANDOFF_MAX_TARGETS``); every one is scope-checked before anything
    is sent. ``method`` is one of GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS.
    ``headers`` overrides the default tagged User-Agent; ``body`` is the
    request body for POST/PUT/PATCH.

    Each request goes through the local Burp proxy (``tools.burp.proxy_url``
    in config.yaml), lands in Burp's history, and the responses are returned so
    the caller can attach them to leads. If Burp is not listening the call
    fails with ``burp_not_running`` — start Burp and retry.

    This is a human-handoff primitive, not a scanner: one request per target,
    nothing automated, and the classes it serves (IDOR, business logic, race
    conditions, cache poisoning) are exactly the ones that end in a human
    reading a request.
    """
    engagement = get_engagement()
    targets = split_targets(target)
    if not targets:
        return {"ok": False, "error": "no_target", "message": "no target supplied"}
    if len(targets) > BURP_HANDOFF_MAX_TARGETS:
        return {
            "ok": False,
            "error": "too_many_targets",
            "message": (
                f"burp_send hands off at most {BURP_HANDOFF_MAX_TARGETS} targets "
                f"per call (got {len(targets)}) — split the batch."
            ),
        }
    method = (method or "GET").strip().upper()
    if method not in _METHODS:
        return {
            "ok": False,
            "error": "bad_method",
            "message": f"method {method!r} not forwarded; use one of {sorted(_METHODS)}",
        }

    proxy = _proxy_config(engagement)

    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", engagement.scope.rules.user_agent)
    if body is not None and "Content-Type" not in request_headers:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Burp's MITM certificate is self-signed by design; verifying against the
    # system store would reject every proxied TLS connection. The proxy is a
    # local loopback listener the operator configured, so this is the one place
    # verification is disabled deliberately.
    results: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            # httpx >= 0.28: a single proxy URL applies to every scheme; the
            # dict form was removed. Burp terminates TLS itself, so verification
            # against the system store would reject every proxied connection —
            # its CA is the configured trust anchor here.
            proxy=proxy,
            verify=False,  # noqa: S501 — Burp's CA is the configured trust anchor
            timeout=60.0,
        ) as client:
            for url in targets:
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    results.append(
                        {
                            "target": url,
                            "ok": False,
                            "error": "bad_target",
                            "message": f"{url!r} is not an absolute http(s) URL",
                        }
                    )
                    continue
                try:
                    response = await client.request(
                        method, url, headers=request_headers, content=body
                    )
                except httpx.ConnectError:
                    return {
                        "ok": False,
                        "error": "burp_not_running",
                        "message": (
                            f"no proxy listening at {proxy}. Burp is the handoff "
                            "target — start it (Proxy → Options → listen on "
                            "127.0.0.1:8080, or set tools.burp.proxy_url in "
                            "config.yaml) and retry."
                        ),
                    }
                except httpx.HTTPError as exc:
                    log.debug("burp handoff failed for %s: %s", url, exc)
                    results.append(
                        {
                            "target": url,
                            "ok": False,
                            "error": "proxy_error",
                            "message": f"request failed through {proxy}: {type(exc).__name__}",
                        }
                    )
                    continue
                engagement.audit.record(
                    "burp_handoff", url=url, method=method,
                    proxy=proxy, status_code=response.status_code,
                )
                results.append(
                    {
                        "target": url,
                        "ok": True,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:100_000],
                    }
                )
    except httpx.ConnectError:
        return {
            "ok": False,
            "error": "burp_not_running",
            "message": (
                f"no proxy listening at {proxy}. Burp is the handoff target — "
                "start it (Proxy → Options → listen on 127.0.0.1:8080, or set "
                "tools.burp.proxy_url in config.yaml) and retry."
            ),
        }

    forwarded = [r for r in results if r.get("ok")]
    return {
        "ok": True,
        "count": len(results),
        "forwarded": len(forwarded),
        "method": method,
        "proxy": proxy,
        "results": results,
        "handoff": (
            "Requests forwarded through Burp — they are in Proxy history for "
            "human follow-up. The responses above are the raw artifacts; attach "
            "each to the lead it belongs to."
        ),
    }

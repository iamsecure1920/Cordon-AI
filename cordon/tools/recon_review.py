"""Recon review: which discovered hosts are worth a human's login/signup.

The recon MCP server's job is not just enumeration — it is *prioritization*.
A 60k-subdomain estate with 3k live hosts is not a work queue; it is noise
until someone separates "worth opening a browser for" from "parked domain,
error page, telemetry host".

This tool reads what recon and probing already recorded and ranks every live
host by signals a human pentester would use:

* content-length — real applications are larger than parked pages
* technology count — an app with a stack is worth more than a static page
* login/signup/auth-shaped titles, paths and technologies
* whether the host is a focus asset the program explicitly named

Nothing here sends a request: it ranks what the asset store already holds.
The result is the hand-off list for ``auth_surface`` (find the login),
``session_register`` + ``auth_crawl`` (test behind it), or a human opening
a browser.
"""

from __future__ import annotations

from typing import Any

from cordon.control_plane.context import get_engagement
from cordon.tools.base import cordon_tool
from cordon.util.parse import host_of

__all__ = ["recon_review"]

#: Title/path/tech fragments that mean "this host has an account system".
_AUTH_MARKERS = (
    "login", "signin", "sign in", "signup", "sign up", "register", "account",
    "auth", "sso", "saml", "oauth", "password", "my ", "portal", "dashboard",
    "admin", "identity", "billing", "pay", "checkout", "cart", "wallet",
)

#: Title fragments that mean "this host is not an application".
_PARKED_MARKERS = (
    "parked", "for sale", "domain is for sale", "coming soon", "under construction",
    "not found", "404", "error", "maintenance", "default page", "test page",
)


def _score(entry: dict[str, Any], *, focus_hosts: set[str]) -> tuple[int, str]:
    """Score one probed host. Higher = more worth a human's time."""
    url = str(entry.get("url") or "")
    title = str(entry.get("title") or "").lower()
    tech = [str(t).lower() for t in (entry.get("tech") or [])]
    length = int(entry.get("content_length") or 0)
    host = host_of(url)

    score = 0
    reasons: list[str] = []

    if host in focus_hosts:
        score += 30
        reasons.append("program focus asset")

    if title and not any(m in title for m in _PARKED_MARKERS):
        score += 5
    if length > 100_000:
        score += 8
        reasons.append(f"large content ({length // 1000}k)")
    elif length > 10_000:
        score += 3
    elif length < 1000:
        score -= 5
        reasons.append("thin page (parked/error?)")

    if len(tech) >= 3:
        score += 5
        reasons.append(f"real stack ({', '.join(tech[:3])})")
    for t in tech:
        if "akamai" in t or "cloudflare" in t:
            continue
        score += 1

    auth_hits = [m for m in _AUTH_MARKERS if m in title or any(m in t for t in tech)]
    if auth_hits:
        score += 12
        reasons.append(f"auth surface ({', '.join(auth_hits[:3])})")

    status = entry.get("status")
    if status == 401 or status == 403:
        score += 6
        reasons.append(f"HTTP {status} (access control exists)")
    elif status and status >= 400:
        score -= 4
        reasons.append(f"HTTP {status}")

    return score, "; ".join(reasons)


@cordon_tool(
    phase="http_probe",
    mode="passive",
    targets_arg=None,
    timeout=60,
    name="recon_review",
    tags={"recon", "prioritization"},
    estimated_requests=0,
    budget_exempt=True,
)
async def recon_review(limit: int = 40) -> dict[str, Any]:
    """Rank live hosts by how worth they are of manual testing.

    Reads the asset store (probe results + scope focus URLs) and returns the
    top ``limit`` hosts with scores and the reasons behind each. Zero traffic.
    The top of the list is the hand-off for ``auth_surface`` (find the login)
    and ``auth_crawl``/``authz_compare`` (test behind it).
    """
    engagement = get_engagement()

    focus_hosts: set[str] = set()
    for host, _path in getattr(engagement.scope, "_allow", None).urls or []:
        if host:
            focus_hosts.add(host.lower())

    ranked: list[dict[str, Any]] = []
    for asset in engagement.assets.all():
        if asset.kind != "url" or "live" not in asset.tags:
            continue
        entry = {
            "url": asset.value,
            "host": asset.host or host_of(asset.value),
            "title": asset.attributes.get("title"),
            "tech": asset.attributes.get("tech") or [],
            "content_length": asset.attributes.get("content_length"),
            "status": asset.attributes.get("status"),
        }
        # The asset store carries the probe scalars only when http_probe wrote
        # them into attributes; older workspaces stored them in phase files.
        # Fall back to what the asset itself has.
        score, reasons = _score(entry, focus_hosts=focus_hosts)
        ranked.append({**entry, "score": score, "why": reasons})

    ranked.sort(key=lambda e: (-e["score"], str(e["host"])))
    top = ranked[: max(1, min(limit, 200))]

    weak = [e for e in ranked if e["score"] <= 0]
    return {
        "ok": True,
        "reviewed": len(ranked),
        "top": top,
        "count": len(top),
        "weak_or_parked": len(weak),
        "focus_assets": sorted(focus_hosts),
        "next_step": (
            "Run auth_surface on the top hosts to find login/signup forms, then "
            "register sessions (session_register) and test behind them with "
            "auth_crawl + authz_compare."
        ),
        "note": (
            "Scores are heuristics over probe data, not findings. A high score "
            "means 'worth a human's time', not 'vulnerable'."
        ),
    }

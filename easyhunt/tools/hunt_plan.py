"""Turn recon output into specific tests worth running.

The gap this fills. EasyHunt drives 81 scanners well and finds almost nothing on
mature targets, because scanners detect *known* CVEs and misconfigurations and a
mature program fixed those years ago. The bugs that pay — IDOR, broken access
control, business logic, auth bypass — are found by understanding an application,
not by firing templates at it.

That understanding is the one thing a model is better at than any scanner, and
until now the model was only used for triage: deciding whether a scanner's guess
was real. That is the commodity half of the work.

This reads what recon actually found — endpoints, parameters, technologies, live
URLs, JS-derived paths — and asks for concrete, testable propositions. It is
deliberately *not* a finding generator:

* It emits **tests to run**, never findings. Nothing it returns is evidence.
* Every proposal names the observation that motivated it, so an operator can
  tell an inference from a guess.
* It sends no traffic. It reads the asset store and returns text.

`Finding.confirm()` still requires a reproducible PoC, and nothing here can
produce one. This is the step *before* hunting, not a substitute for it.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.tools.base import easyhunt_tool

__all__ = ["hunt_plan"]

#: Categories worth proposing, and the reason each is worth a model's attention
#: rather than a scanner's. Kept in the prompt so proposals stay in the space
#: where automation is weakest.
_FOCUS = """\
- Broken access control / IDOR: object references in paths or parameters that
  look guessable, sequential, or user-scoped.
- Authentication and session flow: login, reset, MFA, SSO callbacks, anything
  that mints or accepts a token.
- Business logic: multi-step flows where a step could be skipped, repeated,
  reordered, or performed with someone else's identifier.
- Server-side request handling: parameters that take a URL, a path, a filename,
  a template, or a redirect destination.
- Trust boundaries between components: an internal hostname, an API that a
  front-end calls, a service that assumes the caller is the app.
"""

_SYSTEM = """\
You are helping a security researcher decide what to test on an authorized \
bug bounty target. You are given only what reconnaissance observed.

Rules you must follow:
- Propose TESTS, never findings. You have no evidence of any vulnerability.
- Every proposal must cite the specific observation that motivated it. If you
  cannot point at something in the input, do not propose it.
- Prefer classes automated scanners miss. Do not propose "run nuclei", "check
  for missing security headers", "test for outdated libraries" or anything a
  template already covers.
- Be concrete: name the endpoint or parameter, say what to change, and say what
  result would indicate a real problem versus normal behaviour.
- If the input is too thin to justify anything, say so. An honest "not enough
  surface here" is more useful than five generic suggestions.

Return JSON: {"proposals": [{"title": str, "category": str, "target": str,
"observation": str, "test": str, "signal_of_a_real_issue": str,
"confidence": "low"|"medium"|"high"}], "gaps": [str]}

"gaps" lists what you would need to see to say more — a logged-in session, the
JS bundle for a specific route, the API schema.

If the input contains an "authenticated" section, treat it as the primary
surface. Those URLs were visible only to a logged-in user, and
"reference_candidates_unfetched" names objects the application disclosed that
nobody has read — the strongest access-control leads available. Anything under
the top-level "live_urls" was seen without a session and is public.
"""


#: Path segments and parameter names that suggest an object reference — the
#: shape of an IDOR before anyone has tested anything. Numeric and UUID-like
#: values are the classic tell; so are names that scope a resource to a user.
_REF_HINT = re.compile(
    r"(?i)(/\d{2,}(?:/|$)|[0-9a-f]{8}-[0-9a-f]{4}-|"
    r"[?&](id|uid|user|user_id|account|customer|order|invoice|doc|file|"
    r"ref|token|key|session|profile|member|tenant|org)=)"
)

#: Parameters worth a second look because of what the server does with them.
_SINK_HINT = re.compile(
    r"(?i)[?&](url|uri|next|redirect|redirect_uri|return|returnTo|continue|dest|"
    r"destination|target|link|src|path|file|filename|template|page|view|"
    r"callback|domain|host|feed|image|img|load|resource)="
)


def _safe_split(url: str) -> Any | None:
    """urlsplit without the crash on non-URL scraps.

    The surface feeds this parser a deliberately mixed bag: live URLs, archived
    URLs, and endpoints scraped out of JavaScript bundles. JS scraping returns
    whatever looked link-like, which is not always a URL — an XPath selector
    (``//*[@id='...']``) is one real example. urlsplit raises ``ValueError:
    Invalid IPv6 URL`` on those bracket-heavy scraps because it reads the ``[``
    as a malformed IPv6 literal. One junk endpoint must not take down the whole
    planning phase; skip what does not parse.
    """
    try:
        return urlsplit(url)
    except ValueError:
        return None


def _interesting(urls: list[str]) -> dict[str, list[str]]:
    """Group URLs by why they are worth a human's attention.

    Scanners already cover known CVEs. What they do not do is notice that a
    parameter is named `redirect_uri`, or that a path ends in a six-digit
    number. Surfacing those groups is what turns a list of 2,700 URLs into a
    short list of things to actually try.
    """
    refs = sorted({u for u in urls if _REF_HINT.search(u)})
    sinks = sorted({u for u in urls if _SINK_HINT.search(u)})
    params: set[str] = set()
    for url in urls:
        parsed = _safe_split(url)
        if parsed is None:
            continue
        params.update(k for k, _ in parse_qsl(parsed.query))
    return {
        "object_reference_candidates": refs[:60],
        "server_side_sink_candidates": sinks[:60],
        "distinct_parameter_names": sorted(params)[:120],
    }


def _surface(engagement: Any, limit: int) -> dict[str, Any]:
    """The observed attack surface, grouped so it can be reasoned over.

    Deliberately more than a dump. 2,747 URLs is not a surface anyone can hold
    in mind; the same 2,747 split into "these carry object references", "these
    take a URL or a path", and "here is every distinct parameter name" is.

    Authenticated URLs are kept in their own group rather than merged into the
    pile. The whole reason 36% of WSTG was unreachable is that the valuable
    categories live behind a login, so "this URL was only visible to a logged-in
    user" is the single most important fact about a URL — and averaging it into
    a list of 2,700 anonymous ones throws that fact away.
    """
    assets = engagement.assets
    live = assets.values("url", tag="live")
    archived = assets.values("url", tag="archived")
    endpoints = assets.values("endpoint")
    authed = assets.values("url", tag="authenticated")
    # Anonymous means "seen without a session", not "seen and not authenticated".
    anonymous = [u for u in live if u not in set(authed)]
    identities = engagement.sessions.counts()
    # Candidates alone are enough to warrant the section. The session store is
    # per-process and a crawl in an earlier phase may have left references
    # behind with no live session in this one — the references are still the
    # sharpest thing here and must not vanish with the session that found them.
    candidates = assets.values("object_reference")

    surface: dict[str, Any] = {
        "live_urls": anonymous[:limit],
        "endpoints_from_js": endpoints[:limit],
        "archived_urls": archived[:limit],
        "subdomains": assets.values("subdomain")[:limit],
        "technologies": assets.values("technology")[:50],
        "asset_counts": assets.counts(),
        # The part a scanner will not tell you.
        "worth_a_look": _interesting(anonymous + archived + endpoints),
    }

    if authed or identities or candidates:
        surface["authenticated"] = {
            "urls": authed[:limit],
            "identities": identities,
            "worth_a_look": _interesting(authed),
            # Named by the application and deliberately never fetched by
            # auth_crawl, because reading another user's record is the test
            # rather than the crawl. These are the sharpest access-control
            # targets in the whole surface: the app said they exist and nobody
            # has looked.
            "reference_candidates_unfetched": candidates[:limit],
        }
    return surface


def _gaps(surface: dict[str, Any]) -> list[str]:
    """What is missing before anything sharper can be said.

    The most useful output on a mature target, and the one a scanner never
    produces. The categories that pay — IDOR, access control, business logic —
    are almost entirely post-login, so saying "there is no session here" is more
    honest than proposing five tests against a marketing page.

    It has to track what has actually been done, though. Telling an operator to
    capture a session they already captured is the advice being wrong rather
    than the target being thin, and the next gap is a different one: one
    identity proves an application works, two prove it distinguishes callers.
    """
    gaps: list[str] = []
    look = surface.get("worth_a_look", {})
    authed = surface.get("authenticated") or {}
    identities = authed.get("identities") or {}

    if not authed:
        gaps.append(
            "Nothing authenticated. IDOR, access control and business logic are all "
            "post-login, which is 42 of 115 WSTG tests — run auth_surface to find "
            "where to register, then session_register and auth_crawl."
        )
    elif len(identities) < 2:
        gaps.append(
            f"Only {len(identities)} identity registered ({', '.join(identities) or 'none'}). "
            "One account proves the application works; authorization testing needs a "
            "second of different privilege so authz_compare has something to compare."
        )
    elif not authed.get("reference_candidates_unfetched") and not authed["worth_a_look"].get(
        "object_reference_candidates"
    ):
        gaps.append(
            "Two identities registered but no object references found behind the login. "
            "authz_compare needs a URL naming something one user owns — crawl deeper, "
            "or look for an API the pages call rather than link to."
        )

    if not look.get("object_reference_candidates") and not authed:
        gaps.append(
            "No object references observed. IDOR and access-control testing needs "
            "authenticated URLs — capture a logged-in session and re-run recon."
        )
    if not surface.get("endpoints_from_js"):
        gaps.append(
            "No JS-derived endpoints. Run js_analyze against live URLs; bundles "
            "usually name API routes that are not linked anywhere."
        )
    if not look.get("distinct_parameter_names"):
        gaps.append(
            "No parameters seen at all. Without input to manipulate there is "
            "nothing to test beyond configuration."
        )
    if len(surface.get("subdomains") or []) < 2:
        gaps.append(
            "One host only. Trust boundaries between components are where access "
            "control tends to fail; a broader surface gives more to compare."
        )
    return gaps


def _actionable_authenticated(surface: dict[str, Any]) -> int:
    """How much post-login surface this engagement holds."""
    authed = surface.get("authenticated") or {}
    return (
        len(authed.get("urls") or [])
        + len(authed.get("reference_candidates_unfetched") or [])
        + sum(
            len(v) for v in (authed.get("worth_a_look") or {}).values()
            if isinstance(v, list)
        )
    )


def _actionable(surface: dict[str, Any]) -> int:
    """Things an agent can act on. Authenticated ones count too, or a run that
    found only post-login surface reports itself as having produced nothing."""
    return (
        sum(len(v) for v in surface["worth_a_look"].values() if isinstance(v, list))
        + _actionable_authenticated(surface)
    )


def _instructions(surface: dict[str, Any]) -> str:
    """How the calling agent should read this surface.

    EasyHunt's L5 strategy layer is a model — the Claude CLI driving these tools
    — so handing it the grouped surface is the intended route, not a fallback.
    """
    base = (
        "No internal LLM is configured, so the surface is returned for the calling "
        "agent to reason over directly. Work through `worth_a_look`: "
        "object_reference_candidates are IDOR shapes, server_side_sink_candidates "
        "are parameters the server acts on (SSRF, open redirect, path traversal, "
        "SSTI), and distinct_parameter_names is the vocabulary this application "
        "uses. Propose specific tests naming the endpoint, the parameter, what to "
        "change, and what result would distinguish a real issue from normal "
        "behaviour. Nothing here is evidence — a finding still needs a reproducible "
        "PoC."
    )
    authed = surface.get("authenticated")
    if not authed:
        return base
    return (
        "Start with `authenticated`, not `worth_a_look`. Those URLs were only "
        "visible to a logged-in user, which is the surface every scanner in this "
        "toolchain has been blind to and where the categories that pay actually "
        "live. `reference_candidates_unfetched` is the sharpest list here: the "
        "application named those objects and auth_crawl deliberately did not read "
        "them, because reading someone else's record is the test rather than the "
        "crawl. Point authz_compare at them with two identities. Then: " + base
    )


def _enrich(proposals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach the matching technique (tool + payload + gf) to each proposal.

    The technique index answers "how" — which EasyHunt tool tests the class a
    proposal names, and which vetted payload list and gf pack belong to it. This
    is deterministic retrieval, not a second LLM call: each proposal's category
    and title are searched against the index and the best match's wiring is
    copied onto the proposal, so a plan reads "test X with tool Y using list Z"
    instead of stopping at "try X".
    """
    from easyhunt.knowledge.techniques import load_index

    index = load_index()
    if not index.available:
        return proposals
    enriched: list[dict[str, Any]] = []
    for proposal in proposals:
        query = " ".join(
            str(proposal.get(k, "") or "") for k in ("category", "title")
        ).strip()
        matches = index.search(query, limit=1) if query else []
        if not matches:
            enriched.append(proposal)
            continue
        tech = matches[0]
        out = dict(proposal)
        out["technique"] = {
            "class": tech["class"],
            "title": tech["title"],
            "tools": tech.get("tools", []),
            "payloads": tech.get("payloads", []),
            "gf": tech.get("gf", []),
        }
        enriched.append(out)
    return enriched


@easyhunt_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=180,
    name="hunt_plan",
    tags={"strategy", "llm"},
    estimated_requests=0,
    rationale="Read the observed surface and propose specific tests worth running.",
)
async def hunt_plan(focus: str | None = None, limit: int = 120) -> dict[str, Any]:
    """Propose concrete tests based on what recon actually observed.

    Sends no traffic. Reads the engagement's asset store and returns testable
    propositions, each citing the observation behind it.

    ``focus`` optionally narrows the request ("authentication", "idor",
    "business logic"). Leave it unset for a general pass.

    Returns ``proposals`` — things to try — and ``gaps``, which is the more
    valuable half: what the model would need in order to say anything sharper.
    On a target where everything interesting sits behind a login, ``gaps`` will
    say so, and that is the honest answer rather than five generic suggestions.
    """
    engagement = get_engagement()
    surface = _surface(engagement, limit)

    # Count the authenticated surface too. It is a nested dict rather than a
    # top-level list, and a sum over top-level lists only reported "the asset
    # store is empty" on a run holding three authenticated URLs and twenty-three
    # object-reference candidates — the most valuable surface this tool has ever
    # been handed, discarded by an emptiness check that could not see it.
    observed = sum(
        len(v) for k, v in surface.items() if isinstance(v, list) and k != "technologies"
    ) + _actionable_authenticated(surface)
    if observed == 0:
        return {
            "ok": False,
            "error": "no_surface",
            "message": (
                "The asset store is empty, so there is nothing to reason about. "
                "Run recon and http_probe first — this reads what they found, it "
                "does not discover anything itself."
            ),
            "proposals": [],
            "gaps": ["any observed endpoint, parameter or live host"],
        }

    from easyhunt.llm.openrouter import LLMClient

    client = LLMClient(engagement)
    if not client.enabled:
        # Not a degraded path. EasyHunt's L5 strategy layer IS a model — the
        # Claude CLI driving these tools — and handing it the grouped surface is
        # the intended route, not a consolation prize. The OpenRouter client
        # exists for unattended runs where no agent is present.
        return {
            "ok": True,
            "mode": "agent",
            "surface": surface,
            "proposals": [],
            "instructions": _instructions(surface),
            "gaps": _gaps(surface),
            # What this phase actually produced. In agent mode the SURFACE is
            # the output — there are no proposals because no internal model was
            # asked for any — so counting proposals would report a working phase
            # as empty. Count the things an agent can act on.
            "actionable": _actionable(surface),
        }

    ask = f"Focus on: {focus}\n\n" if focus else ""
    response = await client.complete(
        [
            {"role": "system", "content": _SYSTEM + "\nCategories:\n" + _FOCUS},
            {
                "role": "user",
                "content": (
                    f"{ask}Observed attack surface for an authorized engagement:\n\n"
                    + json.dumps(surface, indent=2)[:24000]
                ),
            },
        ],
        tier="t2",
        phase="method",
        purpose="hunt_plan",
        json_mode=True,
        temperature=0.3,
    )

    try:
        parsed = json.loads(response.text)
    except (json.JSONDecodeError, AttributeError):
        return {
            "ok": False,
            "error": "unparseable_response",
            "message": "The model did not return usable JSON; nothing is inferred from that.",
            "raw": str(getattr(response, "text", ""))[:1500],
            "proposals": [],
        }

    proposals = parsed.get("proposals") or []
    # A proposal with no observation behind it is a guess wearing a citation.
    grounded = [p for p in proposals if str(p.get("observation", "")).strip()]
    # Each proposal carries its technique wiring (tool + payload + gf) from the
    # technique index, so the plan names the "how" as well as the "what".
    grounded = _enrich(grounded)

    return {
        "ok": True,
        "mode": "llm",
        "actionable": len(grounded),
        "authenticated_surface": bool(surface.get("authenticated")),
        "proposals": grounded,
        "dropped_ungrounded": len(proposals) - len(grounded),
        "gaps": parsed.get("gaps") or [],
        "surface_summary": surface["asset_counts"],
        "cost_usd": getattr(response, "cost_usd", None),
        "note": (
            "These are TESTS TO RUN, not findings. Nothing here is evidence, and "
            "nothing here has touched the target. Every finding still needs a "
            "reproducible PoC before it can be confirmed. Each proposal's "
            "`technique` field names the EasyHunt tool, vetted payload list and "
            "gf pack that correspond to it."
        ),
    }

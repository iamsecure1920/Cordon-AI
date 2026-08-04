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
from typing import Any

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
"""


def _surface(engagement: Any, limit: int) -> dict[str, Any]:
    """The observed attack surface, compressed enough to reason over."""
    assets = engagement.assets
    return {
        "live_urls": assets.values("url", tag="live")[:limit],
        "endpoints_from_js": assets.values("endpoint")[:limit],
        "archived_urls": assets.values("url", tag="archived")[:limit],
        "subdomains": assets.values("subdomain")[:limit],
        "technologies": assets.values("technology")[:50],
        "asset_counts": assets.counts(),
    }


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

    observed = sum(
        len(v) for k, v in surface.items() if isinstance(v, list) and k != "technologies"
    )
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
        return {
            "ok": False,
            "error": "llm_disabled",
            "message": (
                "No LLM configured (set OPENROUTER_API_KEY). The observed surface "
                "is returned below so it can be reasoned about by hand — that is "
                "the same input the model would have received."
            ),
            "surface": surface,
            "proposals": [],
            "gaps": [],
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

    return {
        "ok": True,
        "proposals": grounded,
        "dropped_ungrounded": len(proposals) - len(grounded),
        "gaps": parsed.get("gaps") or [],
        "surface_summary": surface["asset_counts"],
        "cost_usd": getattr(response, "cost_usd", None),
        "note": (
            "These are TESTS TO RUN, not findings. Nothing here is evidence, and "
            "nothing here has touched the target. Every finding still needs a "
            "reproducible PoC before it can be confirmed."
        ),
    }

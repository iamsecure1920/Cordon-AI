"""Where the login is, and which host is worth having an account on.

The session primitive made authenticated testing *possible*; this makes it
actionable. Holding two sessions is only useful once someone knows which of 200
subdomains has a registration form and is an application rather than a
marketing page — and on a real estate that is not a question anybody wants to
answer by hand.

So this reads the surface already discovered, fetches a small bounded set of
well-known auth paths, and reports two things:

**What authentication exists** — signup, login, password reset, MFA, OAuth/SSO,
API tokens. That is WSTG's Identity Management and Authentication categories
becoming visible instead of theoretical.

**Which hosts are worth an account.** Ranked, with the evidence for each rank,
because the operator is the one who has to go and register. A tool that says
"try these 200 hosts" has not helped.

What it deliberately does not do
--------------------------------
It does not create accounts, submit forms, or send credentials. Every request
is a GET. Self-registration is a policy question — of four programs read during
this project two permitted it and two were silent, and silence is not
permission — so the workflow ends with a recommendation to a human, who
registers by hand and brings the session back via ``session_register``.

It is also not content discovery. The path list is short, fixed, and made of
conventional endpoints; it exists to answer "is there a login here", not to
enumerate the application. Anything larger belongs in ``content_discovery``,
which is aggressive and gated accordingly.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import targets_or_assets

__all__ = ["auth_surface"]

#: Conventional auth endpoints. Short and fixed on purpose — this answers
#: "is there a login here", not "what does this application contain".
_PROBE_PATHS: tuple[str, ...] = (
    "/",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/account/login",
    "/users/sign_in",
    "/password/reset",
    "/.well-known/openid-configuration",
)

#: Signals, each with the weight it contributes and why it matters.
#:
#: Registration outranks everything: a login form on a host whose accounts are
#: provisioned by an administrator is a door the operator cannot open, and the
#: whole point of the ranking is to find doors that can be opened legitimately.
_SIGNALS: dict[str, tuple[int, str]] = {
    "registration": (5, "self-service signup — an account can be obtained legitimately"),
    "password_login": (3, "a password form, so there is a session to capture"),
    "oauth": (2, "OAuth/OIDC — token handling, redirect_uri, scope confusion"),
    "password_reset": (2, "reset flow — token entropy, user enumeration, account takeover"),
    "mfa": (2, "MFA present — bypass and enrolment logic are high-value"),
    "session_cookie": (2, "the server issues sessions, so state is tracked per user"),
    "api_auth": (1, "bearer/API-key auth — an API surface behind the same identity"),
}

_PATTERNS: dict[str, re.Pattern[str]] = {
    # Two password inputs, or a password input next to a confirmation field, is
    # a registration form rather than a login form.
    "registration": re.compile(
        r"""(?ix)
        (?:type=["']password["'][^>]*>.{0,800}?type=["']password["'])
        | (?:confirm[_\-\s]*password|password[_\-\s]*confirmation|repeat[_\-\s]*password)
        | (?:href=["'][^"']*/(?:sign[_\-]?up|register|join|create[_\-]?account)\b)
        | (?:\b(?:create|open)\s+(?:an?\s+)?account\b)
        """,
        re.DOTALL,
    ),
    "password_login": re.compile(r"""(?i)type=["']password["']"""),
    "oauth": re.compile(
        r"""(?i)(?:/oauth2?/authorize|/\.well-known/openid-configuration
            |response_type=|client_id=|"authorization_endpoint"
            |sign\s*in\s*with\s*(?:google|github|microsoft|apple|okta|sso))""",
        re.VERBOSE,
    ),
    "password_reset": re.compile(
        r"""(?i)(?:forgot[_\-\s]*password|reset[_\-\s]*password|/password/reset
            |can'?t\s+(?:log|sign)\s*in)""",
        re.VERBOSE,
    ),
    "mfa": re.compile(
        r"""(?i)(?:two[_\-\s]*factor|\bmfa\b|\b2fa\b|one[_\-\s]*time[_\-\s]*(?:code|password)
            |authenticator\s+app|verification\s+code)""",
        re.VERBOSE,
    ),
}

#: A single-page application serves the same shell for every path, and that
#: shell contains no forms — the login is a client-side route rendered by a
#: bundle. Reading only the HTML of an SPA and concluding "no authentication
#: surface" is wrong about most modern applications, and it is wrong in the
#: dangerous direction: it looks like a clean answer.
#:
#: Caught immediately on the first live run of this tool, against a target whose
#: entire purpose is having a login.
_SPA_SHELL = re.compile(
    r"""(?i)(?:<app-root|<div\s+id=["'](?:root|app|__next)["']
        |ng-version=|__NUXT__|__NEXT_DATA__|data-reactroot)""",
    re.VERBOSE,
)

#: Same-origin bundles referenced by a shell. The auth routes are in here.
_SCRIPT_SRC = re.compile(r"""(?i)<script[^>]+src=["']([^"']+)["']""")

#: A minified bundle is not HTML and must not be read as if it were. Searching
#: a compiled Angular bundle for ``type="password"`` finds nothing, and
#: searching it for the word "register" finds ``registerOnChange`` 14 times —
#: a false negative and a false positive from the same mistake.
#:
#: What a bundle does contain, reliably, is its route table. ``path:"login"``
#: and ``path:"register"`` are declarations, not incidental substrings, and they
#: describe the application's own view of itself.
_ROUTE = re.compile(r"""(?:\bpath\s*[:=]\s*|['"]route['"]\s*:\s*)["']([^"']{0,64})["']""")

#: What a route may look like. Deliberately narrow.
_ROUTE_SHAPE = re.compile(r"^/?[A-Za-z0-9][A-Za-z0-9/_:.-]{1,47}$")

_JS_PATTERNS: dict[str, re.Pattern[str]] = {
    "registration": re.compile(
        r"""(?ix)
        (?:\b(?:repeat|confirm|verify)Password\b)
        | (?:\bpassword(?:Repeat|Confirmation|Confirm)\b)
        | (?:\bpassword_confirmation\b)
        """
    ),
    "password_login": re.compile(
        r"""(?ix) (?:type\s*:\s*["']password["']) | (?:["']currentPassword["'])"""
    ),
    "password_reset": re.compile(r"""(?ix)\b(?:forgot|reset)[_\-]?password\b"""),
    "mfa": re.compile(
        r"""(?ix)\b(?:twoFactor|two_factor|totpSecret|otpToken|2fa/[a-z]+)\b"""
    ),
}

#: Route names that mean a particular kind of page exists.
_ROUTE_SIGNALS: dict[str, re.Pattern[str]] = {
    "registration": re.compile(r"""(?i)^/?(?:auth/|account/|user/)?(?:register|sign[_-]?up|signup|join|create[_-]?account)/?$"""),
    "password_login": re.compile(r"""(?i)^/?(?:auth/|account/|user/)?(?:login|sign[_-]?in|signin)/?$"""),
    "password_reset": re.compile(r"""(?i)^/?(?:auth/|account/|user/)?(?:forgot|reset|recover)[_-]?password/?$"""),
    "mfa": re.compile(r"""(?i)^/?(?:auth/)?(?:2fa|mfa|totp|two[_-]?factor)(?:/.*)?$"""),
    "oauth": re.compile(r"""(?i)^/?(?:oauth2?|sso|saml)(?:/.*)?$"""),
}

#: Routes worth testing first once a session exists. Two kinds: pages that
#: should be unreachable for an ordinary user, and pages that return a
#: user-scoped object — which is precisely what `authz_compare` needs, because
#: an IDOR test has to be pointed at something somebody owns.
_PRIVILEGED_ROUTE = re.compile(
    r"""(?ix) ^/?(?:.*/)?(?:admin(?:istration)?|accounting|billing|invoices?|
        internal|staff|manage(?:ment)?|console|dashboard|settings|users?|
        finance|audit|report(?:s|ing)?)(?:/.*)?$"""
)
_OWNED_OBJECT_ROUTE = re.compile(
    r"""(?ix) ^/?(?:.*/)?(?:order[_-]?(?:history|summary|completion)?|basket|cart|
        wallet|payment[s]?|saved[_-].*|address(?:es)?|profile|account|
        data[_-]export|subscription[s]?|invoice[s]?)(?:/.*)?$
        | :\w+$"""
)

#: Cookie names that indicate a real server-side session rather than analytics.
_SESSION_COOKIE = re.compile(
    r"""(?i)^(?:.*sess.*|.*auth.*|.*token.*|jwt|sid|csrftoken|xsrf-token
        |phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session)$""",
    re.VERBOSE,
)


def _routes(body: str) -> list[str]:
    """Client-side routes declared in a bundle.

    Independently useful beyond auth: a route table is the application telling
    you what it is for. `/order-history`, `/address/saved`, `/data-export` say
    more about where the interesting logic lives than any amount of crawling
    a shell that renders nothing server-side.
    """
    out: list[str] = []
    for route in _ROUTE.findall(body[:2_000_000]):
        candidate = route.strip()
        # `path` is also an SVG attribute, a filesystem key and a local variable
        # in minified code. A route is a slug: letters, digits, slashes, dashes,
        # underscores and `:param` placeholders, and nothing else. Anything that
        # fails that is noise, and noise in this list is worse than a short list
        # because it is the part an operator is meant to read.
        if not _ROUTE_SHAPE.match(candidate):
            continue
        if candidate.startswith("http") or candidate in {"/", ""}:
            continue
        if candidate not in out:
            out.append(candidate)
    return out


def _classify(body: str, headers: Any, *, kind: str = "html") -> set[str]:
    """Which signals this one response carries.

    ``kind`` selects the pattern set. HTML markup and a minified bundle are
    different languages that happen to describe the same application, and
    reading one with the other's patterns is how this tool first reported "no
    authentication surface" about a target built entirely around a login.
    """
    found: set[str] = set()
    sample = body[:400_000]
    patterns = _JS_PATTERNS if kind == "js" else _PATTERNS
    for name, pattern in patterns.items():
        if pattern.search(sample):
            found.add(name)
    if kind == "js":
        for route in _routes(body):
            for name, matcher in _ROUTE_SIGNALS.items():
                if matcher.match(route):
                    found.add(name)
    # OAuth reads the same in both languages: an endpoint name or a query
    # parameter, not markup.
    if _PATTERNS["oauth"].search(sample):
        found.add("oauth")

    for value in _header_values(headers, "set-cookie"):
        cookie_name = value.split("=", 1)[0].strip()
        if _SESSION_COOKIE.match(cookie_name):
            found.add("session_cookie")
            break

    for value in _header_values(headers, "www-authenticate"):
        if value:
            found.add("api_auth")
    if re.search(r"""(?i)(?:authorization:\s*bearer|["']?api[_\-]?key["']?\s*[:=])""", sample):
        found.add("api_auth")

    # A login form is implied by a registration form, but not the reverse. Do
    # not let the stronger signal hide the weaker one from the report.
    if "registration" in found:
        found.add("password_login")
    return found


def _header_values(headers: Any, name: str) -> list[str]:
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        return list(getter(name))
    value = headers.get(name) if hasattr(headers, "get") else None
    return [value] if value else []


def _bundle_urls(body: str, base: str, limit: int = 4) -> list[str]:
    """Same-origin script bundles referenced by an SPA shell.

    Same-origin only: a CDN or analytics script is not this application's code,
    and fetching third-party hosts would put traffic on assets the scope never
    authorized.
    """
    out: list[str] = []
    for src in _SCRIPT_SRC.findall(body[:200_000]):
        if src.startswith(("http://", "https://")):
            if not src.startswith(base):
                continue
            url = src
        elif src.startswith("//"):
            continue
        else:
            url = f"{base}/{src.lstrip('/')}"
        if url not in out:
            out.append(url)
        if len(out) >= limit:
            break
    return out


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or url).lower()


def _origin(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme or "https"
    netloc = parts.netloc or parts.path
    return f"{scheme}://{netloc}"


def _verdict(score: int, signals: set[str]) -> str:
    if "registration" in signals:
        return "register here — self-service signup, and the authenticated surface is reachable"
    if score >= 5:
        return "worth an account, but signup was not found — check for an invite or trial"
    if "password_login" in signals:
        return "login exists with no visible signup; credentials must come from the program"
    return "no authentication surface found"


@easyhunt_tool(
    phase="method",
    mode="passive",
    targets_arg="target",
    timeout=600,
    name="auth_surface",
    tags={"auth", "identity", "session"},
    # One GET per path per host. Declared honestly so the limiter charges for
    # what this actually costs rather than the floor of 1.
    estimated_requests=len(_PROBE_PATHS) * 25,
    rationale="Find the login, and rank which hosts are worth having an account on.",
)
async def auth_surface(
    target: str, max_hosts: int = 25, timeout: int = 15
) -> dict[str, Any]:
    """Detect authentication functionality and rank hosts by account-worthiness.

    ``target`` takes one host or a comma-separated list — normally the live
    URLs `http_probe` found, which is how `scripts/hunt.sh` chains it. Targets
    are scope-checked before this body runs, so the list cannot be widened here.

    Every request is a GET against a conventional path. Nothing is submitted,
    no account is created, and no credential is sent. The output is a
    recommendation to a human: register on these hosts, by hand, if the
    program's rules permit it — then bring the sessions back with
    ``session_register`` and ``authz_compare`` can finally test authorization.
    """
    import httpx

    engagement = get_engagement()
    candidates, origin = targets_or_assets(target, kind="url", tool="auth_surface")
    hosts: dict[str, str] = {}
    for url in candidates:
        if not url.startswith("http"):
            url = f"https://{url}"
        hosts.setdefault(_host_of(url), _origin(url))
        if len(hosts) >= max(1, max_hosts):
            break

    if not hosts:
        return {
            "ok": False,
            "error": "no_targets",
            "message": (
                "No live URLs to examine. Run http_probe first — auth_surface reads "
                "what probing found rather than guessing hostnames."
            ),
        }

    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": engagement.scope.rules.user_agent},
    ) as client:
        for host, base in hosts.items():
            signals: set[str] = set()
            evidence: dict[str, str] = {}
            reached = 0
            errors: list[str] = []
            spa_shell = ""
            for path in _PROBE_PATHS:
                url = f"{base}{path}"
                async with engagement.limiter.slot(host=url):
                    try:
                        response = await client.get(url)
                    except httpx.HTTPError as exc:
                        errors.append(f"{path}: {type(exc).__name__}")
                        continue
                reached += 1
                if response.status_code >= 400:
                    continue
                body = response.text or ""
                if not spa_shell and _SPA_SHELL.search(body[:200_000]):
                    spa_shell = body
                for name in _classify(body, response.headers):
                    signals.add(name)
                    evidence.setdefault(name, str(response.url))

            # The shell said nothing because a shell never says anything. The
            # routes are in the bundles, so read those before concluding.
            bundles: list[str] = []
            routes: list[str] = []
            if spa_shell:
                for url in _bundle_urls(spa_shell, base):
                    async with engagement.limiter.slot(host=url):
                        try:
                            response = await client.get(url)
                        except httpx.HTTPError as exc:
                            errors.append(f"bundle: {type(exc).__name__}")
                            continue
                    if response.status_code >= 400:
                        continue
                    bundles.append(url)
                    text = response.text or ""
                    routes.extend(r for r in _routes(text) if r not in routes)
                    for name in _classify(text, response.headers, kind="js"):
                        signals.add(name)
                        evidence.setdefault(name, url)

            score = sum(_SIGNALS[s][0] for s in signals)
            # An SPA whose bundles could not be read has not been examined for
            # authentication — the only place its login exists was never opened.
            blind_spa = bool(spa_shell) and not bundles
            results.append({
                "host": host,
                "score": score,
                "signals": sorted(signals),
                "why": [f"{s}: {_SIGNALS[s][1]}" for s in sorted(signals)],
                "evidence": evidence,
                "paths_reached": reached,
                "paths_tried": len(_PROBE_PATHS),
                "spa": bool(spa_shell),
                "bundles_read": bundles,
                # The application's own map of itself. Where the logic worth
                # testing lives, once there is a session to test it with.
                "routes": routes[:80],
                # Where to point authz_compare once there are two sessions.
                "privileged_routes": [r for r in routes if _PRIVILEGED_ROUTE.match(r)][:20],
                "user_scoped_routes": [r for r in routes if _OWNED_OBJECT_ROUTE.match(r)][:20],
                # A host that answered nothing has not been shown to lack a
                # login — it has not been examined. Saying "no auth surface"
                # about an unreachable host is the same defect as calling a
                # crashed scanner a clean target.
                "examined": reached > 0 and not blind_spa,
                "errors": errors[:5],
                "verdict": (
                    "UNEXAMINED — no path responded" if not reached
                    else "UNEXAMINED — single-page app whose bundles could not be read; "
                         "its login is client-side and was never seen"
                    if blind_spa
                    else _verdict(score, signals)
                ),
            })

    results.sort(key=lambda r: (-r["score"], r["host"]))
    examined = [r for r in results if r["examined"]]
    unexamined = [r["host"] for r in results if not r["examined"]]
    registerable = [r for r in examined if "registration" in r["signals"]]
    with_login = [r for r in examined if "password_login" in r["signals"]]

    return {
        "ok": True,
        "target_origin": origin,
        "hosts_examined": len(examined),
        "hosts_unexamined": unexamined,
        "complete": not unexamined,
        "ranked": results,
        "worth_an_account": [
            {"host": r["host"], "score": r["score"], "why": r["why"],
             "signup_seen_at": r["evidence"].get("registration")}
            for r in registerable[:10]
        ],
        "has_login_no_signup": [r["host"] for r in with_login if r not in registerable][:10],
        "coverage": {
            "paths_per_host": len(_PROBE_PATHS),
            "signals_looked_for": sorted(_SIGNALS),
        },
        "next_step": _next_step(registerable, with_login, examined),
        "note": (
            "Nothing here created an account or submitted a form — every request "
            "was a GET. Registration is a decision for you: check the program's "
            "rules permit self-registration (silence is not permission), create "
            "two accounts of differing privilege by hand, then register them with "
            "session_register so authz_compare can test authorization."
        ),
    }


def _next_step(
    registerable: list[dict[str, Any]],
    with_login: list[dict[str, Any]],
    examined: list[dict[str, Any]],
) -> str:
    if registerable:
        top = ", ".join(r["host"] for r in registerable[:3])
        aim = [route for r in registerable[:3] for route in r.get("user_scoped_routes") or []]
        where = (
            f" Point it at {', '.join(aim[:3])} — those routes return something a "
            "particular user owns, which is what an access-control test needs."
            if aim else ""
        )
        return (
            f"Register two accounts by hand on {top} — a normal user and, if the "
            "application offers roles, a second of different privilege. Then "
            "session_register each one and run authz_compare." + where +
            " That is the shortest path from here to the 42 WSTG tests nothing "
            "currently covers."
        )
    if with_login:
        top = ", ".join(r["host"] for r in with_login[:3])
        return (
            f"{top} has a login but no self-service signup. Ask the program for "
            "test credentials — many provide them on request, and it is the only "
            "legitimate way into this surface."
        )
    if examined:
        return (
            "No authentication surface found on any host examined. The valuable "
            "categories — IDOR, access control, business logic — are all "
            "post-login, so this estate may simply not have much to find without "
            "credentials. Widen recon before concluding that."
        )
    return "Nothing was examined. Run http_probe and try again."

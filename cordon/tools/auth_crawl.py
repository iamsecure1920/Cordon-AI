"""Walk an application as a logged-in user.

The last missing piece of authenticated testing. `session_register` can hold an
identity and `authz_compare` can diff two of them, but neither discovers
anything — the differ can only test URLs a human typed. Everything this project
has ever scanned was the third of the surface that needs no account, and that
third is where mature programs fixed everything years ago.

This crawls the other two thirds, and hands `authz_compare` the thing it
actually needs: URLs carrying an object reference that belongs to somebody.

Three properties do the real work
---------------------------------
**The session is proven before anything is believed.** The entry point is
fetched twice — once with the session, once without — and if the two responses
match, the session is not authenticating anything. A crawl under a dead cookie
produces a perfectly ordinary list of public pages and calling that "the
authenticated surface" is a lie the rest of the pipeline would build on.

**Liveness is re-checked as it goes.** Sessions expire, and an application that
logs you out at page 40 yields 80 more pages that look fine and are anonymous.
The crawl re-tests periodically and stops the moment the session stops working,
reporting how far it got rather than what it hoped for.

**It refuses to touch anything that changes state.** GET is not a promise —
plenty of applications delete, cancel and log out on a link. Logout is the
sharpest case: following it once silently anonymises every subsequent request,
which is the previous property's failure mode arriving by our own hand. Paths
that look destructive are skipped and counted, never fetched.

**It reads the JavaScript, because on a single-page app that is the surface.**
Following ``<a href>`` on an Angular or React shell finds nothing: there are no
links, the routes are a table inside a bundle and the API calls are string
literals next to them. A link crawler pointed at such an application fetches one
document, finds no links, and reports an authenticated surface of exactly one
page — which is not a small error, it is the whole application missing. Bundles
referenced by a shell are fetched and mined for same-origin paths, and those
paths are seeded into the crawl under every guard below, counted separately so
an operator can see what came from JavaScript rather than from a link.

What it does not do
-------------------
Only read-only forms are submitted, and they are submitted with empty values —
the point is the page the form *returns*, not a state change. A form whose
method is GET is submitted; a POST form is submitted only when every field name
is a search/filter parameter and neither the action nor any field carries a
state-changing verb. Login, registration, comment, checkout and delete forms are
reported and never touched — deciding to exercise those is a human's call under
the program's rules.

A path mined out of JavaScript is still a path, and the enumerate/dereference
line holds there too: ``/api/orders`` is a route the application calls and
fetching it as ourselves is browsing, but ``/api/orders/1042`` names one
object, and that one is recorded as a candidate and never fetched.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from cordon.control_plane.context import get_engagement
from cordon.knowledge.findings import Asset
from cordon.tools.base import cordon_tool
from cordon.tools.common import split_targets

__all__ = ["auth_crawl"]

#: Never fetched. GET is not a promise that nothing changes — applications
#: delete, cancel, revoke and log out on links all the time.
#:
#: Logout is the one that matters most: following it once anonymises every
#: request after it, and the crawl then reports a public site as the
#: authenticated surface. The liveness check would eventually catch that, but
#: not stepping on the rake is better than noticing you have.
_DESTRUCTIVE = re.compile(
    r"""(?ix)
    (?:^|[/?&=_-])
    (?: log[_-]?out | sign[_-]?out | delete | destroy | remove | revoke | purge
      | deactivate | disable | cancel | terminate | unsubscribe | unlink
      | reset | wipe | clear | archive | ban | suspend | refund | withdraw )
    (?:[/?&=_-]|$)
    """
)

#: An object reference: the thing an access-control test has to point at.
#: A URL with no identifier in it belongs to everybody and proves nothing.
_NUMERIC_ID = re.compile(r"/(\d{2,})(?:/|$)")
_UUID = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", re.I
)
_ID_PARAM = re.compile(r"(?i)^(?:.*_)?(?:id|uuid|guid|ref|no|num|key|order|account|user)$")

_LINK = re.compile(r"""(?i)<a\b[^>]*?href\s*=\s*["']([^"'#]+)""")
_FORM = re.compile(r"""(?is)<form\b([^>]*)>(.*?)</form>""")
_ATTR = re.compile(r"""(?i)\b(action|method)\s*=\s*["']([^"']*)["']""")
_FIELD = re.compile(r"""(?i)<(?:input|select|textarea)\b[^>]*?\bname\s*=\s*["']([^"']+)["']""")

#: Extensions that are bytes, not application surface.
_BORING = re.compile(
    r"""(?i)\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|css|map|mp[34]|pdf|zip|gz)$"""
)

# ── Seeding the crawl from JavaScript ────────────────────────────────────────
#
# `auth_surface` already detects an SPA shell and reads its bundles, and these
# four patterns are deliberate duplicates of `_SPA_SHELL`, `_SCRIPT_SRC`,
# `_ROUTE` and `_ROUTE_SHAPE` in that module rather than imports of them. They
# are private names: importing another tool's underscore-prefixed internals
# couples two tools through an interface neither promises to keep, and the next
# person to tune auth_surface's detection for its own purposes would silently
# change what this crawler fetches while logged in. A copy that drifts is
# visible; a shared private name that drifts is not. If a third caller ever
# needs these, they belong in `cordon/tools/common.py` as a public helper.

#: A single-page app serves the same shell for every path and that shell holds
#: no links. Reading only its HTML and concluding "one page" is wrong about most
#: modern applications, and wrong in the direction that looks like a result.
_SPA_SHELL = re.compile(
    r"""(?i)(?:<app-root|<div\s+id=["'](?:root|app|__next)["']
        |ng-version=|__NUXT__|__NEXT_DATA__|data-reactroot)""",
    re.VERBOSE,
)

#: Same-origin bundles referenced by a shell. The routes and the API paths are
#: in here, and nowhere else.
_SCRIPT_SRC = re.compile(r"""(?i)<script[^>]+src\s*=\s*["']([^"']+)["']""")

#: A route table is the application's own map of itself: `path:"order-history"`
#: is a declaration, not an incidental substring.
_ROUTE = re.compile(r"""(?:\bpath\s*[:=]\s*|['"]route['"]\s*:\s*)["']([^"']{0,64})["']""")
_ROUTE_SHAPE = re.compile(r"^/?[A-Za-z0-9][A-Za-z0-9/_:.-]{1,47}$")

#: A string literal handed to something that performs a request. On a readable
#: bundle this is the direct evidence of an endpoint; on a minified Angular
#: build it usually finds nothing, because the URL is assembled from a base and
#: a constant. `_API_LITERAL` below is what catches those, and both are needed.
_JS_CALL = re.compile(
    r"""(?ix)
    (?: \bfetch \s* \(
      | \baxios \s* (?: \. \s* (?:get|post|put|patch|delete|head|options|request) )? \s* \(
      | \. \s* open \s* \( \s* ["'][A-Za-z]{3,7}["'] \s* ,
      | \b (?: \$?http | httpClient ) \s* \. \s* (?:get|post|put|patch|delete) \s* \(
    )
    \s* ["'`] ( / [^"'`\s]{0,200} | https?://[^"'`\s]{1,200} ) ["'`]
    """
)

#: A bare path literal shaped like an API route. Narrow on purpose: a bundle is
#: full of strings, and anything that is not obviously an endpoint is noise that
#: this crawler would spend authenticated requests on.
_API_LITERAL = re.compile(
    r"""(?ix)
    ["'`]
    ( / (?: api | rest | graphql | gql | v\d{1,2} | services? | internal )
        (?: / [A-Za-z0-9._~-]{1,48} ){0,8} /? )
    (?: \? [^"'`\s]{0,120} )?
    ["'`]
    """
)

#: What a mined literal must look like before it is fetched with a credential.
_PATH_OK = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9/._~%-]{0,200}$")

#: A route declared with a parameter placeholder — `/order-completion/:id`,
#: `/user/{id}`, `` `/basket/${n}` ``. There is no such URL: the literal names a
#: shape, and fetching it sends a credential at a path the application never
#: calls. Reported so the operator can see the id-bearing routes exist.
_TEMPLATE = re.compile(r"""[:{}$*]|%[sd]|<[a-z_]+>""")


def _js_routes(body: str) -> list[str]:
    """Client-side routes declared in a bundle."""
    out: list[str] = []
    for route in _ROUTE.findall(body):
        candidate = route.strip()
        # `path` is also an SVG attribute, a filesystem key and a local variable
        # in minified code. A route is a slug and nothing else; noise here is
        # paid for in authenticated requests.
        if not _ROUTE_SHAPE.match(candidate) or candidate.startswith("http"):
            continue
        if candidate in {"/", ""} or candidate in out:
            continue
        out.append(candidate)
    return out


def _js_paths(
    body: str, base: str, limit: int = 150
) -> tuple[list[tuple[str, str]], list[str]]:
    """Same-origin paths a bundle names: ``([(url, source)], templates)``.

    ``source`` is ``"endpoint"`` for a request the code makes and ``"route"``
    for a client-side route declaration. They are not the same kind of thing and
    the caller has to be able to tell them apart: an endpoint returns data, and
    a route on an SPA returns the shell no matter what it is. Endpoints are
    listed first, because the page budget is finite.

    Nothing is filtered for origin or scope here. An off-origin literal is
    returned as an absolute URL so the caller's existing checks reject it *and
    count it*; dropping it silently inside the extractor would make a bundle
    full of third-party endpoints look like a bundle with nothing in it.
    """
    sample = body[:2_000_000]
    raw: list[tuple[str, str]] = []
    for pattern in (_JS_CALL, _API_LITERAL):
        raw.extend((hit, "endpoint") for hit in pattern.findall(sample))
    raw.extend(
        (r if r.startswith("/") else f"/{r}", "route") for r in _js_routes(sample)
    )

    urls: list[tuple[str, str]] = []
    seen_urls: set[str] = set()
    templates: list[str] = []
    for literal, source in raw:
        text = literal.strip()
        if not text or len(text) > 200:
            continue
        if not text.startswith(("/", "http://", "https://")):
            continue
        path = urlsplit(text).path or "/"
        if not _PATH_OK.match(path):
            if _TEMPLATE.search(path) and text not in templates:
                templates.append(text)
            continue
        url = _canonical(urljoin(base, text))
        if url not in seen_urls:
            seen_urls.add(url)
            urls.append((url, source))
        if len(urls) >= limit:
            break
    return urls, templates


def _bundle_urls(body: str, base: str, limit: int = 6) -> list[str]:
    """Scripts referenced by a shell, absolute. Origin is the caller's to judge."""
    out: list[str] = []
    for src in _SCRIPT_SRC.findall(body[:200_000]):
        if src.lower().startswith(("data:", "javascript:")):
            continue
        url = _canonical(urljoin(base, src.strip()))
        if url not in out:
            out.append(url)
        if len(out) >= limit:
            break
    return out


def _canonical(url: str) -> str:
    """Drop the fragment; keep the query, which is where the references live."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _fingerprint(status: int, body: str) -> str:
    """Identity of a response, for telling authenticated from anonymous."""
    return f"{status}:{hashlib.sha256(body.encode('utf-8', 'replace')).hexdigest()[:16]}"


def _object_reference(url: str) -> dict[str, Any] | None:
    """The identifier this URL carries, if any, and where it sits."""
    path = urlsplit(url).path
    for pattern, kind in ((_UUID, "uuid"), (_NUMERIC_ID, "numeric")):
        match = pattern.search(path)
        if match:
            return {"where": "path", "kind": kind, "value": match.group(1)}
    for key, value in parse_qsl(urlsplit(url).query):
        if _ID_PARAM.match(key) and value:
            return {"where": "query", "kind": "parameter", "param": key, "value": value}
    return None


def _forms(body: str, base: str) -> list[dict[str, Any]]:
    """Forms on a page: reported always, submitted only when read-only."""
    out: list[dict[str, Any]] = []
    for attrs, inner in _FORM.findall(body[:400_000]):
        found = dict(_ATTR.findall(attrs))
        action = found.get("action", "")
        out.append({
            "action": urljoin(base, action) if action else base,
            "method": (found.get("method") or "GET").upper(),
            "fields": sorted(set(_FIELD.findall(inner)))[:25],
        })
        if len(out) >= 20:
            break
    return out


#: A parameter name that reads and does not write. The whitelist is the whole
#: rule for a POST form: every field must match it, or the form is refused.
#: An unrecognised field is treated as a write and skipped — fail closed.
_SEARCH_FIELD = re.compile(
    r"(?i)^(?:q|query|search|keyword|keywords|filter|filters|term|terms|text|find|s"
    r"|lookup|sort|order|dir|page|per_page|perpage|limit|offset|from|to|since|until"
    r"|facet|facets|category|categories|tag|tags|type|types|format|lang|language"
    r"|locale|ref|next|return|returnurl|url|redirect|redirect_uri|dest|path)$"
)

#: A form action that changes state is never submitted, whatever its fields.
#: Deliberately broader than _DESTRUCTIVE: a POST to /api/orders/create is a
#: write even though no word here is "logout" or "delete".
_MUTATING_ACTION = re.compile(
    r"""(?ix)
    (?: login | sign[_-]?in | sign[_-]?up | register | subscribe | unsubscribe
      | comment | reply | message | send | post | publish | upload | checkout
      | pay | purchase | buy | place | confirm | submit | agree | accept
      | reset | change | update | edit | save | create | insert | add | new
      | delete | remove | destroy | revoke | grant | ban | flag | report
      | follow | block | approve | reject )
    """
)


def _is_read_only_form(form: dict[str, Any]) -> bool:
    """Whether auth_crawl may submit this form to discover what is behind it.

    GET is submitted — the method itself is a read, and the discovery value is
    the page it returns. POST is submitted only when *every* field name matches
    the search/filter whitelist and neither the action nor any field carries a
    state-changing verb. A login form (``email``, ``password``), a comment form
    (``body``), a search form with a stray ``submit`` input — all refused, because
    a field outside the whitelist is treated as a write.
    """
    fields = form.get("fields") or []
    action = form.get("action", "")
    if _MUTATING_ACTION.search(action):
        return False
    if form.get("method") == "GET":
        return bool(fields)
    return bool(fields) and all(_SEARCH_FIELD.match(f) for f in fields)


def _form_signature(form: dict[str, Any]) -> str:
    """Identity of a form for deduplication, so one search box is not re-submitted
    on every page that carries it."""
    return f"{form.get('method', 'GET')}:{form.get('action', '')}:" + ",".join(
        form.get("fields") or []
    )


def _json_refs(
    data: Any, base: str, follow: list[str], candidates: list[str], depth: int = 0
) -> None:
    """Split what an API response gives us into what may be fetched and what may not.

    A single-page app's authenticated surface is its API, and an API has no
    ``<a href>`` to follow. Without reading JSON the crawler fetches one document,
    finds no links, and reports an authenticated surface of exactly one page.

    But the two kinds of reference in a JSON body are not equivalent:

    ``follow`` — a path the response actually contains. The application handed us
    a URL; fetching it is browsing.

    ``candidates`` — an item URL *synthesised* from an id in a collection. These
    are recorded and **never fetched**, because a collection frequently lists
    objects belonging to other people. Discovered on the first live run: an
    authenticated ``/api/Users/`` returned every account on the system, and the
    crawler dutifully read thirteen other users' records. That is not discovery,
    it is the IDOR — and reading another user's data is something programs
    forbid outright and this project gates behind ``authz_compare``, with two
    identities, an approval, and a human deciding.

    Enumerate the reference; do not dereference it.
    """
    if depth > 6:
        return
    collection = urlsplit(base).path.rstrip("/")
    if isinstance(data, dict):
        for key, value in data.items():
            if key in {"id", "_id", "uuid", "guid"} and isinstance(value, (int, str)):
                url = _canonical(urljoin(base, f"{collection}/{value}"))
                if url not in candidates:
                    candidates.append(url)
            elif isinstance(value, str) and value.startswith("/") and len(value) < 200:
                url = _canonical(urljoin(base, value))
                if url not in follow:
                    follow.append(url)
            else:
                _json_refs(value, base, follow, candidates, depth + 1)
    elif isinstance(data, list):
        for item in data[:50]:
            _json_refs(item, base, follow, candidates, depth + 1)


def _links(body: str, base: str) -> list[str]:
    out: list[str] = []
    for href in _LINK.findall(body[:400_000]):
        if href.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        url = _canonical(urljoin(base, href))
        if url not in out:
            out.append(url)
    return out


@cordon_tool(
    phase="method",
    mode="aggressive",
    targets_arg="target",
    timeout=1800,
    name="auth_crawl",
    tags={"auth", "crawl", "idor"},
    estimated_requests=150,
    risk_notes=[
        "Browses an application while logged in as the operator's account. It visits "
        "real pages with real credentials, and submits read-only forms (GET forms, "
        "and POST forms whose fields are all search/filter parameters) with empty "
        "values to reach pages a link crawler cannot.",
        "Links that look destructive — logout, delete, cancel, revoke — are skipped "
        "rather than fetched, because GET does not guarantee a page is read-only.",
        "State-changing forms (login, registration, checkout, comment, any form with a "
        "field outside the search/filter whitelist) are reported and never submitted.",
        "On a single-page app it fetches the shell's own script bundles and seeds the "
        "crawl with the same-origin paths they name. Those paths are fetched under "
        "every guard a link gets; ones carrying an object id are recorded, not fetched.",
        "Volume: up to max_pages requests against one application, plus up to "
        "max_bundles scripts, rate-limited by the engagement.",
    ],
    rationale="Discover the surface that only exists behind a login.",
)
async def auth_crawl(
    target: str,
    session: str,
    max_pages: int = 120,
    max_depth: int = 3,
    liveness_every: int = 10,
    max_bundles: int = 6,
    max_form_submissions: int = 20,
    timeout: int = 15,
) -> dict[str, Any]:
    """Crawl an application as a registered session and map what is behind the login.

    ``session`` names a session from ``session_register``; it is only sent to the
    host it was issued for.

    Before crawling, the entry point is fetched with and without the session. If
    the two responses are identical the session authenticates nothing, and the
    crawl is refused — a list of public pages labelled "authenticated surface"
    would poison every conclusion drawn from it.

    When a page turns out to be a single-page-app shell, its same-origin script
    bundles are fetched and mined for paths — API literals, request call sites,
    and the route table. Those become crawl seeds under the same guards as a
    link, and are counted separately in ``coverage`` so it is visible how much
    of the map a link crawler alone would have missed. ``max_bundles`` bounds
    the extra requests.

    Returns the discovered URLs, the forms found (read-only ones submitted with
    empty values, state-changing ones reported and never touched), and — the
    useful part — the URLs carrying an object reference, which is what
    ``authz_compare`` must be pointed at. A URL with no identifier in it belongs
    to everyone and proves nothing about access control.
    """
    import httpx

    engagement = get_engagement()
    seeds: list[str] = []
    for raw in split_targets(target):
        url = raw if "://" in raw else f"https://{raw}"
        url = _canonical(url)
        if url not in seeds:
            seeds.append(url)
    start = seeds[0]
    host = urlsplit(start).hostname or ""
    # Extra seeds must be the same host as the one the session belongs to; the
    # session check below is per host, and a credential does not travel.
    seeds = [s for s in seeds if (urlsplit(s).hostname or "") == host]

    identity = engagement.sessions.get(session)
    if identity is None:
        return {
            "ok": False, "error": "unknown_session",
            "registered": engagement.sessions.names(),
            "message": f"No session named {session!r}. Register it with session_register first.",
        }
    if identity not in engagement.sessions.for_host(host):
        return {
            "ok": False, "error": "session_host_mismatch",
            "message": (
                f"Session {session!r} was not issued for {host}. Refusing to send it — "
                "attaching a credential to the wrong host leaks it."
            ),
        }

    rules = engagement.scope.rules
    auth_headers = {"User-Agent": rules.user_agent, **identity.as_headers()}
    anon_headers = {"User-Agent": rules.user_agent}

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, headers=anon_headers
    ) as client:
        # 1. Prove the session does something before believing anything it finds.
        try:
            async with engagement.limiter.slot(host=start):
                signed_in = await client.get(start, headers=auth_headers)
            async with engagement.limiter.slot(host=start):
                anonymous = await client.get(start, headers=anon_headers)
        except httpx.HTTPError as exc:
            return {
                "ok": False, "error": "entry_unreachable", "complete": False,
                "message": (
                    f"Could not reach {start} ({type(exc).__name__}). The authenticated "
                    "surface is UNTESTED, not empty."
                ),
            }

        authed_print = _fingerprint(signed_in.status_code, signed_in.text or "")
        anon_print = _fingerprint(anonymous.status_code, anonymous.text or "")
        if authed_print == anon_print:
            return {
                "ok": False,
                "error": "session_not_authenticated",
                "complete": False,
                "entry": start,
                "message": (
                    f"{start} returned an identical response with and without session "
                    f"{session!r}, so the session is authenticating nothing — it may have "
                    "expired, or this page may simply be public. Crawling now would "
                    "produce a list of public pages labelled as the authenticated "
                    "surface, which is worse than no result. Re-capture the session, or "
                    "point this at a page that requires a login."
                ),
            }

        # 2. Crawl. Same origin, in scope, non-destructive, bounded.
        seen: set[str] = set(seeds)
        queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
        pages: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        skipped: dict[str, int] = {}
        # Item URLs synthesised from ids in a collection. Recorded, never
        # fetched — see _json_refs.
        item_candidates: list[str] = []
        # Where each URL came from, so the report can separate the surface a
        # link crawler would have found from the surface only the bundles name.
        came_from: dict[str, str] = dict.fromkeys(seeds, "seed")
        bundles_seen: set[str] = set()
        bundles_read: list[str] = []
        route_templates: list[str] = []
        errors: list[str] = []
        session_died_at: int | None = None
        # Read-only forms submitted, and the pages they returned. Bounded by
        # max_form_submissions so one search box is not re-submitted on every
        # page that carries it, and a deep crawl cannot become a fuzz run.
        submitted_forms: set[str] = set()
        form_results: list[dict[str, Any]] = []
        # Responses that look exactly like the anonymous entry page. Most
        # applications answer an expired session with one generic "please sign
        # in" body, so this catches expiry on the page it happens rather than
        # up to `liveness_every` pages later.
        anon_streak = 0

        async def still_signed_in() -> bool:
            async with engagement.limiter.slot(host=start):
                try:
                    check = await client.get(start, headers=auth_headers)
                except httpx.HTTPError:
                    return False
            return _fingerprint(check.status_code, check.text or "") != anon_print

        def skip(reason: str) -> None:
            skipped[reason] = skipped.get(reason, 0) + 1

        def enqueue(found: list[str], depth: int, via: str) -> None:
            """The only way anything enters the queue. One gate, one set of rules.

            Links and JavaScript-derived paths go through exactly this code:
            a mined path is not more trusted than a linked one, and giving it a
            second, laxer route into the queue is how a guard stops applying.
            """
            for link in found:
                if link in seen:
                    continue
                seen.add(link)
                link_host = urlsplit(link).hostname or ""
                if link_host != host:
                    # Same origin only. A logged-in crawl that wanders is a
                    # credentialed request to somebody else's server.
                    skip("off_origin")
                    continue
                if not engagement.scope.check(link_host).in_scope:
                    skip("out_of_scope")
                    continue
                if _DESTRUCTIVE.search(link):
                    skip("destructive")
                    continue
                if _BORING.search(urlsplit(link).path):
                    skip("static_asset")
                    continue
                came_from[link] = via
                queue.append((link, depth + 1))

        async def read_bundles(body: str, page_url: str, depth: int) -> None:
            """Mine an SPA shell's scripts for paths, and seed them.

            The shell itself says nothing — that is what a shell is. Everything
            this application does is in the bundles, so not reading them is the
            difference between mapping the app and reporting one page.
            """
            for bundle in _bundle_urls(body, page_url):
                # Two ceilings, because they bound different things: bundles
                # actually read, and requests spent trying. Every client-side
                # route re-offers the same relative `src`, resolved against a
                # different path, so an unbounded attempt count is a request per
                # route for scripts that do not exist.
                if len(bundles_read) >= max_bundles or len(bundles_seen) >= max_bundles * 3:
                    return
                if bundle in bundles_seen:
                    continue
                bundles_seen.add(bundle)
                bundle_host = urlsplit(bundle).hostname or ""
                if bundle_host != host:
                    # A CDN or analytics script is not this application's code,
                    # and it is not on a host anyone authorized.
                    skip("off_origin_script")
                    continue
                if not engagement.scope.check(bundle_host).in_scope:
                    skip("out_of_scope")
                    continue
                async with engagement.limiter.slot(host=bundle):
                    try:
                        script = await client.get(bundle, headers=auth_headers)
                    except httpx.HTTPError as exc:
                        errors.append(f"{bundle}: {type(exc).__name__}")
                        continue
                if script.status_code >= 400:
                    # A bundle that could not be read is a bundle whose routes
                    # were never seen. Recorded as an error so `complete` says
                    # so, rather than an empty result reading as a clean one.
                    errors.append(f"{bundle}: HTTP {script.status_code}")
                    continue
                content_type = script.headers.get("content-type", "").lower()
                if "javascript" not in content_type and "ecmascript" not in content_type:
                    # An SPA answers 200 with its shell for *every* unknown path,
                    # so a relative `src="main.js"` on the client-side route
                    # `/address/create` resolves to `/address/main.js` and comes
                    # back as HTML. Measured on Juice Shop: three of six bundle
                    # slots spent re-reading index.html. Not an error — the
                    # server answered — but it is not a bundle and must not be
                    # counted as one or listed as though its routes were read.
                    skip("script_was_not_javascript")
                    continue
                bundles_read.append(bundle)
                mined, templates = _js_paths(script.text or "", bundle)
                for template in templates:
                    skip("js_route_template")
                    if template not in route_templates:
                        route_templates.append(template)
                seeds_from_js: list[str] = []
                for url, source in mined:
                    # THE GUARD. A mined path that carries an identifier names
                    # one object, and that object usually belongs to somebody
                    # else — the same line _json_refs draws for item URLs, in
                    # the same place, for the same reason. `/api/orders` is a
                    # route we may browse; `/api/orders/1042` is a record, and
                    # reading it is the access-control test, not the crawl.
                    if _object_reference(url) is not None:
                        skip("js_object_reference_not_fetched")
                        # Only an endpoint is worth handing to authz_compare. A
                        # *client-side* route that happens to contain digits is
                        # not an object: Juice Shop declares `path:"403"`, which
                        # _object_reference reads as a numeric id and which
                        # returns the SPA shell to anyone who asks. Not fetched
                        # either way — but naming it as the thing to test would
                        # send an operator at an error page.
                        if source == "endpoint" and url not in item_candidates:
                            item_candidates.append(url)
                        continue
                    seeds_from_js.append(url)
                enqueue(seeds_from_js, depth, "js")

        async def submit_read_only_form(
            form: dict[str, Any], page_url: str, depth: int
        ) -> None:
            """Submit one read-only form and mine the page it returns.

            Only :func:`_is_read_only_form` forms reach this — GET forms and
            POST forms whose every field is a search/filter parameter. Empty
            values are sent: the discovery value is the *page the form returns*
            (links, JSON, object references), not the result of any particular
            query, and empty input is the smallest request that reveals it.

            The returned page is mined for links and JSON references exactly as
            a crawled page is, so a search results page — which no link points
            at — still contributes its object references and its own links.
            """
            if len(form_results) >= max_form_submissions:
                skip("form_budget_exhausted")
                return
            signature = _form_signature(form)
            if signature in submitted_forms:
                return
            submitted_forms.add(signature)

            action = form["action"]
            action_host = urlsplit(action).hostname or ""
            if action_host != host:
                skip("form_action_off_origin")
                return
            if not engagement.scope.check(action_host).in_scope:
                skip("out_of_scope")
                return
            if _DESTRUCTIVE.search(action):
                skip("destructive")
                return

            method = form.get("method", "GET")
            data = {f: "" for f in form.get("fields") or []}
            async with engagement.limiter.slot(host=action):
                try:
                    if method == "POST":
                        result = await client.post(action, data=data, headers=auth_headers)
                    else:
                        result = await client.get(action, params=data, headers=auth_headers)
                except httpx.HTTPError as exc:
                    errors.append(f"{action}: {type(exc).__name__}")
                    return

            body = result.text or ""
            kind = "json" if "json" in result.headers.get("content-type", "") else "html"
            form_results.append({
                "action": action,
                "method": method,
                "status": result.status_code,
                "bytes": len(body),
                "kind": kind,
                "from": page_url,
                "object_reference": _object_reference(action),
            })
            if kind == "json":
                found: list[str] = []
                try:
                    _json_refs(json.loads(body), action, found, item_candidates)
                except (ValueError, TypeError):
                    errors.append(f"{action}: unparsable JSON")
                    found = []
            else:
                found = _links(body, action)
            enqueue(found, depth, "form")

        while queue and len(pages) < max_pages and session_died_at is None:
            url, depth = queue.popleft()

            # Re-prove the session periodically. An application that logs you
            # out at page 40 hands back 80 more pages that look completely
            # normal and are anonymous.
            if pages and len(pages) % max(1, liveness_every) == 0 and not await still_signed_in():
                session_died_at = len(pages)
                break

            async with engagement.limiter.slot(host=url):
                try:
                    response = await client.get(url, headers=auth_headers)
                except httpx.HTTPError as exc:
                    errors.append(f"{url}: {type(exc).__name__}")
                    continue

            body = response.text or ""
            if _fingerprint(response.status_code, body) == anon_print:
                anon_streak += 1
                if anon_streak >= 3 and not await still_signed_in():
                    session_died_at = len(pages)
                    break
            else:
                anon_streak = 0
            kind = "json" if "json" in response.headers.get("content-type", "") else "html"
            pages.append({
                "url": url,
                "status": response.status_code,
                "depth": depth,
                "bytes": len(body),
                "kind": kind,
                "via": came_from.get(url, "seed"),
                "object_reference": _object_reference(url),
            })
            if kind == "html":
                page_forms = _forms(body, url)
                for form in page_forms:
                    if form not in forms:
                        forms.append(form)

            if depth >= max_depth:
                continue

            # Read-only forms reveal the surface a link crawler cannot: a search
            # or filter endpoint is reached only by submitting it, and no link
            # points at its results. Submitted under every guard a GET gets.
            for form in page_forms if kind == "html" else []:
                if _is_read_only_form(form):
                    await submit_read_only_form(form, url, depth)
            # An SPA shell: no links, no forms, and the entire application
            # inside the scripts it loads.
            if kind == "html" and _SPA_SHELL.search(body[:200_000]):
                await read_bundles(body, url, depth)
            if kind == "json":
                found: list[str] = []
                try:
                    _json_refs(json.loads(body), url, found, item_candidates)
                except (ValueError, TypeError):
                    errors.append(f"{url}: unparsable JSON")
                    found = []
            else:
                found = _links(body, url)
            enqueue(found, depth, "link")

    # 3. Record what was found, tagged so later phases know it needed a login.
    engagement.assets.add_many(
        Asset(value=p["url"], kind="url", source="auth_crawl", host=host,
              tags=["authenticated", "live"])
        for p in pages
    )
    # Deliberately kind "object_reference", not "url". These were never fetched,
    # and a `url` asset is what the scan and js phases inherit — filing them
    # there would hand nuclei a list of other people's records to request, which
    # is precisely the read this tool declined to make.
    engagement.assets.add_many(
        Asset(value=u, kind="object_reference", source="auth_crawl", host=host,
              tags=["authenticated", "not-fetched"],
              attributes={"reference": _object_reference(u)})
        for u in item_candidates
    )
    engagement.assets.save(engagement.workspace / "assets.json")

    with_refs = [p for p in pages if p["object_reference"]]
    js_pages = sum(1 for p in pages if p.get("via") == "js")
    # Candidates we never visited are the sharpest access-control targets we
    # have: the application named them, and we deliberately did not look.
    unvisited_refs = [u for u in item_candidates if u not in seen]
    exhausted = not queue and session_died_at is None
    complete = exhausted and not errors

    return {
        "ok": True,
        "complete": complete,
        "entry": start,
        "seeds": seeds,
        "session": identity.name,
        "role": identity.role,
        "pages_crawled": len(pages),
        "pages": pages[:200],
        "forms": forms,
        "forms_submitted": form_results,
        "forms_submitted_count": len(form_results),
        # The payload. Everything else is context for this list.
        "object_reference_urls": [
            {"url": p["url"], "reference": p["object_reference"]} for p in with_refs
        ][:60],
        # Named by the application, never fetched. Point authz_compare here.
        "object_reference_candidates": unvisited_refs[:60],
        "object_reference_candidates_total": len(unvisited_refs),
        "coverage": {
            "queued_unvisited": len(queue),
            "skipped": skipped,
            "errors": errors[:10],
            "max_pages": max_pages,
            "max_depth": max_depth,
            "liveness_every": liveness_every,
            "not_dereferenced": len(unvisited_refs),
            "html_pages": sum(1 for p in pages if p.get("kind") == "html"),
            "json_documents": sum(1 for p in pages if p.get("kind") == "json"),
            # What the JavaScript bought. Separated from link-derived discovery
            # because on an SPA the first number is the whole map and the
            # second is zero, and an operator has to be able to see that.
            "bundles_read": bundles_read,
            "js_seeds_queued": sum(1 for v in came_from.values() if v == "js"),
            "js_pages_crawled": js_pages,
            "link_pages_crawled": sum(1 for p in pages if p.get("via") == "link"),
            # Mined, id-bearing, deliberately not fetched — the same line
            # _json_refs draws, drawn again on the JavaScript.
            "js_references_not_fetched": skipped.get("js_object_reference_not_fetched", 0),
            "js_route_templates": route_templates[:40],
            "max_bundles": max_bundles,
            "max_form_submissions": max_form_submissions,
            "forms_submitted": len(form_results),
            "stopped_because": (
                "session_expired" if session_died_at is not None
                else "page_budget" if len(pages) >= max_pages
                else "crawl_exhausted"
            ),
        },
        "session_verified": True,
        "session_died_after_pages": session_died_at,
        "note": _note(session_died_at, len(pages), len(with_refs), len(queue), js_pages),
        "next_step": _next_step(unvisited_refs, with_refs),
    }


def _next_step(candidates: list[str], visited_refs: list[dict[str, Any]]) -> str:
    aim = candidates[0] if candidates else (visited_refs[0]["url"] if visited_refs else "")
    if not aim:
        return (
            "No object references found. Without an identifier in a URL there is "
            "nothing for an access-control test to aim at — crawl deeper, or look for "
            "an API the pages call rather than link to."
        )
    held_back = (
        f" {len(candidates)} of these were named by the application and deliberately "
        "not fetched: reading somebody else's record is the test, not the crawl."
        if candidates else ""
    )
    return (
        "Register a second account of different privilege, then run authz_compare as "
        f"both identities against {aim} — a URL carrying an object reference is what "
        "an access-control test needs." + held_back + " If both identities get the "
        "same response and that object belongs to one of them, that is an IDOR."
    )


def _note(died_at: int | None, pages: int, refs: int, queued: int, js_pages: int = 0) -> str:
    if died_at is not None:
        return (
            f"The session stopped authenticating after {died_at} pages. Everything "
            "found up to that point is real; the crawl stopped there rather than "
            "continuing anonymously and reporting public pages as the authenticated "
            "surface. Re-capture the session and resume."
        )
    via_js = (
        f" {js_pages} of them were reached only because a script bundle named the "
        "path — no link on any page points at them."
        if js_pages else ""
    )
    if queued:
        return (
            f"{pages} pages crawled, {refs} carrying an object reference. {queued} URLs "
            "were queued and not visited — this is a PARTIAL map of the authenticated "
            "surface, bounded by max_pages/max_depth, not the whole of it." + via_js
        )
    reach = (
        "links, the paths the script bundles name, and the read-only forms found "
        "on them."
        if js_pages else
        "links and the read-only forms found on them. Anything reached only by a "
        "state-changing form (login, checkout, comment) or an XHR the pages do "
        "not link to is not in here."
    )
    return (
        f"{pages} pages crawled, {refs} carrying an object reference. The queue "
        "emptied, so this is the reachable authenticated surface from this entry "
        f"point — {reach}" + via_js
    )

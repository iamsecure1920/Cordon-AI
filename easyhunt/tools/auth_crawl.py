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

What it does not do
-------------------
No forms are submitted, no method other than GET is used, and nothing is
written. Discovered forms are *reported* — they are the state-changing surface,
and deciding to exercise it is a human's call under the program's rules.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Asset
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import split_targets

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
    """Forms on a page: the state-changing surface, reported and not touched."""
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


@easyhunt_tool(
    phase="method",
    mode="aggressive",
    targets_arg="target",
    timeout=1800,
    name="auth_crawl",
    tags={"auth", "crawl", "idor"},
    estimated_requests=140,
    risk_notes=[
        "Browses an application while logged in as the operator's account. GET only, "
        "no forms submitted, but it visits real pages with real credentials.",
        "Links that look destructive — logout, delete, cancel, revoke — are skipped "
        "rather than fetched, because GET does not guarantee a page is read-only.",
        "Volume: up to max_pages requests against one application, rate-limited by "
        "the engagement.",
    ],
    rationale="Discover the surface that only exists behind a login.",
)
async def auth_crawl(
    target: str,
    session: str,
    max_pages: int = 120,
    max_depth: int = 3,
    liveness_every: int = 10,
    timeout: int = 15,
) -> dict[str, Any]:
    """Crawl an application as a registered session and map what is behind the login.

    ``session`` names a session from ``session_register``; it is only sent to the
    host it was issued for.

    Before crawling, the entry point is fetched with and without the session. If
    the two responses are identical the session authenticates nothing, and the
    crawl is refused — a list of public pages labelled "authenticated surface"
    would poison every conclusion drawn from it.

    Returns the discovered URLs, the forms found (reported, never submitted),
    and — the useful part — the URLs carrying an object reference, which is what
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
        errors: list[str] = []
        session_died_at: int | None = None
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
                "object_reference": _object_reference(url),
            })
            if kind == "html":
                for form in _forms(body, url):
                    if form not in forms:
                        forms.append(form)

            if depth >= max_depth:
                continue
            if kind == "json":
                found: list[str] = []
                try:
                    _json_refs(json.loads(body), url, found, item_candidates)
                except (ValueError, TypeError):
                    errors.append(f"{url}: unparsable JSON")
                    found = []
            else:
                found = _links(body, url)
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
                queue.append((link, depth + 1))

    # 3. Record what was found, tagged so later phases know it needed a login.
    engagement.assets.add_many(
        Asset(value=p["url"], kind="url", source="auth_crawl", host=host,
              tags=["authenticated", "live"])
        for p in pages
    )
    engagement.assets.save(engagement.workspace / "assets.json")

    with_refs = [p for p in pages if p["object_reference"]]
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
            "stopped_because": (
                "session_expired" if session_died_at is not None
                else "page_budget" if len(pages) >= max_pages
                else "crawl_exhausted"
            ),
        },
        "session_verified": True,
        "session_died_after_pages": session_died_at,
        "note": _note(session_died_at, len(pages), len(with_refs), len(queue)),
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


def _note(died_at: int | None, pages: int, refs: int, queued: int) -> str:
    if died_at is not None:
        return (
            f"The session stopped authenticating after {died_at} pages. Everything "
            "found up to that point is real; the crawl stopped there rather than "
            "continuing anonymously and reporting public pages as the authenticated "
            "surface. Re-capture the session and resume."
        )
    if queued:
        return (
            f"{pages} pages crawled, {refs} carrying an object reference. {queued} URLs "
            "were queued and not visited — this is a PARTIAL map of the authenticated "
            "surface, bounded by max_pages/max_depth, not the whole of it."
        )
    return (
        f"{pages} pages crawled, {refs} carrying an object reference. The queue "
        "emptied, so this is the reachable authenticated surface from this entry "
        "point — links only. Anything reached solely by a form submission or an "
        "XHR the pages do not link to is not in here."
    )

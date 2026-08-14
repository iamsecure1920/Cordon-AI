"""Crawling as a logged-in user, and the four ways that quietly goes wrong.

Everything this project has scanned was the third of the surface that needs no
account. This is the tool that reaches the rest — which means it is the tool
holding the operator's credentials while it walks somebody else's application,
and the failure modes are correspondingly sharp:

1. **The session was never authenticating anything.** A dead cookie produces a
   perfectly ordinary list of public pages, and labelling that "the
   authenticated surface" poisons every conclusion drawn from it. The entry
   point is fetched with and without the session first, and the crawl is refused
   if they match.
2. **The session dies partway.** Everything after is anonymous and looks fine.
   Liveness is re-checked as it goes and the crawl stops where it broke.
3. **A link changed state.** GET is not a promise. Logout is the worst case,
   because following it is failure mode 2 arriving by our own hand.
4. **Discovery became the attack.** Found on the first live run: an
   authenticated `/api/Users/` returned every account on the system and the
   crawler read thirteen other users' records. Item URLs synthesised from ids
   are now recorded and never fetched — enumerate the reference, do not
   dereference it.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.tools import auth_crawl as ac
from easyhunt.tools.sessions import session_register

pytestmark = pytest.mark.asyncio

HOST = "https://www.example.com"

ANON = "<html><body>Please sign in</body></html>"


def page(*links: str, extra: str = "") -> str:
    body = "".join(f'<a href="{h}">x</a>' for h in links)
    return f"<html><body>welcome back{body}{extra}</body></html>"


def shell(*scripts: str) -> str:
    """A single-page-app shell: no links, no forms, nothing but a script tag.

    This is what most modern applications answer with on every path, and a
    crawler that only follows `<a href>` sees exactly one page of it.
    """
    tags = "".join(f'<script src="{s}" type="module"></script>' for s in scripts)
    return f'<html><body><app-root ng-version="17.0.0"></app-root>{tags}</body></html>'


JS = "application/javascript"


def serve(monkeypatch, routes: dict[str, Any], *, anon_body: str = ANON) -> list[str]:
    """Serve `routes` to an authenticated caller and `anon_body` to everyone else."""
    fetched: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        authed = "authorization" in request.headers or "cookie" in request.headers
        if not authed:
            return httpx.Response(200, text=anon_body)
        fetched.append(request.url.path)
        entry = routes.get(request.url.path)
        if entry is None:
            return httpx.Response(404, text="nope")
        if isinstance(entry, tuple):
            body, ctype = entry
        else:
            body, ctype = entry, "text/html"
        return httpx.Response(200, text=body, headers={"content-type": ctype})

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )
    return fetched


async def register(engagement, name: str = "alice") -> None:
    engagement.approval.backend = PolicyBackend(auto_approve=["auth_crawl"])
    await session_register(
        name=name, host="www.example.com", role="user-a",
        headers="Authorization: Bearer live-token-value",
    )


class TestSessionMustBeProven:
    async def test_an_identical_response_refuses_the_crawl(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # The session changes nothing: the page is public, or the cookie is dead.
        serve(monkeypatch, {"/": ANON}, anon_body=ANON)
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert result["ok"] is False
        assert result["error"] == "session_not_authenticated"
        assert result["complete"] is False

    async def test_an_unknown_session_is_refused(self, engagement, monkeypatch) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["auth_crawl"])
        serve(monkeypatch, {"/": page()})
        result = await ac.auth_crawl(f"{HOST}/", session="nobody")
        assert result["ok"] is False
        assert result["error"] == "unknown_session"

    async def test_a_session_is_not_sent_to_another_host(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        serve(monkeypatch, {"/v2/": page()})
        result = await ac.auth_crawl("https://app.example.org/v2/", session="alice")
        assert result["ok"] is False
        assert result["error"] == "session_host_mismatch"

    async def test_an_unreachable_entry_is_untested_not_empty(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)

        async def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(refuse)}),
        )
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert result["ok"] is False
        assert result["error"] == "entry_unreachable"
        assert "UNTESTED" in result["message"]


class TestItRefusesToChangeState:
    async def test_logout_is_never_followed(self, engagement, monkeypatch) -> None:
        await register(engagement)
        fetched = serve(monkeypatch, {
            "/": page("/logout", "/account"),
            "/account": page(),
            "/logout": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        # Following it once anonymises every request after it.
        assert "/logout" not in fetched
        assert "/account" in fetched
        assert result["coverage"]["skipped"]["destructive"] == 1

    @pytest.mark.parametrize(
        "link", ["/orders/7/delete", "/subscription/cancel", "/api/keys/revoke",
                 "/account/deactivate", "/session/sign-out"],
    )
    async def test_destructive_links_are_skipped(
        self, engagement, monkeypatch, link: str
    ) -> None:
        await register(engagement)
        fetched = serve(monkeypatch, {"/": page(link), link: page()})
        await ac.auth_crawl(f"{HOST}/", session="alice")
        assert link not in fetched

    async def test_only_get_is_used(self, engagement, monkeypatch) -> None:
        methods: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            methods.append(request.method)
            authed = "authorization" in request.headers
            return httpx.Response(200, text=page("/next") if authed else ANON)

        await register(engagement)
        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        await ac.auth_crawl(f"{HOST}/", session="alice", max_pages=5)
        assert methods and set(methods) == {"GET"}

    async def test_forms_are_reported_not_submitted(
        self, engagement, monkeypatch
    ) -> None:
        form = '<form action="/transfer" method="post"><input name="amount"></form>'
        await register(engagement)
        fetched = serve(monkeypatch, {"/": page(extra=form)})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert result["forms"][0]["action"] == f"{HOST}/transfer"
        assert result["forms"][0]["fields"] == ["amount"]
        assert "/transfer" not in fetched


class TestReadOnlyFormSubmission:
    """A search or filter form is the surface a link crawler cannot reach.

    The results page has no ``<a href>`` pointing at it — it exists only after
    someone submits the form. Read-only forms (GET, and POST whose every field
    is a search/filter parameter) are submitted with empty values so the pages
    they return contribute their links and object references. Anything that
    could write — login, checkout, a field outside the whitelist — is reported
    and never touched.
    """

    async def test_a_read_only_get_form_is_submitted_and_mined(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        form = '<form action="/search" method="get"><input name="q"></form>'
        fetched = serve(monkeypatch, {
            "/": page(extra=form),
            "/search": page("/search-result"),
            "/search-result": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "/search" in fetched
        # The results page is only reachable by submitting the form, and its
        # own links are still followed.
        assert "/search-result" in fetched
        assert result["forms_submitted_count"] == 1
        assert result["forms_submitted"][0]["action"] == f"{HOST}/search"
        assert result["forms_submitted"][0]["method"] == "GET"

    async def test_a_read_only_post_form_is_submitted_as_post(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        form = '<form action="/search" method="post"><input name="q"><input name="sort"></form>'
        seen_methods: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            authed = "authorization" in request.headers or "cookie" in request.headers
            if not authed:
                return httpx.Response(200, text=ANON)
            if request.url.path == "/search":
                seen_methods.append(request.method)
            routes = {"/": page(extra=form), "/search": page("/result"), "/result": page()}
            entry = routes.get(request.url.path)
            if entry is None:
                return httpx.Response(404, text="nope")
            return httpx.Response(200, text=entry, headers={"content-type": "text/html"})

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "POST" in seen_methods
        assert result["forms_submitted"][0]["method"] == "POST"
        assert result["forms_submitted"][0]["action"] == f"{HOST}/search"

    async def test_a_login_form_is_never_submitted(self, engagement, monkeypatch) -> None:
        await register(engagement)
        form = ('<form action="/login" method="post">'
                '<input name="email"><input name="password"></form>')
        fetched = serve(monkeypatch, {"/": page(extra=form), "/login": page("/account")})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "/login" not in fetched
        assert result["forms_submitted_count"] == 0
        assert result["forms"][0]["action"] == f"{HOST}/login"

    async def test_a_form_whose_action_writes_is_never_submitted(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # Every field is a search parameter, but the action says "create".
        form = '<form action="/api/orders/create" method="post"><input name="q"></form>'
        fetched = serve(monkeypatch, {"/": page(extra=form)})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "/api/orders/create" not in fetched
        assert result["forms_submitted_count"] == 0

    async def test_a_post_form_with_an_unrecognised_field_is_never_submitted(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # "q" is a search parameter, but "amount" is not — the whole form is
        # treated as a write and refused. Fail closed on the unknown field.
        form = ('<form action="/filter" method="post">'
                '<input name="q"><input name="amount"></form>')
        fetched = serve(monkeypatch, {"/": page(extra=form)})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "/filter" not in fetched
        assert result["forms_submitted_count"] == 0

    async def test_a_form_results_page_contributes_object_references(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # A search results page is the classic IDOR entrance: it lists records
        # reached only by submitting the form, each carrying someone's id.
        form = '<form action="/search" method="get"><input name="q"></form>'
        fetched = serve(monkeypatch, {
            "/": page(extra=form),
            "/search": page("/orders/1042", "/orders/8899"),
            "/orders/1042": page(),
            "/orders/8899": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert "/search" in fetched
        # The results page's links were followed — the references came from the
        # page the form returned, which no link from the entry pointed at.
        assert "/orders/1042" in fetched
        assert f"{HOST}/orders/1042" in [p["url"] for p in result["pages"]]


class TestDiscoveryIsNotTheAttack:
    async def test_item_urls_from_a_collection_are_not_fetched(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        users = json.dumps([{"id": 1, "email": "a@x"}, {"id": 2, "email": "b@x"}])
        fetched = serve(monkeypatch, {
            "/api/Users/": (users, "application/json"),
            "/api/Users/1": ("{}", "application/json"),
            "/api/Users/2": ("{}", "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/api/Users/", session="alice")

        # The whole point: a collection frequently lists other people's objects,
        # and reading one is the IDOR rather than the crawl.
        assert "/api/Users/1" not in fetched
        assert "/api/Users/2" not in fetched
        assert f"{HOST}/api/Users/1" in result["object_reference_candidates"]
        assert result["coverage"]["not_dereferenced"] == 2

    async def test_a_path_the_response_actually_contains_is_followed(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        doc = json.dumps({"next": "/api/orders", "id": 9})
        fetched = serve(monkeypatch, {
            "/api/me": (doc, "application/json"),
            "/api/orders": ("[]", "application/json"),
        })
        await ac.auth_crawl(f"{HOST}/api/me", session="alice")
        # The application handed us this URL; fetching it is browsing.
        assert "/api/orders" in fetched

    async def test_the_crawl_stays_on_the_session_host(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        fetched = serve(monkeypatch, {
            "/": page("https://other.example.com/x", "/ok"),
            "/ok": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        # A logged-in crawl that wanders sends credentials to another server.
        assert "/x" not in fetched
        assert result["coverage"]["skipped"]["off_origin"] == 1


class TestTheBundlesAreTheSurface:
    """An SPA has no links. Everything it does is a string inside a script.

    A link crawler pointed at one fetches the shell, finds no `<a href>`, and
    reports an authenticated surface of a single page — which is not a small
    error, it is the entire application missing while the output looks fine.
    """

    async def test_a_path_from_a_bundle_is_fetched(self, engagement, monkeypatch) -> None:
        await register(engagement)
        # Only the call site names this path: it is not api-shaped and not in a
        # route table, so it can only have come from the fetch() pattern.
        bundle = 'const r=await fetch("/dashboard/summary",{headers:h});'
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"),
            "/main.js": (bundle, JS),
            "/dashboard/summary": ('{"a":1}', "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/main.js" in fetched
        assert "/dashboard/summary" in fetched
        assert f"{HOST}/dashboard/summary" in [p["url"] for p in result["pages"]]
        # No link on any page points at it; only the bundle named it.
        via = {p["url"]: p["via"] for p in result["pages"]}
        assert via[f"{HOST}/dashboard/summary"] == "js"

    async def test_bare_api_literals_and_route_tables_are_seeded(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # How a minified Angular build actually looks: the URL is assembled from
        # a base and a constant, so there is no literal at the call site — only
        # the bare path, and the route table beside it.
        bundle = (
            'const B=this.hostServer;this.http.get(B+"/api/v2/accounts/summary");'
            'const R=[{path:"order-history",component:x},{path:"wallet",component:y}];'
        )
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"),
            "/main.js": (bundle, JS),
            "/api/v2/accounts/summary": ("{}", "application/json"),
            "/order-history": page(),
            "/wallet": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/api/v2/accounts/summary" in fetched
        assert "/order-history" in fetched
        assert "/wallet" in fetched
        assert result["coverage"]["js_pages_crawled"] == 3

    async def test_a_mined_path_carrying_an_id_is_recorded_not_fetched(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # `/api/orders` is a route the application calls, and fetching it as
        # ourselves is browsing. `/api/orders/1042` is one record, and it is
        # very unlikely to be ours — that read is the access-control test, and
        # it belongs behind authz_compare with two identities and an approval.
        bundle = 'fetch("/api/orders");fetch("/api/orders/1042");'
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"),
            "/main.js": (bundle, JS),
            "/api/orders": ("[]", "application/json"),
            "/api/orders/1042": ('{"total":1}', "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/api/orders" in fetched
        assert "/api/orders/1042" not in fetched
        assert f"{HOST}/api/orders/1042" in result["object_reference_candidates"]
        assert result["coverage"]["js_references_not_fetched"] == 1
        assert result["coverage"]["skipped"]["js_object_reference_not_fetched"] == 1

    async def test_a_numeric_client_route_is_not_offered_as_a_test_target(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # Juice Shop declares `path:"403"`. _object_reference reads "403" as a
        # numeric id, so the guard holds it back — correctly, in the safe
        # direction — but it is an error page, not somebody's record, and
        # pointing authz_compare at it wastes the operator's time.
        bundle = '[{path:"403"}];fetch("/api/orders/1042");'
        fetched = serve(monkeypatch, {"/": shell("/main.js"), "/main.js": (bundle, JS)})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/403" not in fetched
        assert f"{HOST}/403" not in result["object_reference_candidates"]
        # The endpoint still is: that one names an object.
        assert f"{HOST}/api/orders/1042" in result["object_reference_candidates"]
        assert result["next_step"].count(f"{HOST}/api/orders/1042")

    async def test_a_route_template_is_not_fetched_but_is_reported(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # There is no URL `/order-completion/:id`. Fetching the literal sends a
        # credential at a path the application never calls; reporting it tells
        # the operator an id-bearing route exists.
        bundle = '[{path:"order-completion/:id"},{path:"about"}]'
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"), "/main.js": (bundle, JS), "/about": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert not [p for p in fetched if "order-completion" in p]
        assert "/about" in fetched
        assert result["coverage"]["skipped"]["js_route_template"] == 1
        assert "/order-completion/:id" in result["coverage"]["js_route_templates"]

    async def test_an_off_origin_url_in_a_bundle_is_not_fetched(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        bundle = 'fetch("https://evil.example.net/api/steal");fetch("/api/ok");'
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"),
            "/main.js": (bundle, JS),
            "/api/ok": ("{}", "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        # The bundle asks the browser to call a third party. We are not the
        # browser, and we are carrying the operator's credential.
        assert "/api/steal" not in fetched
        assert "/api/ok" in fetched
        assert result["coverage"]["skipped"]["off_origin"] == 1

    async def test_an_off_origin_script_is_not_fetched(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        fetched = serve(monkeypatch, {
            "/": shell("https://cdn.example.net/vendor.js", "/main.js"),
            "/main.js": ('fetch("/api/ok");', JS),
            "/api/ok": ("{}", "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        # A CDN script is not this application's code and its host authorized
        # nothing.
        assert "/vendor.js" not in fetched
        assert result["coverage"]["skipped"]["off_origin_script"] == 1
        assert result["coverage"]["bundles_read"] == [f"{HOST}/main.js"]

    async def test_a_bundle_that_404s_does_not_crash_the_crawl(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        fetched = serve(monkeypatch, {
            "/": shell("/gone.js") + '<a href="/inbox">x</a>',
            "/inbox": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert result["ok"] is True
        assert "/inbox" in fetched
        assert result["coverage"]["bundles_read"] == []
        # A bundle that could not be read is a bundle whose routes were never
        # seen. That is an incomplete crawl, not a clean one.
        assert any("gone.js" in e for e in result["coverage"]["errors"])
        assert result["complete"] is False

    async def test_a_bundle_that_never_answers_does_not_crash_the_crawl(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)

        async def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return httpx.Response(200, text=ANON)
            if request.url.path == "/dead.js":
                raise httpx.ReadTimeout("no answer")
            return httpx.Response(200, text=shell("/dead.js"))

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        assert result["ok"] is True
        assert any("ReadTimeout" in e for e in result["coverage"]["errors"])

    async def test_mined_paths_get_every_guard_a_link_gets(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # Nothing about coming from JavaScript makes a path safe to fetch.
        bundle = 'fetch("/api/session/logout");fetch("/api/theme.css");fetch("/api/ok");'
        fetched = serve(monkeypatch, {
            "/": shell("/main.js"),
            "/main.js": (bundle, JS),
            "/api/ok": ("{}", "application/json"),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/api/session/logout" not in fetched
        assert "/api/theme.css" not in fetched
        assert "/api/ok" in fetched
        assert result["coverage"]["skipped"]["destructive"] == 1
        assert result["coverage"]["skipped"]["static_asset"] == 1

    async def test_the_js_derived_count_is_reported(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        bundle = 'fetch("/api/a");fetch("/api/b");'
        serve(monkeypatch, {
            "/": shell("/main.js") + '<a href="/linked">x</a>',
            "/main.js": (bundle, JS),
            "/api/a": ("{}", "application/json"),
            "/api/b": ("{}", "application/json"),
            "/linked": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        coverage = result["coverage"]
        # An operator has to be able to see which half of the map came from
        # where: on a real SPA the link half is zero.
        assert coverage["js_seeds_queued"] == 2
        assert coverage["js_pages_crawled"] == 2
        assert coverage["link_pages_crawled"] == 1
        assert coverage["bundles_read"] == [f"{HOST}/main.js"]
        assert "script bundle named the path" in result["note"]

    async def test_a_shell_served_in_place_of_a_script_is_not_a_bundle(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # Measured against Juice Shop: an SPA answers 200 with its shell for
        # every unknown path, so `src="main.js"` on the client-side route
        # /address/create resolves to /address/main.js and returns HTML. Three
        # of six bundle slots went on re-reading index.html.
        spa = shell("main.js")
        fetched = serve(monkeypatch, {
            "/": spa,
            "/main.js": ('[{path:"address/create"}]', JS),
            "/address/create": spa,
            "/address/main.js": spa,
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/address/main.js" in fetched  # the request was spent
        assert result["coverage"]["bundles_read"] == [f"{HOST}/main.js"]
        assert result["coverage"]["skipped"]["script_was_not_javascript"] == 1

    async def test_a_page_that_is_not_a_shell_costs_no_extra_requests(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        # Ordinary server-rendered HTML: no shell marker, so no bundle is
        # fetched even though the page loads scripts.
        body = page("/inbox", extra='<script src="/analytics.js"></script>')
        fetched = serve(monkeypatch, {"/": body, "/inbox": page()})
        result = await ac.auth_crawl(f"{HOST}/", session="alice")

        assert "/analytics.js" not in fetched
        assert result["coverage"]["bundles_read"] == []
        assert result["coverage"]["js_seeds_queued"] == 0


class TestSessionExpiry:
    async def test_a_session_that_dies_stops_the_crawl(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        state = {"served": 0}

        async def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return httpx.Response(200, text=ANON)
            state["served"] += 1
            # Logged out after 12 authenticated responses: from here the server
            # returns exactly what an anonymous caller sees.
            if state["served"] > 12:
                return httpx.Response(200, text=ANON)
            links = [f"/p{state['served']}{i}" for i in range(3)]
            return httpx.Response(200, text=page(*links))

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        result = await ac.auth_crawl(f"{HOST}/", session="alice", max_pages=100)

        assert result["session_died_after_pages"] is not None
        assert result["coverage"]["stopped_because"] == "session_expired"
        assert result["complete"] is False
        assert "stopped authenticating" in result["note"]


class TestOutput:
    async def test_object_references_are_recognised(self, engagement, monkeypatch) -> None:
        await register(engagement)
        serve(monkeypatch, {
            "/": page("/orders/1042", "/doc?ref=88", "/about"),
            "/orders/1042": page(),
            "/doc?ref=88": page(),
            "/doc": page(),
            "/about": page(),
        })
        result = await ac.auth_crawl(f"{HOST}/", session="alice")
        found = {r["url"]: r["reference"] for r in result["object_reference_urls"]}
        assert found[f"{HOST}/orders/1042"]["kind"] == "numeric"
        assert found[f"{HOST}/doc?ref=88"]["where"] == "query"
        # A URL with no identifier belongs to everybody and proves nothing.
        assert f"{HOST}/about" not in found

    async def test_pages_are_recorded_as_authenticated_assets(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        serve(monkeypatch, {"/": page("/inbox"), "/inbox": page()})
        await ac.auth_crawl(f"{HOST}/", session="alice")
        # Tagged so later phases know this surface needed a login to see.
        assert f"{HOST}/inbox" in engagement.assets.values("url", tag="authenticated")

    async def test_hitting_the_page_budget_is_not_complete(
        self, engagement, monkeypatch
    ) -> None:
        await register(engagement)
        counter = {"n": 0}

        async def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                return httpx.Response(200, text=ANON)
            counter["n"] += 1
            return httpx.Response(200, text=page(*[f"/q{counter['n']}{i}" for i in range(4)]))

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        result = await ac.auth_crawl(f"{HOST}/", session="alice", max_pages=10)
        # A truncated map must not read as the whole authenticated surface.
        assert result["pages_crawled"] == 10
        assert result["complete"] is False
        assert result["coverage"]["stopped_because"] == "page_budget"
        assert result["coverage"]["queued_unvisited"] > 0
        assert "PARTIAL" in result["note"]

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

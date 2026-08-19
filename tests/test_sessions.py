"""The session primitive and the two-identity differ.

42 of 115 WSTG tests had no tool behind them, and they were not scattered: they
were every test in Authentication, Session management, Business logic,
Authorization and Identity management. What those categories share is that they
require being logged in — and the authorization ones require being logged in
twice, as different people. That is one missing primitive, not 42 features.

Three properties carry the weight here, and each is a way this can silently do
the wrong thing:

1. **A session goes only to the host it was issued for.** Attaching a credential
   to a host that did not issue it is a credential leak dressed as convenience.
   The check fails closed: no host recorded means no host matched.
2. **Credentials never appear in output.** Results are read by triagers, pasted
   into tickets and mailed on. A live cookie that survives that journey is a
   credential in a system nobody threat-modelled for it.
3. **A session compared with itself is not a finding.** Caught on the first live
   run: a SQL-injection login bypass returned the same admin token for two
   different email addresses, so both "identities" were one account and the tool
   filed a HIGH severity IDOR candidate about nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon.control_plane.approval import PolicyBackend
from cordon.knowledge.sessions import Session, SessionStore, mask
from cordon.tools import sessions as st

SECRET = "eyJhbGciOiJIUzI1NiJ9.super-secret-token-value.signature"


class TestMasking:
    def test_a_credential_is_not_reproduced_in_full(self) -> None:
        out = mask(SECRET)
        assert SECRET not in out
        # Still identifiable — an operator has to be able to tell which token
        # a result is talking about.
        assert out.startswith(SECRET[:4]) and out.endswith(SECRET[-4:])

    def test_a_short_value_is_hidden_entirely(self) -> None:
        # Keeping four leading and four trailing characters of an eight-character
        # secret keeps the whole secret.
        assert "abcd1234" not in mask("abcd1234")

    def test_safe_output_masks_cookies_and_auth_headers(self) -> None:
        s = Session(
            name="admin", host="example.com",
            cookies={"sid": SECRET},
            headers={"Authorization": f"Bearer {SECRET}", "X-Trace": "on"},
        )
        rendered = repr(s.safe())
        assert SECRET not in rendered
        # Non-credential headers stay legible; masking everything would make the
        # output useless for deciding whether a session is set up correctly.
        assert "on" in rendered

    def test_as_headers_still_carries_the_real_value(self) -> None:
        # Masking is a rendering concern. The value that goes on the wire must
        # be intact or the session does not authenticate anything.
        s = Session(name="a", host="example.com", cookies={"sid": SECRET})
        assert s.as_headers()["Cookie"] == f"sid={SECRET}"


class TestHostBinding:
    def _store(self) -> SessionStore:
        store = SessionStore()
        store.add(Session(name="app", host="app.example.com", cookies={"sid": "x"}))
        return store

    def test_the_issuing_host_matches(self) -> None:
        assert [s.name for s in self._store().for_host("app.example.com")] == ["app"]

    def test_a_subdomain_of_the_issuing_host_matches(self) -> None:
        assert [s.name for s in self._store().for_host("api.app.example.com")] == ["app"]

    def test_an_unrelated_host_does_not_match(self) -> None:
        assert self._store().for_host("evil.example.com") == []

    def test_a_suffix_lookalike_does_not_match(self) -> None:
        # "notapp.example.com" ends with "app.example.com" as a string but is a
        # different host. The check is on the dot boundary for this reason.
        assert self._store().for_host("notapp.example.com") == []

    def test_an_empty_host_matches_nothing(self) -> None:
        # Fails closed. The alternative — treating "unknown" as "anywhere" —
        # sends the operator's credentials to a third party.
        assert self._store().for_host("") == []

    def test_a_session_with_no_recorded_host_is_never_attached(self) -> None:
        store = SessionStore()
        store.add(Session(name="loose", host="", cookies={"sid": "x"}))
        assert store.for_host("example.com") == []


class TestPersistence:
    def test_a_saved_store_round_trips(self, tmp_path: Path) -> None:
        store = SessionStore()
        store.add(Session(name="a", role="admin", host="example.com", cookies={"sid": SECRET}))
        path = tmp_path / "sessions.json"
        store.save(path)

        loaded = SessionStore()
        assert loaded.load(path) == 1
        assert loaded.get("a").cookies["sid"] == SECRET

    def test_the_file_is_not_world_readable(self, tmp_path: Path) -> None:
        store = SessionStore()
        store.add(Session(name="a", host="example.com", cookies={"sid": SECRET}))
        path = tmp_path / "sessions.json"
        store.save(path)
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
class TestRegister:
    async def test_a_session_is_registered_and_masked(self, engagement) -> None:
        result = await st.session_register(
            name="alice", host="www.example.com", cookies=f"sid={SECRET}"
        )
        assert result["ok"] is True
        assert SECRET not in repr(result)

    async def test_an_out_of_scope_host_is_refused(self, engagement) -> None:
        result = await st.session_register(
            name="x", host="blog.example.com", cookies="sid=abc"
        )
        # A session for an out-of-scope host would be attached to requests this
        # engagement is not authorized to make.
        assert result["ok"] is False
        assert result["error"] == "scope_denied"

    async def test_a_session_without_a_host_is_refused(self, engagement) -> None:
        result = await st.session_register(name="x", host="", cookies="sid=abc")
        assert result["ok"] is False
        assert result["error"] == "host_required"

    async def test_a_session_with_no_credentials_is_refused(self, engagement) -> None:
        result = await st.session_register(name="x", host="www.example.com")
        assert result["ok"] is False
        assert result["error"] == "empty_session"

    async def test_the_audit_entry_records_names_not_values(self, engagement) -> None:
        await st.session_register(
            name="alice", host="www.example.com",
            headers=f"Authorization: Bearer {SECRET}",
        )
        # The audit log is hash-chained and kept. A credential written into it
        # is a credential kept forever.
        trail = (engagement.workspace / "audit.jsonl")
        if trail.exists():
            assert SECRET not in trail.read_text(encoding="utf-8")

    async def test_one_session_prompts_for_a_second(self, engagement) -> None:
        result = await st.session_register(
            name="alice", host="www.example.com", cookies="sid=abc", role="user"
        )
        # One account only tests that the application works. Two of differing
        # privilege is what tests authorization.
        assert "second account" in result["next_step"]


@pytest.mark.asyncio
class TestAuthzCompare:
    async def _two(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["authz_compare"])
        await st.session_register(
            name="alice", host="www.example.com", cookies="sid=alice-token", role="user-a"
        )
        await st.session_register(
            name="bob", host="www.example.com", cookies="sid=bob-token", role="user-b"
        )

    async def test_a_write_method_is_refused(self, engagement) -> None:
        await self._two(engagement)
        result = await st.authz_compare(
            "https://www.example.com/api/orders/1", "alice", "bob", method="DELETE"
        )
        # Proving broken access control requires reading another user's data,
        # never writing to it. Every program in this space forbids the latter.
        assert result["ok"] is False
        assert result["error"] == "method_not_permitted"

    async def test_an_unknown_session_is_refused(self, engagement) -> None:
        await self._two(engagement)
        result = await st.authz_compare(
            "https://www.example.com/api/orders/1", "alice", "nobody"
        )
        assert result["ok"] is False
        assert result["error"] == "unknown_session"

    async def test_a_session_is_not_sent_to_a_host_it_was_not_issued_for(
        self, engagement
    ) -> None:
        await self._two(engagement)
        result = await st.authz_compare(
            "https://app.example.org/v2/orders/1", "alice", "bob"
        )
        assert result["ok"] is False
        assert result["error"] == "session_host_mismatch"

    async def test_comparing_a_session_with_itself_is_refused(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["authz_compare"])
        # Two names, one identity — exactly what a login bypass produces when it
        # hands back the same admin token regardless of the email supplied.
        for name in ("one", "two"):
            await st.session_register(
                name=name, host="www.example.com", cookies="sid=same-token"
            )
        result = await st.authz_compare(
            "https://www.example.com/api/orders/1", "one", "two"
        )
        assert result["ok"] is False
        assert result["error"] == "identical_sessions"

    async def test_a_failed_request_is_untested_not_authorized(
        self, engagement, monkeypatch
    ) -> None:
        await self._two(engagement)
        import httpx

        async def boom(self, *a, **kw):  # noqa: ANN001, ANN002, ANN003
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "request", boom)
        result = await st.authz_compare(
            "https://www.example.com/api/orders/1", "alice", "bob"
        )
        # A request that never completed says nothing about authorization. The
        # dangerous reading is "no difference observed" — which is what a naive
        # comparison of two failures would produce.
        assert result["ok"] is False
        assert result["error"] == "request_failed"
        assert "UNTESTED" in result["message"]


@pytest.mark.asyncio
class TestAccountRegister:
    """Account creation is a state change, so it is gated on explicit policy."""

    async def test_refused_when_the_policy_is_silent(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["account_register"])
        result = await st.account_register(
            host="www.example.com",
            signup_url="https://www.example.com/signup",
            username_field="username",
            password_field="password",
        )
        # A created account persists after the scan and is someone else's data
        # to hold. Of four programs read during this project, two allowed it
        # and two said nothing — and silence is not permission.
        assert result["ok"] is False
        assert result["error"] == "self_registration_not_permitted"

    async def test_a_signup_on_a_different_host_is_refused(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["account_register"])
        engagement.scope.rules.allow_self_registration = True
        result = await st.account_register(
            host="www.example.com",
            signup_url="https://evil.example.net/signup",
            username_field="username",
            password_field="password",
        )
        # The signup POST would carry credentials to a host the operator did not name.
        assert result["ok"] is False
        assert result["error"] == "signup_host_mismatch"

    async def test_an_account_is_created_and_the_session_registered(
        self, engagement, monkeypatch
    ) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["account_register"])
        engagement.scope.rules.allow_self_registration = True
        import httpx

        posted: dict[str, str] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            posted["url"] = str(request.url)
            posted["body"] = request.content.decode()
            return httpx.Response(
                200, headers={"set-cookie": "sid=created-token; Path=/; HttpOnly"}
            )

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
        )
        result = await st.account_register(
            host="www.example.com",
            signup_url="https://www.example.com/signup",
            username_field="username",
            password_field="password",
            email_field="email",
            username="alice",
            password="pw",
            email="alice@example.com",
            name="alice",
        )
        assert result["ok"] is True
        assert posted["url"] == "https://www.example.com/signup"
        assert "username=alice" in posted["body"]
        assert "password=pw" in posted["body"]
        assert "email=alice%40example.com" in posted["body"]
        # The captured cookie becomes a registered session, not a logged secret.
        session = engagement.sessions.get("alice")
        assert session is not None
        assert session.cookies["sid"] == "created-token"
        # The generated credentials are returned for the operator and nowhere
        # else — never written to the audit trail.
        trail = engagement.workspace / "audit.jsonl"
        if trail.exists():
            assert "alice@example.com" not in trail.read_text(encoding="utf-8")

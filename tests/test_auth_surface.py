"""Finding the login, and knowing when you have not found it.

This tool's first live run reported "no authentication surface found" against
OWASP Juice Shop — an application whose entire purpose is having a login. It was
right about the HTML and wrong about the target: a single-page app serves the
same empty shell for every path, so the only place the login exists is a
compiled bundle nothing had opened.

That is the project's recurring defect wearing a new costume. A tool that looks
in the wrong place produces the same output as a target with nothing there.

So the tests below are mostly about the negative case:

1. **An SPA shell is not evidence of anything.** If the bundles cannot be read,
   the host is UNEXAMINED, not clean.
2. **A bundle is not HTML.** ``type="password"`` never appears in minified
   Angular, and the word "register" appears in ``registerOnChange``. The two
   content kinds get different patterns, and the route table — a declaration,
   not an incidental substring — is what carries the signal.
3. **Nothing is submitted.** Every request is a GET; no account is created and
   no credential is sent, because self-registration is a policy question the
   operator answers, not a technical one this tool may assume.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from easyhunt.tools import auth_surface as asf

pytestmark = pytest.mark.asyncio

# A conventional server-rendered login page.
LOGIN_HTML = """
<html><body><form action="/login" method="post">
<input name="email"><input type="password" name="password">
</form><a href="/signup">Create an account</a></body></html>
"""

# The Juice Shop case: an Angular shell that says nothing at all.
SPA_HTML = """
<html><head><title>Shop</title></head>
<body><app-root ng-version="18.0.0"></app-root>
<script src="polyfills.js"></script><script src="main.js"></script>
</body></html>
"""

# A minified bundle, shaped the way the real one is.
BUNDLE_JS = (
    'const r=[{path:"login",component:M},{path:"register",component:N},'
    '{path:"forgot-password",component:O},{path:"2fa/enter",component:P},'
    '{path:"order-history",component:Q},{path:"administration",component:R}];'
    'class F{writeValue(a){this.value=a}registerOnChange(b){this.onChange=b}}'
    'const form={password:"",repeatPassword:""};'
)


def serve(monkeypatch, routes: dict[str, tuple[int, str, dict[str, str]]]) -> list[str]:
    """Answer requests from a table; record what was asked for."""
    asked: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        asked.append(f"{request.method} {request.url.path}")
        status, body, headers = routes.get(
            request.url.path, (404, "not found", {})
        )
        return httpx.Response(status, text=body, headers=headers)

    real_client = httpx.AsyncClient

    def fake_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    return asked


def all_paths(body: str, headers: dict[str, str] | None = None):
    """Every probe path answers with the same body — the SPA catch-all case."""
    return dict.fromkeys(asf._PROBE_PATHS, (200, body, headers or {}))


class TestRouteExtraction:
    def test_routes_are_read_from_a_bundle(self) -> None:
        routes = asf._routes(BUNDLE_JS)
        assert "login" in routes and "register" in routes
        assert "administration" in routes

    def test_minified_noise_is_not_a_route(self) -> None:
        # `path` is also an SVG attribute and a minified local. Anything that is
        # not slug-shaped is noise, and noise here is worse than a short list
        # because this list is the part an operator reads.
        noisy = 'path:"M10 20l5-5z",path:"+(f||",path:"a,b,c",path:"http://x/y"'
        assert asf._routes(noisy) == []

    def test_a_route_table_names_privileged_and_owned_pages(self) -> None:
        assert asf._PRIVILEGED_ROUTE.match("administration")
        assert asf._OWNED_OBJECT_ROUTE.match("order-history")
        assert not asf._PRIVILEGED_ROUTE.match("about")


class TestClassifyKnowsWhatItIsReading:
    def test_html_patterns_find_an_html_login(self) -> None:
        found = asf._classify(LOGIN_HTML, httpx.Headers(), kind="html")
        assert "password_login" in found
        assert "registration" in found

    def test_html_patterns_miss_a_route_only_bundle(self) -> None:
        # The bug, preserved. A bundle whose auth surface is expressed purely as
        # route declarations contains no HTML markup and no English words, so
        # the HTML pattern set sees an application with no login — which is what
        # was reported about a target built entirely around one.
        routes_only = 'const r=[{path:"login",c:A},{path:"register",c:B}];'
        assert asf._classify(routes_only, httpx.Headers(), kind="html") == set()
        assert {"password_login", "registration"} <= asf._classify(
            routes_only, httpx.Headers(), kind="js"
        )

    def test_js_patterns_find_the_login_in_the_bundle(self) -> None:
        found = asf._classify(BUNDLE_JS, httpx.Headers(), kind="js")
        assert {"password_login", "registration", "password_reset", "mfa"} <= found

    def test_register_on_change_is_not_a_signup_form(self) -> None:
        # `registerOnChange` appears 14 times in a real Angular bundle. Matching
        # the bare word "register" would call every Angular app a signup page.
        found = asf._classify(
            'class F{registerOnChange(a){}registerOnTouched(b){}}',
            httpx.Headers(), kind="js",
        )
        assert "registration" not in found

    def test_a_session_cookie_is_recognised(self) -> None:
        headers = httpx.Headers({"set-cookie": "connect.sid=abc123; HttpOnly"})
        assert "session_cookie" in asf._classify("<html></html>", headers)

    def test_an_analytics_cookie_is_not_a_session(self) -> None:
        headers = httpx.Headers({"set-cookie": "_ga=GA1.2.3; Path=/"})
        assert "session_cookie" not in asf._classify("<html></html>", headers)


class TestLiveBehaviour:
    async def test_a_server_rendered_login_is_found(self, engagement, monkeypatch) -> None:
        serve(monkeypatch, all_paths(LOGIN_HTML))
        result = await asf.auth_surface("https://www.example.com/")
        host = result["ranked"][0]
        assert "registration" in host["signals"]
        assert result["worth_an_account"][0]["host"] == "www.example.com"

    async def test_an_spa_is_read_through_its_bundles(self, engagement, monkeypatch) -> None:
        routes = all_paths(SPA_HTML)
        routes["/main.js"] = (200, BUNDLE_JS, {})
        routes["/polyfills.js"] = (200, "void 0;", {})
        serve(monkeypatch, routes)

        result = await asf.auth_surface("https://www.example.com/")
        host = result["ranked"][0]
        assert host["spa"] is True
        assert "registration" in host["signals"]
        assert "administration" in host["privileged_routes"]
        assert "order-history" in host["user_scoped_routes"]

    async def test_an_spa_whose_bundles_fail_is_unexamined(
        self, engagement, monkeypatch
    ) -> None:
        # The whole point. The shell parsed fine and every path returned 200 —
        # and none of that is evidence about authentication.
        serve(monkeypatch, all_paths(SPA_HTML))  # bundles 404
        result = await asf.auth_surface("https://www.example.com/")
        host = result["ranked"][0]
        assert host["examined"] is False
        assert "UNEXAMINED" in host["verdict"]
        assert result["complete"] is False
        assert "www.example.com" in result["hosts_unexamined"]

    async def test_an_unreachable_host_is_unexamined_not_clean(
        self, engagement, monkeypatch
    ) -> None:
        async def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        real = httpx.AsyncClient
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(refuse)}),
        )
        result = await asf.auth_surface("https://www.example.com/")
        host = result["ranked"][0]
        assert host["examined"] is False
        assert "UNEXAMINED" in host["verdict"]

    async def test_only_get_requests_are_sent(self, engagement, monkeypatch) -> None:
        asked = serve(monkeypatch, all_paths(LOGIN_HTML))
        await asf.auth_surface("https://www.example.com/")
        # Nothing is submitted and no account is created: registering is a
        # policy decision belonging to the operator, not to this tool.
        assert asked and all(a.startswith("GET ") for a in asked)

    async def test_third_party_bundles_are_not_fetched(
        self, engagement, monkeypatch
    ) -> None:
        shell = (
            '<html><body><app-root></app-root>'
            '<script src="https://cdn.other.test/vendor.js"></script>'
            '<script src="main.js"></script></body></html>'
        )
        routes = all_paths(shell)
        routes["/main.js"] = (200, BUNDLE_JS, {})
        asked = serve(monkeypatch, routes)
        await asf.auth_surface("https://www.example.com/")
        # A CDN is not this application's code, and the scope never authorized it.
        assert not any("vendor.js" in a for a in asked)

    async def test_a_target_with_no_usable_url_is_an_error_not_a_clean_result(
        self, engagement, monkeypatch
    ) -> None:
        serve(monkeypatch, {})
        # max_hosts=0 leaves nothing to examine. "Examined nothing and found no
        # login" must not render as "this estate has no login".
        result = await asf.auth_surface("https://www.example.com/", max_hosts=0)
        assert result["ok"] is True
        assert result["hosts_examined"] <= 1

class TestVendorKeysAreNotAnAuthSurface:
    """A public analytics token is not evidence that a host authenticates callers.

    Both halves of this were live false positives on a real bank's hosts. First
    `api[_-]?key` with no word boundary matched inside `googleAPIKey`, scoring a
    login page as having API-auth because it loads a map. Then, after a vendor
    list was added to suppress exactly that, `var _rollbarConfig = { accessToken:
    "..." }` produced the same signal — because `\brollbar` cannot match
    `_rollbarConfig`: `_` is a word character, so there is no boundary there.

    The guard is a lookbehind on letters and digits rather than `\b`, and a
    trailing guard is deliberately absent: it would break `googleAPIKey`, where
    the vendor name runs straight into the field name. Generic English words are
    kept out of the list instead, since `heap` matched "heaps of data".
    """

    @pytest.mark.parametrize(
        "body",
        [
            'var _rollbarConfig = { accessToken: "0123456789abcdef0123456789abcdef" }',
            '{"googleAPIKey":"AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0"}',
            '{"datadogClientToken":"pub123"}',
            '{"bugsnagApiKey":"abc123"}',
            '{"apiKey":"x","authDomain":"y.firebaseapp.com"}',
        ],
    )
    def test_a_public_vendor_token_is_not_api_auth(self, body: str) -> None:
        assert asf._api_auth_evidence(body) is False

    @pytest.mark.parametrize(
        "body",
        [
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
            'headers: {"X-Api-Key": userSuppliedKey}',
            '"api_key": config.secret',
            # A vendor token nearby must never hide a real mechanism.
            'var _rollbarConfig={accessToken:"x"}; Authorization: Bearer real',
        ],
    )
    def test_a_real_mechanism_still_registers(self, body: str) -> None:
        assert asf._api_auth_evidence(body) is True

    @pytest.mark.parametrize("word", ["sitemaps", "heaps of data", "drifting apart"])
    def test_generic_words_are_not_vendors(self, word: str) -> None:
        # A false vendor match suppresses a real signal, so the list must not
        # contain ordinary English.
        assert asf._VENDOR_KEY.search(word) is None



class TestRetireActuallyRuns:
    """`retire --js` was fixed twice, in the argument policy, and never worked.

    First it was declared value-taking, so the sanitizer swallowed the following
    --path and the directory arrived as a bare positional and was refused.
    That was "fixed" by declaring it boolean — which made the sanitizer accept
    it, and retire then answered:

        error: unknown option '--js'   (exit 1, zero output)

    retire 5.x removed --js entirely; `retire --help` lists --path and --jspath
    and nothing else for scanning JavaScript. Two rounds of fixes to the
    argument policy, neither to the thing that runs. JS library CVE detection
    has never produced a result in this project's life.
    """

    def test_the_policy_does_not_allow_a_flag_retire_rejects(self) -> None:
        import easyhunt.tools.js_analysis  # noqa: F401  registers the policy
        from easyhunt.control_plane.sanitize import get_policy

        policy = get_policy("retire")
        assert "--js" not in policy.allowed_flags, "retire 5.x has no --js"
        assert "--path" in policy.allowed_flags

    async def test_js_analyze_builds_an_argv_retire_accepts(
        self, engagement, monkeypatch
    ) -> None:
        from easyhunt.control_plane.sanitize import sanitize_argv
        from easyhunt.tools import js_analysis as js
        from easyhunt.tools.base import REGISTRY
        from easyhunt.tools.common import ToolRun

        seen: list[list[str]] = []

        async def spy(name: str, argv: list[str], **kwargs):
            if name == "retire":
                seen.append(list(argv))
            return ToolRun(tool=name, ran=True, values=[], exit_code=0)

        monkeypatch.setattr(js, "run_one", spy)
        await REGISTRY["js_analyze"].fn(target="https://www.example.com/")

        assert seen, "js_analyze never invoked retire"
        for argv in seen:
            assert "--js" not in argv
            sanitize_argv("retire", argv)


class TestLinkFinderActuallyRuns:
    """linkfinder was catalogued, installed and never called for the project's
    whole life. Its exemption in test_wiring.py read "WIRING PROPOSED" — the
    call site is now in js_analyze, and this test holds it there.

    The bug class it closes is the one this file documents for retire: a tool
    with a spec, a binary and no caller reports `ran: false` on every
    engagement and is indistinguishable from a clean bundle. linkfinder's own
    trap was its `-i` value pattern, which accepted only URLs — so even once
    wired, running it over saved files would have built an argv its own
    sanitizer refused.
    """

    def test_the_policy_accepts_a_filesystem_path_for_minus_i(self) -> None:
        import easyhunt.tools.js_analysis  # noqa: F401  registers the policy
        from easyhunt.control_plane.sanitize import get_policy

        policy = get_policy("linkfinder")
        assert policy is not None
        pattern = policy.value_patterns["-i"]
        assert pattern.fullmatch("/work/raw/js-123456.js"), "-i must accept a saved file path"
        assert pattern.fullmatch("https://example.com/app.js"), "-i must still accept a URL"

    async def test_js_analyze_invokes_linkfinder_over_saved_files(
        self, engagement, monkeypatch, tmp_path
    ) -> None:
        from easyhunt.control_plane.sanitize import sanitize_argv
        from easyhunt.tools import js_analysis as js
        from easyhunt.tools.base import REGISTRY
        from easyhunt.tools.common import ToolRun

        # Seed a saved bundle so js_analyze has a file to hand linkfinder.
        saved = engagement.raw_path("js", "js")
        saved.write_text("const x='/api/hidden?id=1';", encoding="utf-8")

        seen: list[list[str]] = []

        async def spy(name: str, argv: list[str], **kwargs):
            if name == "linkfinder":
                seen.append(list(argv))
                return ToolRun(
                    tool=name, ran=True, values=["/api/hidden?id=1"], exit_code=0
                )
            if name == "retire":
                return ToolRun(tool=name, ran=True, values=[], exit_code=0)
            if name == "jsluice":
                return ToolRun(tool=name, ran=True, values=[], exit_code=0)
            return ToolRun(tool=name, ran=True, values=[], exit_code=0)

        monkeypatch.setattr(js, "run_one", spy)
        result = await REGISTRY["js_analyze"].fn(target="https://www.example.com/")

        assert seen, "js_analyze never invoked linkfinder"
        files_handed_to_linkfinder = []
        for argv in seen:
            sanitize_argv("linkfinder", argv)
            files_handed_to_linkfinder.append(argv[argv.index("-i") + 1])
        # The fetch loop saves its own bundle too; the seeded file must be among
        # the inputs linkfinder scanned, not the only one.
        assert str(saved) in files_handed_to_linkfinder
        # Its findings flow into the endpoint set and the result summary. The
        # spy returns the same value for every file it is handed, so the count
        # is at least one, not exactly one.
        assert "/api/hidden?id=1" in result["endpoints"]
        assert result["linkfinder"]["endpoints_found"] >= 1


class TestBasicAuthUrlDetector:
    """A HIGH severity credential finding that fired on JSON-LD.

    The pattern was `https?://[^:\\s/]+:[^@\\s/]+@[A-Za-z0-9.-]+`. `[^@\\s/]+`
    matches anything up to the next "@", so on a page carrying JSON-LD it ran
    from `https://schema.org` through `","@type"` and called the result a
    credential in a URL. Yoast SEO emits that block on every WordPress page.

    Found on a live target: one HIGH "finding", zero credentials.
    """

    def _detector(self):
        import re

        from easyhunt.tools.js_analysis import SECRET_PATTERNS

        for name, pattern, _sev in SECRET_PATTERNS:
            if name == "basic-auth-url":
                return re.compile(pattern)
        raise AssertionError("basic-auth-url detector is gone")

    def test_json_ld_is_not_a_credential(self) -> None:
        blob = (
            '{"@context":"https://schema.org","@type":"WebPage",'
            '"@id":"https://stage-www.example.com/en/"}'
        )
        assert self._detector().search(blob) is None

    def test_a_real_credential_url_still_matches(self) -> None:
        """The control — tightening must not blind the detector."""
        m = self._detector().search("fetch('https://admin:s3cret@internal.example.com/api')")
        assert m and m.group(0).startswith("https://admin:s3cret@")

    def test_percent_encoded_password_still_matches(self) -> None:
        m = self._detector().search("https://svc:p%40ssw0rd@10.0.0.5/")
        assert m is not None

    def test_a_port_is_not_a_password(self) -> None:
        assert self._detector().search("https://example.com:8443/path") is None


class TestTemplateLiteralRoutes:
    """The endpoint miner must see the routes an SPA builds in template literals.

    ``this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)`` is how
    modern frontends call their APIs, and it was invisible to the previous
    pattern: the route sits between a ``}`` and a ``${``, not between quotes.
    That one gap is why the unattended run never aimed a validator at the
    search endpoint an authenticated human would test first.
    """

    def test_extracts_template_literal_route_with_param(self) -> None:
        from easyhunt.tools.js_analysis import _scan_text

        blob = (
            'search(e){return this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)'
            '.pipe(W(i=>i.data))}'
        )
        _secrets, endpoints = _scan_text(blob, "http://x")
        assert "/rest/products/search?q=" in endpoints

    def test_plain_quoted_route_still_matches(self) -> None:
        from easyhunt.tools.js_analysis import _scan_text

        blob = 'findBy(e){return this.http.get(this.hostServer+"/rest/user/security-question?email="+e)}'
        _secrets, endpoints = _scan_text(blob, "http://x")
        assert "/rest/user/security-question?email=" in endpoints


class TestScriptUrls:
    """An HTML shell's value is the bundles it names; js_analyze must follow them."""

    def test_relative_script_src_resolves_against_the_page(self) -> None:
        from easyhunt.tools.js_analysis import _script_urls

        body = '<html><script src="main.js"></script><script src="/assets/app.js"></script></html>'
        urls = list(_script_urls(body, "http://127.0.0.1:3000/"))
        assert "http://127.0.0.1:3000/main.js" in urls
        assert "http://127.0.0.1:3000/assets/app.js" in urls

    def test_modulepreload_is_followed_too(self) -> None:
        from easyhunt.tools.js_analysis import _script_urls

        body = '<link rel="modulepreload" href="chunk-x.js">'
        assert "http://127.0.0.1:3000/chunk-x.js" in list(
            _script_urls(body, "http://127.0.0.1:3000/")
        )


class TestFetchBudgetPrioritisation:
    """The fetch budget must not be spent on wildcard phantoms.

    Measured against a live estate with wildcard DNS: `js_analyze` took the
    first 25 URLs in asset-store order — alphabetical — and 22 of them were
    hosts like `blairwalnuts`, `hellofreshuk`, `humble` and `husband` that
    exist only because `*.target` resolves. Every one returned the same
    960,758-byte edge interstitial. files_fetched: 25, files_scanned: 0.

    The phase reported PARTIAL rather than clean, which was honest, but the
    budget was already gone and not one real bundle was read.
    """

    def test_https_wins_over_http_for_the_same_host(self) -> None:
        from easyhunt.tools.js_analysis import _prioritise

        chosen = _prioritise(["http://a.example.com/", "https://a.example.com/"], 10)
        assert chosen == ["https://a.example.com/"], "plain HTTP is the worse read"

    def test_one_url_per_host(self) -> None:
        from easyhunt.tools.js_analysis import _prioritise

        chosen = _prioritise(
            [f"https://a.example.com/page{i}" for i in range(5)]
            + ["https://b.example.com/"],
            10,
        )
        hosts = {u.split("/")[2] for u in chosen}
        assert hosts == {"a.example.com", "b.example.com"}
        assert len(chosen) == 2, "five paths on one host cannot yield five bundle sets"

    def test_a_script_path_outranks_a_page(self) -> None:
        from easyhunt.tools.js_analysis import _prioritise

        chosen = _prioritise(["https://a.example.com/", "https://b.example.com/app.js"], 1)
        assert chosen == ["https://b.example.com/app.js"], "a bundle is what we came for"

    def test_budget_reaches_distinct_hosts_not_one_hosts_paths(self) -> None:
        """The regression, in the shape it actually occurred."""
        from easyhunt.tools.js_analysis import _prioritise

        wildcard = [f"http://phantom{i}.example.com/" for i in range(40)]
        real = ["https://app.example.com/main.js", "https://api.example.com/"]
        chosen = _prioritise(real + wildcard, 25)
        assert chosen[0] == "https://app.example.com/main.js"
        assert "https://api.example.com/" in chosen[:2], "https must outrank 40 http phantoms"
        assert len({u.split("/")[2] for u in chosen}) == len(chosen), "no host twice"

    def test_non_http_input_is_dropped(self) -> None:
        from easyhunt.tools.js_analysis import _prioritise

        assert _prioritise(["ftp://x.example.com/", "not-a-url", ""], 5) == []



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

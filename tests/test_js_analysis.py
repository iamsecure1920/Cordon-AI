

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

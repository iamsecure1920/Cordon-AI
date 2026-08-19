"""Program-mandated attribution headers and containerised tool config.

Both of these were found by running a real Bugcrowd engagement rather than by
reading the code, and both failed *quietly* — the shape of bug this codebase
keeps producing:

* the tagged user-agent was passed to a generic ``-H`` flag without ``Name:``
  syntax, so it went on the wire malformed and attribution silently did not
  happen;
* containerised tools had no access to their host config, so subfinder returned
  a config error that read like "this domain has few subdomains".
"""

from __future__ import annotations

import pytest

from cordon.control_plane.scope import ScopeRules
from cordon.tools.base import _config_mounts


class TestRequiredHeaders:
    def test_headers_are_parsed(self) -> None:
        rules = ScopeRules.from_dict(
            {"required_headers": ["X-Bug-Bounty: Bugcrowd-someone"]}
        )
        assert rules.required_headers == ["X-Bug-Bounty: Bugcrowd-someone"]

    def test_default_is_empty(self) -> None:
        assert ScopeRules.from_dict({}).required_headers == []

    @pytest.mark.parametrize("bad", ["X-Bug-Bounty", "  ", ": novalue"])
    def test_malformed_header_is_refused(self, bad: str) -> None:
        # A header without a name and colon becomes junk on the wire. Accepting
        # it would look like compliance while providing none — so it fails at
        # load, where a human is still watching.
        with pytest.raises(ValueError, match="Name: value"):
            ScopeRules.from_dict({"required_headers": [bad]})

    def test_whitespace_is_trimmed(self) -> None:
        rules = ScopeRules.from_dict({"required_headers": ["  X-A: b  "]})
        assert rules.required_headers == ["X-A: b"]


class TestUserAgentInjection:
    """The distinction between a header flag and a dedicated user-agent flag."""

    async def test_dedicated_agent_flag_gets_the_bare_value(
        self, engagement, monkeypatch
    ) -> None:
        # whatweb takes --user-agent, which expects the agent string alone.
        # Prefixing 'User-Agent:' there would send a literally wrong agent.
        engagement.scope.rules.user_agent = "Cordon/test"
        engagement.scope.rules.required_headers = ["X-Bug-Bounty: Bugcrowd-me"]

        captured: dict[str, list[str]] = {}

        def fake_plan(*, tool, binary, argv, **kwargs):
            captured["argv"] = list(argv)
            raise RuntimeError("stop here")

        monkeypatch.setattr(engagement.sandbox, "plan", fake_plan)

        from cordon.errors import ToolUnavailable
        from cordon.tools.base import guarded_run
        from cordon.tools.http_probe import WHATWEB

        with pytest.raises((RuntimeError, ToolUnavailable)):
            await guarded_run(WHATWEB, ["https://example.com"], timeout=5)

        argv = captured.get("argv", [])
        assert "Cordon/test" in argv
        assert "User-Agent: Cordon/test" not in argv
        # A tool with no generic header flag cannot carry the mandated header;
        # that gap must not be papered over by mangling the agent flag.
        assert "X-Bug-Bounty: Bugcrowd-me" not in argv

    async def test_agent_and_headers_reach_the_command(self, engagement, monkeypatch) -> None:
        engagement.scope.rules.user_agent = "Cordon/test"
        engagement.scope.rules.required_headers = ["X-Bug-Bounty: Bugcrowd-me"]

        captured: dict[str, list[str]] = {}

        def fake_plan(*, tool, binary, argv, **kwargs):
            captured["argv"] = list(argv)
            raise RuntimeError("stop here — the argv is what we are asserting on")

        monkeypatch.setattr(engagement.sandbox, "plan", fake_plan)

        from cordon.errors import ToolUnavailable
        from cordon.tools.base import guarded_run
        from cordon.tools.http_probe import HTTPX

        with pytest.raises((RuntimeError, ToolUnavailable)):
            await guarded_run(HTTPX, ["-u", "https://example.com"], timeout=5)

        argv = captured.get("argv", [])
        # The agent must carry 'User-Agent:' because httpx's flag is -H.
        assert "User-Agent: Cordon/test" in argv
        # And the program's mandated header must be there too.
        assert "X-Bug-Bounty: Bugcrowd-me" in argv


class TestConfigMounts:
    def test_unknown_tool_gets_no_mount(self) -> None:
        assert _config_mounts("definitely-not-a-tool") == []

    def test_mounts_are_read_only(self, monkeypatch, tmp_path) -> None:
        # A scan must never be able to rewrite the operator's API keys.
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".config" / "subfinder").mkdir(parents=True)
        mounts = _config_mounts("subfinder")
        assert mounts and all(mode == "ro" for _, _, mode in mounts)

    def test_absent_config_is_skipped_not_faked(self, monkeypatch, tmp_path) -> None:
        # Mounting a non-existent path makes Docker create an empty directory,
        # which would look configured and behave as if it were not.
        monkeypatch.setenv("HOME", str(tmp_path))
        assert _config_mounts("subfinder") == []

    def test_container_path_matches_tool(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".config" / "nuclei").mkdir(parents=True)
        [(host, container, _)] = _config_mounts("nuclei")
        assert container == "/root/.config/nuclei"
        assert host.name == "nuclei"

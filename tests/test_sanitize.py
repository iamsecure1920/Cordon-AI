"""Sanitizer: reject, never clean-and-run."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon.control_plane.sanitize import (
    ArgPolicy,
    register_policy,
    sanitize_argv,
    sanitize_path,
    sanitize_value,
)
from cordon.errors import SanitizeError


@pytest.fixture(autouse=True)
def demo_policy() -> ArgPolicy:
    return register_policy(
        ArgPolicy(
            tool="demo",
            allowed_flags={"-u", "-o", "-rate", "-severity", "-t"},
            boolean_flags=set(),
            denied_flags={"-danger"},
            value_patterns={"-severity": re.compile(r"[a-z,]+")},
            numeric_caps={"-rate": 10},
            denied_values={"-t": {"dos", "fuzz"}},
            allow_positional=True,
            positional_pattern=re.compile(r"[A-Za-z0-9._:/-]+"),
        )
    )


class TestValues:
    @pytest.mark.parametrize("payload", ["a;b", "a|b", "a&b", "a`b`", "a$(b)", "a\nb", "a&&b", "x||y"])
    def test_shell_metacharacters_rejected(self, payload: str) -> None:
        with pytest.raises(SanitizeError):
            sanitize_value(payload, name="-u")

    def test_rejection_does_not_mutate(self) -> None:
        # The value must never come back "cleaned" — that teaches the caller that
        # malformed input sometimes works.
        with pytest.raises(SanitizeError) as excinfo:
            sanitize_value("example.com; rm -rf /", name="-u")
        assert "never permitted" in str(excinfo.value)

    def test_soft_chars_rejected_by_default_and_relaxable(self) -> None:
        with pytest.raises(SanitizeError):
            sanitize_value("(a|b)", name="-r")
        # Even relaxed, a pipe stays denied: it is on the hard list.
        with pytest.raises(SanitizeError):
            sanitize_value("(a|b)", name="-r", relaxed_chars=frozenset("()"))
        assert sanitize_value("(ab)", name="-r", relaxed_chars=frozenset("()")) == "(ab)"

    def test_credential_file_markers_rejected(self) -> None:
        with pytest.raises(SanitizeError, match="refused"):
            sanitize_value("/etc/shadow", name="-o")

    def test_length_cap(self) -> None:
        with pytest.raises(SanitizeError, match="exceeds"):
            sanitize_value("a" * 5000, name="-u")


class TestArgv:
    def test_allowed_argv_passes_through_unchanged(self) -> None:
        argv = ["-u", "https://example.com", "-rate", "5"]
        assert sanitize_argv("demo", argv) == argv

    def test_unknown_flag_rejected(self) -> None:
        with pytest.raises(SanitizeError, match="not on the allowlist"):
            sanitize_argv("demo", ["-x", "1"])

    def test_tool_denied_flag_rejected(self) -> None:
        with pytest.raises(SanitizeError, match="denied"):
            sanitize_argv("demo", ["-danger", "1"])

    @pytest.mark.parametrize(
        "flag", ["--os-shell", "--os-cmd", "--file-write", "--eval", "--tor", "--random-agent"]
    )
    def test_globally_denied_flags(self, flag: str) -> None:
        policy = ArgPolicy(tool="permissive", allowed_flags={flag}, allow_positional=True)
        register_policy(policy)
        # On the tool's own allowlist, and still refused.
        with pytest.raises(SanitizeError, match="globally denied"):
            sanitize_argv("permissive", [flag, "x"])

    def test_numeric_cap_enforced(self) -> None:
        with pytest.raises(SanitizeError, match="exceeds the ceiling"):
            sanitize_argv("demo", ["-rate", "5000"])

    def test_denied_value_in_comma_list(self) -> None:
        with pytest.raises(SanitizeError, match="denied"):
            sanitize_argv("demo", ["-t", "cve,dos"])

    def test_value_pattern_enforced(self) -> None:
        with pytest.raises(SanitizeError, match="permitted shape"):
            sanitize_argv("demo", ["-severity", "HIGH!!"])

    def test_flag_without_value_rejected(self) -> None:
        with pytest.raises(SanitizeError, match="requires a value"):
            sanitize_argv("demo", ["-u"])

    def test_unregistered_tool_cannot_execute(self) -> None:
        with pytest.raises(SanitizeError, match="no argument policy"):
            sanitize_argv("never-registered", ["-u", "example.com"])

    def test_argv_length_cap(self) -> None:
        with pytest.raises(SanitizeError, match="argv too long"):
            sanitize_argv("demo", ["x"] * 200)


class TestPaths:
    def test_traversal_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(SanitizeError, match="escapes"):
            sanitize_path("../../var/log/out.json", workspace=tmp_path)

    def test_absolute_escape_blocked(self, tmp_path: Path) -> None:
        with pytest.raises(SanitizeError, match="escapes"):
            sanitize_path("/var/tmp/loot.json", workspace=tmp_path)

    @pytest.mark.parametrize("path", ["../../etc/passwd", "/root/.ssh/id_rsa"])
    def test_sensitive_targets_refused_on_the_value_rule_first(
        self, path: str, tmp_path: Path
    ) -> None:
        # These trip the credential-marker rule before traversal is even checked;
        # either refusal is correct, but the message should name the real reason.
        with pytest.raises(SanitizeError, match="refused"):
            sanitize_path(path, workspace=tmp_path)

    def test_inside_workspace_allowed(self, tmp_path: Path) -> None:
        assert sanitize_path("out/results.json", workspace=tmp_path).is_relative_to(tmp_path)


class TestHeaderValues:
    """A header field-value is not a shell fragment.

    This class exists because the sanitizer once refused every conventional
    user-agent. `Cordon-AI/2.0 (owner-authorized-testing; contact=handle)`
    carries a semicolon, ";" is in HARD_DENY_CHARS, and so testssl, corscanner
    and every other tool that identifies itself refused to start — reporting
    UNTESTED and blaming a missing binary. The project tells the operator to
    transcribe the program's mandated identifiers; it then has to send them.
    """

    @pytest.fixture(autouse=True)
    def header_policy(self) -> ArgPolicy:
        return register_policy(
            ArgPolicy(
                tool="hdr",
                allowed_flags={"-H", "--user-agent", "-u"},
                header_flags={"-H", "--user-agent"},
            )
        )

    def test_semicolon_permitted_in_a_user_agent(self) -> None:
        ua = "Cordon-AI/2.0 (owner-authorized-testing; contact=your-handle)"
        assert sanitize_argv("hdr", ["--user-agent", ua]) == ["--user-agent", ua]

    def test_browser_shaped_user_agent_permitted(self) -> None:
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        sanitize_argv("hdr", ["-H", f"User-Agent: {ua}"])

    @pytest.mark.parametrize("bad", ["\r", "\n", "\x00", "\x1b", "\v"])
    def test_control_characters_still_refused(self, bad: str) -> None:
        """Response splitting is the actual threat in this position."""
        with pytest.raises(SanitizeError):
            sanitize_argv("hdr", ["-H", f"X-Test: a{bad}X-Injected: b"])

    def test_crlf_header_split_refused(self) -> None:
        with pytest.raises(SanitizeError) as err:
            sanitize_argv("hdr", ["-H", "X-A: 1\r\nX-B: 2"])
        assert "control character" in str(err.value).lower()

    def test_non_ascii_refused(self) -> None:
        """Encoding surprises must not smuggle a newline past the check."""
        with pytest.raises(SanitizeError):
            sanitize_argv("hdr", ["--user-agent", "Cordon AI"])

    def test_relaxation_does_not_leak_to_other_flags(self) -> None:
        """-u is not a header flag, so it keeps the shell rules."""
        with pytest.raises(SanitizeError):
            sanitize_argv("hdr", ["-u", "https://x/;id"])

    def test_denied_value_markers_still_apply(self) -> None:
        with pytest.raises(SanitizeError):
            sanitize_argv("hdr", ["-H", "X-Read: /etc/passwd"])

    def test_user_agent_flag_is_declared_as_a_header_flag_automatically(self) -> None:
        """The flag that carries a header is, by construction, checked as one.

        `guarded_run` injects the user-agent through `spec.user_agent_flag`. If
        that registration were left to each policy by hand it would drift, and
        the drift is silent: the tool simply stops running.
        """
        from cordon.tools.base import ToolSpec

        spec = ToolSpec(
            name="uatool",
            user_agent_flag="--agent",
            arg_policy=ArgPolicy(tool="uatool", allowed_flags={"--agent"}),
        )
        assert "--agent" in spec.arg_policy.header_flags
        sanitize_argv("uatool", ["--agent", "Tool/1.0 (a; b)"])

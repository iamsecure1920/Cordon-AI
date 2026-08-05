"""Injection probes: the argv they build must survive their own sanitizer.

Three properties are load-bearing here, and each has bitten this project before:

1. **The argv a wrapper builds passes its own policy.** A policy that refuses its
   own tool's call is inert — the tool never runs, and the surface silently reads
   as clean. Every test in :class:`TestArgvPassesItsOwnSanitizer` drives the real
   wrapper, captures the real argv, and feeds it back through ``sanitize_argv``.
2. **Value-less flags are declared.** A flag missing from ``boolean_flags`` is
   treated as value-taking and swallows the next argument. That is precisely what
   made ``retire`` un-runnable for the entire life of the project.
3. **An absent tool reports UNTESTED.** Not ``ok``, not zero findings.
"""

from __future__ import annotations

from typing import Any

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.sanitize import GLOBAL_DENIED_FLAGS, sanitize_argv, sanitize_value
from easyhunt.errors import SanitizeError
from easyhunt.knowledge.findings import Status
from easyhunt.tools import injection as inj
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import CATALOG, ToolRun

pytestmark = pytest.mark.asyncio

SPECS = {
    "ssrfmap": inj.SSRFMAP,
    "sstimap": inj.SSTIMAP,
    "commix": inj.COMMIX,
    "smuggler": inj.SMUGGLER,
    "nosqli": inj.NOSQLI,
}

#: MCP tool name -> (underlying binary, kwargs that drive it, output that reads
#: as a hit for that tool).
PROBES: dict[str, dict[str, Any]] = {
    "ssrf_probe": {
        "binary": "ssrfmap",
        "kwargs": {"target": "https://www.example.com/fetch?url=https://example.org/", "parameter": "url"},
        "hit": ["[00:00:01] IP:127.0.0.1  , Found open      port n°6379"],
    },
    "ssti_probe": {
        "binary": "sstimap",
        "kwargs": {"target": "https://www.example.com/greet?name=bob", "injection_points": "QB",
                   "level": 2, "engine": "jinja2"},
        "hit": ["SSTImap identified the following injection point:", "Engine: Jinja2",
                "Injection: *", "Context: text", "OS: linux"],
    },
    "cmdi_probe": {
        "binary": "commix",
        "kwargs": {"target": "https://www.example.com/ping?addr=127.0.0.1", "parameter": "addr",
                   "level": 2},
        "hit": ["[+] The (GET) 'addr' parameter appears to be injectable via "
                "(results-based) classic command injection technique."],
    },
    "smuggling_probe": {
        "binary": "smuggler",
        "kwargs": {"target": "https://www.example.com/login", "method": "POST"},
        "hit": ["[CRITICAL] Potential CLTE Issue Found - POST @ https://www.example.com/login"],
    },
    "nosqli_probe": {
        "binary": "nosqli",
        # One body pair, not a body: '&' is hard-denied for every argument value
        # in EasyHunt and no policy may relax it.
        "kwargs": {"target": "https://www.example.com/login?user=alice", "data": "user=alice"},
        "hit": ["Injection Found!", "Error based NoSQL Injection", "Parameter: user"],
    },
}


def approve(engagement, tool: str) -> None:
    """These are exploit-mode tools; the gate is real and must be satisfied."""
    engagement.approval.backend = PolicyBackend(auto_approve=[tool])


def capture(monkeypatch, *, ran: bool = True, values: list[str] | None = None) -> dict[str, Any]:
    """Intercept run_one, recording the argv the wrapper actually built."""
    seen: dict[str, Any] = {}

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        seen["tool"] = name
        seen["argv"] = list(argv)
        seen["kwargs"] = kwargs
        if not ran:
            return ToolRun(tool=name, ran=False, error="not installed")
        return ToolRun(tool=name, ran=True, values=list(values or []), exit_code=0)

    monkeypatch.setattr(inj, "run_one", fake_run_one)
    return seen


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


class TestRegistration:
    """The defect being fixed: installed, specced, and still unreachable."""

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_tool_is_registered(self, name: str) -> None:
        assert name in REGISTRY, f"{name} is not on the MCP surface"

    @pytest.mark.parametrize("binary", sorted(SPECS))
    async def test_binary_is_in_the_catalog(self, binary: str) -> None:
        # Without a CATALOG entry `easyhunt doctor` never looks at the tool, which
        # is how a present-but-broken binary ships unnoticed.
        assert CATALOG.get(binary) is SPECS[binary]

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_mode_is_gated(self, name: str) -> None:
        # Every one of these sends attack payloads. None may run unattended.
        assert REGISTRY[name].mode in {"aggressive", "exploit"}

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_wrapper_declares_its_spec(self, name: str) -> None:
        # spec= is what makes the license and binary show up in the report's tool
        # inventory, and what gives caller arguments the policy's relaxed_chars.
        assert REGISTRY[name].spec is SPECS[PROBES[name]["binary"]]

    async def test_approval_is_not_bypassed(self, engagement) -> None:
        from easyhunt.errors import ApprovalDenied

        # The config fixture's backend denies everything.
        with pytest.raises(ApprovalDenied):
            await inj.smuggling_probe(target="https://www.example.com/login")


# --------------------------------------------------------------------------- #
# 1. The argv each wrapper builds must pass its own policy
# --------------------------------------------------------------------------- #


class TestArgvPassesItsOwnSanitizer:
    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_real_argv_survives_sanitize_argv(self, engagement, monkeypatch, name: str) -> None:
        probe = PROBES[name]
        approve(engagement, name)
        seen = capture(monkeypatch)

        result = await REGISTRY[name].fn(**probe["kwargs"])
        assert result["ok"] is True

        spec = SPECS[probe["binary"]]
        assert seen["tool"] == spec.name
        # The assertion that matters: the exact vector the wrapper hands to
        # run_one is accepted by the policy registered for that tool.
        assert sanitize_argv(spec.name, seen["argv"], policy=spec.arg_policy) == seen["argv"]

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_workspace_paths_are_accepted(self, engagement, monkeypatch, name: str) -> None:
        """Paths generated into the engagement workspace must match the policy.

        pytest's tmp_path carries the test id, so a value pattern that is too
        narrow fails here and nowhere else until an operator hits it.
        """
        probe = PROBES[name]
        approve(engagement, name)
        seen = capture(monkeypatch)
        await REGISTRY[name].fn(**probe["kwargs"])

        spec = SPECS[probe["binary"]]
        workspace = str(engagement.workspace)
        for item in seen["argv"]:
            if item.startswith(workspace):
                sanitize_value(item, tool=spec.name, relaxed_chars=spec.arg_policy.relaxed_chars)

    @pytest.mark.parametrize(
        "name", [n for n in sorted(SPECS) if SPECS[n].user_agent_flag is not None]
    )
    async def test_tagged_user_agent_is_not_rejected(self, engagement, name: str) -> None:
        """guarded_run injects 'EasyHunt-AI/2.0 (authorized-testing)'.

        The parentheses are soft-denied globally, so a policy that does not relax
        them cannot carry the engagement's own attribution string.
        """
        spec = SPECS[name]
        agent = engagement.scope.rules.user_agent
        sanitize_value(agent, name=spec.user_agent_flag, tool=name,
                       relaxed_chars=spec.arg_policy.relaxed_chars)

    async def test_ssrfmap_request_file_is_a_parsable_raw_request(self, engagement, monkeypatch) -> None:
        approve(engagement, "ssrf_probe")
        seen = capture(monkeypatch)
        result = await inj.ssrf_probe(
            target="https://www.example.com/fetch?next=1", parameter="url"
        )

        from pathlib import Path

        request = Path(result["request_file"]).read_text(encoding="utf-8")
        lines = request.splitlines()
        # ssrfmap's Requester parses "METHOD path HTTP/x" then 'Name: value'
        # headers, and indexes self.headers['Host'] unconditionally.
        assert lines[0].startswith("GET /fetch?") and lines[0].endswith("HTTP/1.1")
        assert "url=" in lines[0], "the parameter -p names must exist in the request"
        assert "Host: www.example.com" in lines
        assert str(request) and "-r" in seen["argv"]


# --------------------------------------------------------------------------- #
# 2. Value-less flags are declared, and dangerous flags are refused
# --------------------------------------------------------------------------- #


class TestBooleanFlagsAreDeclared:
    """A flag missing from boolean_flags swallows the argument after it."""

    @pytest.mark.parametrize("name", sorted(SPECS))
    async def test_boolean_flags_are_also_allowed(self, name: str) -> None:
        policy = SPECS[name].arg_policy
        assert policy.boolean_flags <= policy.allowed_flags

    @pytest.mark.parametrize("name", sorted(SPECS))
    async def test_boolean_flags_take_no_numeric_cap_or_pattern(self, name: str) -> None:
        policy = SPECS[name].arg_policy
        for flag in policy.boolean_flags:
            assert flag not in policy.value_patterns
            assert flag not in policy.numeric_caps

    @pytest.mark.parametrize(
        ("tool", "argv"),
        [
            # If --ssl or -v were treated as value-taking they would eat the flag
            # that follows and leave a bare positional, which is refused.
            ("ssrfmap", ["--ssl", "-p", "url", "-m", "portscan"]),
            ("ssrfmap", ["-v", "-p", "url", "-m", "portscan"]),
            ("nosqli", ["scan", "--insecure", "--https", "--target", "https://www.example.com/"]),
            ("smuggler", ["-x", "-q", "--no-color", "-u", "https://www.example.com/"]),
            ("sstimap", ["--no-color", "--verify-ssl", "-u", "https://www.example.com/"]),
            ("commix", ["--batch", "--smart", "--skip-waf", "-u", "https://www.example.com/"]),
        ],
    )
    async def test_value_less_flag_does_not_swallow_the_next_argument(
        self, tool: str, argv: list[str]
    ) -> None:
        assert sanitize_argv(tool, argv, policy=SPECS[tool].arg_policy) == argv


#: Every flag here turns a detector into an exploit, a data thief, or a way to
#: put a host on the wire that the scope engine never saw.
DANGEROUS: list[tuple[str, str]] = [
    # ssrfmap: reverse shell handler and its listener coordinates.
    ("ssrfmap", "-l"),
    ("ssrfmap", "--lhost"),
    ("ssrfmap", "--lport"),
    # ssrfmap: file read out of the victim, and a domain nobody scope-checked.
    ("ssrfmap", "--rfiles"),
    ("ssrfmap", "--ldomain"),
    ("ssrfmap", "--proxy"),
    # sstimap: the entire "payload" section — shells, eval, upload, download.
    ("sstimap", "-s"),
    ("sstimap", "--os-shell"),
    ("sstimap", "-S"),
    ("sstimap", "--os-cmd"),
    ("sstimap", "-x"),
    ("sstimap", "--eval-shell"),
    ("sstimap", "-X"),
    ("sstimap", "--eval-code"),
    ("sstimap", "-T"),
    ("sstimap", "--tpl-code"),
    ("sstimap", "-B"),
    ("sstimap", "--bind-shell"),
    ("sstimap", "-R"),
    ("sstimap", "--reverse-shell"),
    ("sstimap", "-U"),
    ("sstimap", "--upload"),
    ("sstimap", "-D"),
    ("sstimap", "--download"),
    ("sstimap", "--proxy"),
    ("sstimap", "--load-urls"),
    ("sstimap", "--crawl"),
    # commix: OS command execution, shellshock, and local RCE via --alert.
    ("commix", "--os-cmd"),
    ("commix", "--os-shell"),
    ("commix", "--shellshock"),
    ("commix", "--alert"),
    ("commix", "--alter-shell"),
    ("commix", "--msf-path"),
    # commix: enumeration and file access on the target host.
    ("commix", "--all"),
    ("commix", "--passwords"),
    ("commix", "--users"),
    ("commix", "--privileges"),
    ("commix", "--sys-info"),
    ("commix", "--file-read"),
    ("commix", "--file-write"),
    ("commix", "--file-dest"),
    ("commix", "--web-root"),
    # commix: targets sourced past the scope engine.
    ("commix", "-m"),
    ("commix", "-r"),
    ("commix", "-x"),
    ("commix", "--crawl"),
    # commix: attribution and evasion.
    ("commix", "--tor"),
    ("commix", "--proxy"),
    ("commix", "--random-agent"),
    ("commix", "--tamper"),
    # smuggler: Host rewriting is scope evasion; a payload config is an unvetted
    # mutation set chosen by an argument.
    ("smuggler", "-v"),
    ("smuggler", "--vhost"),
    ("smuggler", "-c"),
    ("smuggler", "--configfile"),
    # nosqli: proxy and request-file targets.
    ("nosqli", "-p"),
    ("nosqli", "--proxy"),
    ("nosqli", "-r"),
    ("nosqli", "--request"),
    ("nosqli", "--config"),
]


class TestDangerousFlagsAreRefused:
    @pytest.mark.parametrize(("tool", "flag"), DANGEROUS, ids=[f"{t}{f}" for t, f in DANGEROUS])
    async def test_flag_is_denied(self, tool: str, flag: str) -> None:
        policy = SPECS[tool].arg_policy
        with pytest.raises(SanitizeError):
            sanitize_argv(tool, [flag, "x"], policy=policy)

    @pytest.mark.parametrize(("tool", "flag"), DANGEROUS, ids=[f"{t}{f}" for t, f in DANGEROUS])
    async def test_flag_is_not_quietly_on_the_allowlist(self, tool: str, flag: str) -> None:
        policy = SPECS[tool].arg_policy
        assert flag not in policy.allowed_flags
        assert flag in policy.denied_flags or flag in GLOBAL_DENIED_FLAGS

    @pytest.mark.parametrize("tool", sorted(SPECS))
    async def test_allowlist_and_denylist_do_not_overlap(self, tool: str) -> None:
        policy = SPECS[tool].arg_policy
        assert not (policy.allowed_flags & policy.denied_flags)

    @pytest.mark.parametrize("tool", sorted(SPECS))
    async def test_no_globally_denied_flag_is_allowed(self, tool: str) -> None:
        policy = SPECS[tool].arg_policy
        assert not (policy.allowed_flags & set(GLOBAL_DENIED_FLAGS))

    async def test_a_traceback_is_not_a_clean_scan(self, engagement, monkeypatch) -> None:
        """sstimap crashed at import and the wrapper called the target clean.

        The container root is read-only and sstimap's utils/config.py calls
        os.makedirs("~/.sstimap") at module scope. It exited 1 — which is inside
        allow_codes, because these tools exit 1 for "found nothing" too — and
        fifteen lines of Python traceback went through the hit-pattern parse. No
        pattern matches a traceback, so ssti_probe reported "No template
        evaluation detected" in 0.6 seconds against an endpoint that renders
        {{7*7}} as 49.
        """
        approve(engagement, "ssti_probe")
        capture(monkeypatch, values=[
            "Traceback (most recent call last):",
            'File "/opt/sstimap/utils/config.py", line 58, in <module>',
            "OSError: [Errno 30] Read-only file system: '/root/.sstimap/'",
        ])
        result = await inj.ssti_probe(target="https://www.example.com/ssti?q=1")

        assert result["ok"] is False
        assert result["status"] == "UNTESTED"
        assert result["error"] == "tool_crashed"
        assert result["complete"] is False
        assert result["findings"] == []
        assert "UNTESTED, not clean" in result["message"]

    @pytest.mark.parametrize(
        "probe,kwargs",
        [
            ("ssrf_probe", {"target": "https://www.example.com/?url=1"}),
            ("ssti_probe", {"target": "https://www.example.com/?q=1"}),
            ("cmdi_probe", {"target": "https://www.example.com/?cmd=1"}),
            ("smuggling_probe", {"target": "https://www.example.com/"}),
            ("nosqli_probe", {"target": "https://www.example.com/"}),
        ],
    )
    async def test_every_probe_detects_a_crash(
        self, engagement, monkeypatch, probe: str, kwargs: dict
    ) -> None:
        """One wrapper being careful is not the fix; the class is."""
        approve(engagement, probe)
        capture(monkeypatch, values=[
            "Traceback (most recent call last):",
            "ModuleNotFoundError: No module named 'requests'",
        ])
        result = await getattr(inj, probe)(**kwargs)
        assert result["error"] == "tool_crashed", probe
        assert result["findings"] == [], probe

    async def test_ssrf_saturated_oracle_raises_no_finding(
        self, engagement, monkeypatch
    ) -> None:
        """1,989 open loopback ports is a fact about the scanner, not the target.

        Measured against the validation target — a Next.js site behind Vercel and Cloudflare
        with no `url` parameter at all. ssrfmap's portscan module calls a port
        open when the response differs from a baseline, so a target whose
        responses already vary saturates it and every port reads as open. It was
        emitted as a HIGH severity SSRF candidate.
        """
        approve(engagement, "ssrf_probe")
        noise = [
            f"[13:03:43] IP:127.0.0.1   , Found open      port n\u00b0{port}"
            for port in range(9000, 9200)
        ] + [f"[13:03:43] Checking port n\u00b0{port}" for port in range(9000, 9400)]
        capture(monkeypatch, values=noise)
        result = await inj.ssrf_probe(target="https://www.example.com/?url=1", parameter="url")

        assert result["findings"] == []
        assert result["oracle_saturated"] is True
        assert result["complete"] is False
        assert result["status"] == "INCONCLUSIVE"
        assert result["ports_reported_open"] == 200
        # And it must not read as clean either.
        assert "INCONCLUSIVE" in result["note"]
        assert "oob_listener" in result["note"]

    async def test_ssrf_a_credible_port_count_still_reports(
        self, engagement, monkeypatch
    ) -> None:
        """The guard must not swallow the bug it exists to make legible."""
        approve(engagement, "ssrf_probe")
        capture(monkeypatch, values=[
            "[13:03:43] IP:127.0.0.1   , Found open      port n\u00b06379",
            "[13:03:43] IP:127.0.0.1   , Found open      port n\u00b08080",
        ] + [f"[13:03:43] Checking port n\u00b0{port}" for port in range(1, 400)])
        result = await inj.ssrf_probe(target="https://www.example.com/?url=1", parameter="url")

        assert len(result["findings"]) == 1
        assert result["oracle_saturated"] is False
        assert result["complete"] is True
        assert result["findings"][0]["severity"] == "high"

    async def test_ssrfmap_exploitation_modules_are_refused(self) -> None:
        """The module is the payload: redis writes a key, aws reads IAM creds."""
        policy = inj.SSRFMAP.arg_policy
        for module in ("redis", "readfiles", "aws", "gce", "socksproxy", "networkscan",
                       "mysql", "smbhash", "zabbix", "docker", "custom"):
            with pytest.raises(SanitizeError):
                sanitize_argv("ssrfmap", ["-m", module], policy=policy)
        assert sanitize_argv("ssrfmap", ["-m", "portscan"], policy=policy)

    async def test_commix_file_based_technique_is_refused(self) -> None:
        """'f' writes a file into the target's web root to read output back."""
        policy = inj.COMMIX.arg_policy
        with pytest.raises(SanitizeError):
            sanitize_argv("commix", ["--technique", "f"], policy=policy)
        with pytest.raises(SanitizeError):
            sanitize_argv("commix", ["--technique", "cetf"], policy=policy)
        assert sanitize_argv("commix", ["--technique", "cet"], policy=policy)

    async def test_ssrfmap_level_is_capped(self) -> None:
        """level>1 multiplies an 8,282-entry port list across a host range."""
        with pytest.raises(SanitizeError):
            sanitize_argv("ssrfmap", ["--level", "5"], policy=inj.SSRFMAP.arg_policy)

    async def test_shell_metacharacters_are_still_refused(self) -> None:
        with pytest.raises(SanitizeError):
            sanitize_argv(
                "commix", ["-u", "https://www.example.com/?a=1;id"], policy=inj.COMMIX.arg_policy
            )

    async def test_a_bare_hostname_is_not_a_target(self, engagement, monkeypatch) -> None:
        approve(engagement, "smuggling_probe")
        capture(monkeypatch)
        with pytest.raises(ValueError, match="absolute http"):
            await inj.smuggling_probe(target="www.example.com")

    async def test_multi_parameter_url_is_refused_with_a_useful_reason(
        self, engagement, monkeypatch
    ) -> None:
        """'&' is in HARD_DENY_CHARS, which has no per-tool relaxation path.

        A two-parameter URL therefore cannot reach any tool in this project. It
        is caught up front so the operator gets the rule rather than a
        "shell control character" error from four layers down.
        """
        approve(engagement, "cmdi_probe")
        capture(monkeypatch)
        with pytest.raises(ValueError, match="more than one query parameter"):
            await inj.cmdi_probe(target="https://www.example.com/p?a=1&b=2")

    @pytest.mark.parametrize("tool", ["commix", "nosqli", "sstimap"])
    async def test_body_flags_do_not_pretend_to_accept_an_ampersand(self, tool: str) -> None:
        """A body pattern that permits '&' is a lie about what can be passed.

        ``sanitize_value`` refuses the value before the pattern is consulted, so
        a permissive pattern only misleads whoever reads the policy. The shared
        ``common.URL_PATTERN`` does contain '&' and is deliberately left alone —
        it is not this module's to redefine, and ``_http_target`` catches the
        case up front instead.
        """
        patterns = SPECS[tool].arg_policy.value_patterns
        for flag in ("-d", "--data"):
            if flag in patterns:
                assert patterns[flag] is inj.BODY_PAIR
                assert "&" not in patterns[flag].pattern

    async def test_url_shape_is_not_sufficient_permission(self) -> None:
        """Matching URL_PATTERN does not exempt a value from sanitize_value.

        This test previously asserted that a multi-parameter URL was refused,
        because '&' was hard-denied with no relaxation path. That denial was
        wrong: tool argv goes to create_subprocess_exec, so there is no shell to
        interpret '&', and refusing it blocked most real targets. '&' is now
        permitted inside the query of a well-formed http(s) URL and nowhere else.

        The original point still stands and is what this now checks: passing
        URL_PATTERN is not permission on its own, because every value is still
        sanitized afterwards.
        """
        from easyhunt.tools.common import URL_PATTERN

        multi_param = "https://www.example.com/p?a=1&b=2"
        assert URL_PATTERN.fullmatch(multi_param)
        # Accepted now — this is the capability the old denial cost us.
        sanitize_argv("smuggler", ["-u", multi_param], policy=inj.SMUGGLER.arg_policy)

        # But the sanitizer still governs: a URL-shaped value carrying a genuine
        # shell metacharacter is refused even though the pattern matches.
        for hostile in (
            "https://www.example.com/p?a=1;id",
            "https://www.example.com/p?a=1|id",
            "https://www.example.com/p?a=1&&b=2",
        ):
            with pytest.raises(SanitizeError):
                sanitize_argv("smuggler", ["-u", hostile], policy=inj.SMUGGLER.arg_policy)

    async def test_nosqli_multi_parameter_body_never_reaches_the_tool(
        self, engagement, monkeypatch
    ) -> None:
        """The decorator sanitizes caller arguments before the body runs.

        ``data`` is not the targets argument, so ``'&'`` is refused by the
        control plane one layer above this module — the wrapper's own shape check
        never gets the chance. Asserting the real boundary, not the one it would
        be tidier to own.
        """
        approve(engagement, "nosqli_probe")
        seen = capture(monkeypatch)
        with pytest.raises(SanitizeError):
            await inj.nosqli_probe(target="https://www.example.com/login", data="user=alice&pass=x")
        assert "argv" not in seen, "the tool must not be invoked at all"

    async def test_nosqli_rejects_a_malformed_body_pair(self, engagement, monkeypatch) -> None:
        approve(engagement, "nosqli_probe")
        capture(monkeypatch)
        result = await inj.nosqli_probe(
            target="https://www.example.com/login", data="user=al ice"
        )
        assert result["ok"] is False
        assert result["error"] == "bad_data"


# --------------------------------------------------------------------------- #
# 3. Absence reports UNTESTED
# --------------------------------------------------------------------------- #


class TestAbsenceIsNotACleanResult:
    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_missing_tool_reports_untested(self, engagement, monkeypatch, name: str) -> None:
        approve(engagement, name)
        capture(monkeypatch, ran=False)

        result = await REGISTRY[name].fn(**PROBES[name]["kwargs"])

        assert result["ok"] is False
        assert result["error"] == "tool_unavailable"
        assert result["untested"] is True
        assert "UNTESTED, not clean." in result["message"]
        # And nothing that could read as a tested-and-sound result.
        assert "findings" not in result
        assert result.get("count") is None

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_missing_tool_records_no_findings(self, engagement, monkeypatch, name: str) -> None:
        approve(engagement, name)
        capture(monkeypatch, ran=False)
        await REGISTRY[name].fn(**PROBES[name]["kwargs"])
        assert engagement.findings.all() == []

    async def test_commix_identity_marker_rejects_the_pypi_impostor(self) -> None:
        """PyPI's `commix` is not commixproject/commix.

        The container installs it with `uv tool install commix`, which fetches a
        2019 package whose whole CLI is a banner and an installer for the real
        tool. Both print the string "commix", so only a marker unique to the real
        tool separates them — without it, the impostor resolves as commix and
        every scan returns "no injection found" for a tool that never ran.
        """
        assert inj.COMMIX.identity_marker == "--shellshock"

    @pytest.mark.parametrize("name", sorted(SPECS))
    async def test_every_spec_has_an_identity_marker(self, name: str) -> None:
        assert SPECS[name].identity_marker, (
            f"{name} resolves by PATH order alone; a same-named binary would run silently"
        )


# --------------------------------------------------------------------------- #
# Findings are candidates, never confirmed
# --------------------------------------------------------------------------- #


class TestFindingsAreCandidates:
    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_a_hit_produces_exactly_one_candidate(
        self, engagement, monkeypatch, name: str
    ) -> None:
        probe = PROBES[name]
        approve(engagement, name)
        capture(monkeypatch, values=probe["hit"])

        result = await REGISTRY[name].fn(**probe["kwargs"])

        assert result["ok"] is True
        assert result["count"] == 1, f"{name} did not recognise its own tool's hit output"
        finding = engagement.findings.all()[0]
        assert finding.status is Status.CANDIDATE
        assert finding.poc is None
        assert finding.validated is False

    @pytest.mark.parametrize("name", sorted(PROBES))
    async def test_no_hit_produces_no_finding(self, engagement, monkeypatch, name: str) -> None:
        approve(engagement, name)
        capture(monkeypatch, values=["nothing interesting here", "scan complete"])

        result = await REGISTRY[name].fn(**PROBES[name]["kwargs"])

        assert result["ok"] is True
        assert result["count"] == 0
        assert engagement.findings.all() == []

    async def test_a_candidate_cannot_be_promoted_by_this_module(
        self, engagement, monkeypatch
    ) -> None:
        approve(engagement, "cmdi_probe")
        capture(monkeypatch, values=PROBES["cmdi_probe"]["hit"])
        await REGISTRY["cmdi_probe"].fn(**PROBES["cmdi_probe"]["kwargs"])

        finding = engagement.findings.all()[0]
        assert finding.status is not Status.CONFIRMED
        assert any("Candidate only" in note for note in finding.triage_notes)


class TestSsrfmapIsUngovernable:
    """ssrfmap cannot be rate-limited, and must not look as though it can.

    The engagement limiter charges one token per *tool call*. ssrfmap then walks
    an 8,282-entry port list through `ThreadPoolExecutor(max_workers=None)`. A
    measured call took 305 seconds and the limiter saw a single request.

    Bounding it was considered and is not possible through any supported
    interface. Its complete argparse definition is
    `-r -p -m -l -v --lhost --lport --ldomain --rfiles --uagent --ssl --proxy
    --level --logfile` — no rate, delay, thread or concurrency flag exists.
    Staging a shorter `data/ports` beside the process does not work either:
    `core/ssrf` calls `os.chdir` to its own install directory before loading a
    module, so the path resolves inside the tool's own tree regardless of cwd.

    So the honest response is to make the cost visible everywhere it matters,
    and these tests are what stop that quietly eroding.
    """

    async def test_estimated_requests_is_the_real_port_count(self) -> None:
        """8,282 ports plus the baseline request. Not a round number, on purpose.

        `estimated_requests` is not documentation: `budget.check` refuses the
        call when that many requests do not remain, and charges them afterwards.
        Trimming it to make a run "fit" restores the silent overspend it exists
        to prevent.
        """
        from easyhunt.tools.base import REGISTRY

        assert inj.SSRFMAP_REQUEST_COST == 8283
        assert REGISTRY["ssrf_probe"].estimated_requests == inj.SSRFMAP_REQUEST_COST

    async def test_the_budget_refuses_a_call_it_cannot_afford(self, engagement) -> None:
        """The number has to bite, or it is a comment with extra steps."""
        from easyhunt.errors import BudgetExceeded

        engagement.budget.limits.max_requests = 2000
        with pytest.raises(BudgetExceeded):
            engagement.budget.check(need_requests=inj.SSRFMAP_REQUEST_COST)

    async def test_risk_notes_say_it_cannot_be_throttled(self) -> None:
        """An operator approving this must be told before, not after."""
        from easyhunt.tools.base import REGISTRY

        notes = " ".join(REGISTRY["ssrf_probe"].risk_notes).lower()
        assert "no rate" in notes
        assert "one call" in notes or "single call" in notes

    async def test_the_result_reports_traffic_the_limiter_never_saw(
        self, engagement, monkeypatch
    ) -> None:
        """A report that omits this claims the run stayed inside its ceiling."""
        approve(engagement, "ssrf_probe")
        capture(monkeypatch, values=["[13:03:43] Checking port n°80"])
        result = await inj.ssrf_probe(target="https://www.example.com/?url=1", parameter="url")

        assert "rate_note" in result
        assert str(inj.SSRFMAP_REQUEST_COST) in result["rate_note"]
        assert "could not throttle" in result["rate_note"]

    async def test_level_stays_capped_so_the_port_list_is_walked_once(self) -> None:
        """--level is the one multiplier that IS bounded.

        ssrfmap generates a host range from the level, and walks the whole port
        list per host. Level 1 is one host; level 5 would be 8,282 requests
        several times over.
        """
        from easyhunt.control_plane.sanitize import get_policy

        assert get_policy("ssrfmap").numeric_caps["--level"] == 1


class TestUsageErrorsAreCrashesNotCleanScans:
    """A tool that rejected its own arguments has not tested anything.

    commix parses --delay with optparse's int type. Given "0.02" — which is what
    a 50 rps ceiling implies — it prints

        commix.py: error: option --delay: invalid integer value: '0.02'

    and EXITS 0. The wrapper saw ran=True, exit=0, two lines of output, no hit
    pattern matched, and reported "commix found no injectable parameter with
    classic, eval or time-based techniques". Measured against a live target:
    0.8 seconds before, 120.6 seconds of real testing after.

    The rate fix that introduced it was correct in intent — derive the delay from
    the engagement rather than hardcode it — and wrong in type.
    """

    async def test_a_usage_error_is_not_a_clean_scan(self, engagement, monkeypatch) -> None:
        approve(engagement, "cmdi_probe")
        capture(monkeypatch, values=[
            "Usage: python commix.py [option(s)]",
            "commix.py: error: option --delay: invalid integer value: '0.02'",
        ])
        result = await inj.cmdi_probe(target="https://www.example.com/?cmd=1")

        assert result["ok"] is False
        assert result["error"] == "tool_crashed"
        assert result["findings"] == []

    @pytest.mark.parametrize("rps", [0.5, 2, 20, 50])
    async def test_commix_delay_is_always_an_integer(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        """Whatever the ceiling implies, commix must be able to parse it."""
        engagement.scope.rules.max_rps = rps
        seen = capture(monkeypatch)
        approve(engagement, "cmdi_probe")
        await inj.cmdi_probe(target="https://www.example.com/?cmd=1")

        argv = seen["argv"]
        delay = argv[argv.index("--delay") + 1]
        assert "." not in delay, f"commix rejects a non-integer delay, got {delay!r}"
        int(delay)

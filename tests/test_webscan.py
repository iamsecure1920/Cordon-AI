"""Web-application scanner wrappers.

Three behaviours are load-bearing and each has a history behind it:

* the argv every wrapper builds must survive that wrapper's own sanitizer — the
  policy and the command are written in the same file and drift apart silently;
* a bounded or killed scan must report INCOMPLETE, because this project has shot
  itself three times by rendering a timed-out scan as a clean result;
* a missing binary must report UNTESTED, never zero findings.

The boolean-flag tests are the ones worth keeping honest. ``ArgPolicy`` treats
any allowed flag that is not in ``boolean_flags`` as value-taking, so a missing
entry makes the sanitizer swallow the following argument — the bug that left
``retire`` un-runnable for the project's entire life.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.sanitize import sanitize_argv
from easyhunt.errors import EasyHuntError, SanitizeError
from easyhunt.knowledge.findings import Severity
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools import webscan as ws
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import CATALOG, ToolRun

# The rest of the tool surface, so cross-module claims (whatweb's spec lives in
# http_probe) are checked against the real catalog.
load_capabilities()

WRAPPERS = (
    "tls_audit", "cors_audit", "graphql_audit", "jwt_inspect",
    "websocket_probe", "nikto_scan", "wapiti_scan",
)

SPEC_NAMES = ("nikto", "testssl", "wapiti", "graphql-cop", "corscanner", "jwt_tool", "websocat")

# A syntactically valid HS256 token. Nothing is signed with a real secret.
SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

ALG_NONE_JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."


def _spy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ran: bool = True,
    values: tuple[str, ...] = (),
    error: str | None = None,
    duration_s: float = 1.0,
    report: Any = None,
    report_flag: str | None = None,
) -> list[dict[str, Any]]:
    """Replace ``run_one`` and record what each wrapper asked for.

    The stand-in runs the real sanitizer over the argv it is handed, so every
    test that exercises a wrapper also proves that wrapper's command line is
    acceptable to its own policy. ``report``/``report_flag`` write a fake tool
    report to whatever output path the wrapper chose.
    """
    calls: list[dict[str, Any]] = []

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        spec = CATALOG[name]
        sanitize_argv(name, list(argv), policy=spec.arg_policy)
        calls.append({"tool": name, "argv": list(argv), **kwargs})
        if report is not None and report_flag is not None and report_flag in argv:
            path = Path(argv[argv.index(report_flag) + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report), encoding="utf-8")
        return ToolRun(
            tool=name, ran=ran, values=list(values), error=error, duration_s=duration_s
        )

    monkeypatch.setattr(ws, "run_one", fake_run_one)
    return calls


def _approve(engagement: Any, *tools: str) -> None:
    engagement.approval.backend = PolicyBackend(auto_approve=list(tools))


# --------------------------------------------------------------------------- #
# Registration — the actual bug being fixed
# --------------------------------------------------------------------------- #


class TestRegistration:
    def test_every_tool_is_catalogued(self) -> None:
        # Absence from CATALOG is why `easyhunt doctor` had no opinion about
        # nikto and testssl while both were shipping broken.
        for name in SPEC_NAMES:
            assert name in CATALOG, f"{name} is installed but not catalogued"

    def test_every_tool_is_reachable_as_an_mcp_tool(self) -> None:
        for name in WRAPPERS:
            assert name in REGISTRY, f"{name} is not registered with the MCP server"

    def test_every_spec_has_a_policy_and_a_licence(self) -> None:
        for name in SPEC_NAMES:
            spec = CATALOG[name]
            assert spec.arg_policy is not None, f"{name} has no argument policy"
            assert spec.license != "unknown", f"{name} has no recorded licence"
            assert spec.homepage.startswith("https://")

    def test_whatweb_is_not_duplicated(self) -> None:
        # whatweb already has a spec in http_probe; a second one would mean two
        # policies for one binary and no way to tell which is enforced.
        assert "whatweb" not in {s.name for s in ws.WEBSCAN_SPECS}
        assert CATALOG["whatweb"].arg_policy is not None


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #


class TestModes:
    @pytest.mark.parametrize(
        "name", ["tls_audit", "cors_audit", "graphql_audit", "jwt_inspect", "websocket_probe"]
    )
    def test_observational_tools_are_passive(self, name: str) -> None:
        assert REGISTRY[name].mode == "passive"

    @pytest.mark.parametrize("name", ["nikto_scan", "wapiti_scan"])
    def test_noisy_scanners_are_gated(self, name: str) -> None:
        tool = REGISTRY[name]
        assert tool.mode == "aggressive"
        assert tool.risk_notes, "an approval prompt with no risk notes tells the human nothing"

    async def test_aggressive_scanners_refuse_without_approval(self, engagement) -> None:
        # The conftest engagement denies by default; that must be enough to stop
        # a scan, with no fallback path.
        for name in ("nikto_scan", "wapiti_scan"):
            with pytest.raises(EasyHuntError):
                await REGISTRY[name].fn(target="https://example.com/")

    def test_jwt_inspection_costs_no_requests(self) -> None:
        # It decodes a string. If it ever grows a network path this must fail.
        assert REGISTRY["jwt_inspect"].estimated_requests == 0


# --------------------------------------------------------------------------- #
# Boolean flags — the retire-class bug
# --------------------------------------------------------------------------- #


class TestBooleanFlags:
    @pytest.mark.parametrize(
        ("tool", "flag"),
        [
            ("nikto", "-nointeractive"), ("nikto", "-nocheck"), ("nikto", "-ssl"),
            ("nikto", "-nossl"), ("nikto", "-no404"), ("nikto", "-followredirects"),
            ("nikto", "-nocookies"), ("nikto", "-noslash"),
            ("testssl", "--quiet"), ("testssl", "--protocols"), ("testssl", "--headers"),
            ("testssl", "--fs"), ("testssl", "--server-defaults"), ("testssl", "--ids-friendly"),
            ("testssl", "--server-preference"), ("testssl", "--std"), ("testssl", "-4"),
            ("wapiti", "--no-bugreport"), ("wapiti", "--flush-session"), ("wapiti", "--color"),
            ("websocat", "-v"), ("websocat", "-u"), ("websocat", "-1"),
            ("websocat", "-n"), ("websocat", "-q"), ("websocat", "-E"),
        ],
    )
    def test_valueless_flags_are_declared_boolean(self, tool: str, flag: str) -> None:
        policy = CATALOG[tool].arg_policy
        assert policy is not None
        assert flag in policy.boolean_flags, (
            f"{tool} {flag} takes no value; leaving it out of boolean_flags makes "
            "the sanitizer eat the next argument"
        )

    def test_a_boolean_flag_does_not_consume_the_next_argument(self) -> None:
        # The concrete symptom: with -nointeractive mis-declared, '-Format' would
        # be read as its value and 'json' would become an unexpected positional.
        spec = CATALOG["nikto"]
        sanitize_argv(
            "nikto",
            ["-h", "https://example.com/", "-nointeractive", "-Format", "json",
             "-output", "/tmp/x.json"],
            policy=spec.arg_policy,
        )

    def test_flags_that_do_take_a_value_are_not_boolean(self) -> None:
        for tool, flag in (
            ("nikto", "-maxtime"), ("nikto", "-Tuning"), ("nikto", "-Pause"),
            ("nikto", "-useragent"), ("testssl", "--jsonfile-pretty"),
            ("testssl", "--user-agent"), ("wapiti", "--max-scan-time"),
            ("corscanner", "-d"), ("graphql-cop", "-H"), ("websocat", "--origin"),
        ):
            policy = CATALOG[tool].arg_policy
            assert policy is not None
            assert flag in policy.allowed_flags
            assert flag not in policy.boolean_flags, f"{tool} {flag} needs a value"


# --------------------------------------------------------------------------- #
# Refusals encoded in the policies
# --------------------------------------------------------------------------- #


class TestPolicyRefusals:
    def test_nikto_tuning_excludes_dos_and_every_attack_category(self) -> None:
        spec = CATALOG["nikto"]
        # The old policy required nikto's reversed selection with 6 present, so
        # denial of service was always excluded — correct as far as it went, but
        # "everything except DoS" also meant injection, command execution and SQL
        # injection were always ON, from a tool declared mode="aggressive".
        # Explicit selection now, with the attack categories absent from the
        # character class entirely.
        sanitize_argv("nikto", ["-Tuning", "123be"], policy=spec.arg_policy)
        for attack in ("x6", "x", "4", "8", "9", "0", "a", "c", "1234"):
            with pytest.raises(SanitizeError):
                sanitize_argv("nikto", ["-Tuning", attack], policy=spec.arg_policy)
        # Denial of service is unreachable in either spelling: 6 is not in the
        # character class, and the reversed form that used to carry it is gone.
        for bad in ("6", "x6b", "123456789", "x1", "123be6", ""):
            with pytest.raises(SanitizeError):
                sanitize_argv("nikto", ["-Tuning", bad], policy=spec.arg_policy)

    def test_nikto_cannot_be_pointed_at_another_config_or_evade(self) -> None:
        spec = CATALOG["nikto"]
        for flag in ("-evasion", "-config", "-Option", "-useproxy", "-mutate", "-Save"):
            with pytest.raises(SanitizeError):
                sanitize_argv("nikto", [flag, "1"], policy=spec.arg_policy)

    def test_testssl_cannot_reach_the_exploit_shaped_probes(self) -> None:
        # -H is --heartbleed, which reads server memory. A tool that calls itself
        # passive may not have a route to it.
        spec = CATALOG["testssl"]
        for flag in ("-U", "--vulnerable", "-H", "--heartbleed", "-I", "--ccs", "--BB"):
            with pytest.raises(SanitizeError):
                sanitize_argv("testssl", [flag], policy=spec.arg_policy)

    def test_testssl_cannot_run_a_supplied_openssl_or_proxy(self) -> None:
        spec = CATALOG["testssl"]
        for flag in ("--openssl", "--proxy", "--mtls", "--add-ca"):
            with pytest.raises(SanitizeError):
                sanitize_argv("testssl", [flag, "/tmp/x"], policy=spec.arg_policy)

    def test_wapiti_cannot_proxy_or_carry_credentials(self) -> None:
        spec = CATALOG["wapiti"]
        for flag in ("-p", "--proxy", "--auth-user", "--auth-password", "-C", "--jwt", "--update"):
            with pytest.raises(SanitizeError):
                sanitize_argv("wapiti", [flag, "x"], policy=spec.arg_policy)

    def test_wapiti_scan_force_cannot_be_raised_past_normal(self) -> None:
        spec = CATALOG["wapiti"]
        sanitize_argv("wapiti", ["-S", "polite"], policy=spec.arg_policy)
        for level in ("aggressive", "insane"):
            with pytest.raises(SanitizeError):
                sanitize_argv("wapiti", ["-S", level], policy=spec.arg_policy)

    def test_wapiti_scan_time_has_a_ceiling(self) -> None:
        spec = CATALOG["wapiti"]
        with pytest.raises(SanitizeError):
            sanitize_argv("wapiti", ["--max-scan-time", "86400"], policy=spec.arg_policy)

    def test_jwt_tool_cannot_forge_crack_or_replay(self) -> None:
        # jwt_tool is an attack tool. Only decoding is reachable, which is what
        # makes jwt_inspect's passive claim true rather than aspirational.
        spec = CATALOG["jwt_tool"]
        for flag in ("-t", "-M", "-X", "-T", "-I", "-S", "-C", "-ju", "-pr", "-d", "-p"):
            with pytest.raises(SanitizeError):
                sanitize_argv("jwt_tool", [SAMPLE_JWT, flag, "x"], policy=spec.arg_policy)

    def test_jwt_tool_accepts_only_a_token(self) -> None:
        spec = CATALOG["jwt_tool"]
        sanitize_argv("jwt_tool", [SAMPLE_JWT], policy=spec.arg_policy)
        with pytest.raises(SanitizeError):
            sanitize_argv("jwt_tool", ["/etc/hosts"], policy=spec.arg_policy)

    def test_websocat_cannot_become_a_local_command_runner(self) -> None:
        # websocat's address grammar includes exec:/sh-c:/cmd: specifiers and a
        # server mode. Only ws:// and wss:// URLs get past the positional shape.
        spec = CATALOG["websocat"]
        for address in ("exec:/bin/sh", "sh-c:id", "cmd:whoami", "writefile:/tmp/x", "tcp:1.2.3.4:80"):
            with pytest.raises(SanitizeError):
                sanitize_argv("websocat", [address], policy=spec.arg_policy)
        sanitize_argv("websocat", ["wss://example.com/socket"], policy=spec.arg_policy)

    def test_websocat_cannot_listen_or_ignore_certificates(self) -> None:
        spec = CATALOG["websocat"]
        for flag in ("-s", "--server-mode", "-e", "-k", "--insecure", "--oneshot"):
            with pytest.raises(SanitizeError):
                sanitize_argv("websocat", [flag], policy=spec.arg_policy)

    def test_graphql_cop_cannot_force_a_scan_or_use_tor(self) -> None:
        spec = CATALOG["graphql-cop"]
        for flag in ("-f", "--force", "-T", "--tor", "-x"):
            with pytest.raises(SanitizeError):
                sanitize_argv("graphql-cop", [flag, "x"], policy=spec.arg_policy)

    def test_corscanner_cannot_be_fed_an_arbitrary_target_list(self) -> None:
        spec = CATALOG["corscanner"]
        with pytest.raises(SanitizeError):
            sanitize_argv("corscanner", ["-i", "/etc/hosts"], policy=spec.arg_policy)

    @pytest.mark.parametrize("tool", SPEC_NAMES)
    def test_shell_metacharacters_are_refused_everywhere(self, tool: str) -> None:
        spec = CATALOG[tool]
        with pytest.raises(SanitizeError):
            sanitize_argv(tool, ["https://example.com/;id"], policy=spec.arg_policy)


# --------------------------------------------------------------------------- #
# The argv each wrapper actually builds
# --------------------------------------------------------------------------- #


class TestConstructedArgv:
    """``_spy`` sanitizes every argv it is handed, so reaching an assertion at
    all means the command line passed its own policy."""

    async def test_tls_audit_argv(self, engagement, monkeypatch) -> None:
        calls = _spy(monkeypatch, report={"scanResult": []}, report_flag="--jsonfile-pretty")
        await REGISTRY["tls_audit"].fn(target="example.com")

        argv = calls[0]["argv"]
        # testssl aborts outright with "Fatal error: URI comes last" if anything
        # follows the target, so the URI must be the final element and the spec
        # must not ask guarded_run to append a user-agent flag after it.
        assert argv[-1] == "example.com:443"
        assert CATALOG["testssl"].user_agent_flag is None
        assert "--user-agent" in argv and argv.index("--user-agent") < len(argv) - 1
        # No vulnerability battery: those probes are exploit-shaped.
        assert "-U" not in argv and "--vulnerable" not in argv

    async def test_cors_audit_argv_carries_attribution(self, engagement, monkeypatch) -> None:
        engagement.scope.rules.required_headers = ["X-Bug-Bounty: h1-tester"]
        calls = _spy(monkeypatch, report=[], report_flag="-o")
        await REGISTRY["cors_audit"].fn(target="https://app.example.com/api")

        argv = calls[0]["argv"]
        assert "-d" in argv
        joined = " ".join(argv)
        assert "User-Agent: " in joined
        assert "X-Bug-Bounty: h1-tester" in joined

    async def test_graphql_audit_sends_valid_json_headers(self, engagement, monkeypatch) -> None:
        calls = _spy(monkeypatch, values=("[]",))
        await REGISTRY["graphql_audit"].fn(target="https://example.com/graphql")

        argv = calls[0]["argv"]
        # graphql-cop's -H takes a JSON object. Handing it a bare 'Name: value'
        # string looks like attribution and sends none.
        headers = json.loads(argv[argv.index("-H") + 1])
        assert "User-Agent" in headers
        assert CATALOG["graphql-cop"].user_agent_flag is None

    async def test_graphql_audit_excludes_the_dos_family(self, engagement, monkeypatch) -> None:
        calls = _spy(monkeypatch, values=("[]",))
        await REGISTRY["graphql_audit"].fn(target="https://example.com/graphql")

        excluded = set(calls[0]["argv"][calls[0]["argv"].index("-e") + 1].split(","))
        assert {"alias_overloading", "batch_query", "circular_query_introspection"} <= excluded

    async def test_websocket_probe_upgrades_an_http_url(self, engagement, monkeypatch) -> None:
        calls = _spy(monkeypatch, values=("Connected to ws, response headers",))
        await REGISTRY["websocket_probe"].fn(target="https://example.com/socket")

        argv = calls[0]["argv"]
        assert argv[-1] == "wss://example.com/socket"
        # -u inhibits the send direction and -1 stops after one message: the
        # probe is a handshake, not traffic.
        assert "-u" in argv and "-1" in argv

    async def test_nikto_argv(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        calls = _spy(monkeypatch, report=[], report_flag="-output")
        await REGISTRY["nikto_scan"].fn(target="https://example.com/", max_minutes=5)

        argv = calls[0]["argv"]
        assert argv[argv.index("-maxtime") + 1] == "300s"
        assert argv[argv.index("-Tuning") + 1] == "123be"
        # The outer process timeout must sit above nikto's own bound, or nikto is
        # killed before it can flush the report it already built.
        assert calls[0]["timeout"] > 300

    async def test_wapiti_argv(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        calls = _spy(monkeypatch, report={"vulnerabilities": {}}, report_flag="-o")
        await REGISTRY["wapiti_scan"].fn(target="https://example.com/", max_minutes=5)

        argv = calls[0]["argv"]
        assert argv[argv.index("--max-scan-time") + 1] == "300"
        assert "--max-attack-time" in argv
        assert "--flush-session" in argv  # a resumed session re-reports old results
        assert "--no-bugreport" in argv  # never mail someone else's app upstream
        assert calls[0]["timeout"] > 300


# --------------------------------------------------------------------------- #
# Rate limits come from the engagement
# --------------------------------------------------------------------------- #


class TestRateLimitsAreNotCallerControlled:
    @pytest.mark.parametrize("name", WRAPPERS)
    def test_no_wrapper_exposes_a_rate_argument(self, name: str) -> None:
        import inspect

        params = set(inspect.signature(REGISTRY[name].fn).parameters)
        forbidden = {"rate", "rps", "max_rps", "rate_limit", "threads", "concurrency",
                     "delay", "pause", "workers", "tasks"}
        assert not (params & forbidden), (
            f"{name} lets the caller set {sorted(params & forbidden)}; a rate the "
            "agent can set is a rate the agent can raise"
        )

    async def test_nikto_pause_follows_the_engagement_rate(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        engagement.scope.rules.max_rps = 2.0
        calls = _spy(monkeypatch, report=[], report_flag="-output")
        await REGISTRY["nikto_scan"].fn(target="https://example.com/")
        argv = calls[0]["argv"]
        assert float(argv[argv.index("-Pause") + 1]) == pytest.approx(0.5)

        engagement.scope.rules.max_rps = 0.5
        calls.clear()
        await REGISTRY["nikto_scan"].fn(target="https://example.com/")
        argv = calls[0]["argv"]
        assert float(argv[argv.index("-Pause") + 1]) == pytest.approx(2.0)

    async def test_corscanner_threads_follow_the_engagement(self, engagement, monkeypatch) -> None:
        engagement.scope.rules.max_concurrency = 2
        calls = _spy(monkeypatch, report=[], report_flag="-o")
        await REGISTRY["cors_audit"].fn(target="https://example.com/")
        argv = calls[0]["argv"]
        assert argv[argv.index("-t") + 1] == "2"

    async def test_wapiti_scan_force_follows_the_engagement(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        engagement.scope.rules.max_rps = 0.5
        calls = _spy(monkeypatch, report={"vulnerabilities": {}}, report_flag="-o")
        result = await REGISTRY["wapiti_scan"].fn(target="https://example.com/")
        argv = calls[0]["argv"]
        assert argv[argv.index("-S") + 1] == "paranoid"
        # wapiti has no rps flag at all, and saying so is better than implying it
        # is rate limited when it is not.
        assert "no requests-per-second flag" in result["rate_note"]


# --------------------------------------------------------------------------- #
# Bounds and incompleteness
# --------------------------------------------------------------------------- #


class TestBoundsAndIncompleteness:
    async def test_nikto_max_minutes_is_clamped(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        calls = _spy(monkeypatch, report=[], report_flag="-output")
        await REGISTRY["nikto_scan"].fn(target="https://example.com/", max_minutes=6000)
        argv = calls[0]["argv"]
        assert argv[argv.index("-maxtime") + 1] == f"{ws.MAX_SCAN_MINUTES * 60}s"

    async def test_wapiti_max_minutes_is_clamped(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        calls = _spy(monkeypatch, report={"vulnerabilities": {}}, report_flag="-o")
        await REGISTRY["wapiti_scan"].fn(target="https://example.com/", max_minutes=6000)
        argv = calls[0]["argv"]
        assert argv[argv.index("--max-scan-time") + 1] == str(ws.MAX_SCAN_MINUTES * 60)

    async def test_killed_nikto_is_incomplete_not_clean(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        _spy(monkeypatch, ran=True, error="timed out")
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/")

        assert result["ok"] is False
        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"
        assert result["error"] == "scan_incomplete"
        assert result["items"] == 0
        assert "INCOMPLETE" in result["message"]

    async def test_nikto_hitting_its_own_bound_is_incomplete(self, engagement, monkeypatch) -> None:
        # nikto stops itself at -maxtime and still writes a report. The findings
        # are real; the coverage is not, and only one of those is obvious.
        _approve(engagement, "nikto_scan")
        _spy(
            monkeypatch,
            values=("+ ERROR: Host maximum execution time of 300 seconds reached",),
            report=[{"host": "example.com", "vulnerabilities": [
                {"id": "999", "msg": "Server leaks inodes", "url": "/", "method": "GET"}
            ]}],
            report_flag="-output",
        )
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/", max_minutes=5)

        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"
        # Partial results are still returned — incomplete does not mean discarded.
        assert result["items"] == 1
        assert "maxtime" in result["message"]

    async def test_nikto_error_limit_is_incomplete(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        _spy(
            monkeypatch,
            values=("+ ERROR: *** Error limit (20) reached for host, giving up. ***",),
            report=[{"host": "example.com", "vulnerabilities": []}],
            report_flag="-output",
        )
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/")
        assert result["complete"] is False
        assert "connection errors" in result["message"]

    async def test_completed_nikto_reports_complete(self, engagement, monkeypatch) -> None:
        _approve(engagement, "nikto_scan")
        _spy(
            monkeypatch,
            values=("+ Scan terminated: 0 errors and 1 item reported on the remote host",),
            report=[{"host": "example.com", "vulnerabilities": [
                {"id": "999", "msg": "Server leaks inodes", "url": "/", "method": "GET"}
            ]}],
            report_flag="-output",
        )
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/")
        assert result["ok"] is True
        assert result["complete"] is True
        assert result["status"] == "COMPLETE"
        assert len(result["findings"]) == 1
        # nikto rates nothing and is false-positive heavy: everything is a
        # low-confidence candidate, never a graded finding.
        stored = engagement.findings.get(result["findings"][0]["id"])
        assert stored.severity is Severity.INFO
        assert stored.confidence < 0.5

    async def test_killed_wapiti_is_incomplete_not_clean(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        _spy(monkeypatch, ran=True, error="timed out")
        result = await REGISTRY["wapiti_scan"].fn(target="https://example.com/")

        assert result["ok"] is False
        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"
        assert result["candidates"] == 0
        assert "INCOMPLETE" in result["message"]

    async def test_wapiti_using_its_whole_budget_is_incomplete(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        _spy(
            monkeypatch,
            duration_s=305.0,
            report={"vulnerabilities": {}, "anomalies": {}, "infos": {"crawled_pages_nbr": 12}},
            report_flag="-o",
        )
        result = await REGISTRY["wapiti_scan"].fn(target="https://example.com/", max_minutes=5)
        assert result["complete"] is False
        assert "max-scan-time" in result["message"]

    async def test_completed_wapiti_maps_levels_to_severity(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        _spy(
            monkeypatch,
            duration_s=5.0,
            report={
                "vulnerabilities": {
                    "SQL Injection": [
                        {"path": "https://example.com/x", "info": "injection in id",
                         "level": 3, "module": "sql", "parameter": "id",
                         "http_request": "GET /x?id=1", "curl_command": "curl ..."}
                    ]
                },
                "anomalies": {},
                "infos": {"crawled_pages_nbr": 12},
            },
            report_flag="-o",
        )
        result = await REGISTRY["wapiti_scan"].fn(target="https://example.com/", max_minutes=5)
        assert result["complete"] is True
        assert result["candidates"] == 1
        stored = engagement.findings.get(result["findings"][0]["id"])
        assert stored.severity is Severity.HIGH

    async def test_unknown_wapiti_profile_is_refused_not_guessed(self, engagement, monkeypatch) -> None:
        _approve(engagement, "wapiti_scan")
        calls = _spy(monkeypatch)
        result = await REGISTRY["wapiti_scan"].fn(target="https://example.com/", profile="everything")
        assert result["ok"] is False
        assert result["error"] == "unknown_profile"
        assert calls == [], "an unknown profile must not fall back to a default scan"

    async def test_wapiti_profiles_exclude_brute_force_modules(self) -> None:
        for modules in ws._WAPITI_PROFILES.values():
            names = set(modules.split(","))
            assert "brute_login_form" not in names
            assert "buster" not in names

    async def test_killed_testssl_is_incomplete(self, engagement, monkeypatch) -> None:
        # testssl writes its JSON only at the very end, so a kill loses
        # everything — "no entries" would otherwise read as a healthy server.
        _spy(monkeypatch, ran=True, error="timed out")
        result = await REGISTRY["tls_audit"].fn(target="example.com")
        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"
        assert "UNTESTED, not clean" in result["message"]

    async def test_killed_cors_scan_is_incomplete(self, engagement, monkeypatch) -> None:
        _spy(monkeypatch, ran=True, error="timed out")
        result = await REGISTRY["cors_audit"].fn(target="https://example.com/")
        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"

    async def test_endpoint_that_is_not_graphql_is_untested(self, engagement, monkeypatch) -> None:
        # graphql-cop prints a notice and runs nothing. The resulting empty list
        # is not a clean bill of health for a URL that was never scanned.
        _spy(
            monkeypatch,
            values=("https://example.com/graphql does not seem to be running GraphQL.", "[]"),
        )
        result = await REGISTRY["graphql_audit"].fn(target="https://example.com/graphql")
        assert result["ok"] is False
        assert result["status"] == "UNTESTED"
        assert result["error"] == "not_graphql"


# --------------------------------------------------------------------------- #
# Absence
# --------------------------------------------------------------------------- #


class TestAbsenceIsUntested:
    @pytest.mark.parametrize(
        ("name", "kwargs"),
        [
            ("tls_audit", {}),
            ("cors_audit", {}),
            ("graphql_audit", {}),
            ("jwt_inspect", {"token": SAMPLE_JWT}),
            ("websocket_probe", {}),
            ("nikto_scan", {}),
            ("wapiti_scan", {}),
        ],
    )
    async def test_missing_binary_reports_untested(
        self, engagement, monkeypatch, name: str, kwargs: dict[str, Any]
    ) -> None:
        _approve(engagement, "nikto_scan", "wapiti_scan")
        _spy(monkeypatch, ran=False, error="not installed")

        result = await REGISTRY[name].fn(target="https://example.com/", **kwargs)

        assert result["ok"] is False, f"{name} reported success with no tool"
        assert result["status"] == "UNTESTED", f"{name} did not report UNTESTED"
        assert result["error"] == "tool_unavailable"
        assert result["complete"] is False
        assert result["findings"] == []
        assert "UNTESTED" in result["message"]
        # The operator needs to know how to fix it, not just that it broke.
        assert "Install it with:" in result["message"]

    async def test_absence_never_creates_findings(self, engagement, monkeypatch) -> None:
        _spy(monkeypatch, ran=False, error="not installed")
        before = len(engagement.findings.all())
        await REGISTRY["tls_audit"].fn(target="example.com")
        assert len(engagement.findings.all()) == before


# --------------------------------------------------------------------------- #
# Result parsing
# --------------------------------------------------------------------------- #


class TestParsing:
    def test_testssl_records_are_found_at_any_nesting(self) -> None:
        # A one-IP scan puts records directly in scanResult; a multi-IP scan
        # nests them under a dozen category keys per target.
        flat = ws._flatten_testssl(
            {"scanResult": [{"id": "DNS_HTTPS_rrecord", "severity": "OK", "finding": "x"}]}
        )
        nested = ws._flatten_testssl(
            {"scanResult": [{"targetHost": "example.com", "protocols": [
                {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
                {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
            ]}]}
        )
        assert len(flat) == 1
        assert {e["id"] for e in nested} == {"SSLv2", "TLS1"}

    async def test_testssl_ok_entries_do_not_become_findings(self, engagement, monkeypatch) -> None:
        _spy(
            monkeypatch,
            report={"scanResult": [{"targetHost": "example.com", "protocols": [
                {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
                {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
            ]}]},
            report_flag="--jsonfile-pretty",
        )
        result = await REGISTRY["tls_audit"].fn(target="example.com")
        assert result["complete"] is True
        assert result["checks"] == 2
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "low"

    async def test_cors_credentials_raise_the_severity(self, engagement, monkeypatch) -> None:
        _spy(
            monkeypatch,
            report=[
                {"url": "https://example.com/a", "type": "reflect_origin",
                 "credentials": "true", "origin": "https://evil.com", "status_code": 200},
                {"url": "https://example.com/b", "type": "trust_null",
                 "credentials": "false", "origin": "null", "status_code": 200},
            ],
            report_flag="-o",
        )
        result = await REGISTRY["cors_audit"].fn(target="https://example.com/")
        severities = {f["severity"] for f in result["findings"]}
        assert severities == {"medium", "low"}

    async def test_graphql_only_positive_results_become_findings(self, engagement, monkeypatch) -> None:
        payload = json.dumps([
            {"title": "Introspection", "description": "Introspection is enabled",
             "severity": "HIGH", "impact": "Information Leakage",
             "result": True, "curl_verify": "curl ..."},
            {"title": "GraphiQL", "description": "GraphiQL enabled",
             "severity": "LOW", "impact": "-", "result": False, "curl_verify": ""},
        ])
        _spy(monkeypatch, values=(payload,))
        result = await REGISTRY["graphql_audit"].fn(target="https://example.com/graphql")
        assert result["checks_run"] == 2
        assert result["issues"] == 1
        assert result["findings"][0]["severity"] == "high"

    async def test_jwt_alg_none_is_a_candidate_not_a_confirmation(
        self, engagement, monkeypatch
    ) -> None:
        _spy(monkeypatch, values=("Decoded Token Values:", '[+] alg = "none"'))
        result = await REGISTRY["jwt_inspect"].fn(
            target="https://example.com/", token=ALG_NONE_JWT
        )
        assert result["algorithm"] == "none"
        assert len(result["findings"]) == 1
        stored = engagement.findings.get(result["findings"][0]["id"])
        # Nothing was forged and nothing was replayed, so nothing is proven.
        assert stored.status.value == "candidate"
        assert stored.poc is None

    async def test_jwt_first_run_config_bootstrap_is_retried(
        self, engagement, monkeypatch
    ) -> None:
        # jwt_tool's very first invocation writes its config and exits without
        # decoding. Accepting that output would report an empty analysis of a
        # token nobody looked at.
        outputs = [
            ("No config file yet created.", "Configuration file built - review contents"),
            ("Decoded Token Values:", '[+] alg = "HS256"'),
        ]
        seen: list[list[str]] = []

        async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
            sanitize_argv(name, list(argv), policy=CATALOG[name].arg_policy)
            seen.append(list(argv))
            return ToolRun(tool=name, ran=True, values=list(outputs[len(seen) - 1]))

        monkeypatch.setattr(ws, "run_one", fake_run_one)
        result = await REGISTRY["jwt_inspect"].fn(
            target="https://example.com/", token=SAMPLE_JWT
        )
        assert len(seen) == 2, "the config-bootstrap run was accepted as a decode"
        assert result["algorithm"] == "HS256"
        assert result["claims"]["sub"] == "1234567890"

    async def test_websocket_origin_acceptance_is_a_candidate(
        self, engagement, monkeypatch
    ) -> None:
        _spy(monkeypatch, values=(
            "[INFO  websocat::ws_client_peer] Connected to ws, response headers: Headers { ... }",
        ))
        result = await REGISTRY["websocket_probe"].fn(target="https://example.com/socket")
        assert result["handshake_accepted"] is True
        assert result["origin_validated"] is False
        assert len(result["findings"]) == 1
        stored = engagement.findings.get(result["findings"][0]["id"])
        assert stored.severity is Severity.MEDIUM
        assert stored.status.value == "candidate"

    async def test_websocket_refusal_produces_no_finding(self, engagement, monkeypatch) -> None:
        _spy(monkeypatch, values=(
            "websocat: WebSocketError: Received unexpected status code (403 Forbidden)",
        ))
        result = await REGISTRY["websocket_probe"].fn(target="https://example.com/socket")
        assert result["handshake_accepted"] is False
        assert result["origin_validated"] is True
        assert result["complete"] is True
        assert result["findings"] == []

    async def test_websocket_transport_failure_is_not_origin_validation(
        self, engagement, monkeypatch
    ) -> None:
        # "The server refused the upgrade" and "we never reached the server"
        # produce the same absent handshake. Reporting the second as
        # origin_validated=True invents a security control out of a dead socket.
        _spy(monkeypatch, values=(
            "[INFO  websocat::net_peer] Failure during connecting TCP: Network unreachable (os error 101)",
            "websocat: error running",
        ))
        result = await REGISTRY["websocket_probe"].fn(target="https://example.com/socket")
        assert result["handshake_accepted"] is False
        assert result["origin_validated"] is None
        assert result["complete"] is False
        assert result["status"] == "INCOMPLETE"
        assert result["findings"] == []

    async def test_plain_http_answer_is_not_a_transport_failure(
        self, engagement, monkeypatch
    ) -> None:
        # Measured on the validation target: TCP connected, the server answered 200 OK because
        # there is no WebSocket at "/", and the wrapper called it a "transport or
        # TLS failure". That sends the operator to debug TLS when the actual next
        # move is to find the real WebSocket path. Three outcomes, not two.
        _spy(monkeypatch, values=(
            "[INFO  websocat::net_peer] Connected to TCP 172.67.71.224:443",
            "websocat: WebSocketError: Received unexpected status code (200 OK)",
            "websocat: error running",
        ))
        result = await REGISTRY["websocket_probe"].fn(target="https://example.com/")
        assert result["error"] == "not_a_websocket"
        assert result["origin_validated"] is None
        assert result["findings"] == []
        assert "200" in result["message"]
        assert "transport" not in result["message"].lower()

    async def test_forbidden_upgrade_is_still_a_refusal(
        self, engagement, monkeypatch
    ) -> None:
        # The counterpart: 400/401/403 is the server understanding the upgrade
        # and declining it, which is a tested result and possibly Origin working.
        _spy(monkeypatch, values=(
            "[INFO  websocat::net_peer] Connected to TCP 10.0.0.1:443",
            "websocat: WebSocketError: Received unexpected status code (403 Forbidden)",
        ))
        result = await REGISTRY["websocket_probe"].fn(target="https://example.com/socket")
        assert result["error"] is None
        assert result["complete"] is True
        assert result["origin_validated"] is True

    async def test_ws_scheme_target_fails_closed(self, engagement, monkeypatch) -> None:
        # The scope engine cannot parse ws:// or wss:// and reports
        # 'unparseable_target'. That is the correct direction to fail in, but it
        # means callers must hand over the https:// form — which the docstring
        # says and this test keeps true.
        calls = _spy(monkeypatch)
        with pytest.raises(EasyHuntError):
            await REGISTRY["websocket_probe"].fn(target="wss://example.com/socket")
        assert calls == []


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


class TestScope:
    @pytest.mark.parametrize(
        ("name", "kwargs"),
        [
            ("tls_audit", {}),
            ("cors_audit", {}),
            ("graphql_audit", {}),
            ("jwt_inspect", {"token": SAMPLE_JWT}),
            ("websocket_probe", {}),
            ("nikto_scan", {}),
            ("wapiti_scan", {}),
        ],
    )
    async def test_out_of_scope_target_is_refused(
        self, engagement, monkeypatch, name: str, kwargs: dict[str, Any]
    ) -> None:
        _approve(engagement, "nikto_scan", "wapiti_scan")
        calls = _spy(monkeypatch)
        with pytest.raises(EasyHuntError):
            await REGISTRY[name].fn(target="https://not-ours.example.net/", **kwargs)
        assert calls == [], f"{name} ran the binary before the scope check"

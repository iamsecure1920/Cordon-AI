"""Web-application scanners: TLS posture, CORS, GraphQL, JWT, WebSocket, and the
two general-purpose HTTP scanners (nikto, wapiti).

Seven binaries shipped in the image with no :class:`ToolSpec`, no catalog entry,
and no wrapper. That combination is worse than not shipping them: they were on
disk, invisible to ``easyhunt doctor``, unreachable from the agent, and — in the
case of nikto and testssl — broken for days without anything noticing, because
nothing in the control plane had an opinion about whether they worked.

Three rules shape everything below.

**A missing tool reports UNTESTED.** Never "no findings". Every wrapper checks
``ToolRun.ran`` first and returns ``status: "UNTESTED"`` when the binary is
absent, because "we did not look" and "we looked and it is clean" are different
answers and only one of them belongs in a report.

**A bounded scan reports INCOMPLETE.** nikto and wapiti will happily run for
hours. Both are given an explicit internal bound (``-maxtime`` /
``--max-scan-time``) that fires *before* the process timeout, so the tool stops
itself and still writes its report. If the bound or the outer timeout is hit, the
result carries ``complete: False`` and an error — a killed scan has never been
allowed to render as a clean one.

**Rate comes from the engagement.** ``scope.rules.max_rps`` and
``max_concurrency`` are read here; no wrapper takes a rate, thread count, or
delay argument. An argument the agent can set is a limit the agent can raise.

``whatweb`` is deliberately absent: it already has a spec in
:mod:`easyhunt.tools.http_probe` and is not duplicated here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    HOST_PATTERN,
    PATH_PATTERN,
    URL_PATTERN,
    ToolRun,
    register_spec,
    run_one,
    split_targets,
)

__all__ = [
    "WEBSCAN_SPECS",
    "cors_audit",
    "graphql_audit",
    "jwt_inspect",
    "nikto_scan",
    "tls_audit",
    "wapiti_scan",
    "websocket_probe",
]

# --------------------------------------------------------------------------- #
# Shared value shapes
# --------------------------------------------------------------------------- #

#: ``Name: value``. Used for the header flags that carry the engagement's
#: attribution headers into tools without a dedicated user-agent option.
HEADER_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}:\s?[A-Za-z0-9 ()+_,./:;=@-]{1,256}")

#: A JSON object of headers — graphql-cop's ``-H`` takes nothing else.
HEADER_JSON_PATTERN = re.compile(
    r'\{"[A-Za-z0-9-]{1,64}": "[^"{}]{1,256}"(, "[A-Za-z0-9-]{1,64}": "[^"{}]{1,256}")*\}'
)

#: ws:// or wss://. Deliberately narrow: websocat's address grammar also accepts
#: ``exec:``, ``sh-c:``, ``cmd:`` and ``writefile:`` specifiers, which turn a
#: WebSocket client into a local command runner. Only URL forms get through.
WS_URL_PATTERN = re.compile(r"wss?://[A-Za-z0-9._~:/?#@!*+,;=%-]{1,1000}")

#: A compact JWS: two or three base64url segments.
JWT_PATTERN = re.compile(r"[A-Za-z0-9_=-]{4,2048}\.[A-Za-z0-9_=-]{2,2048}(\.[A-Za-z0-9_=-]{0,2048})?")

#: testssl takes ``host``, ``host:port`` or an ``https://`` URL — and nothing else.
TESTSSL_URI_PATTERN = re.compile(
    r"(https://)?[A-Za-z0-9._-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,256})?"
)

#: nikto's ``-Tuning`` in exclusion form (``x`` prefix), and the excluded set must
#: contain ``6`` — nikto's Denial of Service test group. Expressing "no DoS" as a
#: regex rather than as a default string means it cannot be argued away later:
#: any tuning value that would enable the DoS group fails the sanitizer.
NIKTO_TUNING_PATTERN = re.compile(r"x[0-9abcde]{0,6}6[0-9abcde]{0,6}")

#: A comma-separated list of wapiti module names.
WAPITI_MODULES_PATTERN = re.compile(r"[a-z_0-9]{2,24}(,[a-z_0-9]{2,24}){0,30}")


# --------------------------------------------------------------------------- #
# Tool specs
# --------------------------------------------------------------------------- #

NIKTO = register_spec(
    ToolSpec(
        name="nikto", binary="nikto", license="GPL-2.0",
        homepage="https://github.com/sullo/nikto",
        # Single-dash long options, and `-h` is *host*, not help. `-Version` is
        # the only spelling that prints a version; `--version` prints usage.
        version_args=["-Version"],
        user_agent_flag="-useragent",
        arg_policy=ArgPolicy(
            tool="nikto",
            allowed_flags={
                "-h", "-p", "-ssl", "-nossl", "-root", "-vhost", "-timeout",
                "-maxtime", "-Pause", "-Tuning", "-Format", "-output", "-Plugins",
                "-nointeractive", "-ask", "-nocheck", "-no404", "-followredirects",
                "-nocookies", "-noslash", "-useragent", "-Display",
            },
            # Every flag nikto documents *without* a trailing `+` takes no value.
            # Getting this list wrong is not a cosmetic error: an omitted boolean
            # makes the sanitizer swallow the next argument as its value, which is
            # exactly how `retire` shipped un-runnable for this project's whole life.
            boolean_flags={
                "-ssl", "-nossl", "-nointeractive", "-nocheck", "-no404",
                "-followredirects", "-nocookies", "-noslash",
            },
            denied_flags={
                # Evasion is out of bounds by policy, not by configuration.
                "-evasion",
                # Guessing usernames/passwords and writing responses to disk.
                "-mutate", "-mutate-options", "-Save", "-id",
                # Re-pointing nikto at another config or overriding nikto.conf
                # would reintroduce every option denied above.
                "-config", "-Option", "-useproxy", "-Userdbs",
                "-key", "-RSAcert", "-dbcheck", "-update",
            },
            value_patterns={
                "-h": URL_PATTERN,
                "-vhost": HOST_PATTERN,
                "-root": re.compile(r"/[A-Za-z0-9._/-]{0,128}"),
                "-Format": re.compile(r"json"),
                "-output": PATH_PATTERN,
                "-maxtime": re.compile(r"[0-9]{1,5}s"),
                "-Tuning": NIKTO_TUNING_PATTERN,
                "-ask": re.compile(r"no"),
                "-Display": re.compile(r"[1234DEPSV]{1,7}"),
                "-Plugins": re.compile(r"[A-Za-z0-9_,@-]{1,120}"),
            },
            numeric_caps={"-timeout": 30, "-p": 65535, "-Pause": 60},
        ),
    )
)

TESTSSL = register_spec(
    ToolSpec(
        name="testssl", binary="testssl", license="GPL-2.0",
        homepage="https://github.com/drwetter/testssl.sh",
        version_args=["--version"],
        # NOT set on purpose. testssl aborts with "Fatal error: URI comes last"
        # if anything follows the target, and guarded_run appends the user-agent
        # flag to the end of argv. Declaring it here would make every testssl run
        # fail — so `--user-agent` is placed before the URI by the wrapper instead.
        user_agent_flag=None,
        arg_policy=ArgPolicy(
            tool="testssl",
            allowed_flags={
                "--quiet", "--color", "--warnings", "--severity", "--protocols",
                "--server-defaults", "--server-preference", "--headers", "--fs",
                "--std", "--client-simulation", "--rating-only", "--disable-rating",
                "--jsonfile-pretty", "--logfile", "--socket-timeout",
                "--openssl-timeout", "--sneaky", "--ids-friendly", "--nodns",
                "--user-agent", "--ip", "--wide", "--hints", "-4",
            },
            boolean_flags={
                "--quiet", "--protocols", "--server-defaults", "--server-preference",
                "--headers", "--fs", "--std", "--client-simulation", "--rating-only",
                "--disable-rating", "--sneaky", "--ids-friendly", "--wide", "--hints", "-4",
            },
            denied_flags={
                # `-H` is --heartbleed, not a header flag. The whole -U family
                # sends exploit-shaped handshakes (Heartbleed reads server memory,
                # CCS injection forces an early key change); this wrapper claims
                # to be passive and so may not reach them.
                "-U", "--vulnerable", "-H", "--heartbleed", "-I", "--ccs",
                "--ccs-injection", "-T", "--ticketbleed", "--BB", "--robot",
                "--OP", "--opossum", "--SI", "--starttls-injection", "-D", "--drown",
                # Runs an operator-supplied binary, or routes traffic elsewhere.
                "--openssl", "--proxy", "--mtls", "--basicauth", "--add-ca",
                # Mass-scan and third-party contact.
                "--file", "-iL", "--mode", "--parallel", "--serial", "--phone-out",
            },
            value_patterns={
                "--color": re.compile(r"[0-3]"),
                "--warnings": re.compile(r"batch|off"),
                "--severity": re.compile(r"LOW|MEDIUM|HIGH|CRITICAL"),
                "--jsonfile-pretty": PATH_PATTERN,
                "--logfile": PATH_PATTERN,
                "--nodns": re.compile(r"min|none"),
                "--ip": re.compile(r"one|[0-9a-fA-F.:]{2,45}"),
            },
            numeric_caps={"--socket-timeout": 30, "--openssl-timeout": 30},
            allow_positional=True,
            positional_pattern=TESTSSL_URI_PATTERN,
            # The engagement user-agent is "EasyHunt-AI/2.0 (authorized-testing)":
            # parentheses are soft-denied globally and are needed for attribution.
            relaxed_chars=frozenset("()"),
        ),
    )
)

WAPITI = register_spec(
    ToolSpec(
        name="wapiti", binary="wapiti", license="GPL-2.0",
        homepage="https://github.com/wapiti-scanner/wapiti",
        version_args=["--version"],
        user_agent_flag="-A",
        arg_policy=ArgPolicy(
            tool="wapiti",
            allowed_flags={
                "-u", "-m", "-l", "-d", "-x", "-S", "-t", "-H", "-A", "-v", "-f", "-o",
                "--scope", "--max-links-per-page", "--max-files-per-dir",
                "--max-scan-time", "--max-attack-time", "--max-parameters",
                "--verify-ssl", "--no-bugreport", "--flush-session",
                "--store-session", "--store-config", "--color",
            },
            boolean_flags={"--no-bugreport", "--flush-session", "--color"},
            denied_flags={
                # `-p` is wapiti's proxy flag, and --mitm-port turns the scanner
                # into an intercepting proxy on this host.
                "-p", "--proxy", "--mitm-port", "--tor",
                # Credentials belong to the operator, never to an automated run.
                "-a", "--auth-cred", "--auth-user", "--auth-password",
                "--form-cred", "--form-user", "--form-password", "--form-script",
                "-c", "--cookie", "-C", "--cookie-value", "--jwt", "-sf", "--side-file",
                # Out-of-band endpoints send target traffic to a third-party host.
                "--external-endpoint", "--internal-endpoint", "--endpoint",
                "--dns-endpoint", "--wapp-url",
                # Pulls and executes new attack modules mid-engagement.
                "--update", "--headless",
            },
            value_patterns={
                "-u": URL_PATTERN,
                "-x": URL_PATTERN,
                "-m": WAPITI_MODULES_PATTERN,
                "-f": re.compile(r"json"),
                "-o": PATH_PATTERN,
                "-v": re.compile(r"[012]"),
                "--scope": re.compile(r"url|page|folder"),
                # "aggressive" and "insane" are wapiti's own names for scan
                # profiles that ignore the URL ceilings. Not reachable.
                "-S": re.compile(r"paranoid|sneaky|polite|normal"),
                "--verify-ssl": re.compile(r"[01]"),
                "--store-session": PATH_PATTERN,
                "--store-config": PATH_PATTERN,
                "-H": HEADER_PATTERN,
            },
            numeric_caps={
                "-d": 5, "-t": 30, "-l": 2,
                "--max-links-per-page": 100, "--max-files-per-dir": 50,
                # The hard ceiling on how long one wapiti call may last, whatever
                # the caller asks for.
                "--max-scan-time": 1800, "--max-attack-time": 600,
                "--max-parameters": 100,
            },
            relaxed_chars=frozenset("()"),
        ),
    )
)

GRAPHQL_COP = register_spec(
    ToolSpec(
        name="graphql-cop", binary="graphql-cop", license="MIT",
        homepage="https://github.com/dolevf/graphql-cop",
        # `-v` is --version here, not verbose.
        version_args=["-v"],
        # Its `-H` takes a JSON object, not `Name: value`, so guarded_run's
        # header injection would produce a header it cannot parse — which reads
        # as attribution while sending none. The wrapper builds the JSON itself.
        user_agent_flag=None,
        arg_policy=ArgPolicy(
            tool="graphql-cop",
            allowed_flags={"-t", "-o", "-e", "-H", "-w"},
            boolean_flags=set(),
            denied_flags={
                "-x", "--proxy", "-T", "--tor", "-d", "--debug",
                # --force scans an endpoint that did not answer as GraphQL, i.e.
                # fires the whole test battery at an arbitrary URL.
                "-f", "--force",
            },
            value_patterns={
                "-t": URL_PATTERN,
                "-o": re.compile(r"json"),
                "-e": re.compile(r"[a-z_]{3,40}(,[a-z_]{3,40}){0,20}"),
                "-H": HEADER_JSON_PATTERN,
                "-w": PATH_PATTERN,
            },
            relaxed_chars=frozenset('"()'),
        ),
    )
)

CORSCANNER = register_spec(
    ToolSpec(
        name="corscanner", binary="corscanner", license="MIT",
        homepage="https://github.com/chenjj/CORScanner",
        version_args=["--help"],
        # `-d` is a `Name: value` list, but it is nargs='*': a bare user-agent
        # string with no colon makes its parser discard *every* header. Built here.
        user_agent_flag=None,
        arg_policy=ArgPolicy(
            tool="corscanner",
            allowed_flags={"-u", "-t", "-o", "-d"},
            # -v takes an *optional* value, which the sanitizer cannot express;
            # it is simply not reachable.
            boolean_flags=set(),
            denied_flags={"-i", "--input", "-v", "--verbose"},
            value_patterns={"-u": URL_PATTERN, "-o": PATH_PATTERN, "-d": HEADER_PATTERN},
            numeric_caps={"-t": 20},
            # `-d` is nargs='*', so additional attribution headers arrive as
            # positionals. They must still look like headers.
            allow_positional=True,
            positional_pattern=HEADER_PATTERN,
            relaxed_chars=frozenset("()"),
        ),
    )
)

JWT_TOOL = register_spec(
    ToolSpec(
        name="jwt_tool", binary="jwt_tool", license="GPL-3.0",
        homepage="https://github.com/ticarpi/jwt_tool",
        version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="jwt_tool",
            # Decoding a token needs no flags at all. Everything jwt_tool can do
            # beyond that either forges a token or sends one at a live target,
            # so the allowlist is empty and the token is the only argument.
            allowed_flags=set(),
            denied_flags={
                "-t", "--targeturl", "-r", "--request", "-M", "--mode",
                "-X", "--exploit", "-T", "--tamper", "-I", "--injectclaims",
                "-S", "--sign", "-C", "--crack", "-V", "--verify",
                "-ju", "--jwksurl", "-pr", "--privkey", "-kf", "--keyfile",
                "-pk", "--pubkey", "-jw", "--jwksfile", "-d", "--dict",
                "-p", "--password", "-Q", "--query",
            },
            allow_positional=True,
            positional_pattern=JWT_PATTERN,
            max_argv=2,
        ),
    )
)

WEBSOCAT = register_spec(
    ToolSpec(
        name="websocat", binary="websocat", license="MIT",
        homepage="https://github.com/vi/websocat",
        version_args=["--version"],
        # Appended after the URL, which websocat accepts (verified).
        user_agent_flag="--ua",
        arg_policy=ArgPolicy(
            tool="websocat",
            allowed_flags={"-v", "-q", "-u", "-1", "-n", "-E", "--origin", "--ua",
                           "-H", "--protocol", "--ping-timeout"},
            boolean_flags={"-v", "-q", "-u", "-1", "-n", "-E"},
            denied_flags={
                # Local command execution and listeners: websocat is netcat for
                # WebSockets and will happily be either end of a shell.
                "-s", "--server-mode", "-e", "--set-environment", "--oneshot",
                "--exec", "--server-header", "--header-to-env",
                # Accepting an invalid certificate hides a finding rather than
                # reporting it.
                "-k", "--insecure",
                "--basic-auth", "--basic-auth-file",
            },
            value_patterns={
                "--origin": URL_PATTERN,
                "-H": HEADER_PATTERN,
                "--protocol": re.compile(r"[A-Za-z0-9._-]{1,64}"),
            },
            numeric_caps={"--ping-timeout": 60},
            allow_positional=True,
            positional_pattern=WS_URL_PATTERN,
            relaxed_chars=frozenset("()"),
        ),
    )
)

#: Everything this module catalogues, for tests and documentation.
WEBSCAN_SPECS = [NIKTO, TESTSSL, WAPITI, GRAPHQL_COP, CORSCANNER, JWT_TOOL, WEBSOCAT]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _as_url(target: str, *, scheme: str = "https") -> str:
    """First target, normalized to a URL."""
    value = split_targets(target)[0]
    if "://" in value:
        return value
    return f"{scheme}://{value}"


def _ua_header(engagement: Any) -> list[str]:
    """The engagement's user-agent plus any headers the program mandates.

    Returned as ``Name: value`` strings for tools whose only header channel is a
    generic flag. Tools that cannot carry them say so in their result rather than
    quietly dropping the program's attribution requirement.
    """
    rules = engagement.scope.rules
    return [f"User-Agent: {rules.user_agent}", *rules.required_headers]


def _untested(
    *, tool: str, run: ToolRun, target: str, install: str, surface: str
) -> dict[str, Any]:
    """The result a wrapper returns when its binary never ran.

    Absence is not a negative result. A report that says "no TLS issues" because
    testssl was missing is worse than one that says nothing at all.
    """
    return {
        "ok": False,
        "status": "UNTESTED",
        "error": "tool_unavailable",
        "complete": False,
        "target": target,
        "findings": [],
        "message": (
            f"{tool} did not run ({run.error or 'unavailable'}). {surface} is "
            f"UNTESTED, not clean — nothing here is evidence of absence. "
            f"Install it with: {install}"
        ),
        "tools": [run.to_dict()],
    }


def _severity_of(value: Any, mapping: dict[str, str]) -> Severity:
    return Severity.parse(mapping.get(str(value).strip().lower(), "info"))


def _record(findings: list[Finding]) -> list[dict[str, Any]]:
    """Persist findings and return a compact view for the agent."""
    engagement = get_engagement()
    for finding in findings:
        engagement.findings.add(finding)
    if findings:
        engagement.findings.save()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "asset": f.asset,
            "status": f.status.value,
        }
        for f in findings
    ]


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace") or "null")
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
# TLS posture — testssl
# --------------------------------------------------------------------------- #

#: testssl's severity vocabulary → ours. OK/INFO/DEBUG describe healthy or
#: descriptive results and are not carried into the findings store.
_TESTSSL_SEVERITY = {
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
    "warn": "low", "fatal": "high",
}


@easyhunt_tool(
    phase="http_probe", mode="passive", targets_arg="target", timeout=1200,
    name="tls_audit", spec=TESTSSL, tags={"tls", "http"}, estimated_requests=60,
)
async def tls_audit(target: str, port: int = 443) -> dict[str, Any]:
    """Audit a host's TLS configuration: protocols, ciphers, certificate, headers.

    Passive. Every check run here is a standard TLS handshake plus one HTTP GET —
    the same traffic any browser produces. testssl's vulnerability battery
    (``-U``: Heartbleed, CCS injection, Ticketbleed, ROBOT, DROWN) is *not* run
    and is denied at the sanitizer: those send malformed or exploit-shaped
    handshakes, and Heartbleed in particular reads server memory. Reaching them
    would make the "passive" label a lie. Use the exploit-phase validators, with
    approval, if a TLS vulnerability needs proving.
    """
    engagement = get_engagement()
    host = split_targets(target)[0]
    if "://" in host:
        from urllib.parse import urlsplit

        parts = urlsplit(host)
        host = parts.hostname or host
        port = parts.port or port
    uri = f"{host}:{int(port)}"

    report = engagement.raw_path("testssl", "json")
    argv = [
        "--quiet",
        "--color", "0",
        # Do not stop and ask a human mid-run; there is no human on stdin.
        "--warnings", "batch",
        # Observational check set only.
        "--protocols", "--server-defaults", "--server-preference", "--headers", "--fs",
        "--ids-friendly",
        "--socket-timeout", "10",
        "--openssl-timeout", "10",
        # Test the first address only. A host behind a large anycast pool
        # otherwise multiplies the run time by the size of the pool.
        "--ip", "one",
        "--jsonfile-pretty", str(report),
        # Attribution goes here rather than through spec.user_agent_flag, because
        # testssl refuses to start if anything follows the URI.
        "--user-agent", engagement.scope.rules.user_agent,
        # Last. Always last.
        uri,
    ]

    run = await run_one("testssl", argv, timeout=1100, allow_codes=(0, 1, 2, 3, 4, 5))
    if not run.ran:
        return _untested(
            tool="testssl", run=run, target=uri, surface="This host's TLS posture",
            install="git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh",
        )

    data = _read_json(report)
    entries = _flatten_testssl(data)

    findings: list[Finding] = []
    for entry in entries:
        severity = _severity_of(entry.get("severity"), _TESTSSL_SEVERITY)
        if severity is Severity.INFO:
            continue
        findings.append(
            Finding(
                asset=f"https://{uri}",
                title=f"TLS: {entry.get('id')} — {str(entry.get('finding'))[:120]}",
                phase="http_probe",
                severity=severity,
                status=Status.CANDIDATE,
                description=str(entry.get("finding"))[:1000],
                how_found=f"testssl check '{entry.get('id')}' reported {entry.get('severity')}",
                source_tool="testssl",
                confidence=0.6,
                tags=["tls"],
                evidence=[
                    Evidence(
                        kind="log",
                        description="testssl JSON entry",
                        excerpt=json.dumps(entry, default=str)[:1000],
                    )
                ],
            )
        )

    # testssl writes its JSON at the end of the run. A killed process leaves no
    # file at all, so "no entries" and "never finished" look identical unless the
    # distinction is made explicitly.
    incomplete = run.error == "timed out" or data is None
    return {
        "ok": not incomplete,
        "status": "INCOMPLETE" if incomplete else "COMPLETE",
        "complete": not incomplete,
        "error": "scan_incomplete" if incomplete else None,
        "message": (
            "testssl did not finish (%s) and writes its report only at the end, so "
            "no result survived. This host's TLS posture is UNTESTED, not clean."
            % (run.error or "no JSON report produced")
        ) if incomplete else None,
        "target": uri,
        "checks": len(entries),
        "findings": _record(findings),
        "detail": entries[:200],
        "tools": [run.to_dict()],
        "coverage_note": (
            "Protocol, cipher, certificate and header posture only. Heartbleed, "
            "ROBOT, CCS injection, Ticketbleed and DROWN were not tested — those "
            "probes are exploit-shaped and are denied to this passive tool."
        ),
    }


def _flatten_testssl(data: Any, *, depth: int = 0) -> list[dict[str, Any]]:
    """Every ``{id, severity, finding}`` record, wherever testssl nested it.

    The shape changes with the target: a single-IP scan puts the records straight
    into ``scanResult``, a multi-IP scan nests them under per-target objects with
    a dozen category keys. Walking for the record shape survives both.
    """
    out: list[dict[str, Any]] = []
    if depth > 6:
        return out
    if isinstance(data, dict):
        if "id" in data and "severity" in data:
            return [{k: data.get(k) for k in ("id", "severity", "finding")}]
        for value in data.values():
            out.extend(_flatten_testssl(value, depth=depth + 1))
    elif isinstance(data, list):
        for item in data:
            out.extend(_flatten_testssl(item, depth=depth + 1))
    return out


# --------------------------------------------------------------------------- #
# CORS — corscanner
# --------------------------------------------------------------------------- #


@easyhunt_tool(
    phase="http_probe", mode="passive", targets_arg="target", timeout=300,
    name="cors_audit", spec=CORSCANNER, tags={"cors", "http"}, estimated_requests=12,
)
async def cors_audit(target: str) -> dict[str, Any]:
    """Check a URL's CORS policy for origin reflection and trust-boundary bugs.

    Passive: a handful of GETs with different ``Origin`` headers, reading the
    ``Access-Control-Allow-*`` response headers. Nothing is submitted, nothing
    changes state.

    A permissive policy is only a vulnerability when the endpoint returns data
    worth stealing *and* ``Allow-Credentials`` is true — findings are filed as
    candidates, never as confirmed.
    """
    engagement = get_engagement()
    url = _as_url(target)
    report = engagement.raw_path("corscanner", "json")

    argv = [
        "-u", url,
        "-o", str(report),
        # Concurrency is the engagement's, not the caller's.
        "-t", str(max(1, min(20, engagement.scope.rules.max_concurrency))),
        # nargs='*': the first header is the flag's value, the rest are positionals.
        "-d", *_ua_header(engagement),
    ]

    run = await run_one("corscanner", argv, timeout=240, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            tool="corscanner", run=run, target=url, surface="This origin's CORS policy",
            install="pipx install corscanner",
        )

    results = _read_json(report) or []
    if not isinstance(results, list):
        results = []

    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        credentials = str(item.get("credentials", "")).lower() == "true"
        findings.append(
            Finding(
                asset=str(item.get("url") or url),
                title=(
                    f"CORS misconfiguration ({item.get('type')}) reflects origin "
                    f"{item.get('origin')}"
                    + (" with credentials" if credentials else "")
                ),
                phase="http_probe",
                # Without Allow-Credentials the attacker reads only what an
                # unauthenticated request would return anyway.
                severity=Severity.MEDIUM if credentials else Severity.LOW,
                status=Status.CANDIDATE,
                description=(
                    f"The endpoint echoed Origin '{item.get('origin')}' in "
                    f"Access-Control-Allow-Origin (check: {item.get('type')}, "
                    f"status {item.get('status_code')}). "
                    "Allow-Credentials: " + ("true" if credentials else "false")
                ),
                how_found=f"corscanner check '{item.get('type')}'",
                source_tool="corscanner",
                confidence=0.6 if credentials else 0.4,
                tags=["cors"],
                evidence=[
                    Evidence(kind="response", description="corscanner result",
                             excerpt=json.dumps(item, default=str)[:1000])
                ],
                remediation=(
                    "Validate Origin against an allowlist and never reflect it "
                    "together with Access-Control-Allow-Credentials: true."
                ),
            )
        )

    incomplete = run.error == "timed out"
    return {
        "ok": not incomplete,
        "status": "INCOMPLETE" if incomplete else "COMPLETE",
        "complete": not incomplete,
        "error": "scan_incomplete" if incomplete else None,
        "message": (
            "corscanner was killed at the timeout; it writes its report at the "
            "end, so this origin's CORS policy is UNTESTED, not clean."
        ) if incomplete else None,
        "target": url,
        "permissive": len(findings),
        "findings": _record(findings),
        "detail": results[:100],
        "tools": [run.to_dict()],
        "next_step": (
            "A reflected origin proves nothing on its own. Confirm the endpoint "
            "returns authenticated data before treating it as a finding."
        ),
    }


# --------------------------------------------------------------------------- #
# GraphQL — graphql-cop
# --------------------------------------------------------------------------- #

#: graphql-cop's own DoS family. Each of these sends one deliberately expensive
#: query (100+ aliases, batched operations, recursive introspection) to see
#: whether the server will do the work. That is a resource-exhaustion probe, and
#: ``scope.rules.no_dos`` exists precisely so nothing here has to decide it is
#: fine. Excluded unconditionally; there is no argument that re-enables them.
_GRAPHQL_DOS_TESTS = (
    "alias_overloading",
    "batch_query",
    "directive_overloading",
    "circular_query_introspection",
    # Upstream currently has this one commented out, so excluding it prints a
    # harmless "cannot be excluded, skipping". Listed anyway: if a future version
    # re-enables it, the exclusion is already in place rather than needing a
    # release-note to notice.
    "field_duplication",
)

_GRAPHQL_SEVERITY = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}


@easyhunt_tool(
    phase="endpoints", mode="passive", targets_arg="target", timeout=600,
    name="graphql_audit", spec=GRAPHQL_COP, tags={"graphql", "api"}, estimated_requests=60,
)
async def graphql_audit(target: str) -> dict[str, Any]:
    """Audit a GraphQL endpoint: introspection, suggestions, GraphiQL, CSRF, trace mode.

    Passive. Every check that remains is a single well-formed query used to read
    what the server discloses. graphql-cop's denial-of-service family (alias
    overloading, batching, directive overloading, circular introspection) is
    excluded unconditionally — those exist to make the server burn CPU, which is
    out of bounds under ``scope.rules.no_dos``.

    If the URL has no path, graphql-cop tries ``/``, ``/graphql``, ``/graphiql``,
    ``/playground`` and ``/console``; give it the exact path to keep the request
    count down.
    """
    engagement = get_engagement()
    url = _as_url(target)

    headers = {}
    for header in _ua_header(engagement):
        name, _, value = header.partition(":")
        headers[name.strip()] = value.strip()

    argv = [
        "-t", url,
        "-o", "json",
        "-e", ",".join(_GRAPHQL_DOS_TESTS),
        "-H", json.dumps(headers),
    ]

    run = await run_one("graphql-cop", argv, timeout=540, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            tool="graphql-cop", run=run, target=url,
            surface="This endpoint's GraphQL posture",
            install="git clone https://github.com/dolevf/graphql-cop /opt/graphql-cop",
        )

    text = "\n".join(run.values)
    results: list[dict[str, Any]] = []
    for line in run.values:
        stripped = line.strip()
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list):
                results = [r for r in parsed if isinstance(r, dict)]
            break

    # graphql-cop prints this and skips the endpoint entirely. Reporting the
    # resulting empty list as "clean" would be a lie about a URL never scanned.
    not_graphql = "does not seem to be running GraphQL" in text and not results

    findings: list[Finding] = []
    for item in results:
        if not item.get("result"):
            continue
        findings.append(
            Finding(
                asset=url,
                title=f"GraphQL: {item.get('title')}",
                phase="endpoints",
                severity=_severity_of(item.get("severity"), _GRAPHQL_SEVERITY),
                status=Status.CANDIDATE,
                description=str(item.get("description") or "")[:1000],
                how_found=f"graphql-cop check '{item.get('title')}'",
                source_tool="graphql-cop",
                confidence=0.6,
                tags=["graphql", "api"],
                evidence=[
                    Evidence(kind="request", description="graphql-cop verification",
                             excerpt=str(item.get("curl_verify") or "")[:2000])
                ],
                extra={"impact": item.get("impact")},
            )
        )

    incomplete = run.error == "timed out"
    return {
        "ok": not incomplete and not not_graphql,
        "status": "UNTESTED" if not_graphql else ("INCOMPLETE" if incomplete else "COMPLETE"),
        "complete": not incomplete and not not_graphql,
        "error": (
            "not_graphql" if not_graphql else ("scan_incomplete" if incomplete else None)
        ),
        "message": (
            f"{url} did not answer as a GraphQL endpoint, so no check ran. This is "
            "UNTESTED, not clean — find the real GraphQL path and pass it explicitly."
        ) if not_graphql else (
            "graphql-cop was killed at the timeout; this endpoint is UNTESTED."
            if incomplete else None
        ),
        "target": url,
        "checks_run": len(results),
        "issues": len(findings),
        "findings": _record(findings),
        "detail": [
            {k: v for k, v in item.items() if k != "curl_verify"} for item in results[:60]
        ],
        "tools": [run.to_dict()],
        "coverage_note": (
            "Denial-of-service checks (alias overloading, batching, directive "
            "overloading, circular introspection) were excluded under "
            "scope.rules.no_dos and were not tested."
        ),
    }


# --------------------------------------------------------------------------- #
# JWT — jwt_tool
# --------------------------------------------------------------------------- #


@easyhunt_tool(
    phase="secrets", mode="passive", targets_arg="target", timeout=120,
    name="jwt_inspect", spec=JWT_TOOL, tags={"jwt", "auth"}, estimated_requests=0,
)
async def jwt_inspect(target: str, token: str) -> dict[str, Any]:
    """Decode a JWT and report its algorithm, claims, and timestamps.

    Fully offline: not one request leaves this machine, which is why it is
    passive and costs zero requests. ``target`` is the in-scope asset the token
    came from — it exists so the call is still scope-checked and the finding has
    an owner, not because jwt_tool contacts it.

    Every jwt_tool mode that forges a token (``-T``/``-I``/``-S``/``-X``), cracks
    a key (``-C``), or replays one at a live host (``-t``/``-M``) is denied by the
    argument policy. Proving a JWT flaw is an exploit-phase action with its own
    approval gate, not something this tool can be talked into.
    """
    run = await run_one("jwt_tool", [token], timeout=90, allow_codes=(0, 1, 2))

    # First ever invocation writes ~/.jwt_tool/jwtconf.ini and exits *without*
    # decoding anything. Reporting that empty run as "nothing notable in this
    # token" is exactly the failure mode this module exists to prevent.
    if run.ran and _jwt_bootstrapped("\n".join(run.values)):
        run = await run_one("jwt_tool", [token], timeout=90, allow_codes=(0, 1, 2))

    if not run.ran:
        return _untested(
            tool="jwt_tool", run=run, target=target, surface="This token",
            install="git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool",
        )

    text = "\n".join(run.values)
    header, payload = _jwt_segments(token)
    algorithm = str(header.get("alg", "")).strip()

    observations: list[str] = []
    findings: list[Finding] = []

    if algorithm.lower() == "none":
        observations.append("alg=none — the signature is not verified by this token's header")
        findings.append(
            Finding(
                asset=target,
                title="JWT advertises alg=none",
                phase="secrets",
                severity=Severity.HIGH,
                status=Status.CANDIDATE,
                description=(
                    "The token header declares alg=none. If the server honours it, "
                    "any party can mint a token with arbitrary claims. Unproven "
                    "until a forged token is accepted — that is an exploit-phase step."
                ),
                how_found="jwt_tool decode of a captured token",
                source_tool="jwt_tool",
                confidence=0.5,
                tags=["jwt", "auth"],
                remediation="Pin the accepted algorithm server-side; reject 'none'.",
            )
        )
    if algorithm.lower().startswith("hs") and "kid" in header:
        observations.append(
            "HMAC algorithm with a 'kid' header — check whether kid is used to "
            "select a key from a path or a database column"
        )
    if "exp" not in payload:
        observations.append("no 'exp' claim — this token does not expire")
    if not header:
        observations.append("header could not be decoded as base64url JSON")

    return {
        "ok": True,
        "status": "COMPLETE",
        "complete": True,
        "target": target,
        "algorithm": algorithm or None,
        "header": header,
        "claims": payload,
        "observations": observations,
        "findings": _record(findings),
        "output": text[-4000:],
        "tools": [run.to_dict()],
        "next_step": (
            "Decoding proves nothing. A JWT finding needs the server to accept a "
            "modified token — route that through the exploit-phase validators, "
            "which are approval-gated."
        ),
    }


def _jwt_bootstrapped(text: str) -> bool:
    """Whether this run only created jwt_tool's config file."""
    return "Configuration file built" in text or "Running config setup" in text


def _jwt_segments(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and payload of a compact JWS, best-effort."""
    import base64

    out: list[dict[str, Any]] = []
    for segment in token.split(".")[:2]:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
            out.append(decoded if isinstance(decoded, dict) else {})
        except (ValueError, json.JSONDecodeError):
            out.append({})
    while len(out) < 2:
        out.append({})
    return out[0], out[1]


# --------------------------------------------------------------------------- #
# WebSocket — websocat
# --------------------------------------------------------------------------- #


@easyhunt_tool(
    phase="endpoints", mode="passive", targets_arg="target", timeout=120,
    name="websocket_probe", spec=WEBSOCAT, tags={"websocket", "api"}, estimated_requests=2,
)
async def websocket_probe(target: str, origin: str | None = None) -> dict[str, Any]:
    """Open a WebSocket handshake and report whether the server validates Origin.

    Pass the ``https://`` (or bare host) form of the endpoint, not ``wss://``:
    the scope engine cannot parse a ``ws``/``wss`` URL and fails closed on one,
    so a ``wss://`` target is refused before this ever runs. The upgrade to
    ``wss://`` happens here, after the scope check has had its say.

    Passive: one upgrade request, no frames sent, connection closed immediately.
    ``-u`` inhibits the send direction and ``-1`` stops after a single message,
    so nothing this tool does can be mistaken for traffic.

    A handshake that succeeds with a foreign ``Origin`` is a *candidate* for
    cross-site WebSocket hijacking. It only becomes a finding when the socket
    also carries authentication that the browser would attach automatically —
    which this tool cannot and does not test.
    """
    url = split_targets(target)[0]
    if url.startswith("https://"):
        url = "wss://" + url[len("https://"):]
    elif url.startswith("http://"):
        url = "ws://" + url[len("http://"):]
    elif "://" not in url:
        url = f"wss://{url}"

    foreign_origin = origin or "https://easyhunt-cswsh-check.example"

    argv = ["-v", "-u", "-1", "--origin", foreign_origin, url]
    # websocat reports the handshake on stderr, including the response headers;
    # stdout carries only frame payloads, of which there are none here.
    run = await run_one(
        "websocat", argv, timeout=60, allow_codes=(0, 1),
        extract=lambda result: (result.stdout + "\n" + result.stderr).splitlines(),
    )
    if not run.ran:
        return _untested(
            tool="websocat", run=run, target=url, surface="This WebSocket endpoint",
            install="curl -sL https://github.com/vi/websocat/releases/latest -o /usr/local/bin/websocat",
        )

    text = "\n".join(run.values)
    connected = "Connected to ws" in text
    # "The server refused the upgrade" and "we never reached the server" look
    # identical if you only check whether the handshake succeeded — and one of
    # them would otherwise be reported as the server validating Origin.
    transport_failed = not connected and any(
        marker in text
        for marker in (
            "Failure during connecting TCP", "I/O failure", "Connection refused",
            "failed to lookup address", "Network unreachable", "os error",
            "error running", "certificate",
        )
    )
    findings: list[Finding] = []

    if connected and origin is None:
        findings.append(
            Finding(
                asset=url,
                title="WebSocket handshake accepted from an unrelated Origin",
                phase="endpoints",
                severity=Severity.MEDIUM,
                status=Status.CANDIDATE,
                description=(
                    f"The server upgraded a WebSocket connection carrying "
                    f"Origin: {foreign_origin}. If the socket is authenticated by a "
                    "cookie the browser attaches automatically, any page can open it "
                    "on a victim's behalf (cross-site WebSocket hijacking). Unproven "
                    "here: this probe sent no credentials and read no data."
                ),
                how_found="websocat handshake with a foreign Origin header",
                source_tool="websocat",
                confidence=0.4,
                tags=["websocket", "cswsh"],
                evidence=[
                    Evidence(kind="response", description="handshake response headers",
                             excerpt=text[-2000:])
                ],
                remediation=(
                    "Validate the Origin header on upgrade, and authenticate the "
                    "socket with a token the browser does not attach automatically."
                ),
            )
        )

    killed = run.error == "timed out"
    incomplete = killed or transport_failed
    return {
        "ok": not incomplete,
        "status": "INCOMPLETE" if incomplete else "COMPLETE",
        "complete": not incomplete,
        "error": "probe_incomplete" if incomplete else None,
        "message": (
            "websocat was killed at the timeout — the endpoint neither accepted "
            "nor refused the handshake. UNKNOWN, not clean."
            if killed else
            "websocat never completed a connection to this endpoint (transport or "
            "TLS failure), so the server never got the chance to validate Origin. "
            "UNKNOWN — do not read this as 'Origin is checked'."
        ) if incomplete else None,
        "target": url,
        "origin_sent": foreign_origin,
        "handshake_accepted": connected,
        # None means "we could not tell", which is different from False.
        "origin_validated": (
            None if (incomplete or origin is not None) else not connected
        ),
        "findings": _record(findings),
        "output": text[-4000:],
        "tools": [run.to_dict()],
        "next_step": (
            "If the handshake was accepted, check whether the socket is "
            "authenticated by a cookie. No cookie, no CSWSH."
        ),
    }


# --------------------------------------------------------------------------- #
# nikto — aggressive
# --------------------------------------------------------------------------- #

#: Ceiling on any single nikto or wapiti call, whatever the caller asks for.
#: Both scanners are happy to run for a working day.
MAX_SCAN_MINUTES = 30


@easyhunt_tool(
    phase="vuln_scan", mode="aggressive", targets_arg="target", timeout=2400,
    name="nikto_scan", spec=NIKTO, tags={"scanner", "http"}, estimated_requests=2500,
    rationale="Probe a web server for known dangerous files, outdated software, and misconfiguration.",
    risk_notes=[
        "Requests several thousand known-bad paths — highly visible in access logs and to a WAF.",
        "Paced from the engagement's max_rps; the DoS test group is excluded at the sanitizer.",
        "Bounded by -maxtime; a scan that hits the bound reports INCOMPLETE, never 'clean'.",
    ],
)
async def nikto_scan(target: str, max_minutes: int = 10) -> dict[str, Any]:
    """Scan a web server with nikto for dangerous files and misconfiguration.

    Aggressive, and gated: nikto walks a database of several thousand paths, so
    it is loud, obvious in logs, and will trip a WAF. That is a decision for a
    human, not a default.

    Two bounds apply and neither is negotiable. ``-maxtime`` stops nikto from the
    inside so its report still gets written, and the process timeout sits above
    it as a backstop. ``max_minutes`` is clamped to ``MAX_SCAN_MINUTES`` (30).

    Pacing comes from ``scope.rules.max_rps`` via ``-Pause``; there is no rate
    argument. The Denial of Service test group is excluded by a sanitizer pattern
    that every ``-Tuning`` value must satisfy.
    """
    engagement = get_engagement()
    url = _as_url(target)
    bound_s = int(max(1, min(MAX_SCAN_MINUTES, max_minutes)) * 60)

    # One pause per test, sized from the program's published ceiling. nikto has
    # no requests-per-second option, so the inverse is the closest honest mapping.
    pause = min(60.0, max(0.0, 1.0 / max(0.1, engagement.scope.rules.max_rps)))

    report = engagement.raw_path("nikto", "json")
    argv = [
        "-h", url,
        "-maxtime", f"{bound_s}s",
        # 'x6' = everything except test group 6, Denial of Service.
        "-Tuning", "x6",
        "-Pause", f"{pause:.2f}",
        "-timeout", "10",
        "-Format", "json",
        "-output", str(report),
        "-nointeractive",
        # Never phone home with a scan summary, and never block on an update check.
        "-ask", "no",
        "-nocheck",
    ]

    # The process timeout sits above nikto's own bound so nikto terminates itself
    # and flushes its report. Being killed by the outer timeout means losing it.
    run = await run_one("nikto", argv, timeout=bound_s + 300, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            tool="nikto", run=run, target=url, surface="This web server",
            install="git clone https://github.com/sullo/nikto /opt/nikto",
        )

    data = _read_json(report)
    hosts = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])

    items: list[dict[str, Any]] = []
    for entry in hosts:
        if isinstance(entry, dict):
            for vuln in entry.get("vulnerabilities") or []:
                if isinstance(vuln, dict):
                    items.append(vuln)

    findings: list[Finding] = []
    for vuln in items[:200]:
        findings.append(
            Finding(
                asset=url.rstrip("/") + str(vuln.get("url") or "/"),
                title=f"nikto: {str(vuln.get('msg') or '')[:180]}",
                phase="vuln_scan",
                # nikto assigns no severity and is famously false-positive heavy.
                # Rating everything INFO with low confidence keeps the triage
                # pass honest instead of inflating a report.
                severity=Severity.INFO,
                status=Status.CANDIDATE,
                description=str(vuln.get("msg") or "")[:1000],
                how_found=f"nikto test {vuln.get('id')} ({vuln.get('method', 'GET')})",
                source_tool="nikto",
                rule_id=str(vuln.get("id") or "") or None,
                confidence=0.25,
                tags=["nikto"],
                references=[r for r in [str(vuln.get("references") or "")] if r.startswith("http")],
            )
        )

    text = "\n".join(run.values)
    hit_bound = "maximum execution time" in text
    error_limit = "Error limit" in text
    killed = run.error == "timed out"
    incomplete = hit_bound or error_limit or killed or data is None

    reasons = []
    if killed:
        reasons.append(f"the process was killed at the {bound_s + 300}s ceiling")
    if hit_bound:
        reasons.append(f"nikto stopped itself at its own {bound_s}s -maxtime bound")
    if error_limit:
        reasons.append("nikto gave up after 20 consecutive connection errors")
    if data is None and not killed:
        reasons.append("no JSON report was produced")

    return {
        "ok": not incomplete,
        "status": "INCOMPLETE" if incomplete else "COMPLETE",
        "complete": not incomplete,
        "error": "scan_incomplete" if incomplete else None,
        "message": (
            "nikto did not cover the whole test database: "
            + "; ".join(reasons)
            + f". {len(items)} item(s) were found before it stopped. "
            "Treat this as partial coverage — a low count here is INCOMPLETE, "
            "not a clean server. Re-run with a larger max_minutes, or narrow the target."
        ) if incomplete else None,
        "target": url,
        "bound_seconds": bound_s,
        "pause_seconds": round(pause, 2),
        "items": len(items),
        "findings": _record(findings),
        "detail": items[:100],
        "tools": [run.to_dict()],
        "next_step": (
            "nikto output is a lead list, not findings. Triage it before anything "
            "reaches a report — most entries are version-banner guesses."
        ),
    }


# --------------------------------------------------------------------------- #
# wapiti — aggressive
# --------------------------------------------------------------------------- #

#: Module sets, chosen from the names present in both wapiti 3.0.x and 3.3.x so a
#: host install and the container agree. The caller picks a set by name and never
#: passes module names, so `brute_login_form` (credential attack), `buster` (path
#: brute force, which content_discovery already owns under a rate limit), `nikto`
#: (duplicates the real thing) and the time-based blind SQL modules stay out.
_WAPITI_PROFILES: dict[str, str] = {
    "safe": "wapp,methods,backup,csrf",
    "injection": "sql,xss,exec,file,redirect,ssrf,crlf,xxe,shellshock,permanentxss",
}


@easyhunt_tool(
    phase="vuln_scan", mode="aggressive", targets_arg="target", timeout=2400,
    name="wapiti_scan", spec=WAPITI, tags={"scanner", "http"}, estimated_requests=2000,
    rationale="Crawl a web application and attack its parameters with wapiti's injection modules.",
    risk_notes=[
        "Crawls the application and submits payloads to every parameter and form it finds.",
        "profile='injection' sends SQLi, XSS, command-injection and SSRF payloads.",
        "Bounded by --max-scan-time and --max-attack-time; hitting either reports INCOMPLETE.",
    ],
)
async def wapiti_scan(
    target: str, profile: str = "safe", max_minutes: int = 15, depth: int = 2
) -> dict[str, Any]:
    """Crawl and attack a web application with wapiti.

    Aggressive, and gated. Even ``profile='safe'`` crawls the whole application;
    ``profile='injection'`` submits SQLi, XSS, command-injection, SSRF, CRLF and
    XXE payloads to every parameter found. Nothing about that is observational.

    Bounds, all enforced server-side: ``--max-scan-time`` caps the run,
    ``--max-attack-time`` caps each module, crawl depth and links-per-page are
    capped, and the process timeout sits above all of them. ``max_minutes`` is
    clamped to ``MAX_SCAN_MINUTES`` (30).

    wapiti exposes no requests-per-second control — the closest it offers is
    ``--scan-force``, which is set from ``scope.rules.max_rps`` here. That is an
    approximation and it is reported as one: a program with a strict published
    rate limit is a reason to prefer nuclei with ``-rl``.
    """
    engagement = get_engagement()
    url = _as_url(target)

    modules = _WAPITI_PROFILES.get(profile)
    if modules is None:
        return {
            "ok": False,
            "error": "unknown_profile",
            "status": "UNTESTED",
            "complete": False,
            "target": url,
            "findings": [],
            "message": (
                f"profile must be one of {sorted(_WAPITI_PROFILES)}; got {profile!r}. "
                "Module names cannot be passed directly."
            ),
        }

    bound_s = int(max(1, min(MAX_SCAN_MINUTES, max_minutes)) * 60)
    rps = engagement.scope.rules.max_rps
    # wapiti's coarsest throttle. Below ~2 rps a program is telling us to tread
    # very lightly; 'polite'/'normal' are the widest settings this wrapper allows
    # and 'aggressive'/'insane' are refused by the argument policy.
    force = "paranoid" if rps < 1 else "sneaky" if rps < 3 else "polite" if rps < 10 else "normal"

    report = engagement.raw_path("wapiti", "json")
    session_dir = engagement.workspace / "wapiti"
    session_dir.mkdir(parents=True, exist_ok=True)

    argv = [
        "-u", url,
        "-m", modules,
        "--scope", "folder",
        "-d", str(max(1, min(5, depth))),
        "--max-links-per-page", "100",
        "--max-files-per-dir", "50",
        "--max-scan-time", str(bound_s),
        # No single module may eat the whole budget and starve the rest.
        "--max-attack-time", str(max(30, min(600, bound_s // 3))),
        "-S", force,
        "-t", "20",
        "-f", "json",
        "-o", str(report),
        "-v", "0",
        # Never send a crash report about someone else's application upstream.
        "--no-bugreport",
        # Start clean: a resumed session would silently re-report old results.
        "--flush-session",
        "--store-session", str(session_dir),
        "--store-config", str(session_dir),
    ]
    for header in engagement.scope.rules.required_headers:
        argv += ["-H", header]

    run = await run_one("wapiti", argv, timeout=bound_s + 420, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            tool="wapiti", run=run, target=url, surface="This application",
            install="pipx install wapiti3",
        )

    data = _read_json(report) or {}
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    anomalies = data.get("anomalies") if isinstance(data, dict) else None
    infos = data.get("infos") if isinstance(data, dict) else None

    findings: list[Finding] = []
    total = 0
    for category, entries in (vulnerabilities or {}).items():
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            total += 1
            if total > 200:
                break
            findings.append(
                Finding(
                    asset=str(entry.get("path") or url),
                    title=f"{category} ({entry.get('module')})",
                    phase="vuln_scan",
                    severity=_WAPITI_LEVELS.get(int(entry.get("level") or 0), Severity.INFO),
                    status=Status.CANDIDATE,
                    description=str(entry.get("info") or "")[:1000],
                    how_found=f"wapiti module '{entry.get('module')}' on parameter "
                              f"{entry.get('parameter') or '(none)'}",
                    source_tool="wapiti",
                    confidence=0.4,
                    tags=["wapiti"],
                    evidence=[
                        Evidence(kind="request", description="wapiti request",
                                 excerpt=str(entry.get("http_request") or "")[:2000])
                    ],
                    extra={"curl": str(entry.get("curl_command") or "")[:1000]},
                )
            )

    crawled = (infos or {}).get("crawled_pages_nbr") if isinstance(infos, dict) else None
    killed = run.error == "timed out"
    # wapiti stops at --max-scan-time and still writes a report, so a run that
    # used its whole budget covered only part of the application.
    hit_bound = run.duration_s >= bound_s
    incomplete = killed or hit_bound or not isinstance(data, dict) or not data

    reasons = []
    if killed:
        reasons.append(f"the process was killed at the {bound_s + 420}s ceiling, discarding the report")
    elif hit_bound:
        reasons.append(f"wapiti stopped at its own {bound_s}s --max-scan-time bound")
    if not data:
        reasons.append("no JSON report was produced")

    return {
        "ok": not incomplete,
        "status": "INCOMPLETE" if incomplete else "COMPLETE",
        "complete": not incomplete,
        "error": "scan_incomplete" if incomplete else None,
        "message": (
            "wapiti did not finish crawling and attacking this application: "
            + "; ".join(reasons or ["the report was empty or unreadable"])
            + f". {total} candidate(s) found in the part it reached"
            + (f", {crawled} page(s) crawled" if crawled is not None else "")
            + ". A partial scan is INCOMPLETE, not a clean application."
        ) if incomplete else None,
        "target": url,
        "profile": profile,
        "modules": modules,
        "bound_seconds": bound_s,
        "scan_force": force,
        "crawled_pages": crawled,
        "candidates": total,
        "findings": _record(findings),
        "anomalies": sum(len(v or []) for v in (anomalies or {}).values()),
        "tools": [run.to_dict()],
        "rate_note": (
            f"wapiti has no requests-per-second flag. --scan-force='{force}' was "
            f"derived from the engagement's max_rps of {rps:g}, which limits how "
            "much it scans rather than how fast. Prefer nuclei for a target with a "
            "hard published rate limit."
        ),
        "next_step": (
            "Every entry is a candidate. Validate before reporting — wapiti's "
            "error-based detectors fire on generic 500s."
        ),
    }


_WAPITI_LEVELS: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


# --------------------------------------------------------------------------- #
# Install recipes
# --------------------------------------------------------------------------- #


def _register_install_recipes() -> None:
    """Teach the installer how to obtain the seven tools catalogued here.

    A tool in :data:`~easyhunt.tools.common.CATALOG` with no install recipe is a
    tool ``easyhunt doctor`` can report as missing and ``easyhunt install``
    cannot fix. The recipes mirror what the Dockerfile already does, so a host
    install and the image converge instead of drifting.
    """
    from easyhunt.install.recipes import RECIPES, Recipe, _python_repo_setup

    for recipe in (
        Recipe(
            tool="nikto", method="git", category="scanner", license="GPL-2.0",
            package="https://github.com/sullo/nikto", clone_to="/opt/nikto",
            # Perl, not Python: no venv, just a wrapper and the XML module nikto
            # loads unconditionally even when asked for JSON output.
            system_deps=("perl", "libnet-ssleay-perl", "libxml-writer-perl"),
            post_install=(
                "ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto; "
                "chmod +x /opt/nikto/program/nikto.pl"
            ),
            caveat=(
                "Needs libxml-writer-perl even for JSON output — without it nikto "
                "installs cleanly and dies at startup with 'Required module not "
                "found: XML::Writer'."
            ),
        ),
        Recipe(
            tool="testssl", method="git", category="scanner", license="GPL-2.0",
            package="https://github.com/drwetter/testssl.sh", clone_to="/opt/testssl.sh",
            system_deps=("bsdextrautils", "procps", "dnsutils"),
            post_install="ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl",
            caveat=(
                "Needs hexdump (bsdextrautils) and procps; without them it exits "
                "at the dependency check with no scan and no clear error."
            ),
        ),
        Recipe(
            tool="wapiti", method="pipx", package="wapiti3", category="scanner",
            license="GPL-2.0",
            caveat=(
                "No requests-per-second option — only --scan-force. Prefer nuclei "
                "where a program publishes a hard rate limit."
            ),
        ),
        Recipe(
            tool="corscanner", method="pipx", package="corscanner", category="scanner",
            license="MIT",
        ),
        Recipe(
            tool="graphql-cop", method="git", category="scanner", license="MIT",
            package="https://github.com/dolevf/graphql-cop",
            clone_to="/opt/graphql-cop",
            post_install=_python_repo_setup("graphql-cop", "graphql-cop.py"),
        ),
        Recipe(
            tool="jwt_tool", method="git", category="scanner", license="GPL-3.0",
            package="https://github.com/ticarpi/jwt_tool", clone_to="/opt/jwt_tool",
            post_install=_python_repo_setup("jwt_tool", "jwt_tool.py"),
            caveat=(
                "The first run writes ~/.jwt_tool/jwtconf.ini and exits without "
                "decoding anything; the wrapper re-runs once to cover that."
            ),
        ),
        Recipe(
            tool="websocat", method="release", category="scanner", license="MIT",
            package="vi/websocat", asset_match="{arch}-unknown-linux-musl",
        ),
    ):
        RECIPES.setdefault(recipe.tool, recipe)


_register_install_recipes()

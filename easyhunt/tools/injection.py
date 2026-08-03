"""Injection-class probes: SSRF, SSTI, OS command, request smuggling, NoSQL.

Five binaries were added to the container and then left unreachable — no
:class:`ToolSpec`, no ``CATALOG`` entry, no wrapper, no call site. That is the
same defect this project has hit before (jsluice shipped with a spec, a binary
and a docstring promising it ran, and zero callers), and it is worse than not
shipping the tool at all: ``easyhunt doctor`` reports a healthy install, the
report's tool inventory implies the surface was covered, and nothing tested it.
This module closes that gap for ssrfmap, sstimap, commix, smuggler and nosqli.

Three rules shape every policy below.

**Detection, never exploitation.** Each of these tools ships a second half that
takes a proven injection point and turns it into a shell, a file read, or a set
of cloud credentials. Those flags are on ``denied_flags``, so no prompt and no
approval can reach them: sstimap's ``-s/--os-shell``, ``-X/--eval-code`` and
``-R/--reverse-shell``; commix's ``--os-cmd``, ``--file-read/--file-write`` and
``--alert`` (which runs a command on *our* host when an injection point is
found); ssrfmap's ``-l`` reverse-shell handler and its ``redis``/``readfiles``
modules. What is left is the part that answers the question — is this parameter
injectable — and nothing that acts on the answer.

**Nothing that sources a target from somewhere the scope engine never saw.**
``@easyhunt_tool`` scope-checks the ``target`` argument. A flag that reads a
second target out of a file, a sitemap, or a crawl (commix ``-m``/``-l``/``-r``/
``-x``/``--crawl``, sstimap ``--load-urls``/``--crawl``, smuggler ``--vhost``)
puts a host on the wire that no verdict was ever recorded for. Those are denied
as scope evasion, not as untidiness.

**Absence is not a clean result.** Four of the five are absent from a stock host
install and one of them — see ``COMMIX`` below — is present as an impostor. Every
wrapper here distinguishes "the tool said no" from "the tool never ran" and says
so in the words this codebase already uses: *Without it this surface is UNTESTED,
not clean.*

Everything these tools produce is a :attr:`Status.CANDIDATE` finding. None of
them emits a PoC. Promotion to ``confirmed`` runs through ``validate_findings``
or a human's ``poc_record`` exactly as it does for every other candidate.

A note on where they run: ``config.yaml``'s ``sandbox.images`` has no entry for
any of these five, so :meth:`Sandbox.plan` resolves them on the host. They are in
the EasyHunt container image, but the control plane never launches that image, so
on a host without them installed these tools report UNTESTED rather than running.
That is the honest outcome, and it is fixed by an image mapping, not here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import URL_PATTERN, ToolRun, register_spec, run_one, split_targets
from easyhunt.util.run import ProcResult

__all__ = [
    "COMMIX",
    "NOSQLI",
    "SMUGGLER",
    "SSRFMAP",
    "SSTIMAP",
    "cmdi_probe",
    "nosqli_probe",
    "smuggling_probe",
    "ssrf_probe",
    "ssti_probe",
]

# --------------------------------------------------------------------------- #
# Shared value shapes
# --------------------------------------------------------------------------- #

#: Workspace file paths handed to a tool via -r/-o/--logfile. Wider than
#: ``common.PATH_PATTERN`` because pytest's tmp_path and parametrised test ids
#: legitimately contain ``[]``, ``+`` and ``=``; a policy that rejects the paths
#: its own tests generate is a policy nobody can exercise.
WORKSPACE_PATH = re.compile(r"[A-Za-z0-9._/@+=:,\[\]-]{1,512}")

#: An HTTP parameter name. Deliberately not a URL and not a path.
PARAM_NAME = re.compile(r"[A-Za-z0-9_.\[\]-]{1,64}")

#: One ``name=value`` pair for a request body.
#:
#: Not a whole body, and it cannot be one: ``&`` is in
#: :data:`sanitize.HARD_DENY_CHARS`, which has no relaxation path for any tool.
#: So no argument value anywhere in EasyHunt may contain ``&`` — which also means
#: a target URL carrying two query parameters is refused before it reaches a
#: tool. That is a project-wide property, not something these policies chose, and
#: the pattern below states it rather than pretending otherwise. Where a tool's
#: body flag is stackable (SSTImap's ``-d``) several pairs can still be passed as
#: separate flags; where it is not (commix, nosqli), one pair is the ceiling.
BODY_PAIR = re.compile(r"[A-Za-z0-9_.%=+/\[\]:@-]{1,256}")

#: HTTP methods a probe may force. No TRACE, no arbitrary verb.
HTTP_METHOD = re.compile(r"GET|POST|PUT|HEAD|OPTIONS")

#: The tagged user-agent (``EasyHunt-AI/2.0 (authorized-testing)``) carries
#: parentheses, and ``guarded_run`` injects it through ``user_agent_flag``. Any
#: tool that takes one has to relax them or its own attribution string is
#: rejected. ``()`` and nothing else — a backtick is never needed here.
UA_CHARS = frozenset("()")


# --------------------------------------------------------------------------- #
# Tool specifications
# --------------------------------------------------------------------------- #

SSRFMAP = register_spec(
    ToolSpec(
        name="ssrfmap",
        binary="ssrfmap",
        license="GPL-3.0",
        homepage="https://github.com/swisskyrepo/SSRFmap",
        version_args=["-h"],
        identity_marker="ssrfmap",
        user_agent_flag="--uagent",
        arg_policy=ArgPolicy(
            tool="ssrfmap",
            allowed_flags={"-r", "-p", "-m", "-v", "--uagent", "--ssl", "--level", "--logfile"},
            # -v and --ssl take no value. --ssl is nargs='?' upstream, which the
            # sanitizer cannot express: listing it here means the argument after
            # it is read as the next flag, which is what we want, and it also
            # means we must never pass a value to it.
            boolean_flags={"-v", "--ssl"},
            denied_flags={
                # -l starts a reverse-shell handler and --lhost/--lport point it
                # at a listener. This is the tool's exploitation half.
                "-l",
                "--lhost",
                "--lport",
                # readfiles' target list: file:// reads out of the victim.
                "--rfiles",
                # AXFR and the domain-scoped modules aim at a domain the scope
                # engine never checked.
                "--ldomain",
                "--proxy",
            },
            value_patterns={
                "-r": WORKSPACE_PATH,
                "-p": PARAM_NAME,
                # The module *is* the payload. Of SSRFmap's 24 modules, redis,
                # mysql, postgres, zabbix, docker, consul, tomcat and fastcgi
                # write to or execute on the internal service; readfiles and
                # smbhash exfiltrate; aws/gce/alibaba/digitalocean read instance
                # credentials; socksproxy turns the target into a pivot;
                # networkscan sweeps RFC1918 hosts nobody authorised. portscan
                # only observes whether an internal port answers, which is the
                # whole question an SSRF candidate needs answered.
                "-m": re.compile(r"portscan"),
                "--logfile": WORKSPACE_PATH,
            },
            # level > 1 multiplies the 8,282-entry port list across an expanding
            # host range. One host is already 8k requests.
            numeric_caps={"--level": 1},
            relaxed_chars=UA_CHARS,
        ),
    )
)

SSTIMAP = register_spec(
    ToolSpec(
        name="sstimap",
        binary="sstimap",
        license="GPL-3.0",
        homepage="https://github.com/vladko312/SSTImap",
        version_args=["-V"],
        identity_marker="sstimap",
        user_agent_flag="--user-agent",
        arg_policy=ArgPolicy(
            tool="sstimap",
            header_flags={"--header", "-H"},
            allowed_flags={
                "-u", "--url", "--no-color", "-l", "--level", "-e", "--engine",
                "-r", "--technique", "--delay", "-a", "--user-agent", "-H", "--header",
                "-C", "--cookie", "-m", "--method", "-d", "--data",
                "-P", "--injection-points", "-M", "--marker", "--verify-ssl",
                "--blind-delay",
            },
            boolean_flags={"--no-color", "--verify-ssl"},
            denied_flags={
                # Everything under SSTImap's "payload" section: template shell,
                # base-language eval, OS shell, bind/reverse shell, upload and
                # download. --eval and --os-shell are globally denied already;
                # the short forms and SSTImap's own long forms are not.
                "-t", "--tpl-shell", "-T", "--tpl-code",
                "-x", "--eval-shell", "-X", "--eval-code",
                "-s", "-S", "--os-cmd",
                "-B", "--bind-shell", "-R", "--reverse-shell", "--remote-shell",
                "-F", "--force-overwrite", "-U", "--upload", "-D", "--download",
                # Interactive modes hang a non-interactive server forever.
                "-i", "--interactive", "--run",
                # Target expansion past the scope check.
                "-c", "--crawl", "-f", "--forms", "--empty-forms",
                "--load-urls", "--load-forms", "--save-urls", "--save-forms",
                "--crawl-domains", "--crawl-exclude",
                # Attribution and config.
                "-A", "--random-user-agent", "-p", "--proxy", "--config",
            },
            value_patterns={
                "-u": URL_PATTERN,
                "--url": URL_PATTERN,
                "-e": re.compile(r"[A-Za-z0-9_:,/*-]{1,120}"),
                "--engine": re.compile(r"[A-Za-z0-9_:,/*-]{1,120}"),
                # R(endered) E(rror) B(oolean blind) T(ime blind). All detection.
                "-r": re.compile(r"[REBT]{1,4}"),
                "--technique": re.compile(r"[REBT]{1,4}"),
                "-m": HTTP_METHOD,
                "--method": HTTP_METHOD,
                # Q(uery) B(ody) H(eaders) C(ookies).
                "-P": re.compile(r"[QBHC]{1,4}"),
                "--injection-points": re.compile(r"[QBHC]{1,4}"),
                # Stackable upstream: one pair per -d flag.
                "-d": BODY_PAIR,
                "--data": BODY_PAIR,
            },
            numeric_caps={
                "-l": 3, "--level": 3,
                "--delay": 5,
                "--blind-delay": 10,
            },
            relaxed_chars=UA_CHARS,
        ),
    )
)

COMMIX = register_spec(
    ToolSpec(
        name="commix",
        binary="commix",
        license="GPL-3.0",
        homepage="https://github.com/commixproject/commix",
        version_args=["--version"],
        # PyPI's `commix` is NOT commixproject/commix. It is a 2019 package
        # (v0.1, author "Parixit Sutariya", homepage github.com/Bhai4You/) that
        # copies the real tool's one-line description and whose entire CLI is
        # `-i` to install the real commix, plus -h/-v/-a/-r. The Dockerfile's
        # `uv tool install commix` installs that one, so the container ships a
        # binary called commix that cannot test anything.
        #
        # `commix` appears in both tools' help text, so it cannot separate them,
        # and the real tool's --version prints a bare version string with no
        # name in it at all ("v4.1"). `--shellshock` is the discriminator:
        # verified present in the real tool's help both from source (v4.2.dev32)
        # and packaged (Kali v4.1), and absent from every output the impostor
        # produces. Without this marker the impostor resolves as commix and this
        # wrapper reports "no injection found" for a tool that never ran.
        identity_marker="--shellshock",
        user_agent_flag="--user-agent",
        arg_policy=ArgPolicy(
            tool="commix",
            header_flags={"--header", "-H"},
            allowed_flags={
                "-u", "--url", "--batch", "--level", "--technique", "--time-sec",
                "--delay", "--timeout", "--retries", "--skip-waf", "--user-agent",
                "--output-dir", "--answers", "--disable-coloring", "--skip-empty",
                "--smart", "--flush-session", "--ignore-session", "--no-logging",
                "--time-limit", "-p", "--skip", "-d", "--data", "--cookie",
                "-H", "--header", "--method", "--skip-calc",
            },
            # Every one of these takes no value. commix parses with optparse, so
            # a flag omitted here would swallow the following argument — the bug
            # that left `retire` un-runnable for the life of this project.
            boolean_flags={
                "--batch", "--skip-waf", "--disable-coloring", "--skip-empty",
                "--smart", "--flush-session", "--ignore-session", "--no-logging",
                "--skip-calc",
            },
            denied_flags={
                # Command execution on the target. commix's whole second half.
                "--os-cmd", "--os-shell", "--shellshock", "--alter-shell", "--msf-path",
                # --alert runs an OS command on *this* host when an injection
                # point is found: local RCE reachable from a scan argument.
                "--alert",
                # Enumeration = reading data off the target host.
                "--all", "--current-user", "--hostname", "--is-root", "--is-admin",
                "--sys-info", "--users", "--passwords", "--privileges", "--ps-version",
                # File access on the target.
                "--file-read", "--file-write", "--file-dest", "--web-root", "--tmp-path",
                # Targets sourced past the scope engine: bulk file, proxy log,
                # saved request, remote sitemap, crawl.
                "-m", "-l", "-r", "-x", "--crawl", "--crawl-exclude",
                # Attribution, evasion, and local mutation.
                "--proxy", "--tor", "--tor-port", "--random-agent", "--tamper",
                "--install", "--update", "--purge", "--wizard", "--url-reload",
                "--ignore-dependencies", "--list-tampers",
                # Credentialed login flows belong to the operator, not a scan.
                "--auth-url", "--auth-data", "--auth-cred", "--auth-type",
            },
            value_patterns={
                "-u": URL_PATTERN,
                "--url": URL_PATTERN,
                # c(lassic) e(val-based) t(ime-based). 'f' is file-based: it
                # writes a file into the target's web root to read output back.
                "--technique": re.compile(r"[cet]{1,3}"),
                "-p": PARAM_NAME,
                "--skip": re.compile(r"[A-Za-z0-9_.,\[\]-]{1,200}"),
                "--method": HTTP_METHOD,
                "--answers": re.compile(r"[A-Za-z=,]{1,120}"),
                "--output-dir": WORKSPACE_PATH,
                # commix's --data is a whole body upstream, but '&' is hard-denied
                # project-wide, so one pair is all that can be expressed.
                "-d": BODY_PAIR,
                "--data": BODY_PAIR,
            },
            numeric_caps={
                "--level": 2, "--time-sec": 10, "--delay": 5, "--timeout": 30,
                "--retries": 2, "--time-limit": 1800,
            },
            relaxed_chars=UA_CHARS,
        ),
    )
)

SMUGGLER = register_spec(
    ToolSpec(
        name="smuggler",
        binary="smuggler",
        license="MIT",
        homepage="https://github.com/defparam/smuggler",
        version_args=["-h"],
        identity_marker="smuggler.py",
        # smuggler writes raw sockets by hand and has no user-agent flag, so the
        # engagement's tagged agent cannot ride along. Recorded in risk_notes so
        # the attribution gap is visible rather than assumed away.
        user_agent_flag=None,
        arg_policy=ArgPolicy(
            tool="smuggler",
            allowed_flags={
                "-u", "--url", "-x", "--exit_early", "-m", "--method",
                "-l", "--log", "-q", "--quiet", "-t", "--timeout", "--no-color",
            },
            boolean_flags={"-x", "--exit_early", "-q", "--quiet", "--no-color"},
            denied_flags={
                # --vhost rewrites the Host header, which addresses a host the
                # scope engine never saw while the URL still looks in-scope.
                "-v", "--vhost",
                # An arbitrary local payload config: an unvetted mutation set,
                # and a file read chosen by an argument.
                "-c", "--configfile",
            },
            value_patterns={
                "-u": URL_PATTERN,
                "--url": URL_PATTERN,
                "-m": HTTP_METHOD,
                "--method": HTTP_METHOD,
                "-l": WORKSPACE_PATH,
                "--log": WORKSPACE_PATH,
            },
            numeric_caps={"-t": 15, "--timeout": 15},
        ),
    )
)

NOSQLI = register_spec(
    ToolSpec(
        name="nosqli",
        binary="nosqli",
        license="MIT",
        homepage="https://github.com/Charlie-belmer/nosqli",
        version_args=["version"],
        identity_marker="nosqli",
        # nosqli's -u is --user-agent, not a URL. The target is --target/-t.
        # Only the long form is wired here; the short one invites exactly the
        # confusion that puts a user-agent string where a URL belongs.
        user_agent_flag="--user-agent",
        arg_policy=ArgPolicy(
            tool="nosqli",
            allowed_flags={"-t", "--target", "-d", "--data", "--user-agent", "--insecure", "--https"},
            boolean_flags={"--insecure", "--https"},
            denied_flags={
                "-p", "--proxy",
                # A saved request file is a target the scope engine never saw.
                "-r", "--request",
                "--config",
            },
            value_patterns={
                "-t": URL_PATTERN,
                "--target": URL_PATTERN,
                "-d": BODY_PAIR,
                "--data": BODY_PAIR,
            },
            allow_positional=True,
            # The only subcommand this wrapper drives. `completion` writes shell
            # scripts and `help` is noise.
            positional_pattern=re.compile(r"scan"),
            relaxed_chars=UA_CHARS,
        ),
    )
)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

#: One line of tool output is capped here. ssrfmap's portscan module redraws a
#: progress counter with `end='\r'`, so its "line" can be megabytes long.
_MAX_LINE = 4000


def _clean(text: str, *, limit: int = 4000) -> list[str]:
    """Merged, de-ANSI'd, line-capped output. Both streams: these tools log to
    stderr as readily as stdout, and a marker on the wrong stream reads as a
    clean result."""
    out: list[str] = []
    for raw in _ANSI.sub("", text).replace("\r", "\n").splitlines():
        line = raw.strip()
        if line:
            out.append(line[:_MAX_LINE])
        if len(out) >= limit:
            break
    return out


def _merged(result: ProcResult) -> list[str]:
    return _clean(f"{result.stdout}\n{result.stderr}")


def _untested(tool: str, run: ToolRun, target: str, *, install: str) -> dict[str, Any]:
    """The response for a tool that did not run.

    Zero findings from a binary that never executed is the most expensive lie a
    scanner can tell, because it is indistinguishable in a report from a surface
    that was tested and found sound.
    """
    return {
        "ok": False,
        "error": "tool_unavailable",
        "target": target,
        "message": (
            f"{tool} could not run ({run.error or 'unavailable'}). {install} "
            "Without it this surface is UNTESTED, not clean."
        ),
        "untested": True,
        "tools": [run.to_dict()],
    }


def _http_target(value: str, *, tool: str) -> str:
    """First target, required to be an absolute HTTP(S) URL.

    ssrfmap, smuggler and the rest take a URL, and a bare hostname reaches them
    as a relative path — the tool then tests nothing and exits zero.
    """
    targets = split_targets(value)
    if not targets:
        raise ValueError(f"{tool}: no target supplied")
    url = targets[0]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(
            f"{tool}: {url!r} is not an absolute http(s) URL. Pass the full URL "
            "including the parameter you want tested."
        )
    if not URL_PATTERN.fullmatch(url):
        raise ValueError(f"{tool}: {url!r} contains characters not permitted in a target URL")
    if "&" in url:
        # sanitize_argv would refuse this several layers down with "shell control
        # character(s) ['&']", which reads as a malformed argument rather than as
        # the project-wide rule it is. '&' is in HARD_DENY_CHARS and no policy can
        # relax it, so a two-parameter URL cannot reach any tool in EasyHunt.
        raise ValueError(
            f"{tool}: {url!r} carries more than one query parameter. '&' is refused in "
            "every EasyHunt argument value and cannot be relaxed per tool. Test one "
            "parameter at a time, or drive the multi-parameter request by hand."
        )
    return url


def _candidate(
    *,
    asset: str,
    title: str,
    tool: str,
    rule_id: str,
    severity: Severity,
    description: str,
    how_found: str,
    remediation: str,
    tags: list[str],
    excerpt: str,
    confidence: float = 0.5,
) -> Finding:
    """A candidate, and only ever a candidate.

    None of these tools produces a reproducible PoC in the shape this project
    requires, and the flags that would let them are denied. Promotion runs
    through ``validate_findings`` or a human's ``poc_record``.
    """
    finding = Finding(
        asset=asset,
        title=title,
        phase="exploit",
        severity=severity,
        status=Status.CANDIDATE,
        description=description,
        how_found=how_found,
        source_tool=tool,
        rule_id=rule_id,
        confidence=confidence,
        evidence=[Evidence(kind="log", description=f"{tool} output", excerpt=excerpt[:2000])],
        remediation=remediation,
        tags=tags,
    )
    finding.note(
        f"Candidate only — {tool} reported this, nothing verified it. Reproduce it "
        "by hand and record the proof with poc_record() before it appears in a "
        "report as confirmed."
    )
    return finding


def _store(findings: list[Finding]) -> None:
    engagement = get_engagement()
    for finding in findings:
        engagement.findings.add(finding)
    if findings:
        engagement.findings.save()


def _result(
    *,
    target: str,
    run: ToolRun,
    findings: list[Finding],
    note: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "target": target,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "tools": [run.to_dict()],
        "note": note,
    }
    if extra:
        payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# ssrfmap
# --------------------------------------------------------------------------- #


def _stage_request(engagement: Any, url: str, parameter: str) -> Path:
    """Write the raw HTTP request ssrfmap's ``-r`` needs into the workspace.

    ssrfmap has no URL argument: it parses a request file and substitutes the
    payload into the parameter named by ``-p``. The file is generated here rather
    than accepted from the caller, because an operator-supplied request file is a
    second target — with its own Host header — that the scope engine never saw.

    The workspace is the one writable mount in the sandbox, and
    ``Sandbox._translate_paths`` rewrites the path for the container.
    """
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    # A parameter that is not already in the URL is added empty: ssrfmap injects
    # into whatever `-p` names, and a missing key means it injects into nothing
    # and reports a clean result.
    query.setdefault(parameter, "")
    path = parsed.path or "/"
    lines = [
        f"GET {path}?{urlencode(query)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        f"User-Agent: {engagement.scope.rules.user_agent}",
        "Accept: */*",
        "Connection: close",
        "",
    ]
    staged = engagement.raw_path("ssrfmap-request", "txt")
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return staged


_SSRF_OPEN = re.compile(r"IP:\s*(\S+)\s*,\s*Found\s+open\s+port n.(\d+)")


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=1800,
    name="ssrf_probe",
    spec=SSRFMAP,
    tags={"exploitation", "ssrf"},
    estimated_requests=8400,
    risk_notes=[
        "Asks the target to fetch internal addresses on our behalf — this is an SSRF attempt.",
        "ssrfmap's portscan module walks an 8,282-entry port list with its own thread pool "
        "and honours no rate limit of ours. Budget for roughly 8,400 requests to the target.",
        "Detection only: the modules that read cloud credentials (aws/gce/alibaba), write to "
        "internal services (redis/mysql/zabbix), read files, or pivot (socksproxy) are denied.",
    ],
    rationale="Confirm whether a URL parameter drives a server-side fetch.",
)
async def ssrf_probe(target: str, parameter: str = "url") -> dict[str, Any]:
    """Test one URL parameter for server-side request forgery with SSRFmap.

    ``parameter`` names the query parameter suspected of taking a URL. The probe
    asks the target to connect back to its own loopback interface across a port
    list; a port that answers differently from the baseline means the target
    performed the fetch, which is the SSRF.

    This is deliberately the narrowest of SSRFmap's 24 modules. The ones that
    make SSRF *interesting* — reading IMDS credentials, writing a Redis key,
    proxying through the victim — are the ones a bug bounty program means when it
    says do not exfiltrate and do not pivot, and they are not on the allowlist.
    Confirm reachability here, then prove impact by hand with ``poc_record()``.
    """
    engagement = get_engagement()
    url = _http_target(target, tool="ssrfmap")
    if not PARAM_NAME.fullmatch(parameter):
        return {
            "ok": False,
            "error": "bad_parameter",
            "message": f"{parameter!r} is not a usable HTTP parameter name.",
        }

    request_file = _stage_request(engagement, url, parameter)
    logfile = engagement.raw_path("ssrfmap", "log")
    argv = ["-r", str(request_file), "-p", parameter, "-m", "portscan", "--level", "1",
            "--logfile", str(logfile)]
    if urlsplit(url).scheme == "https":
        argv.append("--ssl")

    run = await run_one(
        "ssrfmap", argv, timeout=1700, extract=_merged, allow_codes=(0, 1)
    )
    if not run.ran:
        return _untested(
            "ssrfmap", run, url,
            install="Install it from https://github.com/swisskyrepo/SSRFmap, or use the "
            "EasyHunt container image.",
        )

    text = "\n".join(run.values)
    open_ports = sorted({f"{ip}:{port}" for ip, port in _SSRF_OPEN.findall(text)})
    findings: list[Finding] = []
    if open_ports:
        findings.append(
            _candidate(
                asset=url,
                title=f"Possible SSRF: parameter '{parameter}' reaches the server's loopback interface",
                tool="ssrfmap",
                rule_id="ssrf.portscan",
                severity=Severity.HIGH,
                description=(
                    f"Supplying an internal URL in '{parameter}' produced responses that "
                    f"differ per port for {len(open_ports)} loopback port(s): "
                    f"{', '.join(open_ports[:12])}. A response that varies with an "
                    "internal port means the server made the connection."
                ),
                how_found=f"ssrfmap -p {parameter} -m portscan against {url}",
                remediation=(
                    "Do not fetch a user-supplied URL. If a fetch is required, resolve the "
                    "host first and reject loopback, link-local and RFC1918 addresses after "
                    "resolution — a denylist applied to the string is bypassed by DNS "
                    "rebinding and by redirects. Send the request from a network segment "
                    "with no route to internal services or the metadata endpoint."
                ),
                tags=["ssrf", "candidate"],
                excerpt=text[-2000:],
                confidence=0.5,
            )
        )
    _store(findings)

    return _result(
        target=url,
        run=run,
        findings=findings,
        note=(
            "Differential port responses are evidence of a fetch, not proof of impact. "
            "Establish what the reachable service is, and record the proof with poc_record(). "
            "Do not read cloud credentials to demonstrate severity."
            if open_ports
            else "No internal port responded differently. SSRF may still exist blind — "
            "run oob_listener() and inject the callback URL into this parameter."
        ),
        extra={"parameter": parameter, "open_ports": open_ports, "request_file": str(request_file)},
    )


# --------------------------------------------------------------------------- #
# sstimap
# --------------------------------------------------------------------------- #

_SSTI_HIT = re.compile(r"SSTImap identified the following injection point")
_SSTI_FIELD = re.compile(r"^\s*(Engine|Injection|Context|Parameter|OS)\s*:\s*(.+)$", re.MULTILINE)


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=900,
    name="ssti_probe",
    spec=SSTIMAP,
    tags={"exploitation", "ssti"},
    estimated_requests=250,
    risk_notes=[
        "Injects template-engine expressions that the target evaluates server-side.",
        "Detection only: --os-shell, --os-cmd, --eval-code, --tpl-code, bind/reverse shell, "
        "and file upload/download are denied for this tool.",
    ],
    rationale="Determine whether a parameter is evaluated by a server-side template engine.",
)
async def ssti_probe(
    target: str,
    injection_points: str = "Q",
    level: int = 1,
    engine: str | None = None,
) -> dict[str, Any]:
    """Detect server-side template injection with SSTImap.

    ``injection_points`` selects where to inject: Q(uery), B(ody), H(eaders),
    C(ookies) — query only by default, because headers and cookies multiply the
    request count and are usually not the reported sink. ``engine`` optionally
    narrows to one template engine once ``http_probe`` has told you the stack
    (``jinja2``, ``twig``, ``freemarker``, ``velocity``, ``smarty``, …).

    A hit here is arithmetic evaluated in a template — ``{{7*7}}`` returning
    ``49`` — and nothing else. SSTImap's shell, eval and file-transfer flags are
    denied, so the tool cannot be talked into demonstrating RCE. Establishing
    that a template engine evaluates attacker input is the finding; proving code
    execution beyond that is a decision a human makes, in writing.
    """
    url = _http_target(target, tool="sstimap")
    if not re.fullmatch(r"[QBHC]{1,4}", injection_points):
        return {
            "ok": False,
            "error": "bad_injection_points",
            "message": "injection_points must be a combination of Q, B, H and C.",
        }
    if engine is not None and not re.fullmatch(r"[A-Za-z0-9_:,/*-]{1,120}", engine):
        return {"ok": False, "error": "bad_engine", "message": f"{engine!r} is not an engine name."}

    argv = [
        "-u", url,
        "--no-color",
        "-P", injection_points,
        "-l", str(max(1, min(int(level), 3))),
        "-r", "REBT",
        "--delay", "1",
    ]
    if engine:
        argv += ["-e", engine]

    run = await run_one("sstimap", argv, timeout=850, extract=_merged, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            "sstimap", run, url,
            install="Install it from https://github.com/vladko312/SSTImap, or use the "
            "EasyHunt container image.",
        )

    text = "\n".join(run.values)
    findings: list[Finding] = []
    details: dict[str, str] = {}
    if _SSTI_HIT.search(text):
        details = {k.lower(): v.strip() for k, v in _SSTI_FIELD.findall(text)}
        engine_name = details.get("engine", "unknown engine")
        findings.append(
            _candidate(
                asset=url,
                title=f"Possible server-side template injection ({engine_name})",
                tool="sstimap",
                rule_id="ssti.sstimap",
                severity=Severity.HIGH,
                description=(
                    f"SSTImap reported an injection point on this URL and identified the "
                    f"template engine as {engine_name}. A parameter reaching a template "
                    "engine as template source, rather than as data passed to one, is "
                    "evaluated with the application's privileges."
                ),
                how_found=f"sstimap -u {url} -P {injection_points} -r REBT",
                remediation=(
                    "Render templates from fixed template files and pass user input as "
                    "context data. Never concatenate request values into template source. "
                    "If user-authored templates are a product requirement, run them in a "
                    "sandboxed environment with no access to object internals."
                ),
                tags=["ssti", "candidate"],
                excerpt=text[-2000:],
                confidence=0.6,
            )
        )
    _store(findings)

    return _result(
        target=url,
        run=run,
        findings=findings,
        note=(
            "SSTImap detected evaluation. Do not escalate to a shell — record the "
            "evaluated expression and its output with poc_record()."
            if findings
            else "No template evaluation detected on the tested injection points. Widening "
            "injection_points to QBHC or raising level increases coverage and request count."
        ),
        extra={"injection_points": injection_points, "engine": engine, "detail": details},
    )


# --------------------------------------------------------------------------- #
# commix
# --------------------------------------------------------------------------- #

_CMDI_HIT = re.compile(r"(?i)parameter.{0,80}?appears to be injectable")
_CMDI_PARAM = re.compile(r"(?i)\((?:GET|POST|JSON|Cookie|HTTP header)\)\s*'([^']{1,64})'\s*parameter")


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=1200,
    name="cmdi_probe",
    spec=COMMIX,
    tags={"exploitation", "rce"},
    estimated_requests=300,
    risk_notes=[
        "Injects OS command separators into request parameters. A vulnerable target executes them.",
        "Detection only: --os-cmd, --os-shell, --shellshock, --file-read/--file-write, the "
        "enumeration flags, and --alert (which runs a command on this host) are denied.",
        "The 'file-based' technique is excluded because it writes a file into the target's web root.",
    ],
    rationale="Determine whether a parameter is concatenated into an OS command.",
)
async def cmdi_probe(target: str, parameter: str | None = None, level: int = 1) -> dict[str, Any]:
    """Detect OS command injection with commix. Detection only, never a shell.

    ``parameter`` restricts testing to one parameter; leave it unset to let
    commix test every parameter it finds in the URL. ``level`` (1-2) widens the
    payload set.

    The techniques available here are classic, eval-based and time-based — the
    three that answer "does this execute" by observing output or delay.
    File-based is excluded: it proves the same thing by writing a file into the
    target's web root, which is a change to the target, not evidence.

    **Read the tool-availability note if this returns UNTESTED.** PyPI's
    ``commix`` package is not commixproject/commix; it is an unrelated 2019
    package that only knows how to print a banner. This spec carries an identity
    marker so the impostor is refused rather than run — a refusal here means the
    real tool is missing, and the surface is untested.
    """
    url = _http_target(target, tool="commix")
    if parameter is not None and not PARAM_NAME.fullmatch(parameter):
        return {
            "ok": False,
            "error": "bad_parameter",
            "message": f"{parameter!r} is not a usable HTTP parameter name.",
        }

    engagement = get_engagement()
    outdir = engagement.workspace / "commix"
    outdir.mkdir(parents=True, exist_ok=True)

    argv = [
        "-u", url,
        "--batch",
        "--technique", "cet",
        "--level", str(max(1, min(int(level), 2))),
        "--time-sec", "5",
        "--timeout", "20",
        "--retries", "1",
        "--delay", "1",
        "--skip-empty",
        "--disable-coloring",
        "--output-dir", str(outdir),
    ]
    if parameter:
        argv += ["-p", parameter]

    run = await run_one("commix", argv, timeout=1150, extract=_merged, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            "commix", run, url,
            install=(
                "Install the real tool from https://github.com/commixproject/commix — "
                "note that `pip install commix` fetches an unrelated package that only "
                "prints a banner, and this spec's identity check refuses it."
            ),
        )

    text = "\n".join(run.values)
    findings: list[Finding] = []
    hit = _CMDI_HIT.search(text)
    if hit:
        match = _CMDI_PARAM.search(text)
        injected = match.group(1) if match else (parameter or "unknown")
        findings.append(
            _candidate(
                asset=url,
                title=f"Possible OS command injection in parameter '{injected}'",
                tool="commix",
                rule_id="rce.commix",
                severity=Severity.CRITICAL,
                description=(
                    f"commix reported '{injected}' as injectable. A parameter concatenated "
                    "into a shell command runs with the web process's privileges, which is "
                    "the highest-impact class this scanner set can surface."
                ),
                how_found=f"commix -u {url} --technique cet --level {level}",
                remediation=(
                    "Do not build shell command strings from request data. Call the binary "
                    "directly with an argument list and no shell, or replace the shell-out "
                    "with a library call. Input escaping is not a fix — every published "
                    "shell-quoting helper for this pattern has had a bypass."
                ),
                tags=["rce", "command-injection", "candidate"],
                excerpt=text[-2500:],
                confidence=0.6,
            )
        )
    _store(findings)

    return _result(
        target=url,
        run=run,
        findings=findings,
        note=(
            "Detected, not proven. Do not run commands to demonstrate this — the flags "
            "that would are denied. Reproduce the timing or output difference by hand and "
            "record it with poc_record()."
            if findings
            else "commix found no injectable parameter with classic, eval or time-based "
            "techniques at this level."
        ),
        extra={"parameter": parameter, "level": level},
    )


# --------------------------------------------------------------------------- #
# smuggler
# --------------------------------------------------------------------------- #

_SMUGGLE_HIT = re.compile(r"(?i)Potential\s+(CLTE|TECL)\s+Issue Found")


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=600,
    name="smuggling_probe",
    spec=SMUGGLER,
    tags={"exploitation", "smuggling"},
    estimated_requests=60,
    risk_notes=[
        "Sends deliberately ambiguous Content-Length/Transfer-Encoding requests. A desync "
        "affects the NEXT request on that connection, which may belong to a real user.",
        "Run this against production only where the program permits smuggling testing, and "
        "stop at the first finding rather than enumerating variants.",
        "smuggler has no user-agent option, so this traffic cannot carry the engagement's "
        "tagged agent. Coordinate with the program before running it.",
    ],
    rationale="Detect an HTTP request smuggling desync on a front-end/back-end pair.",
)
async def smuggling_probe(target: str, method: str = "POST") -> dict[str, Any]:
    """Detect HTTP request smuggling (CL.TE / TE.CL desync) with smuggler.

    Unlike everything else in this module, a hit here has collateral: a desync
    poisons the connection for whoever uses it next. ``--exit_early`` is always
    passed so the scan stops on the first finding instead of confirming it a
    dozen more times, and the timeout is held low.

    The probe is timing-based — smuggler measures whether the back-end waits for
    a body the front-end already terminated. Treat a hit as a strong lead and
    re-test manually against a target you control, or with the program's
    explicit agreement, before writing it up.
    """
    url = _http_target(target, tool="smuggler")
    if not HTTP_METHOD.fullmatch(method):
        return {
            "ok": False,
            "error": "bad_method",
            "message": f"{method!r} is not one of GET, POST, PUT, HEAD, OPTIONS.",
        }

    engagement = get_engagement()
    logfile = engagement.raw_path("smuggler", "log")
    argv = ["-u", url, "-m", method, "-x", "-q", "--no-color", "-t", "10", "-l", str(logfile)]

    run = await run_one("smuggler", argv, timeout=550, extract=_merged, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            "smuggler", run, url,
            install="Install it from https://github.com/defparam/smuggler, or use the "
            "EasyHunt container image.",
        )

    text = "\n".join(run.values)
    kinds = sorted({m.group(1).upper() for m in _SMUGGLE_HIT.finditer(text)})
    findings: list[Finding] = []
    if kinds:
        findings.append(
            _candidate(
                asset=url,
                title=f"Possible HTTP request smuggling ({'/'.join(kinds)}) on {urlsplit(url).netloc}",
                tool="smuggler",
                rule_id="smuggling.desync",
                severity=Severity.HIGH,
                description=(
                    f"smuggler observed {'/'.join(kinds)} desync behaviour: the front-end and "
                    "back-end disagree about where this request ends. That lets a request "
                    "prefix be left in the connection buffer and prepended to the next "
                    "user's request."
                ),
                how_found=f"smuggler -u {url} -m {method} (timing-based desync probe)",
                remediation=(
                    "Make the front-end and back-end agree on message length: reject any "
                    "request carrying both Content-Length and Transfer-Encoding, normalise "
                    "before forwarding, and prefer HTTP/2 end-to-end. Disabling connection "
                    "reuse to the back-end removes the impact at a performance cost."
                ),
                tags=["http-smuggling", "candidate"],
                excerpt=text[-2000:],
                confidence=0.4,
            )
        )
    _store(findings)

    return _result(
        target=url,
        run=run,
        findings=findings,
        note=(
            "Timing-based desync detection is prone to false positives on a loaded or "
            "rate-limited origin. Re-run at a quiet time before reporting, and never "
            "demonstrate impact by capturing another user's request."
            if findings
            else "No desync behaviour observed for this method. Front-ends differ per "
            "endpoint — a different path or method may still desync."
        ),
        extra={"method": method, "desync_types": kinds, "log": str(logfile)},
    )


# --------------------------------------------------------------------------- #
# nosqli
# --------------------------------------------------------------------------- #

_NOSQL_HIT = re.compile(r"(?i)injection found")
_NOSQL_TYPE = re.compile(r"(?i)(error based|blind) nosql injection")


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=600,
    name="nosqli_probe",
    spec=NOSQLI,
    tags={"exploitation", "nosqli"},
    estimated_requests=120,
    risk_notes=[
        "Injects MongoDB operators ($ne, $where, $regex) into request parameters.",
        "A $where payload runs JavaScript inside the database process on a vulnerable target; "
        "this probe uses the tool's own detection payloads and reads no data.",
    ],
    rationale="Determine whether a parameter is interpolated into a NoSQL query.",
)
async def nosqli_probe(target: str, data: str | None = None) -> dict[str, Any]:
    """Detect NoSQL injection (MongoDB operator injection) with nosqli.

    ``data`` supplies **one** ``name=value`` body parameter, and it should be a
    *valid* value (``username=alice``): the tool mutates what you give it, and a
    body rejected before it reaches the query tests nothing.

    One pair, not a body, because ``&`` is hard-denied for every argument in this
    project and nosqli's ``--data`` takes a single string. A login form needing
    both a username and a password cannot be expressed here — test that by hand,
    or with a proxy-driven request. Saying so is the point: the alternative is a
    probe that silently tests half the form.

    Authentication bypass is the usual impact: ``{"password": {"$ne": ""}}``
    matching every document. This probe stops at detection, and enumerating a
    collection to show severity is exactly what "do not exfiltrate" means.
    """
    url = _http_target(target, tool="nosqli")
    argv = ["scan", "--target", url]
    if data:
        if not BODY_PAIR.fullmatch(data):
            return {
                "ok": False,
                "error": "bad_data",
                "message": (
                    "data must be a single urlencoded 'name=value' pair, e.g. 'user=alice'. "
                    "'&' is refused for every argument in EasyHunt, so a multi-parameter "
                    "body cannot be passed here, and raw JSON needs quoting the sanitizer "
                    "refuses."
                ),
            }
        argv += ["--data", data]

    run = await run_one("nosqli", argv, timeout=550, extract=_merged, allow_codes=(0, 1))
    if not run.ran:
        return _untested(
            "nosqli", run, url,
            install="Build it from https://github.com/Charlie-belmer/nosqli, or use the "
            "EasyHunt container image.",
        )

    text = "\n".join(run.values)
    findings: list[Finding] = []
    kinds = sorted({m.group(0) for m in _NOSQL_TYPE.finditer(text)})
    if _NOSQL_HIT.search(text):
        findings.append(
            _candidate(
                asset=url,
                title="Possible NoSQL injection in a request parameter",
                tool="nosqli",
                rule_id="nosqli.operator",
                severity=Severity.HIGH,
                description=(
                    "nosqli reported an injection vector"
                    + (f" ({', '.join(kinds)})" if kinds else "")
                    + ". A parameter interpolated into a MongoDB query lets an attacker "
                    "supply an operator object instead of a value, which most commonly "
                    "turns an equality check into a match-anything predicate."
                ),
                how_found=f"nosqli scan --target {url}",
                remediation=(
                    "Cast request values to the type the query expects before building it — "
                    "an operator injection is a string parameter arriving as a dict. Reject "
                    "keys beginning with '$' in decoded request bodies, and disable "
                    "server-side JavaScript ($where, mapReduce) on the database."
                ),
                tags=["nosqli", "candidate"],
                excerpt=text[-2000:],
                confidence=0.5,
            )
        )
    _store(findings)

    return _result(
        target=url,
        run=run,
        findings=findings,
        note=(
            "Detected, not proven. Show the authentication or authorization consequence "
            "with a single request and record it with poc_record(). Do not enumerate "
            "documents."
            if findings
            else "No NoSQL operator injection detected. If the endpoint takes a JSON body, "
            "nosqli's urlencoded 'data' input may not reach the vulnerable parameter — "
            "test that case by hand."
        ),
        extra={"data": data, "injection_types": kinds},
    )

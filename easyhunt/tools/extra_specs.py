"""Catalog entries for tools EasyHunt knows about but does not drive directly.

These complete the tool table from the build guide. Each has an argument policy
and a recorded license, so ``easyhunt doctor`` reports them, the report's tool
inventory lists them, and a plugin author can call one through ``run_one()``
without needing to define a policy first.

They are catalogued rather than wrapped because in each case an already-wrapped
tool covers the same ground better:

* ``gobuster`` / ``dirsearch`` — ffuf and feroxbuster are faster and already have
  rate ceilings wired in.
* ``subjack`` / ``Subdominator`` / ``SubdomainSleuth`` — subzy and dnsReaper feed
  the verified takeover flow. SubdomainSleuth is the exception worth reaching for
  if you hold authoritative zone files: it catches lame NS delegations that
  HTTP-only scanners never see.
* ``secretfinder`` — the built-in JS pattern scan plus jsluice covers it.
* ``xsstrike`` — dalfox verifies execution context; XSStrike mostly reports
  reflection.
* ``uncover``, ``gitdorker``, ``CloudPEASS`` — each needs API keys or credentials
  that belong to the operator, not to an automated run.

Adding a wrapper for any of them means writing a function decorated with
``@easyhunt_tool`` — the policy and license are already here.
"""

from __future__ import annotations

import re

from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.tools.base import ToolSpec
from easyhunt.tools.common import HOST_PATTERN, PATH_PATTERN, URL_PATTERN, register_spec

__all__ = ["EXTRA_SPECS"]

UNCOVER = register_spec(
    ToolSpec(
        name="uncover", binary="uncover", license="MIT",
        homepage="https://github.com/projectdiscovery/uncover", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="uncover",
            allowed_flags={"-q", "-e", "-l", "-json", "-silent", "-duc", "-f", "-nc"},
            boolean_flags={"-json", "-silent", "-duc", "-nc"},
            value_patterns={
                # Search-engine queries, not shell input.
                "-q": re.compile(r"[A-Za-z0-9._:\"= -]{1,200}"),
                "-e": re.compile(r"[a-z,]{1,64}"),
            },
            numeric_caps={"-l": 1000},
            relaxed_chars=frozenset('"'),
        ),
    )
)

SECRETFINDER = register_spec(
    ToolSpec(
        name="secretfinder", binary="secretfinder", license="GPL-3.0",
        homepage="https://github.com/m4ll0k/SecretFinder", version_args=["-h"],
        identity_marker="secretfinder",
        arg_policy=ArgPolicy(
            tool="secretfinder",
            allowed_flags={"-i", "-o", "-e", "-g", "-c", "-r"},
            boolean_flags={"-e", "-g"},
            value_patterns={"-i": URL_PATTERN, "-o": re.compile(r"cli|" + PATH_PATTERN.pattern)},
        ),
    )
)

GOBUSTER = register_spec(
    ToolSpec(
        name="gobuster", binary="gobuster", license="Apache-2.0",
        homepage="https://github.com/OJ/gobuster", version_args=["version"],
        arg_policy=ArgPolicy(
            tool="gobuster",
            allowed_flags={"-u", "-w", "-t", "-o", "-q", "-k", "-s", "-b", "--delay", "--timeout"},
            boolean_flags={"-q", "-k"},
            # No -x with arbitrary methods, no -H injection of auth headers.
            denied_flags={"-m", "--method", "-P", "-U"},
            value_patterns={"-u": URL_PATTERN, "-w": PATH_PATTERN},
            numeric_caps={"-t": 20, "--timeout": 30},
            allow_positional=True,
            positional_pattern=re.compile(r"dir|dns|vhost|fuzz|s3"),
        ),
    )
)

DIRSEARCH = register_spec(
    ToolSpec(
        name="dirsearch", binary="dirsearch", license="GPL-2.0",
        homepage="https://github.com/maurosoria/dirsearch", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="dirsearch",
            allowed_flags={"-u", "-w", "-t", "-o", "--format", "-q", "--delay", "--timeout", "-x"},
            boolean_flags={"-q"},
            denied_flags={"--data", "-m", "--method"},
            value_patterns={
                "-u": URL_PATTERN, "-w": PATH_PATTERN,
                "--format": re.compile(r"json|csv|simple|plain"),
                "-x": re.compile(r"[0-9,]{1,64}"),
            },
            numeric_caps={"-t": 20, "--timeout": 30, "--delay": 5},
        ),
    )
)

SUBJACK = register_spec(
    ToolSpec(
        name="subjack", binary="subjack", license="MIT",
        homepage="https://github.com/haccer/subjack", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="subjack",
            allowed_flags={"-w", "-t", "-timeout", "-o", "-ssl", "-c", "-v", "-m", "-a"},
            boolean_flags={"-ssl", "-v", "-m", "-a"},
            value_patterns={"-w": PATH_PATTERN, "-c": PATH_PATTERN},
            numeric_caps={"-t": 50, "-timeout": 30},
        ),
    )
)

SUBDOMINATOR = register_spec(
    ToolSpec(
        name="subdominator", binary="subdominator", license="MIT",
        homepage="https://github.com/Stratus-Security/Subdominator", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="subdominator",
            # --domain-list, not -l, and there is no --validate at any spelling.
            # takeover.py was calling `subdominator -l <file> --validate`;
            # subdominator answered "[WRN]: Please use the command for more
            # infromation" and exited, so the third takeover detector produced
            # nothing on every run. Measured against the lab, not inferred.
            allowed_flags={"--domain-list", "-dL", "-o", "-t", "-d", "--domain"},
            boolean_flags=set(),
            value_patterns={
                "--domain-list": PATH_PATTERN,
                "-dL": PATH_PATTERN,
                "-d": HOST_PATTERN,
                "--domain": HOST_PATTERN,
            },
            numeric_caps={"-t": 50},
        ),
    )
)

SUBDOMAINSLEUTH = register_spec(
    ToolSpec(
        name="subdomainsleuth", binary="subdomainsleuth", license="Apache-2.0",
        homepage="https://github.com/yahoo/SubdomainSleuth", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="subdomainsleuth",
            # Reads authoritative zone files — catches lame NS delegations that
            # HTTP-only takeover scanners cannot see.
            allowed_flags={"-zonefile", "-checks", "-out", "-domain", "-json"},
            boolean_flags={"-json"},
            value_patterns={
                "-zonefile": PATH_PATTERN,
                "-checks": re.compile(r"[a-z,]{1,64}"),
                "-domain": HOST_PATTERN,
            },
        ),
    )
)

GITDORKER = register_spec(
    ToolSpec(
        name="gitdorker", binary="gitdorker", license="MIT",
        homepage="https://github.com/obheda12/GitDorker", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="gitdorker",
            allowed_flags={"-tf", "-q", "-d", "-o", "-e"},
            value_patterns={"-q": re.compile(r"[A-Za-z0-9._-]{1,120}"), "-d": PATH_PATTERN},
            numeric_caps={"-e": 30},
        ),
    )
)

CLOUDPEASS = register_spec(
    ToolSpec(
        name="cloudpeass", binary="cloudpeass", license="MIT",
        homepage="https://github.com/carlospolop/CloudPEASS", version_args=["--help"],
        arg_policy=ArgPolicy(
            tool="cloudpeass",
            allowed_flags={"--profile", "--out-json", "--threads", "--not-use-ht-ai", "--region"},
            boolean_flags={"--not-use-ht-ai"},
            value_patterns={
                "--profile": re.compile(r"[A-Za-z0-9._-]{1,64}"),
                "--region": re.compile(r"[a-z0-9-]{4,32}"),
            },
            numeric_caps={"--threads": 20},
        ),
    )
)

GF = register_spec(
    ToolSpec(
        name="gf", binary="gf", license="MIT",
        homepage="https://github.com/tomnomnom/gf", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="gf",
            # gf's whole CLI is three boolean flags plus a pattern name and
            # optional files. `-save` writes a pattern into ~/.gf/ — a local
            # convenience, not something the sanitizer needs to defend against.
            allowed_flags={"-save", "-list", "-dump"},
            boolean_flags={"-save", "-list", "-dump"},
            allow_positional=True,
            positional_pattern=re.compile(r"[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)

XSSTRIKE = register_spec(
    ToolSpec(
        name="xsstrike", binary="xsstrike", license="GPL-3.0",
        homepage="https://github.com/s0md3v/XSStrike", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="xsstrike",
            allowed_flags={"-u", "--crawl", "-l", "-t", "--timeout", "--json", "--skip-dom", "-f"},
            boolean_flags={"--crawl", "--json", "--skip-dom"},
            # No --file-based payload loading and no --data: dalfox is the
            # supported path for anything that submits a request body.
            denied_flags={"--data", "--seeds", "--headers"},
            value_patterns={"-u": URL_PATTERN},
            numeric_caps={"-t": 10, "--timeout": 30, "-l": 3},
            relaxed_chars=frozenset("()<>"),
        ),
    )
)

#: Everything defined here, for tests and documentation.
EXTRA_SPECS = [
    UNCOVER, SECRETFINDER, GOBUSTER, DIRSEARCH, SUBJACK, SUBDOMINATOR,
    SUBDOMAINSLEUTH, GITDORKER, CLOUDPEASS, XSSTRIKE, GF,
]

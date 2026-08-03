"""Passive recon: subdomains, ASN, certificates, org intelligence.

Everything here reads public sources. Nothing sends a request to the target's own
infrastructure beyond DNS resolution and one TLS handshake, which is why these run
without an approval prompt. BBOT covers most of this ground already — these
wrappers exist for the cases where you want one specific source, or where BBOT is
not installed.

**Rate governance.** The control plane's limiter charges one token per *tool
call*, not per HTTP request, so a wrapper that hands a target list to a tool with
its own thread pool is ungoverned unless the tool is told otherwise on its command
line. Every rate or concurrency flag used here is sourced from
``scope.rules.max_rps`` / ``max_concurrency`` and never from a caller argument —
a rate an agent can set is a rate an agent can raise.

Where a tool has no such flag it is named in the wrapper's ``risk_notes`` rather
than left to look governed. As of this audit:

* ``subfinder`` — ``-rl`` (requests/second, global). Governed.
* ``findomain`` — ``--rate-limit`` (whole seconds *between targets*). Passed, but
  it is an inter-target delay and does not bound the per-request rate.
* ``tlsx`` — ``-c`` (concurrency, default **300**) and ``-delay``. Governed.
* ``assetfinder``, ``asnmap``, ``theHarvester``, ``whois`` — no rate, concurrency,
  or delay flag exists. Ungoverned; declared.
* ``amass`` — v4 had ``-max-dns-queries``; v5 dropped it and offers no
  replacement. Version-dependent, so treated as ungoverned.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    HOST_PATTERN,
    grouped_result,
    in_scope_only,
    lines_of,
    merge_runs,
    register_spec,
    run_many,
    run_one,
    split_targets,
    store_assets,
)

# The wildcard probe runs dig through the governed runner. Importing the spec
# rather than trusting module load order keeps `run_one("dig", ...)` from
# degrading to "not in catalog", which would report "no wildcard" for a domain
# that has one.
from easyhunt.tools.takeover import DIG  # noqa: F401

__all__ = ["asn_lookup", "subdomain_enum", "tls_info", "whois_lookup"]

SUBFINDER = register_spec(
    ToolSpec(
        name="subfinder", binary="subfinder", image="projectdiscovery/subfinder:latest",
        license="MIT", homepage="https://github.com/projectdiscovery/subfinder",
        version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="subfinder",
            allowed_flags={
                "-d", "-dL", "-silent", "-nc", "-all", "-timeout", "-t", "-o", "-duc", "-rl",
            },
            boolean_flags={"-silent", "-nc", "-all", "-duc"},
            value_patterns={"-d": HOST_PATTERN},
            # -rl is subfinder's global requests-per-second ceiling. Capped here
            # as well as set from the engagement, so a future caller cannot pass
            # a larger one through.
            numeric_caps={"-timeout": 60, "-t": 50, "-rl": 100},
        ),
    )
)

ASSETFINDER = register_spec(
    ToolSpec(
        name="assetfinder", binary="assetfinder", license="MIT",
        homepage="https://github.com/tomnomnom/assetfinder", version_args=["--help"],
        arg_policy=ArgPolicy(
            tool="assetfinder",
            allowed_flags={"--subs-only"},
            boolean_flags={"--subs-only"},
            allow_positional=True,
            positional_pattern=HOST_PATTERN,
            max_argv=4,
        ),
    )
)

FINDOMAIN = register_spec(
    ToolSpec(
        name="findomain", binary="findomain", license="GPL-3.0",
        homepage="https://github.com/Findomain/Findomain", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="findomain",
            allowed_flags={"-t", "--quiet", "-u", "--external-subdomains", "--rate-limit"},
            boolean_flags={"--quiet", "--external-subdomains"},
            value_patterns={"-t": HOST_PATTERN},
            # findomain's --rate-limit is whole seconds of delay *per target*, not
            # a requests-per-second ceiling. Capped so it cannot be turned into a
            # multi-hour stall, but see the note in subdomain_enum's risk_notes.
            numeric_caps={"--rate-limit": 60},
        ),
    )
)

AMASS = register_spec(
    ToolSpec(
        name="amass", binary="amass", license="Apache-2.0",
        homepage="https://github.com/owasp-amass/amass", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="amass",
            allowed_flags={"-d", "-asn", "-org", "-passive", "-silent", "-timeout", "-json", "-o"},
            boolean_flags={"-passive", "-silent"},
            value_patterns={"-d": HOST_PATTERN, "-org": re.compile(r"[A-Za-z0-9 ._&-]{1,120}")},
            numeric_caps={"-timeout": 30, "-asn": 4_294_967_295},
            allow_positional=True,
            positional_pattern=re.compile(r"enum|intel"),
        ),
    )
)

ASNMAP = register_spec(
    ToolSpec(
        name="asnmap", binary="asnmap", license="MIT",
        homepage="https://github.com/projectdiscovery/asnmap", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="asnmap",
            allowed_flags={"-d", "-a", "-i", "-org", "-silent", "-json", "-duc"},
            boolean_flags={"-silent", "-json", "-duc"},
            value_patterns={"-d": HOST_PATTERN, "-a": re.compile(r"(?i)AS[0-9]{1,10}")},
        ),
    )
)

TLSX = register_spec(
    ToolSpec(
        name="tlsx", binary="tlsx", license="MIT",
        homepage="https://github.com/projectdiscovery/tlsx", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="tlsx",
            allowed_flags={
                "-u", "-l", "-json", "-silent", "-san", "-cn", "-so", "-duc", "-c", "-nc",
                "-delay",
            },
            boolean_flags={"-json", "-silent", "-san", "-cn", "-so", "-duc", "-nc"},
            value_patterns={
                "-u": HOST_PATTERN,
                # A Go duration, e.g. "200ms" or "2s". tlsx waits this long between
                # connections on each thread.
                "-delay": re.compile(r"[0-9]{1,6}(?:ms|s)"),
            },
            # tlsx defaults to 300 concurrent threads. The cap matters as much as
            # the value the wrapper passes: without -c, one tls_info call opens up
            # to 300 simultaneous handshakes against the target.
            numeric_caps={"-c": 30},
        ),
    )
)

WHOIS = register_spec(
    ToolSpec(
        name="whois", binary="whois", license="GPL-2.0", homepage="https://en.wikipedia.org/wiki/WHOIS",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="whois", allowed_flags=set(), allow_positional=True,
            positional_pattern=HOST_PATTERN, max_argv=2,
        ),
    )
)

THEHARVESTER = register_spec(
    ToolSpec(
        name="theHarvester", binary="theHarvester", license="GPL-2.0",
        homepage="https://github.com/laramies/theHarvester", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="theHarvester",
            allowed_flags={"-d", "-b", "-l", "-f"},
            value_patterns={
                "-d": HOST_PATTERN,
                "-b": re.compile(r"[a-z0-9,_-]{1,120}"),
            },
            numeric_caps={"-l": 500},
        ),
    )
)


# --------------------------------------------------------------------------- #
# Wildcard DNS
# --------------------------------------------------------------------------- #


async def _detect_wildcard(seed: str, probes: int = 3) -> dict[str, Any]:
    """Does ``*.seed`` answer for names that cannot exist?

    A wildcard record turns passive enumeration into fiction: every source has
    recorded whatever nonsense anyone ever queried, and all of it resolves. On a
    real engagement this produced 156 "subdomains" of which roughly 90 were
    recursive permutations like ``update.update.update.trust``. Left undetected,
    http_probe reports them all live (the wildcard answers) and the scanner then
    spends the whole budget on hosts that do not exist.

    Each probe is a real query against the target's authoritative nameservers, so
    each one takes a token from the engagement limiter and goes through the
    sandboxed runner. This used to call ``create_subprocess_exec`` directly, which
    meant three queries that the rate limiter never saw and the sandbox never
    contained.
    """
    import secrets

    engagement = get_engagement()
    addresses: set[str] = set()
    answered = 0
    attempted = 0
    for _ in range(probes):
        label = f"eh-{secrets.token_hex(6)}"
        async with engagement.limiter.slot(host=seed):
            run = await run_one(
                "dig",
                ["+short", "+time", "3", "+tries", "1", f"{label}.{seed}"],
                timeout=30,
            )
        if not run.ran:
            # dig absent or unregistered. Say so rather than reporting "no
            # wildcard" — a silent false negative here re-poisons every later
            # phase with hosts that do not exist.
            continue
        attempted += 1
        found = [v.strip() for v in run.values if v.strip() and not v.strip().endswith(".")]
        if found:
            answered += 1
            addresses.update(found)

    # Every probe must answer. One stray hit is a resolver quirk, not a wildcard.
    return {
        "wildcard": attempted == probes and answered == probes and bool(addresses),
        "addresses": sorted(addresses),
        "probes": probes,
        "answered": answered,
        "checked": attempted == probes,
    }


def _looks_like_wildcard_noise(host: str, seed: str) -> bool:
    """Recursive permutations that only exist because a wildcard answered.

    Conservative on purpose: it flags repetition, not unfamiliarity. A real host
    with an unusual name is not noise, and calling it noise would hide an asset.
    """
    prefix = host[: -len(seed)].rstrip(".") if host.endswith(seed) else host
    labels = [p for p in prefix.split(".") if p]
    if len(labels) < 2:
        return False
    # "update.update.x" or "www.www.x": a label repeated in the same name.
    return len(labels) != len(set(labels))


@easyhunt_tool(
    phase="recon",
    mode="passive",
    targets_arg="target",
    timeout=900,
    name="subdomain_enum",
    tags={"recon"},
    # Honest, not tidy. subfinder with -all queries roughly 40 passive sources,
    # assetfinder about 6, findomain about 10; each source is one or more HTTP
    # requests and several paginate. Plus 3 DNS probes at the target's own
    # nameservers for the wildcard check. ~200 is the realistic total for the
    # default configuration, and nearly all of it lands on third parties rather
    # than the target — but it is still traffic this engagement is accountable
    # for, and budgeting it at 50 understated it fourfold.
    estimated_requests=200,
    risk_notes=[
        "subfinder is held to the engagement's max_rps via -rl; findomain gets "
        "--rate-limit, which is a delay between targets and does NOT bound its "
        "per-request rate.",
        "assetfinder, amass (v5) and theHarvester expose no rate, concurrency, or "
        "delay flag of any kind. Their request rate to third-party data sources is "
        "ungoverned by this system and cannot be governed without patching them.",
        "Only the 3 wildcard DNS probes touch the target directly; those are "
        "charged to the limiter individually.",
    ],
)
async def subdomain_enum(
    target: str, include_amass: bool = False, thorough: bool = False
) -> dict[str, Any]:
    """Enumerate subdomains from every installed passive source and merge them.

    Runs whichever of subfinder / assetfinder / findomain / amass / theHarvester
    are present, in parallel, and returns the deduplicated union filtered through
    the engagement scope. Installing more sources widens coverage with no code
    change — the tool set is discovered, not hardcoded.

    ``include_amass`` defaults off. On a real engagement amass ran the full 15
    minutes and returned **zero** subdomains — its productive sources want API
    keys — while subfinder and assetfinder found 322 and 301. It also spawns an
    ``amass engine`` child that calls ``setsid`` itself, so it escapes the
    process-group kill on timeout and keeps running, unthrottled, after the
    engagement believes the tool stopped. Turn it on when amass is configured
    with datasource credentials; leave it off otherwise.

    thorough adds slower sources (theHarvester, amass with more providers).
    Prefer bbot_scan when BBOT is available: it covers more sources than all of
    these combined.
    """
    engagement = get_engagement()
    rules = engagement.scope.rules
    domains = split_targets(target)
    seed = domains[0]

    # Every source that is actually installed contributes. `run_one` reports a
    # missing tool rather than failing, so the set is effectively self-tuning.
    tasks = [
        run_one(
            "subfinder",
            [
                "-d", seed, "-silent", "-nc", "-duc", "-all",
                # subfinder's global requests-per-second ceiling. Without it the
                # tool fans out across ~40 sources at whatever rate they allow.
                "-rl", str(max(1, int(rules.max_rps))),
            ],
            timeout=600,
        ),
        run_one("assetfinder", ["--subs-only", seed], timeout=300),
        run_one(
            "findomain",
            [
                "-t", seed, "--quiet",
                # Whole seconds between targets, which is the only throttle
                # findomain has. It does not pace requests within a target.
                "--rate-limit", str(max(1, round(1 / max(0.01, rules.max_rps)))),
            ],
            timeout=300,
        ),
    ]
    if include_amass:
        # -timeout bounds amass itself (minutes). Without it amass runs until the
        # outer kill fires, which measured 15 minutes for zero results on a real
        # engagement — it dominated the recon wall clock and contributed nothing,
        # because its useful sources want API keys this install does not have.
        # Bounded to 5 minutes so it can help when configured without being able
        # to monopolise the phase when it is not.
        tasks.append(
            run_one(
                "amass",
                ["enum", "-passive", "-d", seed, "-silent", "-timeout", "5"],
                timeout=360,
            )
        )
    if thorough:
        tasks.append(
            run_one(
                "theHarvester",
                ["-d", seed, "-b", "crtsh,anubis,hackertarget,otx,rapiddns,urlscan", "-l", "500"],
                timeout=900,
            )
        )

    runs = await run_many(tasks)

    # Per-source contribution: which tool found something nothing else did. This
    # is what tells an operator whether a source is earning its runtime.
    unique: dict[str, int] = {}
    for run in runs:
        others = {v.lower() for other in runs if other is not run for v in other.values}
        unique[run.tool] = len({v.lower() for v in run.values} - others)

    merged = merge_runs(runs)
    kept, dropped = in_scope_only(merged, phase="recon", tool="subdomain_enum")

    wildcard = await _detect_wildcard(seed)
    extra: dict[str, Any] = {
        "seed": seed,
        "unique_per_source": {k: v for k, v in unique.items() if v},
        "next_step": "Resolve these with dns_resolve, then probe with http_probe.",
    }
    if wildcard["wildcard"]:
        suspect = [h for h in kept if _looks_like_wildcard_noise(h, seed)]
        extra["wildcard_dns"] = {
            **wildcard,
            "likely_noise": len(suspect),
            "warning": (
                f"*.{seed} resolves every name to {sorted(wildcard['addresses'])}. "
                f"{len(suspect)} of {len(kept)} results are recursive permutations "
                "with no independent evidence of existence. Probing them will report "
                "them all live because the wildcard answers, and scanning them burns "
                "budget on hosts that do not exist. Confirm with http_probe titles or "
                "content length before treating any of them as real."
            ),
            "examples": sorted(suspect)[:5],
        }

    store_assets(kept, kind="subdomain", source="subdomain_enum", tags=["passive"])
    for host in kept:
        engagement.discovered("subdomain", host, source="subdomain_enum")
    engagement.assets.save(engagement.workspace / "assets.json")

    return grouped_result(
        kind="subdomains", runs=runs, values=kept, dropped=dropped, extra=extra
    )


@easyhunt_tool(
    phase="recon", mode="passive", targets_arg="target", timeout=300,
    name="asn_lookup", tags={"recon"},
    # asnmap is one API call; amass intel is a handful of whois/RIR lookups.
    estimated_requests=10,
    risk_notes=[
        "asnmap and 'amass intel' have no rate, concurrency, or delay flag. Their "
        "request rate is ungoverned — acceptable here only because the volume is a "
        "handful of RIR lookups, none of them against the target.",
    ],
)
async def asn_lookup(target: str) -> dict[str, Any]:
    """Look up ASN and netblocks for a domain or organization.

    Netblocks are returned for context only — an ASN belonging to the target
    does not put its ranges in scope. Check anything you find with scope_check
    before touching it.
    """
    domain = split_targets(target)[0]
    runs = await run_many(
        [
            run_one("asnmap", ["-d", domain, "-silent", "-json", "-duc"], timeout=120),
            run_one("amass", ["intel", "-d", domain, "-silent"], timeout=180),
        ]
    )

    netblocks: list[str] = []
    asns: list[str] = []
    for line in runs[0].values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        asns.extend(str(a) for a in ([record.get("as_number")] if record.get("as_number") else []))
        netblocks.extend(str(r) for r in (record.get("as_range") or []))

    in_scope, dropped = in_scope_only(netblocks, phase="recon", tool="asn_lookup")
    return {
        "ok": True,
        "domain": domain,
        "asns": sorted(set(asns)),
        "netblocks": sorted(set(netblocks)),
        "netblocks_in_scope": in_scope,
        "netblocks_out_of_scope": dropped,
        "tools": [r.to_dict() for r in runs],
        "note": (
            "Ownership of an ASN is not authorization. Only the ranges your "
            "scope.yaml lists may be touched."
        ),
    }


@easyhunt_tool(
    phase="recon", mode="passive", targets_arg="target", timeout=300,
    name="tls_info", tags={"recon"},
    # One host, one TLS handshake, up to 3 retries on failure.
    estimated_requests=4,
)
async def tls_info(target: str) -> dict[str, Any]:
    """Read TLS certificates and pull subject-alternative names.

    SANs frequently reveal internal hostnames and sibling domains. They are
    scope-filtered before being stored, since one certificate often covers hosts
    belonging to several organizations.

    tlsx opens TLS connections to the target, so its concurrency and inter-
    connection delay are pinned to the engagement. Its default concurrency is 300.
    """
    engagement = get_engagement()
    rules = engagement.scope.rules
    hosts = split_targets(target)
    run = await run_one(
        "tlsx",
        [
            "-u", hosts[0], "-json", "-silent", "-san", "-cn", "-duc", "-nc",
            # Default is 300 concurrent handshakes. That is a load test, not a
            # certificate read.
            "-c", str(max(1, int(rules.max_concurrency))),
            # tlsx waits this long between connections on each thread; at
            # concurrency N the effective ceiling is N/delay, which is why both
            # are set together.
            "-delay", f"{max(1, int(1000 / max(0.01, rules.max_rps)))}ms",
        ],
        timeout=180,
    )

    names: list[str] = []
    certificates: list[dict[str, Any]] = []
    for line in run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        certificates.append(
            {
                "host": record.get("host"),
                "issuer": record.get("issuer_cn"),
                "subject_cn": record.get("subject_cn"),
                "not_after": record.get("not_after"),
                "self_signed": record.get("self_signed"),
            }
        )
        names.extend(str(n) for n in (record.get("subject_an") or []))
        if record.get("subject_cn"):
            names.append(str(record["subject_cn"]))

    cleaned = sorted({n.lstrip("*.").lower() for n in names if n})
    kept, dropped = in_scope_only(cleaned, phase="recon", tool="tls_info")
    store_assets(kept, kind="subdomain", source="tlsx:san", tags=["certificate"])

    return {
        "ok": True,
        "host": hosts[0],
        "certificates": certificates,
        "san_names": cleaned,
        "san_in_scope": kept,
        "dropped_out_of_scope": dropped,
        "tools": [run.to_dict()],
    }


@easyhunt_tool(
    phase="recon", mode="passive", targets_arg="target", timeout=120,
    name="whois_lookup", tags={"recon"}, estimated_requests=1,
    risk_notes=[
        "whois(1) has no rate flag. Ungoverned, but it is a single query to a "
        "registrar and never touches the target.",
    ],
)
async def whois_lookup(target: str) -> dict[str, Any]:
    """WHOIS registration data for a domain: registrar, org, dates, nameservers.

    Useful for confirming an asset actually belongs to the program before you
    spend requests on it.
    """
    domain = split_targets(target)[0]
    run = await run_one("whois", [domain], timeout=60, allow_codes=(0, 1))

    fields: dict[str, list[str]] = {}
    for line in lines_of("\n".join(run.values)):
        if ":" not in line or line.startswith(("%", "#", ">>>")):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if value and len(key) < 40:
            fields.setdefault(key, []).append(value)

    return {
        "ok": True,
        "domain": domain,
        "registrar": fields.get("registrar", []),
        "organization": fields.get("registrant organization", []) or fields.get("org", []),
        "created": fields.get("creation date", []),
        "expires": fields.get("registry expiry date", []) or fields.get("expiry date", []),
        "nameservers": sorted({n.lower() for n in fields.get("name server", [])}),
        "fields": {k: v[:5] for k, v in list(fields.items())[:40]},
        "tools": [run.to_dict()],
    }

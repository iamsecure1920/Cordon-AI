"""Passive recon: subdomains, ASN, certificates, org intelligence.

Everything here reads public sources. Nothing sends a request to the target's own
infrastructure beyond DNS resolution, which is why these run without an approval
prompt. BBOT covers most of this ground already — these wrappers exist for the
cases where you want one specific source, or where BBOT is not installed.
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

__all__ = ["asn_lookup", "subdomain_enum", "tls_info", "whois_lookup"]

SUBFINDER = register_spec(
    ToolSpec(
        name="subfinder", binary="subfinder", image="projectdiscovery/subfinder:latest",
        license="MIT", homepage="https://github.com/projectdiscovery/subfinder",
        version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="subfinder",
            allowed_flags={"-d", "-dL", "-silent", "-nc", "-all", "-timeout", "-t", "-o", "-duc"},
            boolean_flags={"-silent", "-nc", "-all", "-duc"},
            value_patterns={"-d": HOST_PATTERN},
            numeric_caps={"-timeout": 60, "-t": 50},
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
            allowed_flags={"-t", "--quiet", "-u", "--external-subdomains"},
            boolean_flags={"--quiet", "--external-subdomains"},
            value_patterns={"-t": HOST_PATTERN},
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
            allowed_flags={"-u", "-l", "-json", "-silent", "-san", "-cn", "-so", "-duc", "-c", "-nc"},
            boolean_flags={"-json", "-silent", "-san", "-cn", "-so", "-duc", "-nc"},
            value_patterns={"-u": HOST_PATTERN},
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


@easyhunt_tool(
    phase="recon",
    mode="passive",
    targets_arg="target",
    timeout=900,
    name="subdomain_enum",
    tags={"recon"},
    estimated_requests=50,
)
async def subdomain_enum(
    target: str, include_amass: bool = True, thorough: bool = False
) -> dict[str, Any]:
    """Enumerate subdomains from every installed passive source and merge them.

    Runs whichever of subfinder / assetfinder / findomain / amass / theHarvester
    are present, in parallel, and returns the deduplicated union filtered through
    the engagement scope. Installing more sources widens coverage with no code
    change — the tool set is discovered, not hardcoded.

    thorough adds slower sources (theHarvester, amass with more providers).
    Prefer bbot_scan when BBOT is available: it covers more sources than all of
    these combined.
    """
    engagement = get_engagement()
    domains = split_targets(target)
    seed = domains[0]

    # Every source that is actually installed contributes. `run_one` reports a
    # missing tool rather than failing, so the set is effectively self-tuning.
    tasks = [
        run_one("subfinder", ["-d", seed, "-silent", "-nc", "-duc", "-all"], timeout=600),
        run_one("assetfinder", ["--subs-only", seed], timeout=300),
        run_one("findomain", ["-t", seed, "--quiet"], timeout=300),
    ]
    if include_amass:
        tasks.append(run_one("amass", ["enum", "-passive", "-d", seed, "-silent"], timeout=900))
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
    store_assets(kept, kind="subdomain", source="subdomain_enum", tags=["passive"])
    for host in kept:
        engagement.discovered("subdomain", host, source="subdomain_enum")
    engagement.assets.save(engagement.workspace / "assets.json")

    return grouped_result(
        kind="subdomains",
        runs=runs,
        values=kept,
        dropped=dropped,
        extra={
            "seed": seed,
            "unique_per_source": {k: v for k, v in unique.items() if v},
            "next_step": "Resolve these with dns_resolve, then probe with http_probe.",
        },
    )


@easyhunt_tool(
    phase="recon", mode="passive", targets_arg="target", timeout=300,
    name="asn_lookup", tags={"recon"}, estimated_requests=5,
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
    name="tls_info", tags={"recon"}, estimated_requests=10,
)
async def tls_info(target: str) -> dict[str, Any]:
    """Read TLS certificates and pull subject-alternative names.

    SANs frequently reveal internal hostnames and sibling domains. They are
    scope-filtered before being stored, since one certificate often covers hosts
    belonging to several organizations.
    """
    hosts = split_targets(target)
    run = await run_one(
        "tlsx",
        ["-u", hosts[0], "-json", "-silent", "-san", "-cn", "-duc", "-nc"],
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

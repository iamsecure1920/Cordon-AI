"""DNS resolution, permutation, and CDN identification.

Resolution is the bridge between "a name appeared in a certificate" and "a host
exists". It is also where takeover candidates first surface: a CNAME that
resolves to a provider with no A record behind it is the shape of a dangling
delegation, and that observation is what feeds the verified takeover flow.

**Rate governance.** These wrappers hand a whole host list to one process, so the
control plane's per-tool-call token is not a per-query limit — the tool's own
flags are. ``dnsx`` gets both ``-rl`` (DNS requests/second) and ``-t`` (threads,
default **100**), sourced from ``scope.rules``.

``-rl`` used to be set to ``max_rps * 10``. Nothing justified the multiplier: a
program that publishes a ceiling means that ceiling, and these queries land on the
target's own authoritative nameservers, which are as much "availability" as the
web tier. It is now ``max_rps``, exactly.

``cdncheck`` has no rate flag and ``alterx`` sends nothing; both are declared as
such rather than left looking governed.
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
    in_scope_only,
    register_spec,
    run_one,
    split_targets,
    store_assets,
)

__all__ = ["cdn_check", "dns_permute", "dns_resolve"]

DNSX = register_spec(
    ToolSpec(
        name="dnsx", binary="dnsx", image="projectdiscovery/dnsx:latest", license="MIT",
        homepage="https://github.com/projectdiscovery/dnsx", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="dnsx",
            allowed_flags={
                "-l", "-d", "-json", "-silent", "-nc", "-duc", "-a", "-aaaa", "-cname",
                "-mx", "-ns", "-txt", "-resp", "-t", "-rl", "-retry", "-w", "-o",
            },
            boolean_flags={
                "-json", "-silent", "-nc", "-duc", "-a", "-aaaa", "-cname", "-mx",
                "-ns", "-txt", "-resp",
            },
            value_patterns={"-d": HOST_PATTERN},
            numeric_caps={"-t": 100, "-rl": 300, "-retry": 3},
        ),
    )
)

ALTERX = register_spec(
    ToolSpec(
        name="alterx", binary="alterx", license="MIT",
        homepage="https://github.com/projectdiscovery/alterx", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="alterx",
            allowed_flags={"-l", "-d", "-silent", "-duc", "-limit", "-en", "-p", "-pp"},
            boolean_flags={"-silent", "-duc", "-en"},
            value_patterns={"-d": HOST_PATTERN},
            numeric_caps={"-limit": 100_000},
            relaxed_chars=frozenset("{}"),
        ),
    )
)

CDNCHECK = register_spec(
    ToolSpec(
        name="cdncheck", binary="cdncheck", license="MIT",
        homepage="https://github.com/projectdiscovery/cdncheck", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="cdncheck",
            allowed_flags={"-i", "-l", "-json", "-silent", "-duc", "-resp", "-nc"},
            boolean_flags={"-json", "-silent", "-duc", "-resp", "-nc"},
        ),
    )
)

#: Registered but not invoked by any wrapper in this module. Left in the catalog
#: so `easyhunt doctor` still reports on it. If it is ever wired up, note that its
#: `-t` defaults to **10,000** concurrent massdns resolves and it has no
#: requests-per-second flag at all — `-t` from `max_concurrency` is the only
#: governor available, and it is a weak one.
SHUFFLEDNS = register_spec(
    ToolSpec(
        name="shuffledns", binary="shuffledns", license="MIT",
        homepage="https://github.com/projectdiscovery/shuffledns", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="shuffledns",
            allowed_flags={"-d", "-list", "-r", "-mode", "-silent", "-duc", "-t", "-o", "-nc"},
            boolean_flags={"-silent", "-duc", "-nc"},
            value_patterns={"-d": HOST_PATTERN, "-mode": re.compile(r"bruteforce|resolve|filter")},
            numeric_caps={"-t": 5000},
        ),
    )
)


def _write_list(name: str, values: list[str]) -> str:
    engagement = get_engagement()
    path = engagement.raw_path(name, "txt")
    path.write_text("\n".join(values) + "\n", encoding="utf-8")
    return str(path)


@easyhunt_tool(
    phase="dns", mode="passive", targets_arg="target", timeout=900,
    name="dns_resolve", tags={"dns"},
    # One query per host per record type. The default record set is A + CNAME, so
    # a typical post-recon list of ~300 subdomains is ~600 queries. Not a
    # constant — the note below carries the scaling law that the number cannot.
    estimated_requests=600,
    risk_notes=[
        "Sends one DNS query per host per record type to the target's own "
        "authoritative nameservers; volume scales with the host list, not with "
        "this estimate.",
        "Paced by dnsx -rl at the engagement's max_rps and -t at max_concurrency.",
    ],
)
async def dns_resolve(target: str, record_types: list[str] | None = None) -> dict[str, Any]:
    """Resolve hosts and return A/AAAA/CNAME/MX/NS/TXT records.

    Flags hosts whose CNAME resolves but which have no address record — the shape
    of a dangling delegation. Those are candidates for takeover_verify, never
    findings on their own.
    """
    engagement = get_engagement()
    hosts = split_targets(target)
    wanted = [t.lower() for t in (record_types or ["a", "cname"])]

    rules = engagement.scope.rules
    argv = ["-l", _write_list("dnsx-targets", hosts), "-json", "-silent", "-nc", "-duc", "-resp"]
    for record in wanted:
        if f"-{record}" in DNSX.arg_policy.allowed_flags:  # type: ignore[union-attr]
            argv.append(f"-{record}")
    # The engagement ceiling, not a multiple of it. dnsx defaults to 100 threads
    # and no rate limit at all, so both flags have to be set or neither binds.
    argv += [
        "-rl", str(max(1, int(rules.max_rps))),
        "-t", str(max(1, int(rules.max_concurrency))),
    ]

    run = await run_one("dnsx", argv, timeout=600)

    resolved: list[dict[str, Any]] = []
    dangling: list[dict[str, Any]] = []
    for line in run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(record.get("host") or "")
        entry = {
            "host": host,
            "a": record.get("a") or [],
            "aaaa": record.get("aaaa") or [],
            "cname": record.get("cname") or [],
            "mx": record.get("mx") or [],
            "ns": record.get("ns") or [],
            "status": record.get("status_code"),
        }
        resolved.append(entry)
        store_assets([host], kind="host", source="dnsx", tags=["resolved"])
        for address in entry["a"] + entry["aaaa"]:
            store_assets([str(address)], kind="ip", source="dnsx")

        # A CNAME with nothing behind it is the classic takeover shape.
        if entry["cname"] and not entry["a"] and not entry["aaaa"]:
            dangling.append({"host": host, "cname": entry["cname"]})

    for candidate in dangling:
        engagement.discovered(
            "dangling_cname",
            candidate["host"],
            source="dns_resolve",
            detail=f"CNAME → {', '.join(candidate['cname'])}",
        )

    engagement.assets.save(engagement.workspace / "assets.json")
    return {
        "ok": True,
        "queried": len(hosts),
        "resolved": len(resolved),
        "records": resolved,
        "dangling_cname_candidates": dangling,
        "tools": [run.to_dict()],
        "next_step": (
            f"{len(dangling)} host(s) have a CNAME with no address record — run "
            "takeover_verify on each before treating any as a finding."
            if dangling
            else "Probe the resolved hosts with http_probe."
        ),
    }


@easyhunt_tool(
    phase="dns", mode="aggressive", targets_arg="target", timeout=1800,
    name="dns_permute", tags={"dns"},
    # One query per generated permutation. `limit` defaults to 20,000 and the
    # wrapper caps it at 100,000; 5,000 was a placeholder that understated the
    # default run by 4x and the maximum by 20x.
    estimated_requests=20_000,
    risk_notes=[
        "Generates and resolves a large permutation wordlist — one DNS query per "
        "permutation, up to 100,000 of them.",
        "High DNS query volume — visible to the target's resolver operator.",
        "Paced by dnsx -rl at the engagement's max_rps. At a 6 rps ceiling a "
        "20,000-name run takes about an hour; that is the ceiling working, not a "
        "hang.",
    ],
)
async def dns_permute(target: str, limit: int = 20000) -> dict[str, Any]:
    """Generate subdomain permutations with alterx and resolve them with dnsx.

    Finds hosts that no passive source knows about. Requires approval: this is a
    brute-force pattern, just against DNS rather than HTTP.
    """
    engagement = get_engagement()
    known = engagement.assets.values("subdomain") or split_targets(target)

    generate = await run_one(
        "alterx",
        ["-l", _write_list("alterx-input", known), "-silent", "-duc", "-limit", str(min(limit, 100_000))],
        timeout=300,
    )
    if not generate.values:
        return {
            "ok": True,
            "generated": 0,
            "resolved": [],
            "tools": [generate.to_dict()],
            "note": "alterx produced no permutations (is it installed?)",
        }

    rules = engagement.scope.rules
    resolve = await run_one(
        "dnsx",
        [
            "-l", _write_list("alterx-permutations", generate.values),
            "-silent", "-nc", "-duc", "-a", "-resp",
            "-rl", str(max(1, int(rules.max_rps))),
            "-t", str(max(1, int(rules.max_concurrency))),
        ],
        timeout=1500,
    )

    found = [line.split()[0] for line in resolve.values if line.strip()]
    kept, dropped = in_scope_only(found, phase="dns", tool="dns_permute")
    store_assets(kept, kind="subdomain", source="alterx+dnsx", tags=["permutation"])

    return {
        "ok": True,
        "generated": len(generate.values),
        "resolved": len(kept),
        "new_hosts": kept,
        "dropped_out_of_scope": dropped,
        "tools": [generate.to_dict(), resolve.to_dict()],
    }


@easyhunt_tool(
    phase="dns", mode="passive", targets_arg="target", timeout=300,
    name="cdn_check", tags={"dns"},
    # cdncheck resolves every host it is handed and matches the address against
    # bundled provider ranges. One query per host; ~300 for a typical list.
    estimated_requests=300,
    risk_notes=[
        "cdncheck has no rate, concurrency, or delay flag — its only tunable is "
        "the resolver list. One DNS query per input host, ungoverned. Hand it "
        "short lists, or accept that the pace is whatever the tool chooses.",
    ],
)
async def cdn_check(target: str) -> dict[str, Any]:
    """Identify which hosts sit behind a CDN, WAF, or cloud provider.

    Worth running before any port scan: scanning a CDN edge tells you about the
    CDN, wastes the program's rate limit, and occasionally violates the CDN's own
    terms rather than the target's.
    """
    hosts = split_targets(target)
    run = await run_one(
        "cdncheck",
        ["-l", _write_list("cdncheck-input", hosts), "-json", "-silent", "-duc", "-resp", "-nc"],
        timeout=180,
    )

    behind_cdn: list[dict[str, Any]] = []
    direct: list[str] = []
    for line in run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(record.get("input") or record.get("host") or "")
        if record.get("cdn") or record.get("waf") or record.get("cloud"):
            behind_cdn.append(
                {
                    "host": host,
                    "cdn": record.get("cdn_name"),
                    "waf": record.get("waf_name"),
                    "cloud": record.get("cloud_name"),
                }
            )
        else:
            direct.append(host)

    return {
        "ok": True,
        "behind_cdn": behind_cdn,
        "direct_origin": direct,
        "tools": [run.to_dict()],
        "note": (
            "Port-scan only the direct-origin hosts. Scanning a CDN edge measures "
            "the CDN, not the target."
        ),
    }

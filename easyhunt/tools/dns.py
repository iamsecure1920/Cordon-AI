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
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    HOST_PATTERN,
    ToolRun,
    in_scope_only,
    register_spec,
    run_one,
    split_targets,
    store_assets,
    subprocess_timeout_for,
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

# shuffledns was catalogued here for months with no call site, and it is removed
# rather than wired. Three independent blockers, each verified against the real
# binaries rather than inferred:
#
# 1. It cannot be paced. `shuffledns -h` lists exactly one flag under RATE-LIMIT:
#    "-t int  Number of concurrent massdns resolves (default 10000)". There is no
#    requests-per-second control, and there is none underneath it either —
#    `massdns --help` offers `-s/--hashmap-size` ("Number of concurrent lookups",
#    default 10000) and `-i/--interval` ("Interval in milliseconds to wait between
#    multiple resolves of the same domain"), which are concurrency and retry
#    spacing, not a global rate. Wiring it would mean declaring that it honours
#    `scope.rules.max_rps` when no layer of the stack has a mechanism to do so.
# 2. It is redundant with a tool that CAN be paced. dnsx takes `-d` (domains to
#    bruteforce) and `-w` (wordlist) alongside both `-rl` (dns requests/second)
#    and `-t` (threads) — all four already on DNSX's allowlist above. The same
#    capability, governed.
# 3. Its prerequisites are unmet. It requires `-r <resolvers file>`; no vetted
#    resolver list exists in the payload store, and the store holds no subdomain
#    bruteforce wordlist either. Invariant 6 requires third-party lists be vetted
#    and pinned, so supplying either ad hoc is not available as a shortcut.
#
# The install recipe still builds shuffledns and massdns. Removing the spec means
# `easyhunt doctor` no longer reports on a binary the installer still places on
# disk — see the note in tests/test_wiring.py.


def _dnsx_pacing(rules: Any) -> list[str]:
    """dnsx's rate and concurrency flags, clamped to its own policy ceilings.

    Both numbers come from the engagement and never from a literal. They are then
    clamped to ``DNSX.arg_policy.numeric_caps``, because an engagement permitting
    more than a per-tool ceiling is not permission to exceed it — and passing a
    larger number does not run faster. It is refused by ``sanitize_argv``, that
    refusal is caught by ``run_one``, and the call comes back ``ran=False``. The
    wrapper then returns ``resolved: 0`` with ``ok: True``: a tool that never ran,
    shaped exactly like a domain whose hosts do not resolve.

    Latent rather than observed — no scope.yaml in this repo sets ``max_rps``
    above the ``-rl`` cap of 300 — but an owned-asset engagement legitimately can,
    and the same clamp is already applied for the same reason in
    ``endpoints.endpoint_discovery``.
    """
    caps = DNSX.arg_policy.numeric_caps  # type: ignore[union-attr]
    return [
        "-rl", str(min(max(1, int(rules.max_rps)), int(caps["-rl"]))),
        "-t", str(min(max(1, int(rules.max_concurrency)), int(caps["-t"]))),
    ]


def _untested(tool: str, run: ToolRun, *, what: str) -> dict[str, Any]:
    """The response for a DNS tool that did not run.

    Measured, not theorised: with dnsx absent, ``dns_resolve`` returned
    ``ok: true``, ``resolved: 0``, ``records: []`` and the next step "Probe the
    resolved hosts with http_probe." The only trace of the failure was
    ``tools[0].ran = false``, four keys down. Every later phase reads that as a
    domain whose hosts do not resolve, which is the same shape as a domain that
    resolves to nothing — and the pipeline then scans an empty host list and
    reports a clean estate.

    Absence is not a clean result, so it is returned as a refusal rather than as
    an empty success.
    """
    return {
        "ok": False,
        "complete": False,
        "error": "tool_unavailable",
        "untested": True,
        "message": (
            f"{tool} could not run ({run.error or 'unavailable'}), so {what} was "
            "not performed. This is UNTESTED, not clean — an empty result here "
            "would be indistinguishable from a target with nothing to find. "
            "Install it or run 'easyhunt doctor' to see what is missing."
        ),
        "tools": [run.to_dict()],
    }


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
    argv += _dnsx_pacing(rules)

    run = await run_one(
        "dnsx", argv,
        timeout=subprocess_timeout_for(hosts, int(rules.max_rps), minimum=600),
    )
    if not run.ran:
        return _untested("dnsx", run, what="DNS resolution")

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
    # "alterx is not installed" and "alterx ran and generated nothing" were both
    # reported as ok:True with a parenthetical guess in a note. They are different
    # answers: the first means this surface is untested, the second means the
    # permutation space is genuinely empty.
    if not generate.ran:
        return _untested("alterx", generate, what="permutation generation")
    if not generate.values:
        return {
            "ok": True,
            "complete": True,
            "generated": 0,
            "resolved": [],
            "tools": [generate.to_dict()],
            "note": "alterx ran and produced no permutations for this input.",
        }

    rules = engagement.scope.rules
    resolve = await run_one(
        "dnsx",
        [
            "-l", _write_list("alterx-permutations", generate.values),
            "-silent", "-nc", "-duc", "-a", "-resp",
            *_dnsx_pacing(rules),
        ],
        timeout=1500,
    )
    if not resolve.ran:
        return _untested("dnsx", resolve, what="resolution of the generated permutations")

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
    if not run.ran:
        return _untested("cdncheck", run, what="CDN identification")

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

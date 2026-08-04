"""Endpoint, URL, and parameter discovery.

Two very different cost profiles, so they are two different tools:

* ``endpoint_discovery`` reads archives (Wayback, Common Crawl, URLScan) and
  optionally crawls. Archive sources cost the target nothing and are passive.
* ``param_discovery`` and ``content_discovery`` guess. They are aggressive, gated,
  and rate-limited, because guessing is indistinguishable from an attack in a log.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    HOST_PATTERN,
    URL_PATTERN,
    grouped_result,
    in_scope_only,
    merge_runs,
    register_spec,
    run_many,
    run_one,
    split_targets,
    store_assets,
)

__all__ = ["content_discovery", "endpoint_discovery", "param_discovery"]

KATANA = register_spec(
    ToolSpec(
        name="katana", binary="katana", image="projectdiscovery/katana:latest", license="MIT",
        homepage="https://github.com/projectdiscovery/katana", version_args=["-version"],
        # PyPI's "katana" is a bioinformatics tool that soft-clips sequencing
        # reads based on primer locations. Verified: -version prints the banner
        # ending "projectdiscovery.io".
        identity_marker="projectdiscovery",
        user_agent_flag="-H",
        arg_policy=ArgPolicy(
            tool="katana",
            allowed_flags={
                "-u", "-list", "-d", "-jc", "-kf", "-silent", "-nc", "-duc", "-json",
                "-c", "-p", "-rl", "-timeout", "-ct", "-o", "-fs", "-em", "-H", "-iqp",
            },
            boolean_flags={"-jc", "-silent", "-nc", "-duc", "-json", "-iqp"},
            value_patterns={"-u": URL_PATTERN, "-kf": re.compile(r"[a-z,]+"), "-fs": re.compile(r"[a-z]+")},
            numeric_caps={"-d": 5, "-c": 20, "-p": 20, "-rl": 150, "-timeout": 30, "-ct": 600},
        ),
    )
)

GAU = register_spec(
    ToolSpec(
        name="gau", binary="gau", license="MIT", homepage="https://github.com/lc/gau",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="gau",
            allowed_flags={"--threads", "--subs", "--blacklist", "--providers", "--timeout", "--o"},
            boolean_flags={"--subs"},
            value_patterns={"--providers": re.compile(r"[a-z,]+"), "--blacklist": re.compile(r"[a-z0-9,.]+")},
            numeric_caps={"--threads": 20, "--timeout": 120},
            allow_positional=True,
            positional_pattern=HOST_PATTERN,
        ),
    )
)

WAYBACKURLS = register_spec(
    ToolSpec(
        name="waybackurls", binary="waybackurls", license="MIT",
        homepage="https://github.com/tomnomnom/waybackurls", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="waybackurls", allowed_flags={"-dates", "-no-subs"},
            boolean_flags={"-dates", "-no-subs"},
            allow_positional=True, positional_pattern=HOST_PATTERN, max_argv=4,
        ),
    )
)

WAYMORE = register_spec(
    ToolSpec(
        name="waymore", binary="waymore", license="MIT",
        homepage="https://github.com/xnl-h4ck3r/waymore", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="waymore",
            allowed_flags={"-i", "-mode", "-oU", "-p", "-t", "-l"},
            value_patterns={"-i": HOST_PATTERN, "-mode": re.compile(r"U|R|B")},
            # -p is capped at 5 by waymore itself; a policy cap of 10 let a
            # value through that the binary then rejected.
            numeric_caps={"-p": 5, "-t": 10, "-l": 10000},
        ),
    )
)

ARJUN = register_spec(
    ToolSpec(
        name="arjun", binary="arjun", license="AGPL-3.0",
        homepage="https://github.com/s0md3v/Arjun", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="arjun",
            allowed_flags={"-u", "-oJ", "-t", "-d", "-m", "-q", "--stable", "-w"},
            boolean_flags={"-q", "--stable"},
            value_patterns={"-u": URL_PATTERN, "-m": re.compile(r"GET|POST|JSON|XML")},
            numeric_caps={"-t": 15, "-d": 10},
        ),
    )
)

PARAMSPIDER = register_spec(
    ToolSpec(
        name="paramspider", binary="paramspider", license="MIT",
        homepage="https://github.com/devanshbatham/ParamSpider", version_args=["--help"],
        arg_policy=ArgPolicy(
            tool="paramspider",
            allowed_flags={"-d", "--domain", "-s", "-o", "--output", "-l", "--level"},
            boolean_flags={"-s"},
            value_patterns={"-d": HOST_PATTERN, "--domain": HOST_PATTERN},
            numeric_caps={"-l": 3, "--level": 3},
        ),
    )
)

NETSANITIZER = register_spec(
    ToolSpec(
        name="netsanitizer", binary="netsanitizer", license="MIT",
        homepage="https://github.com/iamsecure1920/NetSanitizer",
        version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="netsanitizer",
            allowed_flags={"-keep-assets", "-keep-scripts", "-q"},
            boolean_flags={"-keep-assets", "-keep-scripts", "-q"},
            allow_positional=True,
            positional_pattern=re.compile(r"[A-Za-z0-9._/-]{1,300}"),
            max_argv=8,
        ),
    )
)

FFUF = register_spec(
    ToolSpec(
        name="ffuf", binary="ffuf", license="MIT", homepage="https://github.com/ffuf/ffuf",
        version_args=["-V"],
        user_agent_flag="-H",
        arg_policy=ArgPolicy(
            tool="ffuf",
            allowed_flags={
                "-u", "-w", "-mc", "-fc", "-fs", "-t", "-rate", "-timeout", "-of", "-o",
                "-s", "-se", "-ac", "-H", "-recursion-depth", "-maxtime",
            },
            boolean_flags={"-s", "-se", "-ac"},
            # -X is absent: fuzzing with PUT/DELETE mutates the target.
            denied_flags={"-X", "-d", "-request", "-recursion"},
            value_patterns={"-u": URL_PATTERN, "-of": re.compile(r"json|csv|md|html")},
            numeric_caps={"-t": 20, "-rate": 50, "-timeout": 30, "-recursion-depth": 2, "-maxtime": 900},
        ),
    )
)

FEROXBUSTER = register_spec(
    ToolSpec(
        name="feroxbuster", binary="feroxbuster", license="MIT",
        homepage="https://github.com/epi052/feroxbuster", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="feroxbuster",
            allowed_flags={"-u", "-w", "-t", "--rate-limit", "-d", "-o", "--json", "-q", "-s", "-C"},
            boolean_flags={"--json", "-q"},
            denied_flags={"-m", "--methods", "--data"},
            value_patterns={"-u": URL_PATTERN},
            numeric_caps={"-t": 20, "--rate-limit": 50, "-d": 3},
        ),
    )
)


@easyhunt_tool(
    phase="endpoints", mode="passive", targets_arg="target", timeout=1200,
    name="endpoint_discovery", tags={"endpoints"}, estimated_requests=20,
)
async def endpoint_discovery(target: str, include_crawl: bool = False) -> dict[str, Any]:
    """Collect known URLs for a domain from public archives.

    Sources: gau (Wayback + Common Crawl + URLScan), waybackurls, waymore. These
    query archives, not the target, so they cost the program nothing.

    include_crawl adds a shallow katana crawl, which *does* touch the target —
    keep it off unless the archives came back thin.
    """
    engagement = get_engagement()
    domain = split_targets(target)[0]

    # Every archive source that is installed contributes; absent ones are
    # reported rather than skipped silently, so partial coverage is visible.
    # Concurrency comes from the engagement, never from a literal. These were
    # "5" and "5" regardless of what the program published — the same defect
    # already fixed in naabu and dnsx, in the files that fix missed. The
    # limiter charges one token per *tool call*, so a tool with its own thread
    # pool is ungoverned unless told a number on its command line.
    rules = engagement.scope.rules
    concurrency = max(1, int(rules.max_concurrency))
    # Clamp to each policy's numeric_cap as well. An engagement permitting 20
    # concurrent is not permission to exceed a per-tool ceiling, and passing a
    # value above the cap does not run fast — it is refused by the sanitizer,
    # which would turn a rate fix into a tool that no longer runs at all.
    tasks = [
        run_one("gau", ["--subs", "--threads", str(min(concurrency, 20)), domain], timeout=600),
        run_one("waybackurls", [domain], timeout=600),
        # waymore refuses anything above 5 itself: "The number of processes must
        # be between 1 and 5. Be kind to Wayback Machine". The policy's
        # numeric_cap said 10, so clamping to the cap still handed it 8 on an
        # engagement permitting 8 and the tool exited with a usage error —
        # sourcing the rate from the scope broke it for every scope above 5.
        # Clamp to what the BINARY accepts, not to what the policy allows.
        run_one("waymore", ["-i", domain, "-mode", "U", "-p", str(min(concurrency, 5))], timeout=900),
        run_one("paramspider", ["-d", domain], timeout=600),
    ]
    if include_crawl:
        url = domain if domain.startswith("http") else f"https://{domain}"
        tasks.append(
            run_one(
                "katana",
                [
                    "-u", url, "-d", "2", "-jc", "-silent", "-nc", "-duc",
                    "-c", str(max(1, engagement.scope.rules.max_concurrency)),
                    "-rl", str(max(1, int(engagement.scope.rules.max_rps))),
                    "-ct", "300",
                ],
                timeout=600,
            )
        )

    runs = await run_many(tasks)
    merged = [u for u in merge_runs(runs) if u.startswith("http")]

    # Archives return the same endpoint hundreds of times with different values
    # in the same parameters. What matters for testing is the set of distinct
    # *injection points*, not distinct URLs: measured on a real engagement,
    # 5,065 archived URLs held 61 of them, and the difference is scan budget
    # spent re-testing one endpoint. netsanitizer collapses on
    # scheme+host+path+parameter-NAMES, keeping the variant with the most
    # parameters. Absence is not fatal — the raw list is still correct, just
    # longer — so this degrades rather than fails.
    collapsed: list[str] | None = None
    if merged:
        raw_urls = engagement.raw_path("endpoint-urls", "txt")
        raw_urls.write_text("\n".join(merged) + "\n", encoding="utf-8")
        dedupe = await run_one(
            "netsanitizer", ["-q", "-keep-scripts", str(raw_urls)], timeout=120
        )
        if dedupe.ran and dedupe.values:
            collapsed = [u for u in dedupe.values if u.startswith("http")]

    kept, dropped = in_scope_only(
        collapsed or merged, phase="endpoints", tool="endpoint_discovery"
    )
    store_assets(kept, kind="url", source="archives", tags=["archived"])

    # Parameter names are the most useful thing in an archive dump.
    parameters: dict[str, int] = {}
    extensions: dict[str, int] = {}
    for url in kept:
        parts = urlsplit(url)
        for name in parse_qs(parts.query):
            parameters[name] = parameters.get(name, 0) + 1
        suffix = parts.path.rsplit(".", 1)[-1].lower() if "." in parts.path.rsplit("/", 1)[-1] else ""
        if suffix and len(suffix) <= 5:
            extensions[suffix] = extensions.get(suffix, 0) + 1

    engagement.assets.save(engagement.workspace / "assets.json")
    return grouped_result(
        kind="urls",
        runs=runs,
        values=kept[:5000],
        dropped=dropped,
        extra={
            "archived_urls": len(merged),
            "distinct_injection_points": len(collapsed) if collapsed else None,
            "deduplicated_by": "netsanitizer" if collapsed else "none (tool absent)",
            "unique_parameters": dict(sorted(parameters.items(), key=lambda kv: -kv[1])[:100]),
            "extensions": dict(sorted(extensions.items(), key=lambda kv: -kv[1])[:30]),
            "total_urls": len(kept),
            "next_step": (
                "Interesting parameter names are the cheapest lead here — they point "
                "at IDOR, SSRF, and redirect surface without spending a request."
            ),
        },
    )


@easyhunt_tool(
    phase="endpoints", mode="aggressive", targets_arg="target", timeout=1200,
    name="param_discovery", tags={"endpoints"}, estimated_requests=500,
    risk_notes=[
        "Sends hundreds of requests guessing parameter names.",
        "Arjun is AGPL-3.0 — relevant if you redistribute an EasyHunt bundle.",
    ],
)
async def param_discovery(target: str, method: str = "GET") -> dict[str, Any]:
    """Discover hidden request parameters on a URL with Arjun.

    Guessing costs requests. Mine endpoint_discovery's archive results for
    parameter names first — they are free and already known to exist.
    """
    engagement = get_engagement()
    url = split_targets(target)[0]
    if method.upper() not in {"GET", "POST", "JSON", "XML"}:
        method = "GET"

    output = engagement.raw_path("arjun", "json")
    # arjun fans out over its own thread pool and had -t hardcoded to 10 with no
    # delay at all — so on a program publishing 5 rps it ran at whatever 10
    # threads could manage. Both now come from the engagement. arjun's --stable
    # already serialises the confirmation passes; -d is the inter-request delay.
    rules = engagement.scope.rules
    run = await run_one(
        "arjun",
        [
            "-u", url, "-m", method.upper(), "-oJ", str(output),
            "-t", str(min(max(1, int(rules.max_concurrency)), 15)),
            "-d", str(min(max(0, round(1 / max(0.01, rules.max_rps), 2)), 10)),
            "-q", "--stable",
        ],
        timeout=900,
    )

    discovered: list[str] = []
    if output.exists():
        import json

        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
            for entry in payload.values() if isinstance(payload, dict) else []:
                if isinstance(entry, dict):
                    discovered.extend(str(p) for p in entry.get("params", []))
        except (json.JSONDecodeError, AttributeError):
            pass

    return {
        "ok": True,
        "url": url,
        "method": method.upper(),
        "parameters": sorted(set(discovered)),
        "count": len(set(discovered)),
        "tools": [run.to_dict()],
    }


#: Pages a server returns for paths that do not exist, while still answering 200.
#: A WAF block page is the worst case: it looks like a hit on every single path.
_SOFT_404_MARKERS = (
    "request rejected", "access denied", "not found", "404", "error",
    "incapsula", "cloudfront", "akamai", "forbidden",
)


async def _soft_404_baseline(fuzz_url: str) -> dict[str, Any]:
    """Probe paths that cannot exist, and learn what "nothing here" looks like.

    Measured on a live estate: /composer.json returned HTTP 200 carrying an
    Imperva "Request Rejected" page, and /static/api/swagger.json returned 200
    with the site's Next.js shell. Both were reported as discovered paths. A
    content-discovery tool without this check reports the whole wordlist as
    findings on any host with a catch-all.
    """
    import secrets as _secrets

    sizes: set[int] = set()
    statuses: set[int] = set()
    for _ in range(2):
        probe = fuzz_url.replace("FUZZ", f"eh-{_secrets.token_hex(8)}")
        run = await run_one(
            "httpx",
            ["-u", probe, "-json", "-silent", "-nc", "-duc",
             "-status-code", "-content-length", "-timeout", "10"],
            timeout=60,
        )
        for line in run.values:
            try:
                import json as _json

                rec = _json.loads(line)
            except Exception:  # noqa: BLE001, S112 — a failed baseline must not stop the scan
                continue  # noqa: S112
            if rec.get("content_length") is not None:
                sizes.add(int(rec["content_length"]))
            if rec.get("status_code"):
                statuses.add(int(rec["status_code"]))
    return {"sizes": sizes, "statuses": statuses}


@easyhunt_tool(
    phase="endpoints", mode="aggressive", targets_arg="target", timeout=1800,
    name="content_discovery", tags={"endpoints"}, estimated_requests=2000,
    risk_notes=[
        "Brute-forces paths — thousands of requests, all 404s in the target's logs.",
        "Only safe HTTP methods are permitted; -X is not on the argument allowlist.",
        "Check the program's policy on directory brute-forcing before approving.",
    ],
)
async def content_discovery(
    target: str, wordlist: str, extensions: str | None = None, max_seconds: int = 600
) -> dict[str, Any]:
    """Brute-force paths with ffuf, at the engagement's rate limit.

    ``wordlist`` is either a **name** from the vetted payload store ("admin",
    "juicy-paths", "api-routes" — call ``payload_catalog`` for the list) or a
    path to a file inside the engagement workspace.

    There is no default. The size of the wordlist is the size of the impact on
    the target, and that should be a deliberate choice.
    """
    engagement = get_engagement()
    url = split_targets(target)[0]
    if not url.startswith("http"):
        url = f"https://{url}"
    # Wordlist entries conventionally start with "/" ("/.git", "/admin"), and
    # FUZZ is substituted literally, so "host/" + "/admin" produced "host//admin".
    # Some servers route that differently from "host/admin", which silently
    # changes what was actually tested. Entries are normalized below instead.
    fuzz_url = url.rstrip("/") + "/FUZZ"

    from easyhunt.control_plane.sanitize import sanitize_path
    from easyhunt.knowledge.payloads import PayloadError, store_from_config

    listed: dict[str, Any] | None = None
    store = store_from_config(engagement.config)

    # A bare name resolves against the vetted store; anything with a separator is
    # treated as a workspace path and goes through sanitize_path as before.
    if "/" not in wordlist and not wordlist.endswith(".txt"):
        try:
            entry = store.resolve(wordlist)
        except PayloadError as exc:
            return {
                "ok": False,
                "error": "wordlist_not_found",
                "message": str(exc),
                "available": [item["name"] for item in store.catalog(tool="ffuf")],
            }
        wordlist_path = entry.path
        listed = entry.to_dict()
    else:
        wordlist_path = sanitize_path(
            wordlist, workspace=engagement.workspace, name="wordlist"
        )
        if not wordlist_path.exists():
            return {
                "ok": False,
                "error": "wordlist_not_found",
                "message": (
                    f"{wordlist_path} does not exist. Use a name from "
                    "payload_catalog, or place the wordlist inside the engagement "
                    "workspace; paths outside it are refused."
                ),
                "available": [item["name"] for item in store.catalog(tool="ffuf")],
            }

    # Normalize into the workspace: strip leading slashes and blank lines. The
    # store itself is mounted read-only and must not be rewritten.
    normalized = engagement.workspace / "raw" / f"wordlist-{wordlist_path.stem}.txt"
    normalized.parent.mkdir(parents=True, exist_ok=True)
    if not normalized.exists():
        cleaned = [
            line.strip().lstrip("/")
            for line in wordlist_path.read_text(encoding="utf-8", errors="replace").splitlines()
        ]
        normalized.write_text("\n".join(w for w in cleaned if w) + "\n", encoding="utf-8")

    baseline = await _soft_404_baseline(fuzz_url)

    output = engagement.raw_path("ffuf", "json")
    run = await run_one(
        "ffuf",
        [
            "-u", fuzz_url, "-w", str(normalized),
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-t", str(max(1, engagement.scope.rules.max_concurrency)),
            "-rate", str(max(1, int(engagement.scope.rules.max_rps))),
            "-timeout", "15", "-ac", "-s",
            "-maxtime", str(min(max_seconds, 900)),
            "-of", "json", "-o", str(output),
        ]
        # Drop the catch-all response sizes outright. ffuf's -ac calibrates on a
        # few random strings and still let an Imperva "Request Rejected" page —
        # served with HTTP 200 — through as a hit on every path tried.
        + (["-fs", ",".join(str(s) for s in sorted(baseline["sizes"]))] if baseline["sizes"] else [])
        + (["-e", extensions] if extensions and "-e" in FFUF.arg_policy.allowed_flags else []),  # type: ignore[union-attr]
        timeout=1500,
    )

    results: list[dict[str, Any]] = []
    if output.exists():
        import json

        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
            for entry in payload.get("results", []):
                results.append(
                    {
                        "url": entry.get("url"),
                        "status": entry.get("status"),
                        "length": entry.get("length"),
                        "words": entry.get("words"),
                    }
                )
        except json.JSONDecodeError:
            pass

    found = [r["url"] for r in results if r.get("url")]
    kept, dropped = in_scope_only(found, phase="endpoints", tool="content_discovery")
    store_assets(kept, kind="url", source="ffuf", tags=["brute-forced"])

    return {
        "ok": True,
        "url": fuzz_url,
        "wordlist": str(wordlist_path),
        "payload_list": listed,
        "count": len(kept),
        "results": [r for r in results if r.get("url") in set(kept)],
        "dropped_out_of_scope": dropped,
        "tools": [run.to_dict()],
    }


@easyhunt_tool(
    phase="endpoints", mode="passive", targets_arg=None, timeout=30,
    name="payload_catalog", tags={"endpoints", "inspection"},
    estimated_requests=0, budget_exempt=True,
)
async def payload_catalog(tool: str | None = None) -> dict[str, Any]:
    """List the payload wordlists available to content and parameter discovery.

    Names returned here are what ``content_discovery`` expects for its
    ``wordlist`` argument. Touches no target and costs no budget.

    Only tier A discovery wordlists appear. Tier B injection payloads belong to
    the approval-gated exploitation tools, and tier C is quarantined and has no
    name bound to it at all — see docs/PAYLOADS.md.
    """
    engagement = get_engagement()
    from easyhunt.knowledge.payloads import store_from_config

    store = store_from_config(engagement.config)
    if not store.available:
        return {
            "ok": False,
            "error": "store_not_built",
            "message": (
                "The payload store has not been fetched. Build it with: "
                "python3 scripts/vet_payloads.py --fetch. Until then, pass "
                "content_discovery a wordlist path inside the engagement workspace."
            ),
            "lists": [],
        }

    listed = store.catalog(tool=tool)
    return {
        "ok": True,
        "count": len(listed),
        "lists": listed,
        "guidance": (
            "Start with 'juicy-paths' or 'fuzz-small'. Pick a stack-specific list "
            "(spring-boot, wordpress, iis) once http_probe identifies the "
            "technology. The large lists (fuzz-large, fuzz-everything, api-routes) "
            "cost hours at a typical rate limit — choose them deliberately."
        ),
    }

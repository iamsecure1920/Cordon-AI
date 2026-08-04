"""HTTP probing and fingerprinting.

``http_probe`` is the highest-value call in the recon phase: it turns a list of
names into live services with status codes, titles, and technologies, which is
what everything downstream selects targets from.

Rule-packs run against every probe response here, so a native detection fires
during recon rather than waiting for a separate scanning pass.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    HOST_PATTERN,
    register_spec,
    run_one,
    split_targets,
    store_assets,
    targets_or_assets,
)

__all__ = ["http_probe", "waf_detect"]

HTTPX = register_spec(
    ToolSpec(
        name="httpx", binary="httpx", image="projectdiscovery/httpx:latest", license="MIT",
        homepage="https://github.com/projectdiscovery/httpx", version_args=["-version"],
        identity_marker="projectdiscovery",
        user_agent_flag="-H",
        arg_policy=ArgPolicy(
            tool="httpx",
            allowed_flags={
                "-l", "-u", "-json", "-silent", "-nc", "-duc", "-title", "-tech-detect",
                "-status-code", "-content-length", "-web-server", "-ip", "-cname",
                "-follow-redirects", "-timeout", "-threads", "-rl", "-retries", "-ports",
                "-H", "-o", "-favicon", "-jarm", "-location", "-cdn", "-mc", "-fc",
            },
            boolean_flags={
                "-json", "-silent", "-nc", "-duc", "-title", "-tech-detect", "-status-code",
                "-content-length", "-web-server", "-ip", "-cname", "-follow-redirects",
                "-favicon", "-jarm", "-location", "-cdn",
            },
            value_patterns={"-u": HOST_PATTERN, "-ports": re.compile(r"[0-9,\-]{1,64}")},
            numeric_caps={"-timeout": 30, "-threads": 50, "-rl": 150, "-retries": 2},
        ),
    )
)

WHATWEB = register_spec(
    ToolSpec(
        name="whatweb", binary="whatweb", license="GPL-2.0",
        homepage="https://github.com/urbanadventurer/WhatWeb", version_args=["--version"],
        user_agent_flag="--user-agent",
        arg_policy=ArgPolicy(
            tool="whatweb",
            allowed_flags={"--log-json", "-a", "--no-errors", "--user-agent", "--max-threads"},
            boolean_flags={"--no-errors"},
            # Aggression level 1 only: 3 and 4 send exploit-shaped probes.
            value_patterns={"-a": re.compile(r"1")},
            numeric_caps={"--max-threads": 20},
            allow_positional=True,
            positional_pattern=re.compile(r"https?://[A-Za-z0-9._:/-]{1,512}"),
        ),
    )
)

WAFW00F = register_spec(
    ToolSpec(
        name="wafw00f", binary="wafw00f", license="BSD-3-Clause",
        homepage="https://github.com/EnableSecurity/wafw00f", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="wafw00f",
            allowed_flags={"-o", "-f", "-a", "--no-colors"},
            boolean_flags={"-a", "--no-colors"},
            value_patterns={"-f": re.compile(r"json|text|csv")},
            allow_positional=True,
            positional_pattern=re.compile(r"https?://[A-Za-z0-9._:/-]{1,512}"),
        ),
    )
)


@easyhunt_tool(
    phase="http_probe", mode="passive", targets_arg="target", timeout=900,
    name="http_probe", tags={"recon", "http"}, estimated_requests=100,
)
async def http_probe(
    target: str, ports: str | None = None, follow_redirects: bool = True
) -> dict[str, Any]:
    """Probe hosts for live HTTP services: status, title, tech, server, IP.

    One request per host per scheme, at the engagement's rate limit. Rule-packs
    are evaluated against each response, so native detections surface here.
    """
    engagement = get_engagement()
    # Called with no target, this probes whatever recon found. That is the
    # normal case in a pipeline: subdomain_enum already merged and deduplicated
    # across subfinder, amass, assetfinder and findomain, and the scope engine
    # already dropped what the program does not cover.
    hosts, origin = targets_or_assets(target, kind="subdomain", tool="http_probe")

    targets_file = engagement.raw_path("httpx-targets", "txt")
    targets_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    argv = [
        "-l", str(targets_file),
        "-json", "-silent", "-nc", "-duc",
        "-title", "-tech-detect", "-status-code", "-content-length",
        "-web-server", "-ip", "-cname", "-cdn", "-location",
        "-timeout", "10",
        "-threads", str(max(1, engagement.scope.rules.max_concurrency)),
        "-rl", str(max(1, int(engagement.scope.rules.max_rps))),
        "-retries", "1",
    ]
    if follow_redirects:
        argv.append("-follow-redirects")
    if ports:
        argv += ["-ports", ports]

    run = await run_one("httpx", argv, timeout=800)

    live: list[dict[str, Any]] = []
    technologies: dict[str, int] = {}
    rule_hits: list[dict[str, Any]] = []

    from easyhunt.plugins.loader import get_registry

    registry = get_registry()

    for line in run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = str(record.get("url") or "")
        if not url or not engagement.scope.check(url).in_scope:
            continue

        entry = {
            "url": url,
            "status": record.get("status_code"),
            "title": record.get("title"),
            "tech": record.get("tech") or [],
            "server": record.get("webserver"),
            "content_length": record.get("content_length"),
            # httpx's "host" is the hostname it was given, not an address —
            # the resolved address is "host_ip", with "a" as the record list.
            # Reading "host" here put hostnames into a field the asset store and
            # CIDR scope checks treat as an IP.
            "ip": record.get("host_ip") or (record.get("a") or [None])[0],
            "cname": (record.get("cname") or [None])[0]
            if isinstance(record.get("cname"), list)
            else record.get("cname"),
            "cdn": record.get("cdn_name"),
            "final_url": record.get("final_url") or record.get("location"),
        }
        live.append(entry)
        store_assets([url], kind="url", source="httpx", tags=["live"])
        for tech in entry["tech"]:
            technologies[str(tech)] = technologies.get(str(tech), 0) + 1
            store_assets([str(tech)], kind="technology", source="httpx")

        # Rule-packs get a look at every response we already paid for.
        matches = registry.evaluate(
            {
                "url": url,
                "status": entry["status"],
                "headers": record.get("header") or {},
                "body": record.get("body") or "",
            }
        )
        for match in matches:
            manifest = registry.get(match.rule_id)
            if manifest is None:
                continue
            finding = Finding(
                asset=url,
                title=manifest.description.split(".")[0][:200],
                phase=manifest.phase,
                severity=Severity.parse(manifest.severity),
                status=Status.CANDIDATE,
                description=manifest.description,
                how_found=f"EasyHunt rule-pack '{manifest.id}' matched via {match.matched_by}",
                source_tool="easyhunt-rules",
                rule_id=manifest.id,
                confidence=0.5,
                remediation=manifest.remediation,
                references=manifest.references,
                tags=manifest.tags,
                evidence=[
                    Evidence(
                        kind="response",
                        description="httpx probe response",
                        excerpt=json.dumps(match.extracted, default=str)[:2000],
                    )
                ],
                extra={"extracted": match.extracted, "verify": manifest.verify.note},
            )
            engagement.findings.add(finding)
            rule_hits.append({"rule": manifest.id, "url": url, "extracted": match.extracted})

    engagement.assets.save(engagement.workspace / "assets.json")
    engagement.findings.save()

    # httpx buffers its JSON output, so a kill at the timeout discards everything
    # it had found. Measured: 764 hosts at 5 rps, ~35% of them dead names each
    # costing a 15s connect timeout, ran past the 800s ceiling and returned zero
    # results — reported as "0 live hosts", which reads exactly like an estate
    # with nothing on it.
    incomplete = run.error in {"timed out"} or (not run.ran)
    return {
        "ok": not incomplete,
        "error": "probe_incomplete" if incomplete else None,
        "message": (
            f"httpx did not finish ({run.error}). It buffers output, so results "
            f"gathered before the cutoff were lost. {len(hosts)} hosts at "
            f"{engagement.scope.rules.max_rps:.0f} rps needs more headroom than the "
            "ceiling allowed — probe in batches. Zero live here means UNKNOWN, "
            "not empty."
        ) if incomplete else None,
        "complete": not incomplete,
        "probed": len(hosts),
        "live": len(live),
        "services": live,
        "technologies": dict(sorted(technologies.items(), key=lambda kv: -kv[1])),
        "rule_matches": rule_hits,
        "tools": [run.to_dict()],
        "next_step": (
            "Crawl the interesting services with endpoint_discovery, then scan "
            "with nuclei_scan."
        ),
    }


@easyhunt_tool(
    phase="http_probe", mode="passive", targets_arg="target", timeout=300,
    name="waf_detect", tags={"recon", "http"}, estimated_requests=10,
)
async def waf_detect(target: str) -> dict[str, Any]:
    """Identify the WAF or protection layer in front of a host.

    Knowing the WAF changes what is worth trying and what will simply be blocked.
    EasyHunt does not implement WAF bypass — identifying one is context for a
    human, not a step toward evasion.
    """
    url = split_targets(target)[0]
    if not url.startswith("http"):
        url = f"https://{url}"

    run = await run_one("wafw00f", ["-a", "--no-colors", url], timeout=120, allow_codes=(0, 1))
    text = "\n".join(run.values)
    detected = re.findall(r"is behind (.+?)(?:\s+WAF|\.|$)", text)

    return {
        "ok": True,
        "url": url,
        "waf_detected": bool(detected),
        "waf": sorted({d.strip() for d in detected}),
        "output": text[-4000:],
        "tools": [run.to_dict()],
        "note": (
            "A WAF is context, not an obstacle to route around. EasyHunt will not "
            "implement evasion; if testing is blocked, say so in the report."
        ),
    }

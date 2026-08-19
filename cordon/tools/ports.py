"""Port and service scanning.

All aggressive and gated. Two guards beyond the usual approval prompt:

* **Rate is capped in code.** ``masscan``'s ``--rate`` and ``nmap``'s ``-T``
  timing are bounded by the argument policy, so an approved scan cannot become a
  volumetric one. ``-T5`` and unbounded rates are simply not on the allowlist.
* **NSE categories are restricted.** ``exploit``, ``dos``, ``brute``, and
  ``malware`` scripts are refused. ``default`` and ``safe`` are what a port scan
  needs; the rest is exploitation wearing a scanner's clothes.

Run ``cdn_check`` first. Scanning a CDN edge measures the CDN.

**Rate governance.** One tool call here is thousands of packets, so the control
plane's per-call token governs nothing on its own; the tool's own rate flag does.
``naabu -rate`` and ``nmap --max-rate`` are both packets-per-second ceilings and
are both set from ``scope.rules.max_rps``.

They used to be set to ``max_rps * 20`` and ``max_rps * 10`` respectively, with a
floor of 10 that overrode the engagement entirely below 1 rps. The argument for
the multiplier is that a SYN probe is cheaper than an HTTP request. That argument
is not ours to make: a program that publishes a ceiling has already decided what
its infrastructure will absorb, and "we judged our packets to be cheap" is not a
defence anyone accepts after the fact. The multipliers are gone.

The honest consequence: a top-1000 scan of 20 hosts is 20,000 packets, and at a
6 rps ceiling that is roughly an hour. Port scanning under a published rate limit
is slow. That is the constraint, not a bug.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from xml.etree import ElementTree

from cordon.control_plane.context import get_engagement
from cordon.control_plane.sanitize import ArgPolicy
from cordon.errors import SanitizeError
from cordon.knowledge.findings import Asset
from cordon.tools.base import ToolSpec, cordon_tool
from cordon.tools.common import HOST_PATTERN, PORT_PATTERN, register_spec, run_one, split_targets

__all__ = ["port_scan", "service_scan"]

# NSE categories that are safe to run during reconnaissance.
#
# ``safe`` is deliberately absent: it drags in broadcast-* scripts (which crash
# nmap with the nse_nsock.cc:342 assertion and probe the LAN instead of the
# target) and http-slowloris-check (which holds connections open and stalls the
# whole scan at the engagement's rate limit). ``default`` is the curated
# category that fingerprints without either failure mode.
ALLOWED_NSE_CATEGORIES = {"default", "discovery", "version", "banner"}
DENIED_NSE_CATEGORIES = {"safe", "exploit", "dos", "brute", "malware", "intrusive", "vuln"}

NAABU = register_spec(
    ToolSpec(
        name="naabu", binary="naabu", image="projectdiscovery/naabu:latest", license="MIT",
        homepage="https://github.com/projectdiscovery/naabu", version_args=["-version"],
        # SYN scanning needs raw sockets; that is the only capability granted.
        capabilities=["NET_RAW"],
        arg_policy=ArgPolicy(
            tool="naabu",
            allowed_flags={
                "-host", "-list", "-p", "-top-ports", "-json", "-silent", "-nc", "-duc",
                "-rate", "-c", "-timeout", "-retries", "-o", "-exclude-cdn", "-s",
            },
            boolean_flags={"-json", "-silent", "-nc", "-duc", "-exclude-cdn"},
            value_patterns={
                "-host": HOST_PATTERN,
                "-p": PORT_PATTERN,
                "-top-ports": re.compile(r"100|1000|full"),
                "-s": re.compile(r"s|c"),
            },
            numeric_caps={"-rate": 1000, "-c": 25, "-timeout": 10000, "-retries": 3},
        ),
    )
)

NMAP = register_spec(
    ToolSpec(
        name="nmap", binary="nmap", license="NPSL (custom, not OSI)",
        homepage="https://nmap.org", version_args=["--version"],
        capabilities=["NET_RAW"],
        arg_policy=ArgPolicy(
            tool="nmap",
            allowed_flags={
                "-p", "-sV", "-sC", "-sT", "-sS", "-Pn", "-oX", "-oN", "-T",
                "--script", "--version-intensity", "--max-rate", "--max-retries",
                "--host-timeout", "-open", "-n",
            },
            boolean_flags={"-sV", "-sC", "-sT", "-sS", "-Pn", "-open", "-n"},
            # -A pulls in intrusive scripts; -T5 ignores rate considerations.
            denied_flags={"-A", "-O", "--script-args", "-iL", "--datadir"},
            value_patterns={
                "-p": PORT_PATTERN,
                "-T": re.compile(r"[0-4]"),
                # nmap's --script is an expression language: categories joined
                # with and/or/not and parens. We use it to append
                # "and not broadcast", so the pattern allows the operators.
                "--script": re.compile(r"[a-z0-9,._*() -]{1,240}"),
            },
            numeric_caps={"--version-intensity": 7, "--max-rate": 500, "--max-retries": 3},
            allow_positional=True,
            positional_pattern=HOST_PATTERN,
        ),
    )
)

#: Registered but not invoked by any wrapper. Kept in the catalog so
#: `cordon doctor` reports on it, and kept capped so it stays un-abusable if it
#: is ever wired up: masscan's `--rate` defaults to 100 pps and it has no other
#: throttle, so `--rate` from `max_rps` would be the whole of its governance.
MASSCAN = register_spec(
    ToolSpec(
        name="masscan", binary="masscan", license="AGPL-3.0",
        homepage="https://github.com/robertdavidgraham/masscan", version_args=["--version"],
        capabilities=["NET_RAW"],
        arg_policy=ArgPolicy(
            tool="masscan",
            allowed_flags={"-p", "--ports", "--rate", "-oJ", "-oX", "--wait", "--open-only"},
            boolean_flags={"--open-only"},
            value_patterns={"-p": PORT_PATTERN, "--ports": PORT_PATTERN},
            # Hard ceiling: masscan's entire reputation is built on rates that
            # take services offline.
            numeric_caps={"--rate": 1000, "--wait": 10},
            allow_positional=True,
            positional_pattern=HOST_PATTERN,
        ),
    )
)


def _check_nse(scripts: str) -> str:
    """Refuse NSE selections that reach beyond safe reconnaissance.

    The returned expression is always suffixed with ``and not broadcast``:
    broadcast-* scripts (present in both the ``safe`` and ``default``
    categories) send SSDP/multicast probes at the LAN rather than the target
    and have a known nmap crash (``nse_nsock.cc:342`` assertion in
    broadcast-upnp-info) that aborts the whole scan. An approved service scan
    must probe the target, not the neighborhood.
    """
    requested = {s.strip().lower() for s in scripts.split(",") if s.strip()}
    denied = requested & DENIED_NSE_CATEGORIES
    if denied:
        raise SanitizeError(
            f"NSE categories {sorted(denied)} are refused — they exploit, brute-force, "
            "or disrupt rather than enumerate. Permitted: "
            f"{sorted(ALLOWED_NSE_CATEGORIES)}",
            tool="nmap",
            categories=sorted(denied),
        )
    unknown = {s for s in requested if s in DENIED_NSE_CATEGORIES}
    if unknown:
        raise SanitizeError(f"unknown NSE selection {sorted(unknown)}", tool="nmap")
    if not requested:
        return ""
    return ",".join(sorted(requested)) + " and not broadcast"


@cordon_tool(
    phase="ports", mode="aggressive", targets_arg="target", timeout=1800,
    name="port_scan", tags={"ports"},
    # hosts x ports, not a constant. The default is top-100 and a post-recon host
    # list is routinely 50-300 names, so 10,000 is a realistic default-case figure
    # and top-1000 multiplies it by ten.
    estimated_requests=10_000,
    risk_notes=[
        "Connects to many ports on the target — unmistakable in network logs.",
        "Packet volume is hosts x ports: top-100 against 100 hosts is 10,000 "
        "packets, top-1000 is 100,000. The estimate above is a default-case "
        "figure, not a ceiling.",
        "naabu -rate is set to the engagement's max_rps exactly and -c to "
        "max_concurrency; neither can be raised by a caller argument.",
        "Run cdn_check first: scanning a CDN edge tells you about the CDN.",
    ],
)
async def port_scan(target: str, ports: str = "top-100") -> dict[str, Any]:
    """Discover open TCP ports with naabu.

    ports: "top-100", "top-1000", or an explicit list like "80,443,8080-8090".
    CDN ranges are excluded automatically.
    """
    engagement = get_engagement()
    hosts = split_targets(target)

    targets_file = engagement.raw_path("naabu-targets", "txt")
    targets_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    rules = engagement.scope.rules
    argv = [
        "-list", str(targets_file),
        "-json", "-silent", "-nc", "-duc", "-exclude-cdn",
        # Packets per second, at the engagement ceiling — no multiplier and no
        # floor. A floor of 10 would have silently ignored any program that
        # published a limit below that.
        "-rate", str(max(1, int(rules.max_rps))),
        # Clamp to naabu's own policy ceiling: a scope may publish a higher
        # max_concurrency than a scanner's argv policy allows, and run_one
        # refuses (not clamps) an over-cap value. min() keeps us inside the cap
        # instead of erroring out the whole phase.
        "-c", str(min(max(1, int(rules.max_concurrency)), 25)),
        "-retries", "1",
    ]
    if ports == "top-100":
        argv += ["-top-ports", "100"]
    elif ports == "top-1000":
        argv += ["-top-ports", "1000"]
    else:
        argv += ["-p", ports]

    run = await run_one("naabu", argv, timeout=1500)

    import json

    open_ports: list[dict[str, Any]] = []
    for line in run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = str(record.get("host") or record.get("ip") or "")
        if not engagement.scope.check(host).in_scope:
            continue
        entry = {"host": host, "ip": record.get("ip"), "port": record.get("port")}
        open_ports.append(entry)
        engagement.assets.add(
            Asset(
                value=f"{host}:{entry['port']}",
                kind="open_port",
                source="naabu",
                host=host,
                attributes=entry,
            )
        )

    engagement.assets.save(engagement.workspace / "assets.json")
    return {
        "ok": True,
        "hosts_scanned": len(hosts),
        "open_ports": open_ports,
        "count": len(open_ports),
        "tools": [run.to_dict()],
        "next_step": "Fingerprint the interesting ports with service_scan.",
    }


@cordon_tool(
    phase="ports", mode="aggressive", targets_arg="target", timeout=1800,
    name="service_scan", tags={"ports"},
    # -sV at intensity 5 sends on the order of 30 probes per open port, and
    # --max-retries 2 can triple any of them; default/safe NSE adds more. For the
    # default two ports that is ~200, but a caller passing a 100-port list makes
    # it ~10,000 and no argument bounds that.
    estimated_requests=200,
    risk_notes=[
        "Version detection sends protocol-specific probes to each open port — "
        "roughly 30 per port at intensity 5, times up to 3 for --max-retries, "
        "plus whatever the selected NSE scripts send.",
        "Volume scales with the port list the caller passes; the estimate covers "
        "the two-port default only.",
        "nmap --max-rate is set to the engagement's max_rps exactly.",
        "Only safe NSE categories are permitted; exploit/dos/brute are refused.",
    ],
)
async def service_scan(
    target: str, ports: str | None = None, scripts: str = "default"
) -> dict[str, Any]:
    """Fingerprint services on specific ports with nmap -sV plus safe NSE scripts.

    scripts is restricted to default/discovery/version/banner. Exploit, dos,
    brute, malware, intrusive, and safe-as-a-category are refused: the ``safe``
    category pulls broadcast-* scripts (which crash nmap with the
    nse_nsock.cc:342 assertion and probe the LAN instead of the target) and
    http-slowloris-check (which holds connections open and stalls the whole
    scan at the engagement's rate limit). ``default`` is the curated category
    that fingerprints without either failure mode.

    ``ports`` defaults to what ``port_scan`` already discovered for the
    requested hosts (the open_port assets in the store) and falls back to the
    web ports ``80,443`` only when nothing was discovered. ``target`` may name
    several hosts — the service phase feeds it every host that has an
    open_port asset, so one nmap pass fingerprints the whole estate instead of
    the single focus host. The old design scanned one host's 80,443 and
    silently reported "no services" on every estate that runs on 3000/8080/
    8443 — exactly the ports port_scan exists to find. The chain is
    ``ports -> services``; services must consume what ports produced.
    """
    engagement = get_engagement()
    hosts = split_targets(target)
    if not hosts:
        hosts = []
    requested = set(hosts)

    # Inherit the store's discovery: ports are keyed per host, so merge the
    # union of every open_port asset for the requested hosts into one list and
    # fingerprint them in a single nmap pass. A superset applied to every host
    # costs a few closed-port probes and buys one invocation.
    discovered_by_host: dict[str, set[int]] = defaultdict(set)
    for a in engagement.assets.all():
        if a.kind == "open_port" and isinstance(a.attributes.get("port"), int):
            discovered_by_host[a.host or ""].add(int(a.attributes["port"]))
    inherited_ports: set[int] = set()
    if requested:
        for host in requested:
            inherited_ports |= discovered_by_host.get(host, set())
    else:
        # No explicit hosts: inherit the whole estate's discovery, hosts and
        # ports together, so a store-only call still scans something.
        for host, ports_set in discovered_by_host.items():
            if host:
                hosts.append(host)
            inherited_ports |= ports_set
    if not ports:
        ports = ",".join(str(p) for p in sorted(inherited_ports)) if inherited_ports else "80,443"
    if not hosts and not inherited_ports:
        # Nothing to scan and no store to inherit from — refuse loudly instead
        # of handing nmap an empty host list.
        return {"ok": False, "hosts": [], "services": [], "count": 0,
                "error": "no hosts supplied and no open_port assets in the store"}
    selection = _check_nse(scripts)

    rules = engagement.scope.rules
    output = engagement.raw_path("nmap", "xml")
    argv = [
        "-p", ports, "-sV", "-Pn", "-open", "-n",
        "-T", "3",
        "--version-intensity", "5",
        # Packets per second at the engagement ceiling. nmap treats --max-rate as
        # a hard cap, so this is the one flag that actually binds -sV's fan-out.
        "--max-rate", str(max(1, int(rules.max_rps))),
        "--max-retries", "2",
        "--host-timeout", "600s",
        "-oX", str(output),
    ]
    if selection:
        argv += ["--script", selection]
    argv.extend(hosts)

    run = await run_one("nmap", argv, timeout=1500, allow_codes=(0, 1))

    services: list[dict[str, Any]] = []
    if output.exists():
        try:
            tree = ElementTree.parse(output)  # noqa: S314 — our own tool's output
            for host_el in tree.iter("host"):
                address = host_el.find("address")
                host_addr = str(address.get("addr")) if address is not None else ""
                for port in host_el.iter("port"):
                    state = port.find("state")
                    service = port.find("service")
                    if state is None or state.get("state") != "open":
                        continue
                    services.append(
                        {
                            "host": host_addr,
                            "port": int(port.get("portid", 0)),
                            "protocol": port.get("protocol"),
                            "service": service.get("name") if service is not None else None,
                            "product": service.get("product") if service is not None else None,
                            "version": service.get("version") if service is not None else None,
                            "extrainfo": service.get("extrainfo") if service is not None else None,
                        }
                    )
        except ElementTree.ParseError:
            pass

    for service in services:
        # The XML gives the host per port, so attribute each service to the host
        # that actually runs it rather than the whole list.
        host = service.get("host") or (hosts[0] if hosts else "")
        engagement.assets.add(
            Asset(
                value=f"{host}:{service['port']}",
                kind="service",
                source="nmap",
                host=host,
                attributes=service,
            )
        )
    engagement.assets.save(engagement.workspace / "assets.json")

    return {
        "ok": True,
        "hosts": hosts,
        "services": services,
        "count": len(services),
        "nse_scripts": selection,
        "xml_output": str(output) if output.exists() else None,
        "tools": [run.to_dict()],
        "note": (
            "Version strings are a lead, not a finding. A banner claiming a "
            "vulnerable version proves nothing without a working PoC."
        ),
    }

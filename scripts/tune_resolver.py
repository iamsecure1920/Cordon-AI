#!/usr/bin/env python3
"""Local caching resolver + kernel tuning for DNS-bound enumeration.

WHEN THIS HELPS
    Permutation brute-forcing (shuffledns, massdns, alterx) does tens of
    thousands of lookups per second against *resolvers*, not against the target.
    No program rate limit applies, so DNS genuinely is the bottleneck there.

WHEN IT DOES NOT
    Target-facing scanning. A bug bounty program that caps you at 6 requests per
    second makes DNS latency irrelevant: measured on a real engagement, an
    uncached lookup took 78ms against a 200ms deliberate inter-request delay.
    Speeding DNS up there changes nothing — the rate limiter simply waits longer.

Run this on a scanning box BEFORE an engagement, not during one. It changes the
system resolver, and a resolver change mid-run is a bad surprise.

    sudo python3 scripts/tune_resolver.py            # dns + kernel
    sudo python3 scripts/tune_resolver.py --dns-only
    sudo python3 scripts/tune_resolver.py --check    # report, change nothing
    sudo python3 scripts/tune_resolver.py --revert
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RESOLV = Path("/etc/resolv.conf")
DNSMASQ = Path("/etc/dnsmasq.conf")
SYSCTL = Path("/etc/sysctl.d/99-cordon-tuning.conf")
BACKUP_SUFFIX = ".cordon-backup"

G, Y, R, C, B, N = (
    "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[1m", "\033[0m"
)


def ok(m: str) -> None:
    print(f"  {G}✓{N} {m}")


def warn(m: str) -> None:
    print(f"  {Y}!{N} {m}")


def bad(m: str) -> None:
    print(f"  {R}✗{N} {m}")


def info(m: str) -> None:
    print(f"  {C}→{N} {m}")


def run(argv: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    """No shell. Every argument is a list element, so nothing is word-split."""
    return subprocess.run(  # noqa: S603
        argv, capture_output=True, text=True, timeout=300, check=check
    )


def docker_bridge_ip() -> str | None:
    """The docker0 address, so containers can reach the cache.

    Without this the whole exercise is theatre for Cordon: tools run in
    containers, and 127.0.0.1 inside a container is the container itself. Docker
    sees a loopback nameserver in the host resolv.conf and silently substitutes
    public DNS — the cache reports healthy and serves nobody.
    """
    result = run(["ip", "-4", "-o", "addr", "show", "docker0"])
    if result.returncode != 0:
        return None
    for token in result.stdout.split():
        if "/" in token and token[0].isdigit():
            return token.split("/")[0]
    return None


# --------------------------------------------------------------------------- #
# Config generation
# --------------------------------------------------------------------------- #

UPSTREAMS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]


def dnsmasq_config(bridge: str | None) -> str:
    listen = ["127.0.0.1"] + ([bridge] if bridge else [])
    lines = [
        "# Cordon — caching resolver for DNS-bound enumeration.",
        "port=53",
        "domain-needed",
        "bogus-priv",
        "no-resolv",
        *(f"server={s}" for s in UPSTREAMS),
        "",
        "cache-size=100000",
        "dns-forward-max=10000",
        "edns-packet-max=4096",
        "",
        "# TTLs are honoured deliberately. Overriding them (min-cache-ttl /",
        "# max-cache-ttl) serves stale CNAME and NXDOMAIN records, and subdomain",
        "# takeover detection depends entirely on those being fresh. A cached",
        "# stale CNAME means a missed takeover or a false one — on a program",
        "# paying four figures for a P1, that is the wrong trade.",
        "",
        *(f"listen-address={addr}" for addr in listen),
    ]
    if bridge:
        lines += [
            "",
            f"# {bridge} is the docker0 bridge: containerised tools resolve",
            "# through the cache instead of silently bypassing it.",
            "except-interface=nonexistent",
        ]
    return "\n".join(lines) + "\n"


SYSCTL_SETTINGS = {
    "net.core.somaxconn": "65535",
    "net.core.netdev_max_backlog": "65535",
    "net.ipv4.tcp_max_syn_backlog": "65535",
    "net.ipv4.ip_local_port_range": "1024 65535",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.core.rmem_max": "134217728",
    "net.core.wmem_max": "134217728",
    "net.ipv4.tcp_rmem": "4096 87380 134217728",
    "net.ipv4.tcp_wmem": "4096 65536 134217728",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.netfilter.nf_conntrack_max": "1048576",
}


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #


def check() -> int:
    """Report only. Safe to run any time, including mid-engagement."""
    print(f"\n{B}Resolver{N}")
    current = RESOLV.read_text() if RESOLV.exists() else ""
    servers = [line.split()[1] for line in current.splitlines()
               if line.startswith("nameserver") and len(line.split()) > 1]
    info(f"nameservers: {', '.join(servers) or 'none'}")
    if run(["systemctl", "is-active", "dnsmasq"]).stdout.strip() == "active":
        ok("dnsmasq active")
    else:
        info("dnsmasq not running")

    bridge = docker_bridge_ip()
    info(f"docker0 bridge: {bridge or 'not present'}")

    print(f"\n{B}Latency{N}")
    times = []
    for i in range(8):
        name = f"probe{i}{int(time.time() * 1000) % 100000}.example.net"
        t0 = time.perf_counter()
        run(["dig", "+short", "+tries=1", "+time=2", name])
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    median = times[len(times) // 2]
    info(f"uncached lookup: median {median:.0f}ms")

    print(f"\n{B}Verdict{N}")
    if median < 120:
        ok(f"{median:.0f}ms is fine for rate-limited target scanning.")
        info("Tuning only pays off for permutation brute-forcing (shuffledns,")
        info("massdns), which is resolver-bound rather than target-bound.")
    else:
        warn(f"{median:.0f}ms is slow — a local cache would help.")
    return 0


def apply(*, do_dns: bool, do_kernel: bool) -> int:
    if os.geteuid() != 0:
        bad("must run as root")
        return 1

    if do_dns:
        print(f"\n{B}Caching resolver{N}")
        bridge = docker_bridge_ip()
        if bridge:
            ok(f"docker0 at {bridge} — containers will use the cache")
        else:
            warn("no docker0 found; containerised tools will bypass the cache")

        if run(["which", "dnsmasq"]).returncode != 0:
            info("installing dnsmasq")
            run(["apt-get", "install", "-y", "-qq", "dnsmasq"])

        for path in (RESOLV, DNSMASQ):
            if path.exists() and not Path(str(path) + BACKUP_SUFFIX).exists():
                shutil.copy2(path, str(path) + BACKUP_SUFFIX)
                ok(f"backed up {path}")

        DNSMASQ.write_text(dnsmasq_config(bridge))
        ok("dnsmasq configured (TTLs honoured, 100k cache)")

        run(["systemctl", "stop", "systemd-resolved"])
        run(["systemctl", "disable", "systemd-resolved"])
        run(["systemctl", "restart", "dnsmasq"])

        if run(["systemctl", "is-active", "dnsmasq"]).stdout.strip() != "active":
            bad("dnsmasq failed to start — restoring resolv.conf and stopping")
            backup = Path(str(RESOLV) + BACKUP_SUFFIX)
            if backup.exists():
                shutil.copy2(backup, RESOLV)
            run(["systemctl", "enable", "--now", "systemd-resolved"])
            return 1

        # NOT chattr +i: an immutable resolv.conf breaks DHCP lease renewal on
        # most VPS providers, and leaves no way to recover DNS remotely.
        RESOLV.write_text("nameserver 127.0.0.1\noptions timeout:2 attempts:2\n")
        ok("resolv.conf → 127.0.0.1 (not locked; DHCP renewal still works)")

        probe = run(["dig", "+short", "+time=3", "example.com", "@127.0.0.1"])
        if probe.stdout.strip():
            ok(f"resolution works — example.com → {probe.stdout.split()[0]}")
        else:
            bad("resolution failed through dnsmasq — run --revert")
            return 1

    if do_kernel:
        print(f"\n{B}Kernel{N}")
        run(["modprobe", "tcp_bbr"])
        run(["modprobe", "nf_conntrack"])
        SYSCTL.write_text(
            "# Cordon — high-concurrency scanning.\n"
            + "".join(f"{k} = {v}\n" for k, v in SYSCTL_SETTINGS.items())
        )
        result = run(["sysctl", "-p", str(SYSCTL)])
        for line in result.stderr.splitlines():
            if line.strip():
                warn(line.strip())
        ok(f"applied {len(SYSCTL_SETTINGS)} settings ({SYSCTL})")

    # A light sanity check, deliberately not a stress test. Firing 500k queries
    # at public resolvers is a good way to get the scanning box rate-limited by
    # the very resolvers the engagement depends on.
    if do_dns:
        print(f"\n{B}Sanity check{N}")
        t0 = time.perf_counter()
        hits = sum(
            1 for i in range(50)
            if run(["dig", "+short", "+tries=1", "+time=2",
                    f"s{i}.example.com", "@127.0.0.1"]).returncode == 0
        )
        info(f"{hits}/50 queries answered in {(time.perf_counter()-t0):.1f}s")

    print(f"\n{G}Done.{N} Revert with: sudo python3 scripts/tune_resolver.py --revert\n")
    return 0


def revert() -> int:
    if os.geteuid() != 0:
        bad("must run as root")
        return 1
    print(f"\n{B}Reverting{N}")
    run(["chattr", "-i", str(RESOLV)])  # in case another script set it
    for path in (RESOLV, DNSMASQ):
        backup = Path(str(path) + BACKUP_SUFFIX)
        if backup.exists():
            shutil.copy2(backup, path)
            ok(f"restored {path}")
    if SYSCTL.exists():
        SYSCTL.unlink()
        ok(f"removed {SYSCTL}")
    run(["systemctl", "stop", "dnsmasq"])
    run(["systemctl", "disable", "dnsmasq"])
    run(["systemctl", "enable", "--now", "systemd-resolved"])
    ok("systemd-resolved restored")
    probe = run(["dig", "+short", "+time=3", "example.com"])
    ok("resolution works") if probe.stdout.strip() else bad("check DNS manually")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="report only, change nothing")
    group.add_argument("--revert", action="store_true", help="undo everything")
    parser.add_argument("--dns-only", action="store_true")
    parser.add_argument("--kernel-only", action="store_true")
    args = parser.parse_args()

    if args.check:
        return check()
    if args.revert:
        return revert()
    return apply(do_dns=not args.kernel_only, do_kernel=not args.dns_only)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{Y}cancelled{N}")
        sys.exit(1)

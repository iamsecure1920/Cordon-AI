#!/usr/bin/env python3
"""Vet a third-party payload collection before EasyHunt is allowed to use it.

Third-party payload lists are untrusted input. This script fetches one at a
pinned commit, classifies every file into a safety tier, quarantines what must
never be fired automatically, and emits a manifest mapping files to the tools
that consume them.

It does not "clean" payloads. Anything dangerous is moved to quarantine intact
so a human can look at it. Silently rewriting an attack string produces
something that looks safe and isn't.

Usage:
    python3 scripts/vet_payloads.py --fetch      # clone at pinned SHA, then vet
    python3 scripts/vet_payloads.py --verify     # re-check an existing store
    python3 scripts/vet_payloads.py --report     # print classification only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "payloads"
QUARANTINE = STORE / "_quarantine"
MANIFEST = STORE / "manifest.json"

# Pinned. A payload list is executable content in every sense that matters;
# tracking a moving branch means the next `git pull` silently changes what gets
# fired at a target. Bump this deliberately, after re-vetting.
SOURCE = {
    "repo": "https://github.com/coffinxp/payloads.git",
    "commit": "ff9bd2045961cbaba00bdc988db62edd2273dcd2",
    "license": "NONE DECLARED — all rights reserved by default",
    "redistribute": False,
}

# ── Tier definitions ─────────────────────────────────────────────────────────
#
# A: discovery wordlists. Requesting a path is what a web client does. Safe to
#    run under normal scope + rate limits, no approval beyond the usual.
# B: injection payloads. These are attacks. Aggressive mode + approval gate.
# C: quarantined. Destructive, or phones home to a third party. Never auto-run.

TIER_A = {
    "admin.txt", "adminer.txt", "api.txt", "apac.txt", "aspx.txt",
    "backup_files_only.txt", "cgi-bin.txt", "cgi-files.txt", "config.txt",
    "env.txt", "extensions.txt", "git_config.txt", "iis.txt", "jsf.txt",
    "jsp.txt", "juicy-paths.txt", "juicy_files.txt", "kibana.txt",
    "params.txt", "param.txt", "phpmyadmin.txt", "robots.txt",
    "spring-boot.txt", "vhosts.txt", "wp-content.txt", "wordpress-random.txt",
    "coffin-wp-fuzz.txt", "all-files-leaked.txt", "zip.txt",
    "httparchive_apiroutes_2022_08_28.txt", "onelistforallmicro.txt",
    "onelistforallshort.txt", "everything.txt", "all_fuzz.txt",
    "fuzz.txt", "fuzz_php_special.txt", "directory_traversal_unix.txt",
    "directory_traversal_win.txt",
}

TIER_B = {
    "xss.txt", "xsspollygots.txt", "xsswafbypss.txt", "sqli2.txt",
    "allsqli.txt", "blindsqli.txt", "SQL.txt", "sqldb.txt", "sqlDB.txt",
    "ssti.txt", "ssrf.txt", "lfi.txt", "crlf.txt", "xml.txt", "xor.txt",
    "all_attacks.txt", "jwt-secrets.txt", "pl.txt", "vulJs.txt",
    "android_all_permissions.txt", "github-dork.txt", "bambda.txt",
}

# ── Dangerous-content detectors ──────────────────────────────────────────────

# Destructive *statements*. Only meaningful inside injection payloads — the same
# words appear harmlessly as path segments in discovery wordlists
# ("actuator/shutdown", "android.permission.SHUTDOWN"), where they are strings
# being requested, not SQL being executed. Applying this to a path list
# quarantines the most useful wordlists for no gain, so classify() gates it on
# the file actually looking like injection content.
DESTRUCTIVE = re.compile(
    r"(?:DROP\s+(?:TABLE|DATABASE)|TRUNCATE\s+TABLE|DELETE\s+FROM"
    r"|xp_cmdshell|INTO\s+(?:OUT|DUMP)FILE|;\s*SHUTDOWN\b|'\s*;\s*SHUTDOWN)",
    re.IGNORECASE,
)

# Path segments that change server state if requested with a write method.
# Harmless under GET (Spring Boot's /actuator/shutdown returns 405), destructive
# under POST. These do not warrant quarantine — they warrant a method constraint.
STATE_CHANGING_PATH = re.compile(
    r"(?:^|/)(?:shutdown|restart|reboot|halt|poweroff|delete-?all|reset|drop|"
    r"destroy|purge|wipe|factory-?reset)(?:$|/|\?)",
    re.IGNORECASE | re.MULTILINE,
)

# Lines that look like executable injection rather than a path/word.
INJECTION_SYNTAX = re.compile(
    r"""(?:['"];|--\s*$|\bUNION\s+(?:ALL\s+)?SELECT\b|<script|onerror\s*=|"""
    r"""onload\s*=|javascript:|\bEXEC\s|\bWAITFOR\b|\$\{|\{\{)""",
    re.IGNORECASE | re.MULTILINE,
)

# Callbacks to infrastructure someone else controls. If one of these fires,
# target data leaves for a third party — that is exfiltration, regardless of
# intent, and it is not ours to authorize.
CALLBACK = re.compile(
    r"\b[a-z0-9.-]+\.(?:oastify\.com|burpcollaborator\.net|interact\.sh"
    r"|oast\.(?:pro|live|site|online|fun|me)|requestbin\.[a-z]+|pipedream\.net"
    r"|canarytokens\.com|dnslog\.cn|ceye\.io|xss\.ht|webhook\.site)\b",
    re.IGNORECASE,
)

REVERSE_SHELL = re.compile(
    r"(?:\bnc\s+-[a-z]*e\b|/bin/(?:ba)?sh\s*-i|bash\s+-i\s*>&)", re.IGNORECASE
)

# Heavy time-delay payloads. Not destructive, but they tarpit the engagement
# clock and look like a DoS attempt from the target's side.
SLOW = re.compile(
    r"(?:SLEEP\(\s*\d+|WAITFOR\s+DELAY|BENCHMARK\(\s*\d+|pg_sleep\(\s*\d+)",
    re.IGNORECASE,
)

# ── File → tool mapping ──────────────────────────────────────────────────────

TOOL_MAP: dict[str, dict[str, str]] = {
    "content_discovery": {
        "tools": "ffuf, feroxbuster",
        "flag": "-w",
        "files": "admin, config, env, juicy-paths, backup_files_only, extensions, "
                 "git_config, phpmyadmin, spring-boot, kibana, adminer, wp-content",
    },
    "param_discovery": {
        "tools": "arjun, ffuf",
        "flag": "-w",
        "files": "params, param",
    },
    "vhost_discovery": {
        "tools": "ffuf",
        "flag": "-w",
        "files": "vhosts",
    },
    "api_discovery": {
        "tools": "ffuf, katana",
        "flag": "-w",
        "files": "api, httparchive_apiroutes_2022_08_28",
    },
    "xss_validate": {
        "tools": "dalfox",
        "flag": "--custom-payload",
        # xss.txt is deliberately absent: it carries a GH0ST.xss.ht callback and
        # is quarantined as tier C. vulJs covers JS-framework payloads instead.
        "files": "xsspollygots, xsswafbypss, vulJs",
        "tier": "B — approval gated, reached via exploitation.XSS_PAYLOAD_LISTS",
    },
    # sqlmap has NO consumer for these lists and the earlier entry claiming
    # "--tamper / -v" was wrong three ways: --tamper is denied (it loads
    # executable Python), -v is verbosity, and sqlmap accepts no payload
    # wordlist at all. sqli2.txt is quarantined tier C besides. Recorded as
    # unconsumed rather than left implying a capability that does not exist.
    "_unconsumed_tier_b": {
        "tools": "none",
        "flag": "n/a",
        "files": "allsqli, blindsqli, ssti, ssrf, lfi, crlf, xml, jwt-secrets, "
                 "403_*, bambda, htaccess, xor, pl, sqldb, github-dork, "
                 "android_all_permissions",
        "tier": "B — fetched and vetted, but no tool in the server accepts a "
                "payload file for these. Either add a consumer deliberately or "
                "drop them from the fetch; leaving them reachable-looking is "
                "what produced this defect.",
    },
}


@dataclass
class FileVerdict:
    name: str
    tier: str
    lines: int
    sha256: str
    kind: str = "wordlist"          # "wordlist" | "injection"
    reasons: list[str] = field(default_factory=list)
    destructive: int = 0
    callbacks: list[str] = field(default_factory=list)
    slow: int = 0
    get_only: bool = False          # wordlist holds state-changing paths


def _kind_of(text: str, sample: int = 4000) -> str:
    """Injection payloads or plain paths?

    Decided by sampling rather than by filename, because the same word means
    different things in each: 'shutdown' as a path is a request, 'SHUTDOWN' in
    SQL is a command. Getting this wrong in either direction is costly — over-
    quarantining discards the best wordlists, under-quarantining fires RCE.
    """
    lines = [ln for ln in text.split("\n", sample)[:sample] if ln.strip()]
    if not lines:
        return "wordlist"
    hits = sum(1 for ln in lines if INJECTION_SYNTAX.search(ln))
    return "injection" if hits / len(lines) > 0.02 else "wordlist"


def classify(path: Path) -> FileVerdict:
    """Assign a tier. Dangerous content overrides the static tier list."""
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    digest = hashlib.sha256(raw).hexdigest()

    kind = _kind_of(text)
    verdict = FileVerdict(
        name=path.name,
        tier="A" if path.name in TIER_A else "B",
        lines=text.count("\n"),
        sha256=digest,
        kind=kind,
    )
    if path.name not in TIER_A and path.name not in TIER_B:
        verdict.reasons.append("unlisted — defaulted to B (gated)")

    callbacks = sorted({m.group(0) for m in CALLBACK.finditer(text)})
    verdict.callbacks = callbacks[:10]

    # A callback exfiltrates target data to infrastructure we do not control.
    # That is true regardless of file kind, so it is checked unconditionally.
    if callbacks:
        verdict.tier = "C"
        verdict.reasons.append(
            f"{len(callbacks)} third-party callback(s) ({', '.join(callbacks[:3])}) — "
            "target data would leave to infrastructure we do not control"
        )

    if kind == "injection":
        destructive = DESTRUCTIVE.findall(text)
        shells = REVERSE_SHELL.findall(text)
        verdict.destructive = len(destructive)
        verdict.slow = len(SLOW.findall(text))
        if destructive:
            verdict.tier = "C"
            verdict.reasons.append(
                f"{len(destructive)} destructive/RCE statement(s) — would damage a live target"
            )
        if shells:
            verdict.tier = "C"
            verdict.reasons.append(f"{len(shells)} reverse-shell payload(s)")
        if verdict.slow and verdict.tier != "C":
            verdict.reasons.append(
                f"{verdict.slow} time-delay payload(s) — heavy on the engagement clock"
            )
    else:
        # Path wordlist. State-changing endpoints are safe to *discover* with a
        # read method; the constraint belongs on the method, not on the file.
        state = STATE_CHANGING_PATH.findall(text)
        if state:
            verdict.get_only = True
            verdict.reasons.append(
                f"{len(state)} state-changing path(s) — GET/HEAD only, never POST/PUT/DELETE"
            )
    return verdict


def fetch() -> Path:
    """Clone the pinned commit into a scratch directory."""
    scratch = STORE / "_src"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.parent.mkdir(parents=True, exist_ok=True)

    print(f"cloning {SOURCE['repo']}")
    subprocess.run(  # noqa: S603
        ["git", "clone", "-q", SOURCE["repo"], str(scratch)], check=True
    )
    print(f"checking out pinned commit {SOURCE['commit'][:12]}")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(scratch), "checkout", "-q", SOURCE["commit"]], check=True
    )
    actual = subprocess.run(  # noqa: S603
        ["git", "-C", str(scratch), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if actual != SOURCE["commit"]:
        raise SystemExit(f"pin mismatch: expected {SOURCE['commit']}, got {actual}")
    print("pin verified\n")
    return scratch


def vet(source: Path, *, apply: bool) -> list[FileVerdict]:
    verdicts = [
        classify(p)
        for p in sorted(source.iterdir())
        if p.is_file() and not p.name.startswith(".") and p.suffix in {".txt", ""}
    ]

    if apply:
        for tier in ("A", "B"):
            (STORE / tier).mkdir(parents=True, exist_ok=True)
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        for v in verdicts:
            dest = QUARANTINE if v.tier == "C" else STORE / v.tier
            shutil.copy2(source / v.name, dest / v.name)

        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps({
            "source": SOURCE,
            "tiers": {
                "A": "discovery wordlists — normal scope + rate limits apply",
                "B": "injection payloads — aggressive mode, approval gate required",
                "C": "QUARANTINED — destructive or exfiltrating. Never auto-run.",
            },
            "tool_map": TOOL_MAP,
            "files": [
                {
                    "name": v.name, "tier": v.tier, "kind": v.kind,
                    "lines": v.lines, "sha256": v.sha256,
                    "get_only": v.get_only, "reasons": v.reasons,
                    "destructive": v.destructive, "callbacks": v.callbacks,
                    "slow_payloads": v.slow,
                }
                for v in verdicts
            ],
        }, indent=2) + "\n")
    return verdicts


def report(verdicts: list[FileVerdict]) -> int:
    counts = {"A": 0, "B": 0, "C": 0}
    total_lines = 0
    for v in verdicts:
        counts[v.tier] += 1
        total_lines += v.lines

    print(f"{'FILE':<42} {'TIER':<5} {'KIND':<10} {'LINES':>9}  NOTES")
    print("-" * 108)
    for v in sorted(verdicts, key=lambda x: (x.tier, -x.lines)):
        note = "GET-only; " if v.get_only else ""
        note += "; ".join(v.reasons)[:40] if v.reasons else ""
        print(f"{v.name:<42} {v.tier:<5} {v.kind:<10} {v.lines:>9,}  {note}")

    print("-" * 108)
    get_only = sum(1 for v in verdicts if v.get_only)
    print(f"\nTier A (safe discovery):     {counts['A']:>3} files")
    print(f"Tier B (approval gated):     {counts['B']:>3} files")
    print(f"Tier C (QUARANTINED):        {counts['C']:>3} files")
    print(f"  of which GET-only pinned:  {get_only:>3} files")
    print(f"Total lines:                 {total_lines:>9,}")

    quarantined = [v for v in verdicts if v.tier == "C"]
    if quarantined:
        print("\nQuarantined — these must never be fired automatically:")
        for v in quarantined:
            print(f"  {v.name}")
            for reason in v.reasons:
                print(f"      - {reason}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="clone at pinned SHA and vet")
    group.add_argument("--verify", action="store_true", help="re-check the existing store")
    group.add_argument("--report", action="store_true", help="classify without writing")
    args = parser.parse_args()

    if args.fetch:
        source = fetch()
        verdicts = vet(source, apply=True)
        shutil.rmtree(source, ignore_errors=True)
        print(f"store written to {STORE}\nmanifest: {MANIFEST}\n")
        return report(verdicts)

    if args.verify:
        if not MANIFEST.exists():
            print(f"no manifest at {MANIFEST} — run --fetch first", file=sys.stderr)
            return 1
        recorded = json.loads(MANIFEST.read_text())
        drift = 0
        for entry in recorded["files"]:
            tier_dir = QUARANTINE if entry["tier"] == "C" else STORE / entry["tier"]
            path = tier_dir / entry["name"]
            if not path.exists():
                print(f"MISSING  {entry['name']}")
                drift += 1
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                print(f"CHANGED  {entry['name']}")
                drift += 1
        print("store verified, no drift" if not drift else f"{drift} file(s) drifted")
        return 1 if drift else 0

    src = STORE / "_src"
    if not src.exists():
        print("nothing to report on — run --fetch first", file=sys.stderr)
        return 1
    return report(vet(src, apply=False))


if __name__ == "__main__":
    raise SystemExit(main())

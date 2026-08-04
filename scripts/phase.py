"""Run one engagement phase through the control plane and report what it did.

`hunt.sh` calls this once per phase. Everything goes through `@easyhunt_tool`, so
scope, sanitize, budget, rate-limit, approval and audit apply exactly as they do
from the MCP transport — this is a different front door, not a bypass.

Two things this does that a bare tool call does not:

**It emits a status line per phase**, appended to `status.jsonl` in the
workspace, so a human or a model can tail the run without touching it.

**It reports whether the phase actually accomplished anything.** A phase that ran
and produced nothing exits 2, not 0. That distinction is the whole reason this
file exists: chaining phases multiplies the cost of a stage that reports success
while testing nothing, and this project has found that defect seventeen times.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from easyhunt.config import Config  # noqa: E402
from easyhunt.control_plane.context import Engagement, set_engagement  # noqa: E402
from easyhunt.control_plane.scope import Scope  # noqa: E402

#: phase -> (tool, kwargs-builder, "what non-empty looks like")
#
# The third element is the gate. It answers "did this phase do its job", and it
# is deliberately per-phase: "live hosts > 0" means something different from
# "findings > 0", and a scan finding nothing is a fine outcome while a probe
# finding nothing is not.
# `url` marks phases whose tool needs an http(s) URL rather than a bare hostname.
# Passing a hostname to js_analyze got `ok: false, error: "no_urls"` in 0.0
# seconds — the tool was right, the caller was wrong.
# `inherits` marks a phase that takes its input from the asset store rather than
# from the target argument. That is the difference between ten tools that each
# work and a pipeline: subdomain_enum merges and deduplicates across four
# binaries, http_probe reads that list, endpoint_discovery reads the live URLs
# http_probe confirmed, and nuclei scans those rather than a hostname nobody
# checked was alive.
#: Cap on inherited targets handed to one phase. A run that found 85,000
#: subdomains must not put all of them on a single command line.
MAX_INHERITED = 500

#: Phases that run ONCE over everything found, not once per target.
#
# hunt.sh loops per target, which is right for probing a host and wrong for
# scanning: `scan` inherits the global asset store, so on a twelve-host run it
# was handed 3 targets, then 4, then 6 ... then 12, failing the sizing gate every
# single time as the set grew underneath it. Twelve refusals for one scan that
# should have been sized once against the real total.
GLOBAL_PHASES = frozenset({"scan", "takeover", "report", "plan"})

PHASES: dict[str, dict[str, Any]] = {
    "recon":     {"tool": "subdomain_enum",      "count": "subdomains"},
    "resolve":   {"tool": "dns_resolve",         "count": "resolved", "inherits": True, "wants": ("subdomain",)},
    "probe":     {"tool": "http_probe",          "count": "live",     "inherits": True, "wants": ("subdomain", "host")},
    "waf":       {"tool": "waf_detect",          "count": None,   "url": True},
    "tls":       {"tool": "tls_audit",           "count": "checks"},
    "cors":      {"tool": "cors_audit",          "count": None,   "url": True},
    "endpoints": {"tool": "endpoint_discovery",  "count": "urls",     "inherits": True, "wants": ("subdomain",)},
    "js":        {"tool": "js_analyze",          "count": None,       "inherits": True, "wants": ("url",), "tag": "live"},
    "takeover":  {"tool": "takeover_detect",     "count": None,       "inherits": True, "wants": ("subdomain",)},
    "scan":      {"tool": "nuclei_scan",         "count": None,       "inherits": True, "wants": ("url",), "tag": "live"},
    "report":    {"tool": "report_generate",     "count": None},
    "plan":      {"tool": "hunt_plan",           "count": "actionable"},
}


#: Phases that only make sense for a name. An IP literal is already resolved.
_DNS_PHASES = frozenset({"resolve", "recon", "takeover"})


def _is_ip_literal(value: str) -> bool:
    """True when every target is an address, however it was written.

    Must handle the URL form. `172.17.0.1` was detected and
    `http://172.17.0.1:3000/` was not, so the same target expressed the way a
    non-default port requires slipped past and the DNS phases ran against it.
    """
    import ipaddress
    from urllib.parse import urlsplit

    seen = False
    for item in value.replace("\n", ",").split(","):
        candidate = item.strip()
        if not candidate:
            continue
        seen = True
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        elif candidate.count(":") == 1:
            candidate = candidate.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return False
    return seen


def emit(workspace: Path, record: dict[str, Any]) -> None:
    record["at"] = time.strftime("%H:%M:%S")
    line = json.dumps(record, default=str)
    (workspace / "status.jsonl").open("a", encoding="utf-8").write(line + "\n")
    print(f"STATUS {line}", flush=True)


async def main() -> int:
    if len(sys.argv) < 3:
        print("usage: phase.py <phase> <target> [extra-json]", file=sys.stderr)
        return 64
    phase, target = sys.argv[1], sys.argv[2]
    extra = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}

    # A phase can be inapplicable rather than failing. dns_resolve given an IP
    # literal has nothing to resolve and returns empty — which, because resolve
    # is a REQUIRED phase, aborted every phase after it and left probe, waf,
    # tls, cors, endpoints and js unrun against a perfectly good target.
    #
    # "Not applicable to this target" is a third answer, distinct from "did its
    # job" and "produced nothing", and the run should continue on it.
    if phase in _DNS_PHASES and _is_ip_literal(target):
        print(
            f"STATUS {json.dumps({'phase': phase, 'state': 'skipped', 'reason': 'target is an IP literal; nothing to resolve'})}",
            flush=True,
        )
        return 0

    spec = PHASES.get(phase)
    if spec is None:
        print(f"unknown phase {phase!r}; known: {', '.join(PHASES)}", file=sys.stderr)
        return 64

    config = Config.load(ROOT / "config.yaml")
    scope = Scope.load(ROOT / "scope.yaml")
    marker = ROOT / ".easyhunt-run"
    workspace = Path(marker.read_text().strip()) if marker.exists() else None
    eng = Engagement(scope, config, workspace=workspace)
    marker.write_text(str(eng.workspace))
    set_engagement(eng)

    import easyhunt.mcp_server as mcp

    mcp.load_capabilities()
    from easyhunt.tools.base import REGISTRY

    entry = REGISTRY.get(spec["tool"])
    if entry is None:
        emit(eng.workspace, {"phase": phase, "state": "unavailable", "tool": spec["tool"]})
        return 3

    emit(eng.workspace, {"phase": phase, "state": "start", "tool": spec["tool"], "target": target})
    started = time.time()
    # An inheriting phase runs against what the previous phase found, not against
    # the argument. The values are passed explicitly rather than left for the
    # wrapper to fetch, so every inherited target still goes through the scope
    # check in the decorator — inheriting input must not mean inheriting trust.
    #
    # `wants` is the asset kind this phase consumes, in preference order. On the
    # first phase the store is empty and the argument seeds the run.
    passed = target
    origin = "argument"
    if spec.get("inherits"):
        for kind in spec.get("wants", ("url", "subdomain")):
            tag = spec.get("tag")
            available = eng.assets.values(kind, tag=tag)
            if available:
                passed = ",".join(available[:MAX_INHERITED])
                origin = f"assets:{kind}{'[' + tag + ']' if tag else ''}({len(available)})"
                break
    if origin == "argument" and spec.get("url") and "://" not in passed:
        passed = f"https://{passed}/"
    kwargs = {"target": passed, **extra} if entry.targets_arg else dict(extra)
    try:
        result = await entry.fn(**kwargs)
    except Exception as exc:  # noqa: BLE001
        emit(eng.workspace, {
            "phase": phase, "state": "error", "tool": spec["tool"],
            "error": f"{type(exc).__name__}: {exc}", "seconds": round(time.time() - started, 1),
        })
        return 3

    took = round(time.time() - started, 1)
    # The target belongs in the filename. Without it a twelve-target run wrote
    # phase-scan.json twelve times and kept only the last — eleven hosts' results
    # silently destroyed, and the summary then reported on one host while
    # appearing to describe the whole run.
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:80] or "target"
    (eng.workspace / f"phase-{phase}--{slug}.json").write_text(
        json.dumps(result, indent=2, default=str), encoding="utf-8"
    )

    # Did it actually do anything? `complete: False` is the wrappers' own way of
    # saying "I did not finish", and it must not be read as a clean result.
    key = spec["count"]
    produced = result.get(key) if key and isinstance(result, dict) else None
    if isinstance(produced, list):
        produced = len(produced)
    incomplete = isinstance(result, dict) and result.get("complete") is False
    findings = len(result.get("findings", [])) if isinstance(result, dict) else 0

    # A wrapper saying `ok: false` has told us it failed. Reading past that in
    # favour of a per-phase count is how js_analyze reported "no_urls" in 0.0
    # seconds and this script printed a green tick over it — the exact defect the
    # gate exists to catch, in the gate itself.
    declared_failure = isinstance(result, dict) and result.get("ok") is False
    state = "ok"
    if declared_failure:
        state = "failed"
    elif incomplete:
        state = "incomplete"
    elif key is not None and not produced:
        state = "empty"

    emit(eng.workspace, {
        "phase": phase, "state": state, "tool": spec["tool"], "seconds": took,
        "produced": produced, "findings": findings,
        # Where the input came from. "which hosts did this actually cover" is the
        # first question anyone asks of a report, and a pipeline that silently
        # scanned the wrong set is worse than one that scanned nothing.
        "input": origin,
        "assets": eng.assets.counts(),
        "message": (result.get("message") or result.get("note") or "")[:180]
        if isinstance(result, dict) else "",
        "workspace": str(eng.workspace),
    })
    # 0 = did its job, 2 = ran but produced nothing, 3 = said it failed.
    if state == "ok":
        return 0
    return 3 if state == "failed" else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

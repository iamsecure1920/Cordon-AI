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
#: Default cap on inherited targets handed to one phase. A run that found
#: 85,000 subdomains must not put all of them on a single command line — but a
#: flat cap samples the *alphabetically first* names, which on a real estate
#: can be one namespace with zero web servers (ATT's first 500 were all
#: ``3pc.example-cdn.net`` telemetry hosts; the required probe then reported "nothing
#: alive" for a 60k-subdomain target). Phases whose tools read a ``-l`` list
#: file (dnsx, httpx, nuclei, subjack) override this with a large cap, and
#: :func:`_inherited_sample` spreads the selection across the whole store
#: instead of taking a prefix.
MAX_INHERITED = 500


def _inherited_sample(available: list[str], cap: int) -> list[str]:
    """Take up to ``cap`` targets, spread across the store, never a prefix.

    ``available`` comes out of the asset store deduplicated but otherwise in
    discovery order, which clusters by source and namespace. Slicing the first
    ``cap`` items therefore concentrates the selection in one zone of the
    estate — ATT's alphabetically-first 500 subdomains were all the ``3pc``
    telemetry namespace, and the run aborted as if nothing were alive. When the
    store is larger than the cap, sample evenly: every Nth item keeps whatever
    the cap misses spread across the estate instead of silently dropping
    entire namespaces.
    """
    if len(available) <= cap:
        return available
    step = len(available) / cap
    return [available[int(i * step)] for i in range(cap)]

#: Phases that run ONCE over everything found, not once per target.
#
# hunt.sh loops per target, which is right for probing a host and wrong for
# scanning: `scan` inherits the global asset store, so on a twelve-host run it
# was handed 3 targets, then 4, then 6 ... then 12, failing the sizing gate every
# single time as the set grew underneath it. Twelve refusals for one scan that
# should have been sized once against the real total.
GLOBAL_PHASES = frozenset({
    "takeover", "scan", "ports", "services", "params", "content",
    "nikto", "wapiti", "forbidden", "exploit", "plan", "report",
})

PHASES: dict[str, dict[str, Any]] = {
    "recon":     {"tool": "subdomain_enum",      "count": "subdomains"},
    # Alterx permutation: generates new subdomain candidates from the observed
    # names and resolves them. Runs after recon, before resolve, so the whole
    # estate (real + permuted) is probed once.
    "permute":   {"tool": "dns_permute",          "count": "new_hosts", "inherits": True, "wants": ("subdomain",), "max": 200000},
    # The DNS and HTTP probes write their targets to a `-l` list file, so the
    # inherited set is not bounded by argv length. On a 60k-subdomain estate the
    # old flat cap of 500 sampled the *alphabetically first* 500 names — all one
    # namespace, in practice the telemetry zone with zero web servers — and the
    # required probe then reported "nothing alive" for a target that had 60k
    # names. These phases must see the whole estate; the rate limiter, not a
    # sample, is what protects the target.
    "resolve":   {"tool": "dns_resolve",         "count": "resolved", "inherits": True, "wants": ("subdomain",), "max": 200000},
    # Prefer resolved hosts over raw subdomains: resolve already filtered the
    # names that answer DNS, so probing them first is the cheap-to-expensive
    # ordering the chain is supposed to be. Subdomains are the fallback for a
    # run that starts at probe.
    "probe":     {"tool": "http_probe",          "count": "live",     "inherits": True, "wants": ("host", "subdomain"), "max": 200000},
    # CDN/WAF posture: which hosts sit behind a CDN, which are direct origins.
    # Cheap and passive; answers "is this the origin or the edge" for every
    # later phase.
    "cdn":       {"tool": "cdn_check",            "count": None,       "inherits": True, "wants": ("host",), "max": 200000},
    "waf":       {"tool": "waf_detect",          "count": None,   "url": True},
    "tls":       {"tool": "tls_audit",           "count": "checks"},
    "cors":      {"tool": "cors_audit",          "count": None,   "url": True},
    "endpoints": {"tool": "endpoint_discovery",  "count": "urls",     "inherits": True, "wants": ("subdomain",), "max": 200000},
    "js":        {"tool": "js_analyze",          "count": None,       "inherits": True, "wants": ("url",), "tag": "live"},
    # After js, before the global phases: it needs live URLs, and what it finds
    # (a signup form, a route table) is what the operator acts on next.
    "auth":      {"tool": "auth_surface",        "count": "hosts_examined", "inherits": True, "wants": ("url",), "tag": "live"},
    # Secrets in the downloaded JS bundles: kingfisher/noseyparker/gitleaks.
    # Scan the workspace raw/ dir (where js_analyze dropped the bundles), not
    # the workspace root — the workspace lives inside the project's git repo,
    # and gitleaks pointed at a directory inside a repo walks the ENTIRE repo
    # history, reporting the project's own test fixtures as leaked secrets.
    # git_history=false keeps it to the files actually on disk.
    "secrets":   {"tool": "secret_scan",          "count": None,       "extra": {"path": "raw", "git_history": False}},
    # White-box pre-recon audit of source fetched into the workspace: semgrep
    # parsing rules + gitleaks merged into code-audit.json/.md. Global (runs
    # once over the workspace, not per target). With no source present it
    # degrades to a graceful empty result — source_fetch must run first.
    "code_audit": {"tool": "code_audit",            "count": "count",    "extra": {"path": "source"}},
    # gf pattern pass: classifies URLs by sink shape (ssrf, sqli, xss, lfi,
    # redirect, idor, debug...) using the vetted rules/gf/ pattern pack.
    "pattern":   {"tool": "pattern_scan",         "count": "count",    "inherits": True, "wants": ("url",), "tag": "live"},
    # GraphQL endpoint audit and WebSocket origin probe: API-surface checks.
    # They take ONE URL, so aim them at the program's focus assets (where the
    # APIs actually live), not at whatever sorted first in the estate.
    "graphql":   {"tool": "graphql_audit",        "count": None,       "focus": True},
    "websocket": {"tool": "websocket_probe",      "count": None,       "focus": True},
    "takeover":  {"tool": "takeover_detect",     "count": None,       "inherits": True, "wants": ("subdomain",), "max": 200000},
    "scan":      {"tool": "nuclei_scan",         "count": None,       "inherits": True, "wants": ("url",), "tag": "live"},
    # Port and service discovery over the live hosts, then the two general
    # web scanners (nikto lead list, wapiti profile scan) and parameter
    # discovery (arjun/paramspider) to feed the exploit chain's injection
    # points. These are global: they consume the whole estate at once.
    # Port scan the hosts that actually answered HTTP (the live URLs' hosts),
    # not all 60k resolved names — naabu over the whole estate at the rate
    # ceiling takes days and mostly scans dead telemetry boxes.
    "ports":     {"tool": "port_scan",            "count": "count",    "inherits": True, "wants": ("url",), "tag": "live", "want_hosts_of": True},
    # service_scan takes ONE host; the focus URLs' hosts are the reward surface.
    "services":  {"tool": "service_scan",         "count": "count",    "focus": True},
    "params":    {"tool": "param_discovery",      "count": "count",    "focus": True},
    "content":   {"tool": "content_discovery",    "count": "count",    "focus": True, "extra": {"wordlist": "juicy-paths"}},
    "nikto":     {"tool": "nikto_scan",           "count": "items",    "focus": True},
    "wapiti":    {"tool": "wapiti_scan",          "count": "candidates", "focus": True},
    # Auto-chain 403-bypass: HEAD-pre-check the live estate for 403s, then fire
    # unKover's 12 access-bypass techniques at each. A 403 is an access
    # decision; leaving it unexplained is leaving the one route an attacker
    # finds by accident. Aggressive — needs forbidden_chain + forbidden_bypass
    # in auto_approve.
    "forbidden": {"tool": "forbidden_chain",      "count": "checked",  "inherits": True, "wants": ("url",), "tag": "live"},
    # Chain the exploit validators over the injection points the earlier phases
    # discovered. Only wired into hunt.sh when --exploit is passed, and only runs
    # then because every sub-validator is itself approval-gated.
    "exploit":   {"tool": "exploit_chain",        "count": "tested",    "inherits": True, "wants": ("url",)},
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


def _workspace_scope_matches(workspace: Path, scope_name: str) -> bool:
    """True when this workspace was created for the named engagement scope.

    The first record in a workspace's audit log is always ``engagement_start``
    and carries the scope name. Anything else — a missing log, an unreadable
    record, a name mismatch — means "not this scope", and the caller starts a
    fresh workspace instead of inheriting a foreign engagement's state.
    """
    audit = workspace / "audit.jsonl"
    if not audit.exists():
        return False
    try:
        first = audit.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        record = json.loads(first)
    except (OSError, IndexError, json.JSONDecodeError):
        return False
    return record.get("event") == "engagement_start" and record.get("engagement") == scope_name


def emit(workspace: Path, record: dict[str, Any]) -> None:
    record["at"] = time.strftime("%H:%M:%S")
    line = json.dumps(record, default=str)
    (workspace / "status.jsonl").open("a", encoding="utf-8").write(line + "\n")
    print(f"STATUS {line}", flush=True)


async def _collect_job_result(entry: Any, eng: Engagement, result: dict[str, Any]) -> dict[str, Any]:
    """Wait out a background job a tool returned, instead of cancelling it.

    Long tools (nuclei_scan, bbot, …) launch a job and return a ``job_id`` when
    it has not finished within the tool's own ``wait_seconds``. That job lives in
    *this* process's event loop, so returning from ``main`` cancels it — a scan
    longer than wait_seconds never completed in the CLI pipeline, and the phase
    reported "still running" with nothing left to poll. Keeping the loop alive
    and awaiting the job here is what lets the unattended pipeline finish.

    Bounded by the tool's own timeout, after which the result is marked partial
    rather than silently read as clean.
    """
    if not (isinstance(result, dict) and result.get("job_id") and result.get("completed") is False):
        return result
    job_id = result["job_id"]
    deadline = time.monotonic() + (entry.timeout or 3600)
    while time.monotonic() < deadline:
        payload = await eng.jobs.wait(job_id, timeout=30)
        if payload.get("ready"):
            if payload.get("ok") and isinstance(payload.get("result"), dict):
                return {**result, **payload["result"], "job_id": job_id, "completed": True}
            return {**result, "completed": False, "job_error": payload.get("error")}
        # Still running — the loop's continued existence is what keeps the job's
        # task scheduled, so just keep polling.
    return {
        **result,
        "note": (
            f"job {job_id} did not finish within the phase timeout "
            f"({entry.timeout:.0f}s); result is partial, not clean"
        ),
    }


async def main() -> int:
    if len(sys.argv) < 3:
        print("usage: phase.py <phase> <target> [extra-json]", file=sys.stderr)
        return 64
    phase, target = sys.argv[1], sys.argv[2]
    extra = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else {}

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
    workspace = None
    if marker.exists():
        # The marker is only an inheritance hint for RESUMING the same
        # engagement. When the active scope has changed since the last phase
        # ran (a fresh target, a different program), reusing the old workspace
        # binds every phase to the previous engagement's budget, assets, and
        # findings — one run inherited the previous engagement's exhausted wall-clock and 96
        # out-of-scope subdomains and failed every phase in 0.0s. Trust the
        # marker only when the workspace actually belongs to this scope.
        candidate = Path(marker.read_text().strip())
        if _workspace_scope_matches(candidate, scope.name):
            workspace = candidate
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
    if spec.get("focus"):
        # Single-target tools (param_discovery, content_discovery, nikto, wapiti,
        # service_scan) take ONE URL or host. Feeding them the whole inherited
        # estate makes them scan whatever happened to sort first — usually a
        # CDN edge or a telemetry host, not the reward surface. Aim them at the
        # program's own focus URLs (High/Critical assets) instead; those are
        # exactly what a human would test first, and they are always in scope
        # by construction.
        # _RuleSet.urls holds (host, path) pairs; rebuild the URL the tools
        # want, defaulting to https and a root path.
        focus = []
        for host, path in (getattr(eng.scope, "_allow", None).urls or []):
            if not host:
                continue
            scheme = "https://" if "://" not in host else ""
            focus.append(f"{scheme}{host}{path or '/'}")
        if focus:
            passed = ",".join(focus)
            origin = f"scope:focus_urls({len(focus)})"
    elif spec.get("inherits"):
        for kind in spec.get("wants", ("url", "subdomain")):
            tag = spec.get("tag")
            available = eng.assets.values(kind, tag=tag)
            if available:
                cap = spec.get("max", MAX_INHERITED)
                sample = _inherited_sample(available, cap)
                if spec.get("want_hosts_of"):
                    # The asset store binds each URL to the host that served it;
                    # pass the distinct hosts, not the URLs (port_scan wants
                    # hostnames).
                    hosts = {}
                    for a in eng.assets.all():
                        if a.value in set(sample) and a.host:
                            hosts[a.host] = True
                    sample = sorted(hosts)
                passed = ",".join(sample)
                origin = f"assets:{kind}{'[' + tag + ']' if tag else ''}({len(available)})"
                break
    if origin == "argument" and spec.get("url") and "://" not in passed:
        passed = f"https://{passed}/"
    # A phase may declare its own default arguments (content discovery needs a
    # wordlist name; secrets needs a path). The caller's extra JSON wins over
    # the default. A tool with targets_arg=None (secret_scan takes a path, not
    # a target) still gets the phase's declared defaults — without this the
    # phase's path was dropped and the tool scanned the workspace root, which
    # contains noseyparker's datastore of secret patterns (100 self-hits).
    declared = spec.get("extra") or {}
    if entry.targets_arg:
        kwargs = {"target": passed, **declared, **extra}
    else:
        kwargs = {**declared, **extra}
    try:
        result = await entry.fn(**kwargs)
    except Exception as exc:  # noqa: BLE001
        emit(eng.workspace, {
            "phase": phase, "state": "error", "tool": spec["tool"],
            "error": f"{type(exc).__name__}: {exc}", "seconds": round(time.time() - started, 1),
        })
        return 3

    result = await _collect_job_result(entry, eng, result)

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

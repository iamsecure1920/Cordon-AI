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
PHASES: dict[str, dict[str, Any]] = {
    "resolve":   {"tool": "dns_resolve",         "count": "resolved"},
    "probe":     {"tool": "http_probe",          "count": "live"},
    "waf":       {"tool": "waf_detect",          "count": None,   "url": True},
    "tls":       {"tool": "tls_audit",           "count": "checks"},
    "cors":      {"tool": "cors_audit",          "count": None,   "url": True},
    "endpoints": {"tool": "endpoint_discovery",  "count": "urls"},
    "js":        {"tool": "js_analyze",          "count": None,   "url": True},
    "takeover":  {"tool": "takeover_detect",     "count": None},
    "scan":      {"tool": "nuclei_scan",         "count": None,   "url": True},
    "report":    {"tool": "report_generate",     "count": None},
}


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
    passed = target
    if spec.get("url") and "://" not in target:
        passed = f"https://{target}/"
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
    (eng.workspace / f"phase-{phase}.json").write_text(
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

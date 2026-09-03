"""Agent-first engagement workflow: create, resume, and run phases in-process.

The shell pipeline (``scripts/hunt.sh``) spawns one process per phase. That
design loses what agents need:

* **Resumability.** An agent session that dies mid-run cannot re-attach to a
  half-finished job — the job's asyncio task lived (and died) in the phase
  process. ``run_pipeline``/``run_phase`` keep the jobs in the *server's* event
  loop, so ``engagement_attach`` (or re-opening the same workspace) polls the
  same jobs an agent left behind.
* **Deterministic phase state.** hunt.sh's phase loop re-reads bash variables
  and re-executes the Python phase machinery from scratch each time;
  ``run_pipeline`` holds one state machine with explicit ``pending / running /
  ok / empty / failed / skipped`` transitions that an agent can read between
  calls.
* **One gate.** The per-phase prove-it-did-something rule, the per-target vs
  global split, and the focus/inherit wiring live here as data (``PHASES``) —
  the same table ``scripts/phase.py`` uses, so the CLI pipeline and the MCP
  pipeline cannot drift.

Security posture is identical to the rest of the toolchain: every phase runs
through its registered ``@cordon_tool`` wrapper, so scope, sanitize, budget,
rate limit, approval and audit apply exactly as they do to a direct call.
``run_pipeline`` is aggressive (it issues aggressive phase tools) and itself
approval-gated; each phase tool is then gated again by its own mode.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cordon.control_plane.context import (
    Engagement,
    current_engagement,
    get_engagement,
    set_engagement,
)
from cordon.errors import CordonError, OutOfScopeError
from cordon.tools.base import cordon_tool

__all__ = ["PHASES", "PipelineRunner", "engagement_attach", "engagement_new", "run_phase", "run_pipeline"]

#: Phase table — the single source of truth shared with scripts/phase.py.
#: ``inherits`` takes input from the asset store; ``focus`` aims at the
#: program's focus URLs; ``count`` is the "did it do something" gate key.
PHASES: dict[str, dict[str, Any]] = {
    "recon": {"tool": "subdomain_enum", "count": "subdomains", "per_target": True},
    "permute": {"tool": "dns_permute", "count": "new_hosts", "inherits": True, "wants": ("subdomain",), "per_target": True},
    "resolve": {"tool": "dns_resolve", "count": "resolved", "inherits": True, "wants": ("subdomain",), "per_target": True},
    "probe": {"tool": "http_probe", "count": "live", "inherits": True, "wants": ("host", "subdomain"), "per_target": True, "required": True},
    "cdn": {"tool": "cdn_check", "inherits": True, "wants": ("host",), "per_target": True},
    "waf": {"tool": "waf_detect", "per_target": True, "url": True},
    "tls": {"tool": "tls_audit", "count": "checks", "per_target": True},
    "cors": {"tool": "cors_audit", "per_target": True, "url": True},
    "endpoints": {"tool": "endpoint_discovery", "count": "urls", "inherits": True, "wants": ("subdomain",), "per_target": True},
    "js": {"tool": "js_analyze", "inherits": True, "wants": ("url",), "tag": "live", "per_target": True},
    "auth": {"tool": "auth_surface", "count": "hosts_examined", "inherits": True, "wants": ("url",), "tag": "live", "per_target": True},
    "secrets": {"tool": "secret_scan", "extra": {"path": "raw", "git_history": False}, "global": True},
    "code_audit": {"tool": "code_audit", "count": "count", "extra": {"path": "source"}, "global": True},
    "pattern": {"tool": "pattern_scan", "count": "count", "inherits": True, "wants": ("url",), "tag": "live", "global": True},
    "graphql": {"tool": "graphql_audit", "focus": True, "global": True},
    "websocket": {"tool": "websocket_probe", "focus": True, "global": True},
    "takeover": {"tool": "takeover_detect", "inherits": True, "wants": ("subdomain",), "global": True},
    "scan": {"tool": "nuclei_scan", "inherits": True, "wants": ("url",), "tag": "live", "global": True},
    "ports": {"tool": "port_scan", "count": "count", "inherits": True, "wants": ("url",), "tag": "live", "want_hosts_of": True, "global": True},
    "services": {"tool": "service_scan", "count": "count", "inherits": True, "wants": ("open_port",), "want_hosts_of": True, "global": True},
    "params": {"tool": "param_discovery", "count": "count", "focus": True, "global": True},
    "content": {"tool": "content_discovery", "count": "count", "focus": True, "extra": {"wordlist": "juicy-paths"}, "global": True},
    "nikto": {"tool": "nikto_scan", "count": "items", "focus": True, "global": True},
    "wapiti": {"tool": "wapiti_scan", "count": "candidates", "focus": True, "global": True},
    "forbidden": {"tool": "forbidden_chain", "count": "checked", "inherits": True, "wants": ("url",), "tag": "live", "global": True},
    "exploit": {"tool": "exploit_chain", "count": "tested", "inherits": True, "wants": ("url",), "global": True},
    "plan": {"tool": "hunt_plan", "count": "actionable", "global": True},
    "report": {"tool": "report_generate", "global": True},
}

_ORDER = (
    "recon", "permute", "resolve", "probe", "cdn", "waf", "tls", "cors",
    "endpoints", "js", "auth",
    "secrets", "code_audit", "pattern", "graphql", "websocket", "takeover",
    "scan", "ports", "services", "params", "content", "nikto", "wapiti",
    "forbidden", "exploit", "plan", "report",
)


@dataclass
class PhaseState:
    phase: str
    state: str = "pending"  # pending | running | ok | empty | failed | skipped
    target: str = ""
    tool: str = ""
    seconds: float = 0.0
    produced: int | None = None
    findings: int = 0
    message: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "state": self.state,
            "target": self.target,
            "tool": self.tool,
            "seconds": round(self.seconds, 1),
            "produced": self.produced,
            "findings": self.findings,
            "message": self.message[:300],
            "error": self.error[:300],
        }


def _state_path(workspace: Path) -> Path:
    return workspace / "pipeline-state.json"


def _is_ip_literal(value: str) -> bool:
    import ipaddress
    from urllib.parse import urlsplit

    for item in value.replace("\n", ",").split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        elif candidate.count(":") == 1:
            candidate = candidate.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return False
    return True


def _inherited_sample(available: list[str], cap: int) -> list[str]:
    if len(available) <= cap:
        return available
    step = len(available) / cap
    return [available[int(i * step)] for i in range(cap)]


class PipelineRunner:
    """Resumable in-process phase runner. One instance per engagement."""

    def __init__(self, engagement: Engagement, *, workspace: Path | None = None) -> None:
        self.engagement = engagement
        self.workspace = Path(workspace) if workspace else engagement.workspace
        self.states: dict[str, PhaseState] = {}
        self._load()

    def _load(self) -> None:
        path = _state_path(self.workspace)
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for record in raw.get("phases", []):
            key = f"{record.get('phase')}:{record.get('target', '')}"
            self.states[key] = PhaseState(**{k: v for k, v in record.items() if k in PhaseState.__dataclass_fields__})

    def save(self) -> None:
        _state_path(self.workspace).write_text(
            json.dumps(
                {
                    "workspace": str(self.workspace),
                    "saved_at": time.time(),
                    "phases": [s.to_dict() for s in self.states.values()],
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

    def snapshot(self) -> dict[str, Any]:
        by_state: dict[str, int] = {}
        for s in self.states.values():
            by_state[s.state] = by_state.get(s.state, 0) + 1
        return {
            "workspace": str(self.workspace),
            "phases": [s.to_dict() for s in self.states.values()],
            "by_state": by_state,
            "next": self._next_phase(),
        }

    def _next_phase(self) -> str | None:
        for phase in _ORDER:
            for s in self.states.values():
                if s.phase == phase and s.state in {"pending", "running"}:
                    return phase
        return None

    def _target_for(self, spec: dict[str, Any], target: str) -> tuple[str, str]:
        """Resolve a phase's input: argument, focus URLs, or inherited assets."""
        eng = self.engagement
        if spec.get("focus"):
            focus: list[str] = []
            for host, path in getattr(eng.scope, "_allow", None).urls or []:
                if not host:
                    continue
                scheme = "https://" if "://" not in host else ""
                focus.append(f"{scheme}{host}{path or '/'}")
            if focus:
                return ",".join(focus), f"scope:focus_urls({len(focus)})"
        if spec.get("inherits"):
            for kind in spec.get("wants", ("url", "subdomain")):
                available = eng.assets.values(kind, tag=spec.get("tag"))
                if available:
                    sample = _inherited_sample(available, spec.get("max", 200_000))
                    if spec.get("want_hosts_of"):
                        hosts: dict[str, bool] = {}
                        for a in eng.assets.all():
                            if a.value in set(sample) and a.host:
                                hosts[a.host] = True
                        sample = sorted(hosts)
                    return ",".join(sample), f"assets:{kind}({len(available)})"
        return target, "argument"

    async def run_one_phase(
        self,
        phase: str,
        target: str,
        *,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from cordon.tools.base import REGISTRY

        spec = PHASES.get(phase)
        if spec is None:
            raise CordonError(f"unknown phase {phase!r}; known: {', '.join(_ORDER)}")

        key = f"{phase}:{target}"
        state = self.states.get(key) or PhaseState(phase=phase, target=target)
        state.tool = spec["tool"]
        if state.state in {"ok", "running"}:
            return {"skipped": True, "reason": f"phase already {state.state}", **state.to_dict()}

        # A phase can be inapplicable rather than failing (dns phases on an IP).
        if phase in {"recon", "resolve", "takeover"} and _is_ip_literal(target):
            state.state = "skipped"
            state.message = "target is an IP literal; nothing to resolve"
            self.states[key] = state
            self.save()
            return {"skipped": True, **state.to_dict()}

        passed, origin = self._target_for(spec, target)
        if spec.get("url") and "://" not in passed:
            passed = f"https://{passed}/"

        entry = REGISTRY.get(spec["tool"])
        if entry is None:
            state.state = "failed"
            state.error = f"tool {spec['tool']} not registered"
            self.states[key] = state
            self.save()
            return {"ok": False, **state.to_dict()}

        state.state = "running"
        self.states[key] = state
        self.save()

        if current_engagement() is None:
            set_engagement(self.engagement)

        declared = dict(spec.get("extra") or {})
        kwargs: dict[str, Any] = dict(declared)
        if extra:
            kwargs.update(extra)
        if entry.targets_arg:
            kwargs[entry.targets_arg] = passed

        started = time.monotonic()
        try:
            result = await entry.fn(**kwargs)
        except OutOfScopeError:
            raise
        except Exception as exc:  # noqa: BLE001 — the runner records, never swallows
            state.state = "failed"
            state.error = f"{type(exc).__name__}: {exc}"
            state.seconds = time.monotonic() - started
            self.states[key] = state
            self.save()
            self.engagement.audit.record(
                "pipeline_phase",
                phase=phase, target=target, state="failed",
                error=state.error, seconds=round(state.seconds, 1),
            )
            return {"ok": False, **state.to_dict()}

        # A tool may hand back a background job; keep the loop alive so it can
        # finish (the server's event loop outlives the call — that is the
        # resumability hunt.sh's process-per-phase model cannot provide).
        if isinstance(result, dict) and result.get("job_id") and result.get("completed") is False:
            result = await self._collect_job(entry, result)

        state.seconds = time.monotonic() - started
        count_key = spec.get("count")
        produced = result.get(count_key) if count_key and isinstance(result, dict) else None
        if isinstance(produced, list):
            produced = len(produced)
        state.produced = produced
        state.findings = len(result.get("findings", [])) if isinstance(result, dict) else 0
        state.message = (result.get("message") or result.get("note") or "")[:300] if isinstance(result, dict) else ""

        result_status = result.get("status") if isinstance(result, dict) else None
        not_finished = result_status in {"PARTIAL", "INCOMPLETE", "UNTESTED"} or (
            isinstance(result, dict) and result.get("complete") is False
        )
        declared_failure = (
            isinstance(result, dict) and result.get("ok") is False and result_status in (None, "COMPLETE")
        )
        if declared_failure:
            state.state = "failed"
            state.error = state.message
        elif not_finished:
            state.state = "failed" if not isinstance(result, dict) else ("empty" if count_key and not produced else "ok")
        elif count_key is not None and not produced:
            state.state = "empty"
        else:
            state.state = "ok"

        # The audit trail for "which hosts did this actually cover".
        self.engagement.audit.record(
            "pipeline_phase",
            phase=phase,
            target=target,
            state=state.state,
            tool=spec["tool"],
            produced=produced,
            findings=state.findings,
            seconds=round(state.seconds, 1),
            input=origin,
        )

        self.states[key] = state
        self.save()
        return {"ok": state.state in {"ok", "skipped"}, **state.to_dict()}

    async def _collect_job(self, entry: Any, result: dict[str, Any]) -> dict[str, Any]:
        job_id = result["job_id"]
        deadline = time.monotonic() + (getattr(entry, "timeout", None) or 3600)
        while time.monotonic() < deadline:
            payload = await self.engagement.jobs.wait(job_id, timeout=30)
            if payload.get("ready"):
                if payload.get("ok") and isinstance(payload.get("result"), dict):
                    return {**result, **payload["result"], "job_id": job_id, "completed": True}
                return {**result, "completed": False, "job_error": payload.get("error")}
        return {
            **result,
            "note": (
                f"job {job_id} did not finish within the phase timeout; "
                "result is partial, not clean"
            ),
        }


@cordon_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="engagement_new",
    tags={"control", "workflow"},
    estimated_requests=0,
)
async def engagement_new(
    scope_path: str,
    config_path: str | None = None,
    workspace: str | None = None,
) -> dict[str, Any]:
    """Create (or re-open) an engagement and make it the active one.

    This is ``cordon_load_scope`` plus the resumability an agent needs: passing
    an existing workspace directory re-opens it — budget, assets, findings,
    sessions, task graph and the phase runner state are all inherited — so a
    session that dropped mid-run resumes instead of starting over.

    Returns the workspace path; every later tool call acts on this engagement
    until another ``engagement_new``/``engagement_attach`` switches it.
    """
    engagement = Engagement.create(
        scope_path=scope_path, config_path=config_path, workspace=workspace
    )
    set_engagement(engagement)
    summary = engagement.summary()
    runner = PipelineRunner(engagement)
    return {
        "ok": True,
        "engagement": summary["engagement"],
        "workspace": summary["workspace"],
        "scope": summary["scope"],
        "seeds": engagement.scope.seeds(),
        "warnings": engagement.warnings,
        "pipeline": runner.snapshot(),
        "next_step": (
            "The engagement is active. Run phases with run_pipeline (all phases, "
            "gated) or run_phase (one phase), and watch progress with "
            "pipeline_status."
        ),
    }


@cordon_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="engagement_attach",
    tags={"control", "workflow"},
    estimated_requests=0,
)
async def engagement_attach(workspace: str, scope_path: str) -> dict[str, Any]:
    """Re-attach to an existing engagement workspace by path.

    Loads the workspace's scope, budget ledger, assets, findings, sessions and
    pipeline state so a new session continues exactly where the previous one
    left off — background jobs included, because they live in the server's
    event loop rather than in a dead shell process.
    """
    from cordon.config import Config, find_scope

    ws = Path(workspace).expanduser()
    if not ws.is_dir():
        return {"ok": False, "error": "no_workspace", "message": f"{ws} is not a directory"}

    scope = find_scope(scope_path)
    if scope is None:
        return {"ok": False, "error": "no_scope", "message": f"no scope file at {scope_path}"}
    from cordon.control_plane.scope import Scope

    engagement = Engagement(Scope.load(scope), Config.load(), workspace=ws)
    set_engagement(engagement)
    runner = PipelineRunner(engagement)
    return {
        "ok": True,
        "engagement": engagement.scope.name,
        "workspace": str(ws),
        "findings": engagement.findings.stats(),
        "assets": engagement.assets.counts(),
        "pipeline": runner.snapshot(),
        "next_step": "Resume with run_pipeline (skips finished phases) or run_phase.",
    }


@cordon_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=60,
    name="pipeline_status",
    tags={"control", "workflow"},
    estimated_requests=0,
)
async def pipeline_status() -> dict[str, Any]:
    """Where the pipeline is right now: per-phase state, next pending phase.

    Machine-readable version of the status.jsonl trail — branch on
    ``state``/``next`` instead of tailing files.
    """
    engagement = get_engagement()
    return {"ok": True, **PipelineRunner(engagement).snapshot()}


@cordon_tool(
    phase="method",
    mode="aggressive",
    targets_arg=None,
    timeout=900,
    name="run_phase",
    tags={"control", "workflow"},
    estimated_requests=250,
    risk_notes=[
        "Runs one engagement phase through its registered MCP tool.",
        "The phase tool's own mode decides whether a human is consulted — a "
        "passive phase (recon, probe) runs unattended; an aggressive or "
        "exploit phase stops for approval exactly as a direct call would.",
    ],
    rationale=(
        "Execute one phase of the engagement in-process, resumably, with the "
        "same scope/sanitize/budget/rate/approval/audit chain as any MCP call."
    ),
)
async def run_phase(
    phase: str,
    target: str | None = None,
    extra_json: str | None = None,
) -> dict[str, Any]:
    """Run a single phase against a target and record its state.

    ``phase`` is one of the pipeline phases (probe, scan, exploit, …).
    ``target`` defaults to the engagement's first seed. ``extra_json`` is an
    optional JSON object of extra kwargs for the phase's tool (e.g.
    ``{"include_heavy": true}`` for the exploit phase).

    The phase result is persisted to ``pipeline-state.json`` and the audit log,
    so ``run_pipeline``/``pipeline_status`` and later sessions see it.
    """
    engagement = get_engagement()
    runner = PipelineRunner(engagement)
    resolved_target = target or (engagement.scope.seeds() or [""])[0]
    extra: dict[str, Any] = {}
    if extra_json:
        try:
            extra = json.loads(extra_json)
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": "bad_extra", "message": f"extra_json is not JSON: {exc}"}
    result = await runner.run_one_phase(phase, resolved_target, extra=extra)
    result["ok"] = result.get("ok", False)
    return result


@cordon_tool(
    phase="method",
    mode="aggressive",
    targets_arg=None,
    timeout=7200,
    name="run_pipeline",
    tags={"control", "workflow"},
    estimated_requests=100,
    risk_notes=[
        "Runs the engagement phase chain in order, in-process.",
        "Every phase tool is individually approval-gated by its own mode: "
        "approving run_pipeline does not approve nuclei_scan, exploit_chain, "
        "or any other aggressive/exploit tool the chain drives.",
        "The required-phase gate applies: if `probe` finds nothing alive, "
        "later per-target phases are skipped rather than scanning hosts "
        "nobody confirmed exist.",
    ],
    rationale=(
        "The unattended engagement chain, resumable and observable: phases run "
        "in order through their MCP tools, each must prove it did something, "
        "and state persists so a later call (or session) continues instead of "
        "restarting."
    ),
)
async def run_pipeline(
    target: str | None = None,
    phases: str | None = None,
    from_phase: str | None = None,
    exploit: bool = False,
) -> dict[str, Any]:
    """Run the engagement pipeline, gated, resumable, in-process.

    ``phases`` restricts to a comma list ("probe,scan"); ``from_phase`` starts
    at a named phase; ``exploit`` adds the exploit phase (still refused unless
    the scope authorizes exploitation).

    Each phase runs through its registered MCP tool — the full control-plane
    chain applies per phase — and results land in ``pipeline-state.json`` +
    the audit log. Finished phases are skipped on re-entry, so a dropped
    session resumes where it stopped.
    """
    engagement = get_engagement()
    runner = PipelineRunner(engagement)
    seeds = engagement.scope.seeds()
    if not seeds:
        return {"ok": False, "error": "no_seeds", "message": "scope declares no seeds"}
    resolved_target = target or seeds[0]

    want = [p.strip() for p in (phases or "").split(",") if p.strip()] or list(_ORDER)
    started = not from_phase
    results: list[dict[str, Any]] = []
    stopped_reason = ""

    for phase in _ORDER:
        if phase not in want:
            continue
        if from_phase and not started:
            if phase == from_phase:
                started = True
            else:
                continue
        if phase == "exploit" and not exploit:
            results.append({"phase": phase, "state": "skipped", "message": "exploit requires --exploit / exploit=True"})
            continue

        extra = {"include_heavy": True} if (phase == "exploit" and exploit) else {}
        result = await runner.run_one_phase(phase, resolved_target, extra=extra)
        results.append(result)

        # The required-phase gate: nothing alive → nothing to scan.
        if phase == "probe" and result.get("state") == "empty":
            stopped_reason = "probe found no live hosts; later phases would scan hosts nobody confirmed exist"
            for later in _ORDER[_ORDER.index(phase) + 1 :]:
                if later in want and PHASES[later].get("per_target"):
                    results.append({"phase": later, "state": "skipped", "message": stopped_reason})
            break

    return {
        "ok": True,
        "workspace": str(engagement.workspace),
        "results": results,
        "stopped": bool(stopped_reason),
        "stopped_reason": stopped_reason,
        "pipeline": runner.snapshot(),
        "note": (
            "Each phase passed through its own MCP tool and control-plane gate. "
            "Findings stay CANDIDATES until a PoC validates them."
        ),
    }

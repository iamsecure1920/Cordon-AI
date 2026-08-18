"""Live engagement dashboard: what the run has found, what phase it is on.

Collects one JSON state blob from an engagement workspace — status.jsonl
(phase machine), findings.json (severity/status ledger), assets.json
(discovered estate), and the neuron brain's activity feed — and renders it
as a self-contained HTML dashboard. Two consumption modes:

    easyhunt dashboard                # static snapshot -> dashboard.html
    easyhunt dashboard --serve        # live local server; page polls /api/state

The page is deliberately dependency-free (single HTML file, inline CSS/JS) so
a snapshot can be attached to a report or opened on any machine, while the
serve mode re-reads the workspace on each poll so a running pipeline is
visible in real time — which phase is executing, what each phase produced,
and what findings are on the ledger right now.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from easyhunt.config import Config  # noqa: E402

#: The canonical pipeline order, shared with brain_watch so the dashboard's
#: phase strip matches the animation's.
PIPELINE = [
    "recon", "resolve", "probe", "waf", "tls", "cors", "endpoints",
    "js", "auth", "takeover", "scan", "exploit", "plan", "report",
]

#: Audit-recorded phase slugs -> canonical pipeline labels (mirror of the
#: mapping in brain_watch; a phase the audit knows but the strip does not is
#: shown under its own name rather than dropped).
_PHASE_ALIASES = {
    "recon_passive": "recon",
    "js_analysis": "js",
    "http_probe": "probe",
    "vuln_scan": "scan",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Severity/status -> CSS class (defined in the page's stylesheet).
_SEVERITY_CLASS = {
    "critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
    "low": "sev-low", "info": "sev-info",
}
_STATUS_CLASS = {
    "confirmed": "st-confirmed", "candidate": "st-candidate",
    "needs_manual_review": "st-review", "untested": "st-review",
    "false_positive": "st-fp", "dismissed": "st-fp",
}


# --------------------------------------------------------------------------- #
# data layer
# --------------------------------------------------------------------------- #
def _canonical_phase(raw: str) -> str:
    return _PHASE_ALIASES.get(raw, raw)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _latest_workspace(root: Path) -> Path | None:
    """The newest engagement workspace, preferring the run marker."""
    marker = root / ".easyhunt-run"
    if marker.exists():
        candidate = Path(marker.read_text().strip())
        if candidate.is_dir():
            return candidate
    eng = root / "engagements"
    if not eng.is_dir():
        return None
    workspaces = sorted(
        (p for p in eng.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime
    )
    return workspaces[-1] if workspaces else None


def _phase_status(workspace: Path) -> dict[str, dict[str, Any]]:
    """Latest status per canonical phase from status.jsonl.

    A phase that logged start but no terminal state is *running*; a phase
    that never appears is *pending*. Outcomes: ok / empty / failed / running.
    """
    status: dict[str, dict[str, Any]] = {
        ph: {"phase": ph, "state": "pending", "tool": None,
             "seconds": None, "findings": None, "message": None}
        for ph in PIPELINE
    }
    path = workspace / "status.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return status
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        phase = _canonical_phase(str(d.get("phase") or ""))
        if phase not in status:
            continue
        state = str(d.get("state") or "")
        entry = status[phase]
        if state == "start":
            entry.update(state="running", tool=d.get("tool"), started_at=d.get("at"))
        elif state in ("ok", "empty", "failed", "error", "skipped", "unavailable"):
            # map phase.py exit semantics: 2 = produced nothing, 3 = failed
            if state == "empty":
                state = "empty"
            elif state in ("failed", "error", "unavailable"):
                state = "failed"
            entry.update(
                state=state, tool=d.get("tool"), seconds=d.get("seconds"),
                findings=d.get("findings"), message=d.get("message"),
                input_=d.get("input"), finished_at=d.get("at"),
            )
    return status


def _collect_findings(workspace: Path) -> dict[str, Any]:
    data = _read_json(workspace / "findings.json") or {}
    findings = data.get("findings") if isinstance(data, dict) else []
    findings = findings or []
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        st = str(f.get("status") or "candidate")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_status[st] = by_status.get(st, 0) + 1
    # stable sort: severity, then confidence desc
    def _key(f: dict) -> tuple[int, float]:
        sev = _SEVERITY_ORDER.get(str(f.get("severity") or "info").lower(), 9)
        conf = float(f.get("confidence") or 0.0)
        return (sev, -conf)

    findings = sorted(findings, key=_key)
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_status": by_status,
        "findings": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "asset": f.get("asset"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "phase": _canonical_phase(str(f.get("phase") or "?")),
                "source_tool": f.get("source_tool"),
                "cvss": f.get("cvss"),
                "confidence": f.get("confidence"),
                "evidence": (f.get("evidence") or [])[:3],
            }
            for f in findings
        ],
    }


def _collect_assets(workspace: Path) -> dict[str, int]:
    data = _read_json(workspace / "assets.json")
    items = data if isinstance(data, list) else (data or {}).get("urls", [])
    counts: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "other")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _collect_activity(root: Path, limit: int = 60) -> list[dict[str, Any]]:
    """The brain's sensed feed (cross-engagement, lives in ~/.easyhunt)."""
    cfg = Config.load(ROOT / "config.yaml") if (ROOT / "config.yaml").exists() else Config()
    raw = cfg.path("memory.brain_activity", "~/.easyhunt/brain-activity.jsonl")
    path = Path(os.path.expanduser(str(raw)))
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return events
    for line in lines[-limit:]:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("kind") != "activity":
            continue
        events.append({
            "ts": d.get("ts"),
            "phase": _canonical_phase(str(d.get("phase") or "")),
            "tool": d.get("tool"),
            "outcome": d.get("outcome"),
            "findings": d.get("findings") or 0,
        })
    return events


def collect_state(root: Path | None = None) -> dict[str, Any]:
    """One JSON blob describing the current engagement — the /api/state body."""
    root = Path(root) if root else Path(__file__).resolve().parent.parent.parent
    workspace = _latest_workspace(root)
    if workspace is None:
        return {"workspace": None, "error": "no engagement workspace found"}
    findings = _collect_findings(workspace)
    phases = _phase_status(workspace)
    running = [p for p, v in phases.items() if v["state"] == "running"]
    completed = [p for p, v in phases.items() if v["state"] == "ok"]
    return {
        "workspace": str(workspace),
        "workspace_name": workspace.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": _read_json(root / "scope.yaml") or None,
        "phases": phases,
        "phase_order": PIPELINE,
        "running_phase": running[-1] if running else None,
        "completed_count": len(completed),
        "findings": findings,
        "assets": _collect_assets(workspace),
        "activity": _collect_activity(root),
        "reports": sorted(
            str(p.relative_to(workspace))
            for p in (workspace / "reports").glob("*")
            if p.is_file()
        ),
    }


# --------------------------------------------------------------------------- #
# HTML page
# --------------------------------------------------------------------------- #
def _render_html(state: dict[str, Any]) -> str:
    state_json = json.dumps(state)
    return _PAGE_TEMPLATE.replace("__STATE_JSON__", state_json)


_PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EasyHunt — live engagement dashboard</title>
<style>
  :root {
    --bg:#0b0e14; --panel:#12161f; --panel2:#0f131b; --line:#232a38;
    --text:#d7dce6; --dim:#7a8496; --accent:#22d3ee;
    --crit:#ff4d6d; --high:#ff8a4d; --med:#ffd166; --low:#7dd3fc; --info:#94a3b8;
    --ok:#34d399; --run:#fbbf24; --fail:#f87171; --empty:#94a3b8;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font:14px/1.5 "SF Mono", "Cascadia Code", Consolas, Menlo, monospace; }
  header { padding:18px 26px; border-bottom:1px solid var(--line);
           display:flex; align-items:baseline; gap:18px; flex-wrap:wrap; }
  header h1 { font-size:17px; color:var(--accent); letter-spacing:1px; }
  header .ws { color:var(--dim); font-size:12px; }
  header .live { margin-left:auto; color:var(--dim); font-size:12px; }
  header .live b { color:var(--ok); }
  .wrap { max-width:1200px; margin:0 auto; padding:22px 26px 60px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:12px; margin-bottom:20px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px;
          padding:14px 16px; }
  .card .k { color:var(--dim); font-size:11px; text-transform:uppercase;
             letter-spacing:.08em; }
  .card .v { font-size:24px; font-weight:700; margin-top:4px; }
  .card .v.crit{color:var(--crit)} .card .v.high{color:var(--high)}
  .card .v.med{color:var(--med)} .card .v.ok{color:var(--ok)}
  .card .sub { color:var(--dim); font-size:11px; margin-top:2px; }
  h2 { font-size:12px; text-transform:uppercase; letter-spacing:.12em;
       color:var(--dim); margin:26px 0 10px; }
  /* phase pipeline */
  .pipeline { display:grid; grid-template-columns:repeat(auto-fit,minmax(86px,1fr));
              gap:8px; margin-bottom:4px; }
  .ph { background:var(--panel); border:1px solid var(--line); border-radius:8px;
        padding:9px 10px; position:relative; overflow:hidden; }
  .ph .nm { font-size:11px; color:var(--dim); text-transform:uppercase;
            letter-spacing:.06em; }
  .ph .st { font-size:12px; margin-top:3px; font-weight:700; }
  .ph.pending .st { color:var(--dim); }
  .ph.running { border-color:var(--run); box-shadow:0 0 14px rgba(251,191,36,.25); }
  .ph.running .st { color:var(--run); }
  .ph.ok .st { color:var(--ok); }
  .ph.empty .st { color:var(--empty); }
  .ph.failed .st { color:var(--fail); }
  .ph .tool { font-size:10px; color:var(--dim); margin-top:2px;
              white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .ph.running::after { content:""; position:absolute; left:0; top:0; bottom:0;
    width:34%; background:linear-gradient(90deg,transparent,rgba(251,191,36,.35),transparent);
    animation:scan 1.6s linear infinite; }
  @keyframes scan { from{transform:translateX(-100%)} to{transform:translateX(340%)} }
  /* findings table */
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th { text-align:left; font-size:10px; text-transform:uppercase;
       letter-spacing:.1em; color:var(--dim); padding:10px 14px;
       border-bottom:1px solid var(--line); background:var(--panel2); }
  td { padding:10px 14px; border-bottom:1px solid var(--line); vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:rgba(34,211,238,.04); }
  .badge { display:inline-block; padding:2px 9px; border-radius:20px;
           font-size:11px; font-weight:700; letter-spacing:.04em; }
  .sev-critical{background:rgba(255,77,109,.15);color:var(--crit)}
  .sev-high{background:rgba(255,138,77,.15);color:var(--high)}
  .sev-medium{background:rgba(255,209,102,.15);color:var(--med)}
  .sev-low{background:rgba(125,211,252,.15);color:var(--low)}
  .sev-info{background:rgba(148,163,184,.15);color:var(--info)}
  .st-confirmed{background:rgba(52,211,153,.15);color:var(--ok)}
  .st-candidate{background:rgba(251,191,36,.15);color:var(--run)}
  .st-review{background:rgba(148,163,184,.2);color:var(--text)}
  .st-fp{background:rgba(248,113,113,.15);color:var(--fail)}
  .empty-note { color:var(--dim); padding:26px; text-align:center;
                border:1px dashed var(--line); border-radius:10px; }
  /* activity feed */
  .feed { background:var(--panel); border:1px solid var(--line); border-radius:10px;
          padding:6px 14px; max-height:230px; overflow-y:auto; }
  .feed div { padding:4px 0; border-bottom:1px dashed rgba(35,42,56,.6);
              font-size:12px; display:flex; gap:10px; }
  .feed div:last-child { border-bottom:none; }
  .feed .t { color:var(--dim); min-width:118px; }
  .feed .ph { background:none; border:none; padding:0; display:inline;
              color:var(--accent); }
  .feed .ok { color:var(--ok); } .feed .clean { color:var(--dim); }
  .feed .err, .feed .refused { color:var(--fail); }
  .feed .hits { color:var(--med); }
  a { color:var(--accent); }
</style>
</head>
<body>
<header>
  <h1>🧠 EASYHUNT · LIVE DASHBOARD</h1>
  <span class="ws" id="ws">scanning…</span>
  <span class="live">mode: <b id="mode">live</b> · updated <span id="clock">—</span></span>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>
  <h2>Phase pipeline</h2>
  <div class="pipeline" id="pipeline"></div>
  <h2>Findings</h2>
  <div id="findings"></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px" class="two-col">
    <div>
      <h2>Recent activity (brain sensing)</h2>
      <div class="feed" id="feed"></div>
    </div>
    <div>
      <h2>Reports</h2>
      <div id="reports"></div>
    </div>
  </div>
</div>
<script>
const ESC = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const $ = id => document.getElementById(id);

function render(state) {
  if (!state || !state.workspace) {
    $("ws").textContent = state && state.error ? state.error : "no data";
    return;
  }
  $("ws").textContent = state.workspace_name;
  const f = state.findings || {};
  const sev = f.by_severity || {}, st = f.by_status || {};
  const total = f.total || 0;
  const cards = [
    ["Findings", total, total ? "med" : "ok", sevText(sev)],
    ["Confirmed", st.confirmed || 0, "ok",
      `review: ${st.needs_manual_review || 0}`],
    ["Candidates", st.candidate || 0, "high",
      "awaiting validation"],
    ["Critical/High", (sev.critical||0)+(sev.high||0), "crit",
      `med ${sev.medium||0} · low ${sev.low||0}`],
    ["Phases done", state.completed_count || 0, "ok",
      state.running_phase ? `running: ${state.running_phase}` : ""],
    ["Assets", Object.values(state.assets||{}).reduce((a,b)=>a+b,0), "ok",
      Object.entries(state.assets||{}).map(([k,v])=>`${v} ${k}`).join(" · ")],
  ];
  $("cards").innerHTML = cards.map(([k,v,cls,sub]) =>
    `<div class="card"><div class="k">${ESC(k)}</div>` +
    `<div class="v ${cls}">${v}</div><div class="sub">${ESC(sub)}</div></div>`
  ).join("");

  // pipeline
  const phases = state.phases || {};
  const order = state.phase_order || Object.keys(phases);
  $("pipeline").innerHTML = order.map(p => {
    const e = phases[p] || {state:"pending"};
    const tool = e.tool ? `<div class="tool">${ESC(e.tool)}</div>` : "";
    const detail = e.seconds != null ? `${e.seconds}s` :
                   e.state === "ok" ? "ok" : "";
    return `<div class="ph ${e.state}"><div class="nm">${ESC(p)}</div>` +
           `<div class="st">${ESC(e.state)}${detail?` · ${detail}`:""}</div>${tool}</div>`;
  }).join("");

  // findings
  const list = f.findings || [];
  if (!list.length) {
    $("findings").innerHTML =
      `<div class="empty-note">No findings on the ledger yet — phases still running.</div>`;
  } else {
    $("findings").innerHTML = `<table><thead><tr>
      <th>Severity</th><th>Finding</th><th>Asset</th><th>Status</th>
      <th>Phase</th><th>Tool</th><th>CVSS</th></tr></thead><tbody>` +
      list.map(x => {
        const sevC = "sev-" + ESC(x.severity||"info").toLowerCase();
        const stC = "st-" + ESC(String(x.status||"").replace(/ /g,"_")).toLowerCase();
        return `<tr><td><span class="badge ${sevC}">${ESC(x.severity||"info")}</span></td>
          <td>${ESC(x.title)}</td>
          <td style="max-width:260px;word-break:break-all">${ESC(x.asset)}</td>
          <td><span class="badge ${stC}">${ESC(x.status||"candidate")}</span></td>
          <td>${ESC(x.phase)}</td><td>${ESC(x.source_tool||"")}</td>
          <td>${x.cvss ?? "—"}</td></tr>`;
      }).join("") + "</tbody></table>";
  }

  // activity feed
  const act = state.activity || [];
  $("feed").innerHTML = act.slice().reverse().map(e => {
    const when = (e.ts||"").replace("T"," ").slice(5,19);
    const o = ESC(e.outcome||"ok");
    const hits = e.findings ? ` <span class="hits">★${e.findings}</span>` : "";
    return `<div><span class="t">${ESC(when)}</span>` +
           `<span class="ph">${ESC(e.phase||"?")}</span>` +
           `<span>${ESC(e.tool||"?")}</span>` +
           `<span class="${o}">${o}</span>${hits}</div>`;
  }).join("") || `<div class="empty-note">No sensed activity yet.</div>`;

  // reports
  const reps = state.reports || [];
  $("reports").innerHTML = reps.length
    ? reps.map(r => `<div><a href="reports/${encodeURIComponent(r.split("/").pop())}">${ESC(r)}</a></div>`).join("")
    : `<div class="empty-note">No reports generated yet.</div>`;
}

function sevText(s) {
  const parts = [];
  if (s.critical) parts.push(`crit ${s.critical}`);
  if (s.high) parts.push(`high ${s.high}`);
  if (s.medium) parts.push(`med ${s.medium}`);
  if (s.low) parts.push(`low ${s.low}`);
  return parts.join(" · ");
}

let boot = true;
window.__live__ = false;  // serve mode flips this to true (polls /api/state)
function tick() {
  $("clock").textContent = new Date().toLocaleTimeString();
  if (boot) {
    try { render(JSON.parse(document.getElementById("boot-state").textContent)); }
    catch (e) { console.error("boot state", e); }
    boot = false;
  }
  if (window.__live__) {
    fetch("/api/state").then(r => r.json()).then(render).catch(() => {});
  }
}
document.addEventListener("DOMContentLoaded", () => { tick(); setInterval(tick, 2000); });
</script>
<script id="boot-state" type="application/json">__STATE_JSON__</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# serve mode — stdlib only, re-reads the workspace on every poll
# --------------------------------------------------------------------------- #
def _serve(root: Path, port: int) -> None:
    state_lock = threading.Lock()

    def _fresh_state() -> dict[str, Any]:
        # The page polls every 2s; a full collect is a few small file reads,
        # so no caching is needed — the lock just keeps concurrent polls from
        # interleaving reads of the same files.
        with state_lock:
            return collect_state(root)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # keep the console quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path == "/api/state":
                state = _fresh_state()
                self._send(200, json.dumps(state).encode(), "application/json")
            elif self.path == "/" or self.path == "/index.html":
                state = _fresh_state()
                page = _render_html(state).replace(
                    "window.__live__ = false;", "window.__live__ = true;", 1
                )
                self._send(200, page.encode(), "text/html; charset=utf-8")
            elif self.path.startswith("/reports/"):
                name = Path(self.path).name
                workspace = Path(_fresh_state()["workspace"])
                target = (workspace / "reports" / name).resolve()
                if target.is_file() and str(target).startswith(str(workspace.resolve())):
                    self._send(200, target.read_bytes(),
                               "application/pdf" if target.suffix == ".pdf" else
                               "application/octet-stream")
                else:
                    self._send(404, b"not found", "text/plain")
            else:
                self._send(404, b"not found", "text/plain")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"dashboard: http://127.0.0.1:{port}  (Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def dashboard(args: argparse.Namespace) -> int:
    root = Path(args.root) if getattr(args, "root", None) else ROOT
    if getattr(args, "serve", False):
        _serve(root, int(args.port or 8765))
        return 0
    state = collect_state(root)
    if state.get("workspace") is None:
        print(f"dashboard: {state.get('error', 'no engagement workspace found')}",
              file=sys.stderr)
        print("Run a phase or hunt.sh first — the dashboard reads the latest workspace.",
              file=sys.stderr)
        return 2
    out = Path(args.out or "dashboard.html")
    out.write_text(_render_html(state), encoding="utf-8")
    f = state["findings"]
    print(
        f"dashboard: {state['workspace_name']} → {out} "
        f"({f['total']} finding(s), "
        f"{sum(1 for p in state['phases'].values() if p['state']=='ok')} phase(s) done)"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="easyhunt dashboard",
        description="Live engagement dashboard: phases, findings, activity, reports.",
    )
    parser.add_argument("--out", help="output path (default dashboard.html)")
    parser.add_argument("--serve", action="store_true",
                        help="run a live local server; the page polls /api/state")
    parser.add_argument("--port", default="8765", help="serve port (default 8765)")
    parser.add_argument("--root", help="project root override (tests)")
    return parser

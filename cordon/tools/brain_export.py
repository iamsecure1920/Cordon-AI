"""``cordon brain export`` — the neuron brain as a self-contained HTML pop-up.

The terminal animation (``brain watch``) is for the operator watching a run live.
This is the shareable version: one HTML file with no external dependencies that
renders the same JSON activity stream as an animated neural net — a pulsing
brain core at the center, a node per phase around it, and electrical pulses
traveling along the connections as tool calls fire. It works in any browser,
offline, and can be attached to a report or dropped in a dashboard.

The JSON contract is identical to the terminal renderer's: the activity feed
(``~/.cordon/brain-activity.jsonl``) is read and embedded into the page, so
what the animation shows is exactly what the brain sensed — nothing fabricated.
A static ``brain-replay.json`` is also written next to the HTML so a live page
can be pointed at a growing feed via ``fetch`` if the file is served.

Usage:

    cordon brain export                 # writes brain.html + brain-replay.json
    cordon brain export --out /tmp/x    # write to /tmp/x.html and /tmp/x.json
    cordon brain export --open          # open the page in the browser
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Any

_PHASES = [
    "recon", "resolve", "probe", "waf", "tls", "cors", "endpoints",
    "js", "auth", "takeover", "scan", "exploit", "plan", "report",
]

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cordon Neuron Brain — live neural activity</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0e14; color: #c9d4e3; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; overflow: hidden; }
  #wrap { position: relative; width: 100vw; height: 100vh; }
  svg { position: absolute; inset: 0; width: 100%; height: 100%; }
  .phase-label { fill: #7d8ea6; font: 12px ui-monospace, monospace; }
  .phase-label.active { fill: #4ade80; }
  .pulse { filter: drop-shadow(0 0 6px currentColor); }
  #hud { position: absolute; top: 14px; left: 20px; z-index: 5; font-size: 13px; line-height: 1.7; }
  #hud .title { color: #22d3ee; font-weight: 700; font-size: 15px; letter-spacing: 2px; }
  #hud .dim { color: #5b6b82; }
  #feed { position: absolute; bottom: 14px; left: 20px; right: 20px; z-index: 5; font-size: 12px;
          color: #5b6b82; border-top: 1px solid #1c2735; padding-top: 10px; max-height: 110px; overflow: hidden; }
  #feed div { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #feed .hit { color: #f87171; }
  #feed .ok { color: #4ade80; }
  #legend { position: absolute; top: 14px; right: 20px; z-index: 5; font-size: 11px; color: #5b6b82; text-align: right; line-height: 1.8; }
  .core { animation: throb 1.2s ease-in-out infinite; }
  @keyframes throb { 0%,100% { r: 11; } 50% { r: 15; } }
</style>
</head>
<body>
<div id="wrap">
  <svg id="net" viewBox="0 0 1000 600" preserveAspectRatio="xMidYMid meet">
    <defs>
      <radialGradient id="coreGrad" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="#67e8f9"/><stop offset="100%" stop-color="#0e7490"/>
      </radialGradient>
    </defs>
    <g id="links"></g>
    <g id="phases"></g>
    <g id="brain"></g>
  </svg>
  <div id="hud">
    <div class="title">◉ NEURON BRAIN</div>
    <div class="dim" id="status">idle — waiting for tool activity…</div>
    <div class="dim" id="counter">0 events · 0 findings</div>
  </div>
  <div id="legend">● brain core<br>▸ pulse = tool firing<br>★ finding filed</div>
  <div id="feed"></div>
</div>
<script>
const EVENTS = __EVENTS__;
const PHASES = __PHASES__;
const cx = 500, cy = 300, R = 230;

// geometry: phase nodes on a circle around the brain core
const nodes = {};
PHASES.forEach((p, i) => {
  const a = -Math.PI / 2 + (2 * Math.PI * i) / PHASES.length;
  nodes[p] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
});

const svg = document.getElementById("net");
const linksG = document.getElementById("links");
const phasesG = document.getElementById("phases");
const brainG = document.getElementById("brain");

// brain core
const core = document.createElementNS("http://www.w3.org/2000/svg", "circle");
core.setAttribute("cx", cx); core.setAttribute("cy", cy);
core.setAttribute("fill", "url(#coreGrad)"); core.classList.add("core");
brainG.appendChild(core);
const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
label.setAttribute("x", cx); label.setAttribute("y", cy + 4);
label.setAttribute("text-anchor", "middle"); label.setAttribute("fill", "#0a0e14");
label.setAttribute("font-size", "9"); label.setAttribute("font-weight", "700");
label.textContent = "BRAIN";
brainG.appendChild(label);

// phase nodes
const phaseEls = {};
PHASES.forEach(p => {
  const n = nodes[p];
  const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
  const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  c.setAttribute("cx", n.x); c.setAttribute("cy", n.y); c.setAttribute("r", 7);
  c.setAttribute("fill", "#16202f"); c.setAttribute("stroke", "#33465f");
  g.appendChild(c);
  const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
  t.setAttribute("x", n.x); t.setAttribute("y", n.y - 14);
  t.setAttribute("text-anchor", "middle"); t.setAttribute("class", "phase-label");
  t.textContent = p;
  g.appendChild(t);
  phasesG.appendChild(g);
  phaseEls[p] = { g, c, t };
});

// static link lines (brain -> phase)
PHASES.forEach(p => {
  const n = nodes[p];
  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", cx); line.setAttribute("y1", cy);
  line.setAttribute("x2", n.x); line.setAttribute("y2", n.y);
  line.setAttribute("stroke", "#1c2735"); line.setAttribute("stroke-width", "1");
  linksG.appendChild(line);
});

// animate a pulse along a link
function pulse(phase, findings) {
  const n = nodes[phase];
  const p = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  p.setAttribute("r", findings ? 6 : 4);
  p.setAttribute("fill", findings ? "#f87171" : "#fbbf24");
  p.setAttribute("class", "pulse");
  p.style.color = findings ? "#f87171" : "#fbbf24";
  svg.appendChild(p);
  const el = phaseEls[phase];
  el.c.classList.add("active");
  el.t.classList.add("active");
  const start = performance.now(), dur = 700;
  (function step(now) {
    const t = Math.min(1, (now - start) / dur);
    p.setAttribute("cx", cx + (n.x - cx) * t);
    p.setAttribute("cy", cy + (n.y - cy) * t);
    if (t < 1) requestAnimationFrame(step);
    else { p.remove(); el.c.classList.remove("active"); el.t.classList.remove("active"); }
  })(start);
}

// replay the sensed events
let idx = 0, findings = 0;
const statusEl = document.getElementById("status");
const counterEl = document.getElementById("counter");
const feedEl = document.getElementById("feed");
function tick() {
  if (idx < EVENTS.length) {
    const e = EVENTS[idx++];
    const f = e.findings | 0;
    findings += f;
    if (e.phase && PHASES.includes(e.phase)) pulse(e.phase, f > 0);
    if (e.event === "tool_call") {
      statusEl.textContent = "sensing: " + (e.phase || "?") + " → " + (e.tool || "?");
      statusEl.style.color = f > 0 ? "#f87171" : "#4ade80";
    }
    const row = document.createElement("div");
    row.textContent = (e.ts ? e.ts.slice(11, 19) : "??") + "  " + (e.phase || "?").padEnd(10) +
                      "  " + (e.tool || "?").padEnd(24) + (f ? "  ★" + f : "");
    row.className = f > 0 ? "hit" : "ok";
    feedEl.appendChild(row);
    while (feedEl.children.length > 6) feedEl.removeChild(feedEl.firstChild);
  }
  counterEl.textContent = Math.min(idx, EVENTS.length) + " / " + EVENTS.length + " events · " + findings + " findings";
  if (idx < EVENTS.length) setTimeout(tick, 120);
}
tick();
</script>
</body>
</html>
"""


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("kind") == "activity":
                events.append(record)
    except OSError:
        pass
    return events


def _default_activity_path() -> Path:
    env = os.environ.get("CORDON_BRAIN_ACTIVITY")
    if env:
        return Path(env)
    return Path.home() / ".cordon" / "brain-activity.jsonl"


def brain_export(args: argparse.Namespace) -> int:
    activity = Path(args.path) if args.path else _default_activity_path()
    events = _load_events(activity)

    base = Path(args.out) if args.out else Path("brain.html")
    if base.suffix == "":
        base = base.with_suffix(".html")
    html_path = base
    json_path = base.with_suffix(".json")

    if not events:
        print(f"brain export: no activity recorded at {activity}", file=sys.stderr)
        print("Run an engagement first — the brain writes activity as tools run.", file=sys.stderr)
        return 2

    page = _TEMPLATE.replace("__EVENTS__", json.dumps(events)).replace(
        "__PHASES__", json.dumps(_PHASES)
    )
    html_path.write_text(page, encoding="utf-8")
    json_path.write_text(json.dumps(events, indent=2), encoding="utf-8")

    print(f"brain export: {len(events)} event(s) → {html_path} (+ {json_path})")
    if getattr(args, "open", False):
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", str(html_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(html_path.as_uri())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cordon brain export",
        description="Self-contained HTML neural animation of the neuron brain's sensed activity.",
    )
    parser.add_argument("--path", help="activity feed path (default ~/.cordon/brain-activity.jsonl)")
    parser.add_argument("--out", help="output base name (default ./brain.html + brain.json)")
    parser.add_argument("--open", action="store_true", help="open the page after writing")
    return parser

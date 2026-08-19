"""``cordon brain watch`` — the neuron brain's live neural animation.

The brain is not a widget; it is the tool's sensing and memory layer. This is its
face: a terminal pop-up that renders the brain as a node firing electrical
pulses along pipelines to the phase currently being worked, fed by the JSON
activity stream the brain writes as every tool call happens.

How it works: every tool call in every script flows through the audit log, and
the brain subscribes to the audit log as an observer. Each sensed call is
appended as one JSON line to the activity feed (``~/.cordon/brain-activity.jsonl``
by default). This module tails that feed — the same stream a web front-end would
consume — and animates a frame each tick:

* a brain node (````) with a pulsing core
* one pipeline per phase, lit by a traveling pulse when a tool fires in it
* a live status line (current phase/tool) and the last few sensed events

Pure stdlib: ANSI escape codes only, no curses dependency (so it works piped,
in tmux, and in the sandbox image). Run it alongside ``hunt.sh`` or
``cordon serve``:

    cordon brain watch            # follow the default activity feed
    cordon brain watch --path x   # follow a specific feed
    cordon brain watch --once     # one frame, then exit (for CI/demos)

The feed format is the animation's JSON contract: one object per line with
``kind: \"activity\"``, ``ts``, ``event``, ``phase``, ``tool``, ``outcome``,
``findings``, ``targets``, ``duration_ms``. Any consumer (an HTML pop-up, a
dashboard) can replay the same stream.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

#: The phases the pipeline knows, in the order hunt.sh runs them (per-target
#: then global). Each gets a pipeline from the brain node.
PHASES = [
    "recon", "resolve", "probe", "waf", "tls", "cors", "endpoints",
    "js", "auth", "takeover", "scan", "exploit", "plan", "report",
]

# Raw phase names the audit layer records (tool-registry slugs) mapped to the
# canonical pipeline labels the animation draws. The audit names are
# tool-owner terms — recon_passive, js_analysis, vuln_scan, http_probe — and
# without this mapping the pulse lookup misses every real event and nothing
# lights. The demo only worked because it fed hand-crafted names.
_PHASE_ALIASES = {
    "recon_passive": "recon",
    "js_analysis": "js",
    "http_probe": "probe",
    "vuln_scan": "scan",
}


def _canonical_phase(raw: str) -> str:
    """Map an audit-recorded phase name to the animation's pipeline label."""
    return _PHASE_ALIASES.get(raw, raw)

_ANSI = {"reset": "\x1b[0m", "bold": "\x1b[1m", "dim": "\x1b[2m", "clear": "\x1b[2J\x1b[H"}
_COLOR = {
    "brain": "\x1b[1;36m",      # bright cyan — the brain core
    "pulse": "\x1b[1;33m",      # bright yellow — the traveling impulse
    "phase": "\x1b[0;37m",      # white — phase labels
    "active": "\x1b[1;32m",     # bright green — currently firing phase
    "hit": "\x1b[1;31m",        # bright red — a finding pulse
    "ok": "\x1b[0;32m",         # green — good outcome
    "err": "\x1b[1;31m",        # red — failure
    "dim": "\x1b[2;37m",
}


def _tail(path: Path, start: int = 0) -> list[dict[str, Any]]:
    """Read activity records appended since ``start`` bytes."""
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(start)
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return events
    return events


def _pulse_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Latest event per phase (for deciding which pipeline pulses are lit)."""
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        phase = str(event.get("phase") or "")
        if phase:
            latest[_canonical_phase(phase)] = event
    return latest


def _render_frame(events: list[dict[str, Any]], now: float) -> str:
    """One animation frame. Pulses travel along the phase pipelines."""
    lines: list[str] = [_ANSI["clear"]]
    latest = _pulse_events(events)

    # --- header: the brain ------------------------------------------------- #
    tick = int(now * 3) % 4
    core = ["@", "#", "%", "#"][tick]
    lines.append(
        f"{_ANSI['bold']}{_COLOR['brain']}    {core} NEURON BRAIN {core}   {_ANSI['reset']}"
        f"{_ANSI['dim']} sensing {len(events)} event(s) · associative + episodic memory{_ANSI['reset']}"
    )
    lines.append("")

    # --- brain → phase pipelines ------------------------------------------- #
    for _i, phase in enumerate(PHASES):
        event = latest.get(phase)
        is_active = event is not None and (
            now - _ts_epoch(event) < 6.0
        )
        findings = int((event or {}).get("findings") or 0)
        outcome = str((event or {}).get("outcome") or "")

        # Pulse position: a bright cell traveling from the brain toward the
        # phase, wrapping on its own cadence so pipelines always look alive.
        width = 26
        if is_active:
            pos = int((now * 4) % width)
            pipeline = ["·"] * width
            if findings:
                pipeline[pos] = "*"
                color = _COLOR["hit"]
            else:
                pipeline[pos] = ">"
                color = _COLOR["pulse"]
            pipeline = "".join(pipeline)
            label = phase
            label_color = _COLOR["active"] if outcome == "ok" else _COLOR["err"]
        else:
            pipeline = "·" * width
            color = _ANSI["dim"]
            label = phase
            label_color = _COLOR["phase"]

        tool = str((event or {}).get("tool") or "")
        if tool and is_active:
            tail = f" {_COLOR['dim']}← {tool}{_ANSI['reset']}"
        elif event is not None:
            tail = ""
        else:
            tail = ""

        lines.append(
            f" {_COLOR['brain']}●{_ANSI['reset']}──{color}{pipeline}{_ANSI['reset']}──"
            f"{label_color}{label:<10}{_ANSI['reset']}{tail}"
        )

    # --- live status + recent events --------------------------------------- #
    current = events[-1] if events else None
    lines.append("")
    if current and current.get("phase"):
        phase = _canonical_phase(str(current["phase"]))
        tool = str(current.get("tool") or "")
        outcome = str(current.get("outcome") or "ok")
        mark = f"{_COLOR['ok']}ok{_ANSI['reset']}" if outcome == "ok" else f"{_COLOR['err']}{outcome}{_ANSI['reset']}"
        lines.append(
            f"{_ANSI['bold']}NOW{_ANSI['reset']}  phase={_COLOR['active']}{phase}{_ANSI['reset']} "
            f"tool={_COLOR['phase']}{tool}{_ANSI['reset']} outcome={mark}"
        )
    else:
        lines.append(f"{_ANSI['dim']}NOW  idle — waiting for tool activity…{_ANSI['reset']}")

    lines.append("")
    for event in events[-3:]:
        phase = _canonical_phase(str(event.get("phase") or "?"))
        tool = str(event.get("tool") or "?")
        outcome = str(event.get("outcome") or "")
        findings = int(event.get("findings") or 0)
        mark = f"{_COLOR['ok']}✓{_ANSI['reset']}" if outcome == "ok" else f"{_COLOR['err']}✗{_ANSI['reset']}"
        if findings:
            mark += f" {_COLOR['hit']}★{findings}{_ANSI['reset']}"
        lines.append(f"  {_ANSI['dim']}{phase:<10}{_ANSI['reset']} {tool:<24} {mark}")

    return "\n".join(lines)


def _ts_epoch(event: dict[str, Any]) -> float:
    try:
        from datetime import datetime

        return datetime.fromisoformat(str(event.get("ts") or "")).timestamp()
    except ValueError:
        return 0.0


def _default_activity_path() -> Path:
    env = os.environ.get("CORDON_BRAIN_ACTIVITY")
    if env:
        return Path(env)
    return Path.home() / ".cordon" / "brain-activity.jsonl"


def brain_watch(args: argparse.Namespace) -> int:
    """Tail the brain's activity feed and animate it. Ctrl-C to stop."""
    path = Path(args.path) if args.path else _default_activity_path()
    if not path.exists():
        print(f"brain watch: no activity feed at {path}", file=sys.stderr)
        print("Run an engagement first — the brain writes activity as tools run.", file=sys.stderr)
        return 2

    # --once renders the existing history (start at 0); live watch tails the
    # feed (start at the current end so old events are not replayed).
    offset = 0 if getattr(args, "once", False) else path.stat().st_size
    events: list[dict[str, Any]] = []
    try:
        while True:
            fresh = _tail(path, start=offset)
            if fresh:
                events.extend(fresh)
                offset = path.stat().st_size
                # Keep the frame bounded: the ring the brain keeps is 256.
                events = events[-256:]
            frame = _render_frame(events, time.time())
            sys.stdout.write(frame)
            sys.stdout.flush()
            if getattr(args, "once", False):
                return 0
            time.sleep(0.33)
    except KeyboardInterrupt:
        sys.stdout.write(_ANSI["reset"] + "\n")
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cordon brain watch",
        description="Live neural animation of what the neuron brain senses.",
    )
    parser.add_argument("--path", help="activity feed path (default ~/.cordon/brain-activity.jsonl)")
    parser.add_argument(
        "--once", action="store_true",
        help="render one frame and exit (for CI/demos; needs --path to a real feed)",
    )
    return parser

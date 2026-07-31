"""Tool-definition pinning — anti rug-pull for the MCP surface.

A "rug pull" is when a tool the user already approved quietly changes what it
does: the description gains an instruction, a parameter appears, a passive tool
becomes aggressive. The agent re-reads the definition every session and has no
memory of what it used to say.

So we remember for it. Each tool's canonical definition is hashed and pinned on
first run. On every later start the hashes are recomputed and any drift is
reported — with the specific fields that changed, because "something changed" is
not actionable and "mode went passive → exploit" is.

Pinning is detection, not prevention. It cannot stop a modified tool from
running; it makes sure nobody finds out about the change six weeks later while
reading an audit log.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("easyhunt.pins")

__all__ = ["compute_pins", "diff_pins", "verify_or_write_pins"]

# Changes to these fields are security-relevant: they alter what a tool is
# allowed to do or how the agent is told to use it.
CRITICAL_FIELDS = {"mode", "phase", "targets_arg", "binary", "image", "description", "params"}


def _digest(definition: dict[str, Any]) -> str:
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_pins(registry: dict[str, Any]) -> dict[str, Any]:
    """Hash every registered tool's canonical definition."""
    pins: dict[str, Any] = {}
    for name, tool in registry.items():
        definition = tool.definition()
        pins[name] = {
            "hash": _digest(definition),
            "mode": definition["mode"],
            "phase": definition["phase"],
            "origin": getattr(tool, "origin", "builtin"),
            "definition": definition,
        }
    return pins


def diff_pins(stored: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare pinned definitions against what is loaded now."""
    added = sorted(set(current) - set(stored))
    removed = sorted(set(stored) - set(current))
    changed: list[dict[str, Any]] = []

    for name in sorted(set(stored) & set(current)):
        if stored[name].get("hash") == current[name].get("hash"):
            continue
        before = stored[name].get("definition", {})
        after = current[name].get("definition", {})
        fields = sorted(
            key for key in set(before) | set(after) if before.get(key) != after.get(key)
        )
        entry: dict[str, Any] = {
            "tool": name,
            "fields_changed": fields,
            "critical": sorted(set(fields) & CRITICAL_FIELDS),
        }
        # Spell out the change that matters most: a tool becoming more powerful.
        if "mode" in fields:
            entry["mode_change"] = f"{before.get('mode')} → {after.get('mode')}"
            escalation = {"passive": 0, "aggressive": 1, "exploit": 2}
            if escalation.get(str(after.get("mode")), 0) > escalation.get(str(before.get("mode")), 0):
                entry["escalation"] = True
        if "description" in fields:
            entry["description_before"] = str(before.get("description", ""))[:200]
            entry["description_after"] = str(after.get("description", ""))[:200]
        changed.append(entry)

    escalations = [c for c in changed if c.get("escalation")]
    critical = [c for c in changed if c.get("critical")]

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "critical_changes": critical,
        "privilege_escalations": escalations,
        "clean": not (added or removed or changed),
    }


def verify_or_write_pins(engagement: Any, registry: dict[str, Any]) -> dict[str, Any]:
    """Check the pin file, or create it on first run.

    Returns a report. A tool that gained privileges since it was pinned is
    reported as a ``privilege_escalation`` and written to the audit log, because
    that is the shape an actual supply-chain attack takes.
    """
    config = engagement.config
    if not bool(config.get("hardening.pin_tool_definitions", True)):
        return {"enabled": False}

    pin_file = config.path("hardening.pin_file", ".easyhunt-pins.json")
    if pin_file is None:
        return {"enabled": False, "reason": "no pin file configured"}

    current = compute_pins(registry)

    if not pin_file.exists():
        pin_file.parent.mkdir(parents=True, exist_ok=True)
        pin_file.write_text(
            json.dumps(
                {"created_at": datetime.now(UTC).isoformat(), "version": 1, "tools": current},
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        engagement.audit.record("pins_created", path=str(pin_file), tools=len(current))
        return {"enabled": True, "created": True, "tools": len(current), "path": str(pin_file)}

    try:
        payload = json.loads(pin_file.read_text(encoding="utf-8"))
        stored = payload.get("tools") or {}
    except (OSError, json.JSONDecodeError) as exc:
        engagement.audit.record("pins_unreadable", path=str(pin_file), error=str(exc))
        return {"enabled": True, "error": f"pin file unreadable: {exc}"}

    report = diff_pins(stored, current)
    report.update({"enabled": True, "path": str(pin_file), "tools": len(current)})

    if not report["clean"]:
        engagement.audit.record(
            "pin_mismatch",
            added=report["added"],
            removed=report["removed"],
            changed=[c["tool"] for c in report["changed"]],
            critical=[c["tool"] for c in report["critical_changes"]],
            escalations=[c["tool"] for c in report["privilege_escalations"]],
        )
        for escalation in report["privilege_escalations"]:
            log.warning(
                "PRIVILEGE ESCALATION in pinned tool %s: %s — review before running",
                escalation["tool"],
                escalation.get("mode_change"),
            )

    return report


def update_pins(engagement: Any, registry: dict[str, Any]) -> dict[str, Any]:
    """Re-pin after a change you have reviewed and accepted."""
    pin_file = engagement.config.path("hardening.pin_file", ".easyhunt-pins.json")
    if pin_file is None:
        return {"ok": False, "reason": "no pin file configured"}
    current = compute_pins(registry)
    pin_file.write_text(
        json.dumps(
            {"updated_at": datetime.now(UTC).isoformat(), "version": 1, "tools": current},
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    engagement.audit.record("pins_updated", path=str(pin_file), tools=len(current))
    return {"ok": True, "path": str(pin_file), "tools": len(current)}

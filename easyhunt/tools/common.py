"""Shared plumbing for atomic tool wrappers.

Two ideas keep the wrapper layer small:

**A catalog, not forty MCP tools.** Every wrapped binary gets a :class:`ToolSpec`
entry in :data:`CATALOG` — that is what ``easyhunt doctor`` reports on and where
each tool's license is recorded. But the *MCP* surface groups them by job:
``subdomain_enum`` runs whichever of subfinder/assetfinder/findomain are present
and merges the results. An agent choosing between four subdomain tools is an
agent spending tokens on a decision that has one right answer: run them all.

**Missing tools degrade, they do not fail.** A wrapper runs the tools it finds and
reports which ones were absent, so a partial install still produces useful recon
instead of an error.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Asset
from easyhunt.tools.base import ToolSpec, guarded_run
from easyhunt.util.parse import host_of
from easyhunt.util.run import ProcResult

__all__ = [
    "CATALOG",
    "ToolRun",
    "register_spec",
    "run_many",
    "split_targets",
    "resolve_binary",
    "store_assets",
    "verify_identity",
]

CATALOG: dict[str, ToolSpec] = {}


def register_spec(spec: ToolSpec) -> ToolSpec:
    """Add a tool to the catalog (and register its argument policy)."""
    CATALOG[spec.name] = spec
    return spec


def installed(name: str) -> bool:
    """Whether a usable copy of this tool is present.

    For tools with a name collision this means *the correct binary*, wherever it
    sits on PATH — a Python CLI called ``httpx`` does not count as httpx being
    installed.
    """
    spec = CATALOG.get(name)
    if spec is None:
        return False
    if spec.binary:
        if spec.identity_marker:
            if resolve_binary(name) is not None:
                return True
        elif shutil.which(spec.binary):
            return True
    if spec.package:
        import importlib.util

        return importlib.util.find_spec(spec.package.replace("-", "_")) is not None
    return False


def _candidates(binary: str) -> list[str]:
    """Every executable of this name on PATH, in order, deduplicated."""
    found: list[str] = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            resolved = os.path.realpath(candidate)
            if resolved not in {os.path.realpath(f) for f in found}:
                found.append(candidate)
    return found


def _identifies_as(binary: str, spec: ToolSpec) -> bool:
    """Whether running this binary produces the tool's identity marker."""
    marker = (spec.identity_marker or "").lower()
    for args in (spec.version_args, ["--version"], ["-version"], ["version"], ["-h"]):
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, *args], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout + proc.stderr).lower()
        if output.strip() and marker in output:
            return True
    return False


@lru_cache(maxsize=128)
def resolve_binary(name: str) -> str | None:
    """The path to the *correct* binary for this tool, ignoring PATH order.

    Several security tools share a name with unrelated software. ``httpx`` is
    both ProjectDiscovery's prober and the Python HTTP library's CLI, and which
    one ``shutil.which`` returns depends on how the operator's PATH happens to be
    ordered. Picking the wrong one is the worst failure mode available to a recon
    tool: it exits zero, prints nothing, and looks exactly like a target with no
    live hosts.

    So for any tool declaring an ``identity_marker``, every candidate on PATH is
    executed once and the first that identifies itself correctly wins. Tools
    without a marker resolve normally. Cached — this spawns processes.
    """
    spec = CATALOG.get(name)
    if spec is None or not spec.binary:
        return None

    if not spec.identity_marker:
        return shutil.which(spec.binary)

    candidates = _candidates(spec.binary)
    for candidate in candidates:
        if _identifies_as(candidate, spec):
            return candidate
    # Nothing identified correctly; report absence rather than run an impostor.
    return None


@lru_cache(maxsize=128)
def verify_identity(name: str) -> tuple[bool, str]:
    """Confirm a correct binary for this tool exists somewhere on PATH.

    Returns ``(ok, detail)``. Tools that declare no ``identity_marker`` are
    assumed correct.
    """
    spec = CATALOG.get(name)
    if spec is None:
        return False, "not in catalog"
    if not spec.identity_marker or not spec.binary:
        return True, "no identity marker declared"

    candidates = _candidates(spec.binary)
    if not candidates:
        return False, "not installed"

    resolved = resolve_binary(name)
    if resolved is None:
        listed = ", ".join(candidates[:3])
        return False, (
            f"none of the {len(candidates)} {spec.binary!r} on PATH look like {name} "
            f"(expected {spec.identity_marker!r} in the version output). Found: {listed}"
        )

    first = candidates[0]
    if os.path.realpath(resolved) != os.path.realpath(first):
        # Correct binary found, just not the one PATH would have picked.
        return True, f"verified at {resolved} (shadowed on PATH by {first})"
    return True, "verified"


@dataclass
class ToolRun:
    """Outcome of one binary's execution inside a grouped wrapper."""

    tool: str
    ran: bool
    values: list[str] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0
    exit_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "ran": self.ran,
            "found": len(self.values),
            "error": self.error,
            "duration_s": round(self.duration_s, 1),
        }


async def run_one(
    name: str,
    argv: list[str],
    *,
    timeout: float = 300.0,
    stdin: str | None = None,
    extract: Callable[[ProcResult], list[str]] | None = None,
    allow_codes: tuple[int, ...] = (0,),
) -> ToolRun:
    """Run one catalog tool, capturing failure rather than propagating it."""
    spec = CATALOG.get(name)
    if spec is None:
        return ToolRun(tool=name, ran=False, error="not in catalog")
    if not installed(name):
        return ToolRun(tool=name, ran=False, error="not installed")

    try:
        result = await guarded_run(
            spec, argv, timeout=timeout, stdin=stdin, output_name=name,
            allow_codes=allow_codes, check=False,
        )
    except Exception as exc:  # noqa: BLE001 — one absent tool must not sink the group
        return ToolRun(tool=name, ran=False, error=str(exc))

    if result.timed_out:
        return ToolRun(tool=name, ran=True, error="timed out", duration_s=result.duration_s)

    values = extract(result) if extract else lines_of(result.stdout)
    return ToolRun(
        tool=name,
        ran=True,
        values=values,
        duration_s=result.duration_s,
        exit_code=result.exit_code,
        error=None if result.exit_code in allow_codes else (result.stderr or "")[-300:],
    )


async def run_many(runs: Iterable[Any]) -> list[ToolRun]:
    """Run several tools concurrently. The rate limiter still governs the total."""
    return list(await asyncio.gather(*runs))


def lines_of(text: str, *, limit: int = 100_000) -> list[str]:
    """Non-empty, non-banner lines from a tool's stdout."""
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        # ProjectDiscovery tools print banners and [INF]/[WRN] lines to stdout.
        if not stripped or stripped.startswith(("[INF]", "[WRN]", "[ERR]", "[FTL]", "__")):
            continue
        out.append(stripped)
        if len(out) >= limit:
            break
    return out


def split_targets(target: str | list[str]) -> list[str]:
    if isinstance(target, list):
        items = target
    else:
        items = target.replace("\n", ",").split(",")
    return [t.strip() for t in items if t and t.strip()]


def in_scope_only(values: Iterable[str], *, phase: str, tool: str) -> tuple[list[str], int]:
    """Filter tool output through the scope engine.

    Recon tools routinely return hosts the target does not own — a certificate
    covering several organizations, a shared CDN name. Those are dropped here so
    they can never become the input to a later active scan.
    """
    engagement = get_engagement()
    kept: list[str] = []
    dropped = 0
    for value in values:
        if engagement.scope.check(value).in_scope:
            kept.append(value)
        else:
            dropped += 1
    if dropped:
        engagement.audit.record(
            "results_filtered", tool=tool, phase=phase, dropped=dropped, kept=len(kept)
        )
    return kept, dropped


def store_assets(
    values: Iterable[str], *, kind: str, source: str, tags: list[str] | None = None
) -> int:
    engagement = get_engagement()
    return engagement.assets.add_many(
        Asset(value=value, kind=kind, source=source, host=host_of(value), tags=list(tags or []))
        for value in values
    )


def merge_runs(runs: list[ToolRun]) -> list[str]:
    """Union of every tool's output, deduplicated and sorted."""
    merged: set[str] = set()
    for run in runs:
        merged.update(v.strip().lower().rstrip(".") for v in run.values if v.strip())
    return sorted(merged)


def grouped_result(
    *,
    kind: str,
    runs: list[ToolRun],
    values: list[str],
    dropped: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Uniform return shape for grouped wrappers."""
    missing = [r.tool for r in runs if not r.ran and r.error == "not installed"]
    payload: dict[str, Any] = {
        "ok": True,
        "kind": kind,
        "count": len(values),
        kind: values,
        "dropped_out_of_scope": dropped,
        "tools": [r.to_dict() for r in runs],
    }
    if missing:
        payload["tools_not_installed"] = missing
        payload["coverage_note"] = (
            f"{len(missing)} tool(s) absent — results are partial. Install them or "
            "run 'easyhunt doctor' to see what is missing."
        )
    if extra:
        payload.update(extra)
    return payload


# Shared value patterns for argument policies.
HOST_PATTERN = re.compile(r"[A-Za-z0-9._*:/-]{1,253}")
URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]{1,2000}")
PORT_PATTERN = re.compile(r"[0-9,\-]{1,64}")
PATH_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,512}")

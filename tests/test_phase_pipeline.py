"""scripts/phase.py: a background job must survive until it finishes, not die
when the short-lived phase process returns.

``nuclei_scan`` and the other long tools launch a job and hand back a ``job_id``
when they have not finished within the tool's own wait window. That job lives in
the phase process's event loop, so a phase that returned immediately cancelled it
— a scan longer than the wait window never completed in the CLI pipeline, and the
phase reported "still running" with nothing left to poll. ``_collect_job_result``
keeps the loop alive until the job reports ready.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

from easyhunt.control_plane.jobs import JobManager

ROOT = Path(__file__).resolve().parent.parent


def _load_phase():
    """Import scripts/phase.py as a module (it is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "easyhunt_phase_script", str(ROOT / "scripts" / "phase.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


phase = _load_phase()


def test_inline_result_passes_through() -> None:
    """A tool that finished inline (no job_id) is returned untouched."""

    async def run() -> None:
        eng = SimpleNamespace(jobs=JobManager())
        entry = SimpleNamespace(timeout=3600)
        result = await phase._collect_job_result(entry, eng, {"ok": True, "count": 0})
        assert result == {"ok": True, "count": 0}

    asyncio.run(run())


def test_background_job_is_waited_out() -> None:
    """A still-running job is awaited to completion and its result merged in."""

    async def _slow_job(job):  # noqa: ARG001 — signature must match the factory
        await asyncio.sleep(0.2)
        return {"ok": True, "count": 3, "complete": True}

    async def run() -> None:
        jobs = JobManager()
        job = jobs.launch(_slow_job, tool="nuclei_scan", phase="vuln_scan", targets=["x"])
        eng = SimpleNamespace(jobs=jobs)
        entry = SimpleNamespace(timeout=30)
        result = await phase._collect_job_result(
            entry, eng, {"job_id": job.id, "completed": False}
        )
        assert result["completed"] is True
        assert result["ok"] is True
        assert result["count"] == 3
        assert result["complete"] is True

    asyncio.run(run())


def _write_audit(workspace: Path, engagement: str) -> None:
    """Create a workspace whose audit log claims the given engagement."""
    import json

    workspace.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": "2026-01-01T00:00:00+00:00",
        "event": "engagement_start",
        "engagement": engagement,
        "seq": 0,
        "prev_hash": "0" * 64,
        "hash": "a" * 64,
    }
    (workspace / "audit.jsonl").write_text(json.dumps(record) + "\n")


def test_workspace_matches_only_its_own_scope(tmp_path) -> None:
    """The resume marker must not hand a phase a foreign engagement's workspace.

    Regression: after one engagement, the .easyhunt-run marker pointed at the
    acme-bbp workspace. Starting the next engagement reused it, so every phase
    inherited the previous engagement's exhausted budget (instant BudgetExceeded) and its 96
    out-of-scope subdomains (instant OutOfScopeError). A workspace belongs to
    exactly the scope named in its first audit record.
    """
    first = tmp_path / "first"
    _write_audit(first, "acme-bbp")

    # Same scope resumes; any other scope starts fresh.
    assert phase._workspace_scope_matches(first, "acme-bbp") is True
    assert phase._workspace_scope_matches(first, "globex-h1") is False

    # A missing or malformed audit log is never treated as "this scope".
    bare = tmp_path / "bare"
    bare.mkdir(parents=True, exist_ok=True)
    assert phase._workspace_scope_matches(bare, "globex-h1") is False

    assert phase._workspace_scope_matches(tmp_path / "absent", "globex-h1") is False


def test_inherited_sample_spreads_instead_of_prefix() -> None:
    """A cap must not concentrate the selection in one namespace.

    Regression: on ATT, resolve inherited the first 500 subdomains of a 60k
    store — all ``3pc.example-cdn.net`` telemetry hosts — and the required probe then
    reported "nothing alive" for a target with 60k names. A sample must spread
    across the whole store so a single alphabetically-early namespace cannot
    starve the run.
    """
    store = [f"host-{i:05d}.example.com" for i in range(10000)]
    sample = phase._inherited_sample(store, 100)

    # Same size as the cap, but spread: the first and last items are both
    # represented, and so is the middle.
    assert len(sample) == 100
    assert sample[0] == "host-00000.example.com"
    assert sample[-1] == "host-09900.example.com"
    assert "host-05000.example.com" in sample

    # The spread is even: consecutive picks are ~len/cap apart.
    gaps = [
        int(store.index(b)) - int(store.index(a))
        for a, b in zip(sample[:-1], sample[1:], strict=True)
    ]
    assert min(gaps) > 0
    assert max(gaps) - min(gaps) <= 1

    # A store smaller than the cap passes through untouched.
    small = ["a.example.com", "b.example.com"]
    assert phase._inherited_sample(small, 500) == small


def test_probe_prefers_resolved_hosts_over_subdomains() -> None:
    """probe consumes what resolve filtered, not the raw subdomain dump.

    Regression: probe's ``wants`` listed subdomain before host, so on a run that
    had both it re-sampled 60k raw subdomains instead of the smaller resolved
    set — wasting the DNS phase and re-probing names that never answered.
    """
    assert phase.PHASES["probe"]["wants"][0] == "host"
    assert phase.PHASES["resolve"]["wants"][0] == "subdomain"


def test_resolve_phase_sees_the_whole_estate() -> None:
    """DNS phases must not be capped at the tiny default.

    Regression: resolve inherited only 500 of 60k subdomains (the argv concern
    the cap was guarding does not apply — dnsx reads a ``-l`` list file), so
    99% of the estate was never examined.
    """
    assert phase.PHASES["resolve"].get("max", phase.MAX_INHERITED) > phase.MAX_INHERITED
    assert phase.PHASES["probe"].get("max", phase.MAX_INHERITED) > phase.MAX_INHERITED


def test_subprocess_timeout_scales_with_input() -> None:
    """A big estate must not be killed by a constant subprocess timeout.

    Regression: dnsx was run with a hard-coded 600s timeout. At the 20 rps
    ceiling, resolving ATT's 60k subdomains needs ~3,000s — the tool was killed
    mid-scan, its partial output discarded, and resolve reported "0 hosts" for
    an estate that had 60k names. The timeout must scale with the input.
    """
    from easyhunt.tools.common import subprocess_timeout_for

    # Small input keeps the old constant (floor), so small runs are unchanged.
    assert subprocess_timeout_for(["a.com"], 20, minimum=600) == 600
    # A 60k-host estate at 20 rps gets hours, not 10 minutes.
    big = subprocess_timeout_for([f"h{i}.com" for i in range(60000)], 20, minimum=600)
    assert big > 3000
    # No rate limit information falls back to the floor rather than crashing.
    assert subprocess_timeout_for(["a.com"], 0, minimum=600) == 600

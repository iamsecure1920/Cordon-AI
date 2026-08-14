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

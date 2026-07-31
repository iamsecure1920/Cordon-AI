"""Async job manager for long-running scans.

An MCP session that blocks for the twenty minutes a BBOT or full Nuclei run takes
is a session the agent cannot use to think. Long tools therefore split into
``*_launch`` (returns a ``job_id`` immediately), ``job_status``, and ``job_fetch``.

:meth:`JobManager.slice` is the other half of the token economy: rather than
shipping a whole result set into the context window, the agent asks for the part
it needs — the multi-step context retrieval pattern from Vulnhuntr.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from easyhunt.errors import EasyHuntError

log = logging.getLogger("easyhunt.jobs")

__all__ = ["Job", "JobManager", "JobStatus"]


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    id: str
    tool: str
    phase: str
    targets: list[str]
    status: JobStatus = JobStatus.QUEUED
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: float | None = None
    finished_at: float | None = None
    result: Any = None
    error: str | None = None
    error_code: str | None = None
    progress: str = ""
    events_seen: int = 0
    output_path: str | None = None
    _task: asyncio.Task[Any] | None = field(default=None, repr=False)

    @property
    def duration_s(self) -> float | None:
        if self.started_at is None:
            return None
        return (self.finished_at or time.monotonic()) - self.started_at

    def brief(self) -> dict[str, Any]:
        """Status without the payload — safe to poll repeatedly."""
        return {
            "job_id": self.id,
            "tool": self.tool,
            "phase": self.phase,
            "targets": self.targets,
            "status": self.status.value,
            "progress": self.progress,
            "events_seen": self.events_seen,
            "duration_s": round(self.duration_s, 1) if self.duration_s else None,
            "error": self.error,
            "error_code": self.error_code,
            "output_path": self.output_path,
        }


class JobManager:
    def __init__(self, *, max_jobs: int = 200) -> None:
        self._jobs: dict[str, Job] = {}
        self._counter = 0
        self.max_jobs = max_jobs

    def _next_id(self, tool: str) -> str:
        self._counter += 1
        return f"{tool}-{self._counter:04d}"

    def launch(
        self,
        factory: Callable[[Job], Awaitable[Any]],
        *,
        tool: str,
        phase: str,
        targets: list[str],
    ) -> Job:
        """Start work in the background and return its handle immediately."""
        self._evict()
        job = Job(id=self._next_id(tool), tool=tool, phase=phase, targets=targets)
        self._jobs[job.id] = job

        async def runner() -> None:
            job.status = JobStatus.RUNNING
            job.started_at = time.monotonic()
            try:
                job.result = await factory(job)
                job.status = JobStatus.DONE
            except asyncio.CancelledError:
                job.status = JobStatus.CANCELLED
                job.error = "cancelled"
                raise
            except Exception as exc:  # noqa: BLE001 — recorded, not swallowed
                job.status = JobStatus.FAILED
                job.error = str(exc)
                job.error_code = getattr(exc, "code", exc.__class__.__name__)
            finally:
                job.finished_at = time.monotonic()

        job._task = asyncio.create_task(runner())
        return job

    def _evict(self) -> None:
        """Drop the oldest finished jobs once the table is full."""
        if len(self._jobs) < self.max_jobs:
            return
        finished = [
            j for j in self._jobs.values()
            if j.status in {JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED}
        ]
        for job in sorted(finished, key=lambda j: j.finished_at or 0)[: max(1, len(finished) // 4)]:
            self._jobs.pop(job.id, None)

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise EasyHuntError(
                f"unknown job_id {job_id!r}", code="unknown_job", known=sorted(self._jobs)[-10:]
            )
        return job

    def status(self, job_id: str) -> dict[str, Any]:
        return self.get(job_id).brief()

    def fetch(self, job_id: str) -> dict[str, Any]:
        """Return the finished payload, or the reason it is not ready."""
        job = self.get(job_id)
        if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
            return {**job.brief(), "ready": False}
        if job.status is JobStatus.FAILED:
            return {**job.brief(), "ready": True, "ok": False}
        return {**job.brief(), "ready": True, "ok": True, "result": job.result}

    async def cancel(self, job_id: str) -> dict[str, Any]:
        job = self.get(job_id)
        if job._task and not job._task.done():
            job._task.cancel()
            try:
                await job._task
            except asyncio.CancelledError:
                # Expected: this is the cancellation we just requested.
                pass
            except Exception as exc:  # noqa: BLE001
                # The job failed while being cancelled. Recorded rather than
                # swallowed — a scan that died mid-cancel is worth knowing about.
                log.debug("job %s raised during cancellation: %s", job_id, exc)
                job.error = job.error or f"error during cancellation: {exc}"
        return job.brief()

    async def wait(self, job_id: str, timeout: float = 60.0) -> dict[str, Any]:
        """Block for a bounded time — useful when a scan is nearly done."""
        job = self.get(job_id)
        if job._task:
            try:
                await asyncio.wait_for(asyncio.shield(job._task), timeout=timeout)
            except TimeoutError:
                return {**job.brief(), "ready": False, "timed_out": True}
        return self.fetch(job_id)

    def list(self, *, status: str | None = None) -> list[dict[str, Any]]:
        jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status.value == status]
        return [j.brief() for j in jobs]

    # -- slicing ------------------------------------------------------------ #

    def slice(
        self,
        job_id: str,
        *,
        path: str | None = None,
        where: str | None = None,
        fields: list[str] | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Pull one window of a job's result instead of the whole thing.

        ``path``   dotted path into the result (``"findings"``, ``"result.hosts"``)
        ``where``  case-insensitive regex the serialized item must match
        ``fields`` keep only these keys of each item — the biggest token saver
        """
        job = self.get(job_id)
        if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
            return {**job.brief(), "ready": False}

        node: Any = job.result
        if path:
            for part in path.split("."):
                if isinstance(node, dict) and part in node:
                    node = node[part]
                elif isinstance(node, list) and part.isdigit():
                    node = node[int(part)]
                else:
                    return {
                        "job_id": job_id,
                        "error": f"path {path!r} not found in result",
                        "available": sorted(node)[:40] if isinstance(node, dict) else None,
                    }

        if not isinstance(node, list):
            return {"job_id": job_id, "path": path, "value": node}

        items = node
        if where:
            try:
                pattern = re.compile(where, re.IGNORECASE)
            except re.error as exc:
                return {"job_id": job_id, "error": f"invalid 'where' regex: {exc}"}
            items = [i for i in items if pattern.search(json.dumps(i, default=str))]

        total = len(items)
        window = items[offset : offset + max(1, min(limit, 500))]
        if fields:
            window = [
                {k: v for k, v in item.items() if k in fields} if isinstance(item, dict) else item
                for item in window
            ]

        return {
            "job_id": job_id,
            "path": path,
            "total": total,
            "offset": offset,
            "returned": len(window),
            "has_more": offset + len(window) < total,
            "items": window,
        }

    def slice_file(
        self, path: str | Path, *, where: str | None = None, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        """Same idea, straight off a raw output file on disk."""
        file_path = Path(path)
        if not file_path.is_file():
            return {"error": f"no such raw output file: {file_path}"}
        pattern = re.compile(where, re.IGNORECASE) if where else None
        matched: list[str] = []
        total = 0
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if pattern and not pattern.search(line):
                    continue
                total += 1
                if total > offset and len(matched) < limit:
                    matched.append(line.rstrip("\n"))
        return {
            "path": str(file_path),
            "total_matching": total,
            "offset": offset,
            "returned": len(matched),
            "lines": matched,
        }

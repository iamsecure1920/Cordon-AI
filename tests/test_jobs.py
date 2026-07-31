"""Async launch/fetch and result slicing."""

from __future__ import annotations

import asyncio

import pytest

from easyhunt.control_plane.jobs import JobManager, JobStatus
from easyhunt.errors import EasyHuntError


@pytest.fixture
def jobs() -> JobManager:
    return JobManager()


class TestLifecycle:
    async def test_launch_returns_immediately(self, jobs: JobManager) -> None:
        async def slow(job) -> dict:  # noqa: ANN001
            await asyncio.sleep(0.2)
            return {"done": True}

        job = jobs.launch(slow, tool="bbot_scan", phase="recon", targets=["example.com"])
        assert jobs.status(job.id)["status"] in {"queued", "running"}
        assert not jobs.fetch(job.id)["ready"]
        await asyncio.sleep(0.3)
        payload = jobs.fetch(job.id)
        assert payload["ready"] and payload["result"] == {"done": True}

    async def test_progress_is_visible_while_running(self, jobs: JobManager) -> None:
        async def chatty(job) -> dict:  # noqa: ANN001
            for i in range(3):
                job.progress = f"step {i}"
                job.events_seen = i * 10
                await asyncio.sleep(0.05)
            return {"ok": True}

        job = jobs.launch(chatty, tool="nuclei_scan", phase="vuln_scan", targets=["example.com"])
        await asyncio.sleep(0.08)
        status = jobs.status(job.id)
        assert status["progress"].startswith("step")
        await asyncio.sleep(0.25)

    async def test_failure_is_captured_not_raised(self, jobs: JobManager) -> None:
        async def boom(job) -> dict:  # noqa: ANN001
            raise ValueError("scanner died")

        job = jobs.launch(boom, tool="x", phase="recon", targets=[])
        await asyncio.sleep(0.05)
        payload = jobs.fetch(job.id)
        assert payload["status"] == JobStatus.FAILED.value
        assert "scanner died" in payload["error"]

    async def test_cancel_stops_the_job(self, jobs: JobManager) -> None:
        async def forever(job) -> dict:  # noqa: ANN001
            await asyncio.sleep(30)
            return {}

        job = jobs.launch(forever, tool="x", phase="recon", targets=[])
        await asyncio.sleep(0.05)
        assert (await jobs.cancel(job.id))["status"] == JobStatus.CANCELLED.value

    async def test_wait_times_out_without_blocking_forever(self, jobs: JobManager) -> None:
        async def slow(job) -> dict:  # noqa: ANN001
            await asyncio.sleep(5)
            return {}

        job = jobs.launch(slow, tool="x", phase="recon", targets=[])
        payload = await jobs.wait(job.id, timeout=0.1)
        assert payload.get("timed_out")
        await jobs.cancel(job.id)

    def test_unknown_job_id_is_an_explicit_error(self, jobs: JobManager) -> None:
        with pytest.raises(EasyHuntError, match="unknown job_id"):
            jobs.status("nope-0001")


class TestSlicing:
    @pytest.fixture
    async def finished(self, jobs: JobManager) -> tuple[JobManager, str]:
        async def produce(job) -> dict:  # noqa: ANN001
            return {
                "findings": [
                    {"host": f"h{i}.example.com", "severity": "high" if i % 10 == 0 else "info",
                     "blob": "x" * 200}
                    for i in range(100)
                ],
                "count": 100,
            }

        job = jobs.launch(produce, tool="nuclei_scan", phase="vuln_scan", targets=["example.com"])
        await asyncio.sleep(0.05)
        return jobs, job.id

    async def test_window(self, finished) -> None:
        jobs, job_id = finished
        page = jobs.slice(job_id, path="findings", offset=10, limit=5)
        assert page["returned"] == 5
        assert page["total"] == 100
        assert page["has_more"]
        assert page["items"][0]["host"] == "h10.example.com"

    async def test_where_filter(self, finished) -> None:
        jobs, job_id = finished
        page = jobs.slice(job_id, path="findings", where="high", limit=100)
        assert page["total"] == 10

    async def test_field_projection_shrinks_the_payload(self, finished) -> None:
        jobs, job_id = finished
        page = jobs.slice(job_id, path="findings", fields=["host", "severity"], limit=3)
        assert set(page["items"][0]) == {"host", "severity"}

    async def test_bad_path_explains_what_is_available(self, finished) -> None:
        jobs, job_id = finished
        page = jobs.slice(job_id, path="nope")
        assert "not found" in page["error"]
        assert "findings" in page["available"]

    async def test_invalid_regex_is_reported_not_raised(self, finished) -> None:
        jobs, job_id = finished
        assert "invalid" in jobs.slice(job_id, path="findings", where="[bad(")["error"]

    async def test_scalar_path_returns_the_value(self, finished) -> None:
        jobs, job_id = finished
        assert jobs.slice(job_id, path="count")["value"] == 100

    def test_file_slicing(self, jobs: JobManager, tmp_path) -> None:
        path = tmp_path / "raw.jsonl"
        path.write_text("\n".join(f'{{"host":"h{i}.example.com","sev":"high"}}' for i in range(50)))
        page = jobs.slice_file(path, where="h4[0-9]", limit=100)
        assert page["total_matching"] == 10

    def test_missing_file_is_reported(self, jobs: JobManager, tmp_path) -> None:
        assert "no such raw output file" in jobs.slice_file(tmp_path / "absent.jsonl")["error"]

"""Async process runner.

Everything executes via ``exec`` with an argv list — no shell, ever. Output is
capped in memory and spilled to the engagement workspace, because a scanner that
prints 400 MB of banners should not be able to take the MCP session with it.

Timeouts kill the whole process group: security tools spawn children, and a
`terminate()` on the parent alone leaves scans running against a target after the
operator thinks they stopped.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

from easyhunt.control_plane.sandbox import ExecPlan
from easyhunt.errors import ToolFailed

__all__ = ["ProcResult", "run_process", "stream_process"]

DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024  # 32 MiB held in memory per stream


@dataclass
class ProcResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False
    output_path: Path | None = None
    env: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def output_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.stdout.encode("utf-8", "replace")).hexdigest()[:32]

    def raise_for_status(self, *, tool: str, allow_codes: tuple[int, ...] = (0,)) -> ProcResult:
        if self.timed_out:
            raise ToolFailed(
                f"{tool} timed out after {self.duration_s:.0f}s",
                tool=tool,
                stderr=self.stderr[-2000:],
            )
        if self.exit_code not in allow_codes:
            raise ToolFailed(
                f"{tool} exited {self.exit_code}",
                tool=tool,
                exit_code=self.exit_code,
                stderr=self.stderr[-2000:],
            )
        return self


def _spawn_kwargs() -> dict[str, object]:
    # New session so the timeout path can signal the entire process group.
    return {"start_new_session": True} if hasattr(os, "setsid") else {}


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError):
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass


async def run_process(
    plan: ExecPlan,
    *,
    timeout: float = 900.0,
    stdin: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    output_path: Path | None = None,
) -> ProcResult:
    """Run a planned command to completion.

    ``output_path`` receives the full stdout regardless of the in-memory cap, so
    a truncated return value can still be sliced later with ``fetch_slice``.
    """
    started = time.monotonic()
    env = {**os.environ, **plan.env}
    try:
        proc = await asyncio.create_subprocess_exec(
            *plan.argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(plan.cwd) if plan.cwd else None,
            env=env,
            **_spawn_kwargs(),
        )
    except (OSError, ValueError) as exc:
        raise ToolFailed(f"failed to start process: {exc}", argv=plan.argv[:3]) from exc

    timed_out = False
    try:
        raw_out, raw_err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout
        )
    except TimeoutError:
        timed_out = True
        await _kill_tree(proc)
        raw_out, raw_err = b"", b"killed after timeout"
    except asyncio.CancelledError:
        await _kill_tree(proc)
        raise

    duration = time.monotonic() - started

    if output_path is not None and raw_out:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(raw_out)

    truncated = len(raw_out) > max_output_bytes
    stdout = raw_out[:max_output_bytes].decode("utf-8", "replace")
    stderr = raw_err[: 1024 * 1024].decode("utf-8", "replace")

    return ProcResult(
        argv=plan.argv,
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        timed_out=timed_out,
        truncated=truncated,
        output_path=output_path,
    )


async def stream_process(
    plan: ExecPlan,
    *,
    timeout: float = 3600.0,
    stdin: str | None = None,
    output_path: Path | None = None,
) -> AsyncIterator[str]:
    """Yield stdout line by line as it arrives.

    Used by long-running engines so findings reach the store during the scan
    rather than only at the end of it.
    """
    env = {**os.environ, **plan.env}
    proc = await asyncio.create_subprocess_exec(
        *plan.argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=str(plan.cwd) if plan.cwd else None,
        env=env,
        **_spawn_kwargs(),
    )
    if stdin is not None and proc.stdin is not None:
        proc.stdin.write(stdin.encode())
        await proc.stdin.drain()
        proc.stdin.close()

    sink = None
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        sink = output_path.open("wb")

    deadline = time.monotonic() + timeout
    try:
        if proc.stdout is None:  # pragma: no cover — PIPE is always requested above
            raise ToolFailed("process was started without a stdout pipe", argv=plan.argv[:3])
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await _kill_tree(proc)
                break
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except TimeoutError:
                await _kill_tree(proc)
                break
            if not line:
                break
            if sink is not None:
                sink.write(line)
            yield line.decode("utf-8", "replace").rstrip("\n")
        await proc.wait()
    except asyncio.CancelledError:
        await _kill_tree(proc)
        raise
    finally:
        if sink is not None:
            sink.close()

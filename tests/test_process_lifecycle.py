"""Process runner lifecycle: a spawned tool must not outlive the process that
started it.

``start_new_session=True`` lets the timeout path ``killpg`` a tool and its
children. The cost of that detachment was an orphan: an *externally* killed
parent (a terminal timeout on ``hunt.sh``, a Ctrl+C on the MCP server) killed the
driver but left the tool running against a target the engagement believed it had
stopped. ``PR_SET_PDEATHSIG`` closes that hole by asking the kernel to signal the
child the moment its parent dies.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from cordon.util.run import _set_pdeathsig, _spawn_kwargs

IS_LINUX = sys.platform.startswith("linux")


def test_spawn_kwargs_detach_on_posix() -> None:
    """POSIX: the child is a session leader so the timeout path can killpg it."""
    if not hasattr(os, "setsid"):
        pytest.skip("POSIX-only")
    assert _spawn_kwargs()["start_new_session"] is True


def test_spawn_kwargs_set_pdeathsig_on_linux() -> None:
    """Linux: the child additionally dies with its parent (PR_SET_PDEATHSIG)."""
    if not IS_LINUX:
        pytest.skip("Linux-only")
    assert _spawn_kwargs()["preexec_fn"] is _set_pdeathsig


def test_set_pdeathsig_is_best_effort() -> None:
    """The guard runs in the child pre-exec and must never raise."""
    _set_pdeathsig()  # no exception on any platform


@pytest.mark.skipif(not IS_LINUX, reason="PR_SET_PDEATHSIG is Linux-only")
def test_child_dies_when_parent_dies() -> None:
    """A process spawned with the runner's kwargs is killed when its parent exits.

    This is the regression test for the subdominator orphan: a tool whose driver
    was killed externally must stop, not keep scanning for an hour.
    """
    read_fd, write_fd = os.pipe()
    parent = os.fork()
    if parent == 0:
        # The "driver": spawns a long-lived child and exits without killing it.
        os.close(read_fd)
        try:
            proc = subprocess.Popen(  # noqa: S603
                [sys.executable, "-c", "import time; time.sleep(30)"],
                **_spawn_kwargs(),
            )
            os.write(write_fd, str(proc.pid).encode())
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    try:
        child_pid = int(os.read(read_fd, 64).decode())
    finally:
        os.close(read_fd)

    os.waitpid(parent, 0)
    # Give the kernel a moment to deliver the parent-death signal.
    deadline = time.time() + 5.0
    while True:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break  # died with its parent, as required
        if time.time() > deadline:
            os.kill(child_pid, signal.SIGKILL)
            pytest.fail(f"child {child_pid} survived its parent's death")
        time.sleep(0.05)

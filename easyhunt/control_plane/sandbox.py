"""Execution sandbox — one container per tool invocation.

Each wrapped binary runs in its own short-lived container with no capabilities, a
read-only root filesystem, memory/CPU ceilings, and exactly one writable mount:
the engagement workspace. Raw-socket tools (naabu, nmap SYN scans) may request
``NET_RAW``/``NET_ADMIN`` and nothing else — the capability allowlist is closed.

``mode: none`` runs on the host instead. That is the right choice inside an
already-isolated VM and the wrong choice on a workstation, so the mode is
recorded in every audit line rather than being assumed.

The sandbox does not decide *whether* a tool may run — that is the scope engine,
the sanitizer, and the approval gate. It decides how much of the host a tool can
reach once those have already said yes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from easyhunt.errors import ToolUnavailable

__all__ = ["ExecPlan", "Sandbox", "SandboxConfig"]

# The only capabilities a wrapped tool may ever ask for.
ALLOWED_CAPABILITIES = frozenset({"NET_RAW", "NET_ADMIN"})

CONTAINER_WORKDIR = "/work"


@dataclass
class SandboxConfig:
    mode: str = "docker"  # docker | none
    fallback_to_host: bool = True
    default_network: str = "bridge"
    memory: str = "2g"
    cpus: str = "2.0"
    read_only_rootfs: bool = True
    drop_all_capabilities: bool = True
    images: dict[str, str] = field(default_factory=dict)
    runtime: str = "docker"
    pull: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SandboxConfig:
        data = data or {}
        return cls(
            mode=str(data.get("mode", "docker")).lower(),
            fallback_to_host=bool(data.get("fallback_to_host", True)),
            default_network=str(data.get("default_network", "bridge")),
            memory=str(data.get("memory", "2g")),
            cpus=str(data.get("cpus", "2.0")),
            read_only_rootfs=bool(data.get("read_only_rootfs", True)),
            drop_all_capabilities=bool(data.get("drop_all_capabilities", True)),
            images=dict(data.get("images") or {}),
            runtime=str(data.get("runtime", "docker")),
            pull=bool(data.get("pull", False)),
        )


@dataclass
class ExecPlan:
    """A concrete command, ready to hand to the process runner."""

    argv: list[str]
    sandboxed: bool
    image: str | None = None
    note: str = ""
    cwd: Path | None = None
    env: dict[str, str] = field(default_factory=dict)

    def describe(self) -> dict[str, Any]:
        return {
            "sandboxed": self.sandboxed,
            "image": self.image,
            "note": self.note,
            "argv_len": len(self.argv),
        }


class Sandbox:
    def __init__(
        self,
        config: SandboxConfig,
        *,
        workspace: Path,
        user_agent: str = "EasyHunt-AI/2.0",
    ) -> None:
        self.config = config
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.user_agent = user_agent

    # -- availability ------------------------------------------------------- #

    @lru_cache(maxsize=1)  # noqa: B019 — one Sandbox per engagement, bounded
    def runtime_available(self) -> bool:
        if self.config.mode != "docker":
            return False
        binary = shutil.which(self.config.runtime)
        if not binary:
            return False
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def image_present(self, image: str) -> bool:
        binary = shutil.which(self.config.runtime)
        if not binary:
            return False
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, "image", "inspect", image],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def image_for(self, tool: str) -> str | None:
        return self.config.images.get(tool)

    # -- planning ----------------------------------------------------------- #

    def plan(
        self,
        *,
        tool: str,
        binary: str,
        argv: list[str],
        network: str | None = None,
        capabilities: list[str] | None = None,
        env: dict[str, str] | None = None,
        extra_mounts: list[tuple[Path, str, str]] | None = None,
        timeout_hint: int | None = None,
    ) -> ExecPlan:
        """Build the command to execute, sandboxed if possible.

        Raises :class:`ToolUnavailable` when neither a container image nor a host
        binary can satisfy the request — the caller should surface that rather
        than silently skipping a phase.
        """
        caps = [c.upper() for c in (capabilities or [])]
        rejected = [c for c in caps if c not in ALLOWED_CAPABILITIES]
        if rejected:
            raise ToolUnavailable(
                f"tool {tool!r} requested disallowed capabilities {rejected}",
                tool=tool,
                allowed=sorted(ALLOWED_CAPABILITIES),
            )

        image = self.image_for(tool)
        if self.config.mode == "docker" and image and self.runtime_available():
            if self.image_present(image) or self.config.pull:
                return self._docker_plan(
                    tool=tool,
                    image=image,
                    argv=argv,
                    network=network,
                    capabilities=caps,
                    env=env,
                    extra_mounts=extra_mounts,
                )
            if not self.config.fallback_to_host:
                raise ToolUnavailable(
                    f"container image {image!r} for {tool} is not present "
                    "(pull it, or enable sandbox.fallback_to_host)",
                    tool=tool,
                    image=image,
                )

        # Host execution.
        resolved = shutil.which(binary)
        if not resolved:
            raise ToolUnavailable(
                f"{tool}: neither a sandbox image nor the host binary {binary!r} is available",
                tool=tool,
                binary=binary,
                image=image,
            )
        if self.config.mode == "docker" and not self.config.fallback_to_host:
            raise ToolUnavailable(
                f"{tool}: sandbox mode is 'docker' with fallback disabled, and no image is configured",
                tool=tool,
            )

        note = "host execution"
        if self.config.mode == "docker":
            note = "host execution (sandbox unavailable — fallback_to_host)"
        return ExecPlan(
            argv=[resolved, *argv],
            sandboxed=False,
            image=None,
            note=note,
            cwd=self.workspace,
            env=self._base_env(env),
        )

    def _docker_plan(
        self,
        *,
        tool: str,
        image: str,
        argv: list[str],
        network: str | None,
        capabilities: list[str],
        env: dict[str, str] | None,
        extra_mounts: list[tuple[Path, str, str]] | None,
    ) -> ExecPlan:
        runtime = shutil.which(self.config.runtime) or self.config.runtime
        command = [
            runtime,
            "run",
            "--rm",
            "--init",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            self.config.memory,
            "--cpus",
            self.config.cpus,
            "--network",
            network or self.config.default_network,
            "--workdir",
            CONTAINER_WORKDIR,
            # Writable scratch even with a read-only root, so tools that insist on
            # /tmp do not need the host filesystem.
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            "-v",
            f"{self.workspace}:{CONTAINER_WORKDIR}:rw",
        ]
        if self.config.drop_all_capabilities:
            command += ["--cap-drop", "ALL"]
        for cap in capabilities:
            command += ["--cap-add", cap]
        if self.config.read_only_rootfs:
            command.append("--read-only")
        # Run as the invoking user so artifacts written into the workspace stay
        # readable outside the container.
        with_uid = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None
        if with_uid:
            command += ["--user", with_uid]
        for key, value in self._base_env(env).items():
            command += ["-e", f"{key}={value}"]
        for host_path, container_path, mode in extra_mounts or []:
            command += ["-v", f"{Path(host_path).resolve()}:{container_path}:{mode}"]
        command.append(image)
        command += self._translate_paths(argv)
        return ExecPlan(
            argv=command,
            sandboxed=True,
            image=image,
            note=f"docker: {image}",
            cwd=self.workspace,
            env={},
        )

    def _translate_paths(self, argv: list[str]) -> list[str]:
        """Rewrite host workspace paths to their in-container equivalents."""
        root = str(self.workspace)
        out = []
        for item in argv:
            if item.startswith(root):
                out.append(CONTAINER_WORKDIR + item[len(root) :])
            else:
                out.append(item)
        return out

    def _base_env(self, env: dict[str, str] | None) -> dict[str, str]:
        base = {"EASYHUNT_USER_AGENT": self.user_agent}
        base.update(env or {})
        return base

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.config.mode,
            "runtime": self.config.runtime,
            "runtime_available": self.runtime_available(),
            "fallback_to_host": self.config.fallback_to_host,
            "workspace": str(self.workspace),
            "images_configured": len(self.config.images),
            "user_agent": self.user_agent,
        }

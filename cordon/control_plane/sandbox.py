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

Two images, two shapes
----------------------
``sandbox.images`` maps a tool to a **single-tool image** whose ``ENTRYPOINT`` is
already that binary (``projectdiscovery/nuclei``); the arguments are appended and
nothing else. ``sandbox.default_image`` names one **multi-tool image** — the
2.7 GB ``cordon:latest`` this repo builds — that carries ~40 binaries at once;
there the binary name has to be passed as the first argument or the image's
entrypoint has nothing to exec.

That distinction is why the default image cannot simply be written into
``images`` 49 times: the two shapes take different argv. The rule is one line —
*if the resolved image is ``default_image``, prepend the binary* — and both
mappings keep working side by side, single-tool images winning where they exist.

Nothing is assumed about what the shared image contains. A build that reported
``!!! FAILED: aderyn`` still produces an image, and a config listing aderyn would
then launch a container that exits 127 "not found". So before the default image
is used for a tool, the binary is *probed for inside it* (:meth:`binary_in_image`,
cached) under the same user and read-only constraints the real run gets. A tool
the image does not actually carry falls back to the host — visibly.

Fallback is never silent
------------------------
Host fallback is the failure mode this module exists to prevent, so every
occurrence is (a) recorded on the plan as :attr:`ExecPlan.fallback_reason`,
(b) accumulated on the sandbox and returned by :meth:`fallback_report`,
(c) logged at WARNING, and (d) written to the engagement's hash-chained audit log
as a ``sandbox_fallback`` event, readable through the ``audit_tail`` MCP tool.
A mapping that quietly degraded to host execution would be indistinguishable
from a sandbox that worked.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from cordon.errors import ToolUnavailable

__all__ = ["ExecPlan", "Sandbox", "SandboxConfig"]

log = logging.getLogger("cordon.sandbox")

# The only capabilities a wrapped tool may ever ask for.
ALLOWED_CAPABILITIES = frozenset({"NET_RAW", "NET_ADMIN"})

CONTAINER_WORKDIR = "/work"

#: Environment forced on the multi-tool image. Its entrypoint prints a 20-line
#: notice to stderr when the vetted payload store is absent, and wrappers surface
#: stderr as the tool's error text — a banner there reads as a tool failure.
SHARED_IMAGE_ENV = {"CORDON_QUIET": "1"}

#: How long a "does this image contain this binary" probe may take.
PROBE_TIMEOUT = 30


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
    #: One multi-tool image used for every tool without its own entry. Empty
    #: string disables it and restores the pre-2.1 "mapped tools only" behaviour.
    default_image: str = ""
    #: Probe the multi-tool image for the binary before committing to it.
    #: Turning this off trades a ~0.4 s once-per-tool check for containers that
    #: exit 127 when the image was built without that tool.
    verify_image_binary: bool = True
    #: Per-tool Docker network mode. ``none`` for anything that analyses local
    #: files: a static analyser with a route to the internet is unnecessary reach.
    networks: dict[str, str] = field(default_factory=dict)
    #: Per-tool extra bind mounts, ``"HOST:CONTAINER[:MODE]"``, MODE defaulting
    #: to ``ro``. Absent host paths are skipped rather than mounted, because
    #: Docker would otherwise create an empty directory that looks configured.
    mounts: dict[str, list[str]] = field(default_factory=dict)
    #: Per-tool writable scratch directories carved out of the read-only root.
    #: A container that cannot create its own cache dir dies on import.
    tmpfs: dict[str, list[str]] = field(default_factory=dict)
    #: Per-tool uid:gid override, or the literal "image" to accept the image's
    #: own USER. Only for images that cannot run as the host user.
    users: dict[str, str] = field(default_factory=dict)
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
            default_image=str(data.get("default_image") or ""),
            verify_image_binary=bool(data.get("verify_image_binary", True)),
            networks={str(k): str(v) for k, v in (data.get("networks") or {}).items()},
            mounts={
                str(k): [str(m) for m in (v or [])]
                for k, v in (data.get("mounts") or {}).items()
            },
            users={str(k): str(v) for k, v in (data.get("users") or {}).items()},
            tmpfs={
                str(k): [str(p) for p in (v or [])]
                for k, v in (data.get("tmpfs") or {}).items()
            },
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
    tool: str = ""
    #: Docker network mode for a sandboxed plan; ``"host"`` for host execution,
    #: which is the truth — an unsandboxed process has the host's whole stack.
    network: str = ""
    #: Why this plan is not sandboxed. Empty when the plan is sandboxed, or when
    #: the sandbox is switched off entirely (``mode: none`` is a choice, not a
    #: degradation).
    fallback_reason: str = ""

    @property
    def fell_back(self) -> bool:
        """True when a sandbox was wanted and the host was used instead."""
        return not self.sandboxed and bool(self.fallback_reason)

    def describe(self) -> dict[str, Any]:
        return {
            "sandboxed": self.sandboxed,
            "image": self.image,
            "network": self.network,
            "note": self.note,
            "fell_back": self.fell_back,
            "fallback_reason": self.fallback_reason or None,
            "argv_len": len(self.argv),
        }


class Sandbox:
    def __init__(
        self,
        config: SandboxConfig,
        *,
        workspace: Path,
        user_agent: str = "Cordon-AI/2.0",
    ) -> None:
        self.config = config
        self.workspace = Path(workspace).resolve()
        # Kept unresolved as well: see :attr:`_workspace_prefixes`.
        self._workspace_given = Path(workspace).absolute()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.user_agent = user_agent
        #: tool -> reason, every host fallback this engagement has taken.
        self.fallbacks: dict[str, str] = {}
        #: Cache for :meth:`binary_in_image`; probes spawn containers.
        self._probe_cache: dict[tuple[str, str], bool] = {}

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

    def binary_in_image(self, image: str, binary: str) -> bool:
        """Whether ``binary`` resolves on PATH inside ``image``.

        Run under the same ``--user`` and ``--read-only`` constraints as the real
        invocation, because "root can see it" is not the question — the question
        is whether the process we are about to start can execute it. The shared
        image installs several tools under ``/root/.local/bin``, which a non-root
        container user cannot traverse, and that has to read as absent rather
        than as a container that starts and immediately exits 127.

        Cached per (image, binary): this spawns a container.
        """
        key = (image, binary)
        cached = self._probe_cache.get(key)
        if cached is not None:
            return cached

        runtime = shutil.which(self.config.runtime)
        if not runtime:
            return False
        command = [
            runtime, "run", "--rm", "--init",
            "--network", "none",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--entrypoint", "sh",
        ]
        if self.config.read_only_rootfs:
            command.append("--read-only")
        user = self._container_user(binary)
        if user:
            command += ["--user", user]
        command += [image, "-c", 'command -v "$1" >/dev/null 2>&1', "_", binary]
        try:
            proc = subprocess.run(  # noqa: S603
                command, capture_output=True, timeout=PROBE_TIMEOUT, check=False
            )
            found = proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            # An unreadable answer is not a yes. Falling back to the host is
            # recoverable; a container that exits 127 mid-engagement is not.
            found = False
        self._probe_cache[key] = found
        return found

    def run_in_image(
        self, image: str, binary: str, args: list[str], *, tool: str | None = None
    ) -> tuple[int | None, str]:
        """Execute ``binary args`` inside ``image`` under the real run's constraints.

        ``binary_in_image`` answers "is it on PATH", which is the same question
        ``shutil.which`` answers on the host — and this project has now been
        bitten by that answer four times. sstimap is on PATH inside the image and
        crashes on every invocation: ``utils/config.py`` calls
        ``os.makedirs("~/.sstimap")`` at module scope and the container root is
        read-only. ``command -v`` says yes; the tool has never once run.

        So this starts it. Same read-only root, same dropped capabilities, same
        user, and — importantly — the same per-tool tmpfs mounts, because a probe
        that runs with scratch the real invocation lacks (or without scratch the
        real invocation has) is answering about a different program.

        Returns (exit code or None on timeout, combined output).
        """
        runtime = shutil.which(self.config.runtime)
        if not runtime:
            return None, "container runtime not installed"

        command = [
            runtime, "run", "--rm", "--init",
            "--network", "none",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            # A writable working directory, because the real invocation has one:
            # `_docker_plan` sets --workdir to the engagement workspace, which is
            # bind-mounted rw. Probing with the image's own WORKDIR under a
            # read-only root is stricter than the real run, and a probe that is
            # stricter than the thing it models reports failures that will not
            # happen. cloudfox opens ./cloudfox-error.log at init and panicked
            # here while working fine in an engagement.
            "--workdir", "/tmp",
        ]
        for scratch in self.config.tmpfs.get(tool or binary, []):
            command += ["--tmpfs", f"{scratch}:rw,nosuid,size=64m"]
        if self.config.read_only_rootfs:
            command.append("--read-only")
        user = self._container_user(tool or binary)
        if user:
            command += ["--user", user]
        # Mirror `_docker_plan`: a single-tool image's ENTRYPOINT *is* the binary,
        # and overriding it breaks images that run as their own user with the
        # tool outside root's PATH. prowler is exactly that — ENTRYPOINT
        # /home/prowler/.venv/bin/prowler, USER prowler — and `--entrypoint
        # prowler` gave "exec prowler failed: Permission denied", which reads as
        # a broken tool rather than as a probe asking the wrong question.
        #
        # Only the shared image needs the name appended; its entrypoint execs
        # whatever it is handed.
        # Not every mapped image sets ENTRYPOINT to the tool: prowler does,
        # semgrep does not. Guessing either way makes a working tool read as
        # broken (permission denied) or absent (exit 127). Try the image's own
        # entrypoint first, and fall back to naming the binary — the fallback is
        # what the shared image needs anyway.
        shared = image == self.config.default_image
        attempts = (
            [["--entrypoint", binary, image, *args]]
            if shared
            else [[image, *args], ["--entrypoint", binary, image, *args]]
        )
        last: tuple[int | None, str] = (None, "")
        for attempt in attempts:
            result = self._run_container(command + attempt)
            code, output = result
            # 125/126/127 are docker's own "could not start" codes, not the
            # tool's opinion of its arguments.
            if code not in (125, 126, 127):
                return result
            last = result
        return last

    def _run_container(self, command: list[str]) -> tuple[int | None, str]:

        try:
            proc = subprocess.run(  # noqa: S603
                command, capture_output=True, text=True,
                timeout=PROBE_TIMEOUT, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"", exc.stderr or b"")
            decoded = "".join(
                part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                for part in out
            )
            return None, decoded
        except OSError as exc:
            return None, str(exc)
        return proc.returncode, f"{proc.stdout}\n{proc.stderr}"

    def image_for(self, tool: str) -> str | None:
        """The image this tool runs in, or None when it has no container home."""
        return self.config.images.get(tool) or (self.config.default_image or None)

    def is_shared_image(self, image: str | None) -> bool:
        """Whether ``image`` is the multi-tool image (argv needs the binary name).

        Explicitly mapping a tool to the same value as ``default_image`` is
        treated as shared too, so ``images: {sqlmap: cordon:latest}`` behaves
        the way anyone writing it would expect.
        """
        return bool(image) and image == self.config.default_image

    def network_for(self, tool: str, explicit: str | None = None) -> str:
        """Network mode for a tool: caller's choice, then config, then default."""
        return explicit or self.config.networks.get(tool) or self.config.default_network

    # -- planning ----------------------------------------------------------- #

    def plan(
        self,
        *,
        tool: str,
        binary: str,
        argv: list[str],
        host_binary: str | None = None,
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

        wanted_network = self.network_for(tool, network)
        image = self.image_for(tool)
        reason = ""

        if self.config.mode == "docker":
            reason = self._why_not_sandboxed(tool=tool, binary=binary, image=image)
            if not reason and image:
                return self._docker_plan(
                    tool=tool,
                    binary=binary,
                    image=image,
                    argv=argv,
                    network=wanted_network,
                    capabilities=caps,
                    env=env,
                    extra_mounts=extra_mounts,
                )
            if not self.config.fallback_to_host:
                raise ToolUnavailable(
                    f"{tool}: cannot be sandboxed ({reason}) and "
                    "sandbox.fallback_to_host is disabled",
                    tool=tool,
                    image=image,
                    reason=reason,
                )

        # Host execution. `host_binary` is the identity-resolved absolute path
        # when the caller had one — it is meaningful HERE and nowhere else. It
        # must never reach the container branch above: an absolute host path has
        # no meaning inside an image, and `command -v /usr/bin/amass` fails there
        # whatever the image contains.
        resolved = shutil.which(host_binary or binary) or (
            host_binary if host_binary and Path(host_binary).is_file() else None
        )
        if not resolved:
            raise ToolUnavailable(
                f"{tool}: neither a sandbox image nor the host binary {binary!r} is available"
                + (f" ({reason})" if reason else ""),
                tool=tool,
                binary=binary,
                image=image,
                reason=reason,
            )

        note = "host execution"
        if reason:
            note = f"host execution (NOT SANDBOXED — {reason})"
            if wanted_network == "none":
                # Worth its own sentence: on the host there is no way to withhold
                # the network from a process that was configured not to have one.
                note += "; requested network isolation 'none' is NOT enforced on the host"
            self._note_fallback(tool, reason)
        return ExecPlan(
            argv=[resolved, *argv],
            sandboxed=False,
            image=None,
            note=note,
            cwd=self.workspace,
            env=self._base_env(env),
            tool=tool,
            network="host",
            fallback_reason=reason,
        )

    def _why_not_sandboxed(self, *, tool: str, binary: str, image: str | None) -> str:
        """Empty string when the tool can run in a container; else the reason."""
        if not self.runtime_available():
            return f"the {self.config.runtime} runtime is not available"
        if not image:
            return (
                "no image is mapped for this tool and sandbox.default_image is unset"
            )
        if not (self.image_present(image) or self.config.pull):
            return f"image {image!r} is not present locally (pull it, or set sandbox.pull)"
        if (
            self.is_shared_image(image)
            and self.config.verify_image_binary
            and not self.binary_in_image(image, binary)
        ):
            return f"{binary!r} is not executable inside {image}"
        return ""

    def _note_fallback(self, tool: str, reason: str) -> None:
        """Make one host fallback impossible to miss."""
        if self.fallbacks.get(tool) == reason:
            return  # already reported this engagement; do not flood the chain
        self.fallbacks[tool] = reason
        log.warning(
            "SANDBOX FALLBACK: %s ran on the HOST, not in a container — %s", tool, reason
        )
        self._audit_fallback(tool, reason)

    def _audit_fallback(self, tool: str, reason: str) -> None:
        """Write the fallback to the engagement's tamper-evident audit log.

        Best-effort and deliberately quiet on failure: a sandbox that cannot find
        its engagement must still run the tool. The WARNING above and
        :meth:`fallback_report` remain regardless.
        """
        try:
            from cordon.control_plane.context import current_engagement

            engagement = current_engagement()
            if engagement is None or getattr(engagement, "sandbox", None) is not self:
                return
            engagement.audit.record(
                "sandbox_fallback",
                tool=tool,
                reason=reason,
                runtime=self.config.runtime,
                configured_mode=self.config.mode,
                default_image=self.config.default_image or None,
            )
        except Exception:  # noqa: BLE001 — never fail a tool over its own audit line
            log.debug("could not audit sandbox fallback for %s", tool, exc_info=True)

    def fallback_report(self) -> list[dict[str, str]]:
        """Every host fallback so far, ready to embed in a tool result."""
        return [{"tool": t, "reason": r} for t, r in sorted(self.fallbacks.items())]

    def _docker_plan(
        self,
        *,
        tool: str,
        binary: str,
        image: str,
        argv: list[str],
        network: str,
        capabilities: list[str],
        env: dict[str, str] | None,
        extra_mounts: list[tuple[Path, str, str]] | None,
    ) -> ExecPlan:
        runtime = shutil.which(self.config.runtime) or self.config.runtime
        shared = self.is_shared_image(image)
        mounts = [*(extra_mounts or []), *self._configured_mounts(tool)]
        taken = {container for _, container, _ in mounts}
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
            network,
            "--workdir",
            CONTAINER_WORKDIR,
            # Writable scratch even with a read-only root, so tools that insist on
            # /tmp do not need the host filesystem.
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            "-v",
            f"{self.workspace}:{CONTAINER_WORKDIR}:rw",
        ]
        # Writable scratch the tool needs but the read-only root denies. Skipped
        # where a bind mount already owns the path — Docker refuses to layer a
        # tmpfs and a bind on the same destination, and the bind is the one
        # carrying real data.
        for scratch in self.config.tmpfs.get(tool, []):
            if scratch not in taken and scratch != "/tmp":
                command += ["--tmpfs", f"{scratch}:rw,nosuid,size=64m"]
        if self.config.drop_all_capabilities:
            command += ["--cap-drop", "ALL"]
        for cap in capabilities:
            command += ["--cap-add", cap]
        if self.config.read_only_rootfs:
            command.append("--read-only")
        # Run as the invoking user so artifacts written into the workspace stay
        # readable outside the container.
        user = self._container_user(tool)
        if user:
            command += ["--user", user]
        run_env = self._base_env(env)
        if shared:
            run_env = {**SHARED_IMAGE_ENV, **run_env}
        for key, value in run_env.items():
            command += ["-e", f"{key}={value}"]
        for host_path, container_path, mode in mounts:
            command += ["-v", f"{Path(host_path).resolve()}:{container_path}:{mode}"]
        command.append(image)
        # A single-tool image's ENTRYPOINT *is* the binary; the shared image's
        # entrypoint execs whatever it is handed, so it needs the name.
        if shared:
            command.append(binary)
        command += self._translate_paths(argv)
        return ExecPlan(
            argv=command,
            sandboxed=True,
            image=image,
            note=f"docker: {image} (network={network})",
            cwd=self.workspace,
            env={},
            tool=tool,
            network=network,
        )

    def _container_user(self, tool: str | None = None) -> str | None:
        """The uid:gid to run as, or None to let the image choose.

        Default is the host user, so files written into the bind-mounted
        workspace are owned by whoever started the engagement rather than by
        root. Some published images do not tolerate it: prowler's puts its
        entrypoint behind a 0700 home owned by uid 1000, and because this
        sandbox drops ALL capabilities — including CAP_DAC_OVERRIDE — even root
        cannot traverse into it. Every prowler call failed with

            [FATAL tini] exec /home/prowler/.venv/bin/prowler: Permission denied

        which is our hardening meeting their layout, not a broken tool. Rather
        than granting the capability back for everyone, `sandbox.users` lets one
        image run as the uid it was built for.
        """
        override = self.config.users.get(tool or "")
        if override:
            return None if str(override).lower() == "image" else str(override)
        return f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None

    def _configured_mounts(self, tool: str) -> list[tuple[Path, str, str]]:
        """``sandbox.mounts`` entries for one tool, as (host, container, mode).

        The image ships a binary; the operator's home ships what the binary needs
        to do its job. Slither is the clearest case: the image's ``solc`` is a
        solc-select shim with no compiler behind it, so on a network-isolated
        container it dies resolving a version. Mounting the host's already-populated
        ``~/.solc-select`` read-only turns that into a working analyser without
        handing a Solidity parser a route to the internet.

        A host path that does not exist is skipped and logged, never mounted:
        Docker would create an empty directory, and an empty template library or
        an empty compiler cache reads as "clean estate" rather than "misconfigured".
        """
        out: list[tuple[Path, str, str]] = []
        for entry in self.config.mounts.get(tool, []):
            parts = entry.split(":")
            if len(parts) < 2:
                log.warning("sandbox.mounts[%s]: ignoring malformed entry %r", tool, entry)
                continue
            host = Path(parts[0]).expanduser()
            container = parts[1]
            mode = parts[2] if len(parts) > 2 else "ro"
            if not host.exists():
                log.warning(
                    "sandbox.mounts[%s]: %s does not exist on the host; not mounting "
                    "(an empty %s would look configured and behave as if it were not)",
                    tool, host, container,
                )
                continue
            out.append((host, container, mode))
        return out

    # -- path translation --------------------------------------------------- #

    @property
    def _workspace_prefixes(self) -> list[str]:
        """Every spelling of the workspace root a wrapper might have produced.

        ``Sandbox`` resolves its workspace; ``Engagement`` does not. When the
        configured root is a symlink (``/tmp`` on macOS, ``/var`` almost
        everywhere) or relative, wrappers build ``str(engagement.raw_path(...))``
        from the *unresolved* path and the resolved prefix never matches. The
        argument then passes through untranslated, the container writes it
        relative to ``/work``, and the wrapper reads an empty file back — a scan
        that looks clean because its output landed somewhere nobody looks.
        """
        seen: list[str] = []
        for candidate in (str(self.workspace), str(self._workspace_given)):
            if candidate and candidate != os.sep and candidate not in seen:
                seen.append(candidate)
        return seen

    def _translate_paths(self, argv: list[str]) -> list[str]:
        """Rewrite host workspace paths to their in-container equivalents."""
        return [self._translate_token(item) for item in argv]

    def _translate_token(self, token: str, *, depth: int = 0) -> str:
        """Translate one argv token, including ``--flag=PATH`` and ``a,b`` forms.

        Tools take paths in more shapes than a bare argument. ``semgrep
        --output=/work/x``, ``nuclei -t a,b`` and ``ffuf -w /ws/list.txt`` all
        carry workspace paths, and only the last one survived a plain
        ``startswith`` rewrite. Anything that does not sit under the workspace is
        returned untouched — this translates, it never invents a path.
        """
        if depth > 2 or not token:
            return token

        # --flag=/path/inside/workspace. Checked before the bare-path rewrite so
        # the flag name survives.
        if token.startswith("-") and "=" in token:
            head, _, tail = token.partition("=")
            translated = self._translate_token(tail, depth=depth + 1)
            return f"{head}={translated}" if translated != tail else token

        # Comma-joined path lists (nuclei -t a,b). Checked before the bare-path
        # rewrite, or a token whose *first* element is a workspace path would be
        # rewritten once and the rest left pointing at host paths the container
        # cannot see. Only rewritten when an element really is a workspace path,
        # so ordinary comma lists ("200,301,403") come back byte-identical, and
        # a comma inside a single filename survives the split/rejoin unchanged.
        if "," in token and any(self._under_workspace(p) for p in token.split(",")):
            return ",".join(
                self._translate_token(part, depth=depth + 1) for part in token.split(",")
            )

        for prefix in self._workspace_prefixes:
            if token == prefix:
                return CONTAINER_WORKDIR
            # The separator check is load-bearing: a workspace at
            # /engagements/acme must not rewrite /engagements/acme-old/....
            if token.startswith(prefix + os.sep):
                return CONTAINER_WORKDIR + token[len(prefix) :].replace(os.sep, "/")

        return token

    def _under_workspace(self, token: str) -> bool:
        return any(
            token == prefix or token.startswith(prefix + os.sep)
            for prefix in self._workspace_prefixes
        )

    def _base_env(self, env: dict[str, str] | None) -> dict[str, str]:
        base = {"CORDON_USER_AGENT": self.user_agent}
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
            "default_image": self.config.default_image or None,
            "verify_image_binary": self.config.verify_image_binary,
            "isolated_networks": len(self.config.networks),
            "host_fallbacks": self.fallback_report(),
            "user_agent": self.user_agent,
        }

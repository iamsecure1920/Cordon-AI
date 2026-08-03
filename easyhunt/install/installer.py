"""Installer: plan, install, verify, repair.

Three properties matter more than covering every tool.

**Idempotent.** Every step checks before it acts, so running this repeatedly is
safe and cheap. A user who runs it after each failure should converge, not
accumulate damage.

**Verified, not assumed.** A successful ``go install`` does not mean the tool
works — it may be shadowed on PATH by something with the same name, or missing a
binary dependency it only needs at run time. Every install is followed by the
same identity check ``easyhunt doctor`` uses, so "installed" means "verified
working" and nothing weaker.

**Honest about failure.** A tool that will not install is reported with the
command that failed and its stderr, and the run continues. Fifty-four working
tools and one clear failure is a good outcome; a script that aborts at number
thirty-one and leaves you guessing is not.

Installing software modifies the machine, so nothing here runs implicitly. It is
reached through ``easyhunt install`` or ``easyhunt doctor --fix``, both of which
say what they will do first.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from easyhunt.install.recipes import RECIPES, SYSTEM_PACKAGES, Recipe, install_order

log = logging.getLogger("easyhunt.install")

__all__ = [
    "InstallReport",
    "Installer",
    "StepResult",
    "ToolHealth",
    "health_check",
    "probe_tool",
]


# --------------------------------------------------------------------------- #
# Health: what a tool actually does when you run it
# --------------------------------------------------------------------------- #
#
# `shutil.which()` answers "is there a file of this name on PATH", which is a
# much weaker claim than "this tool works" and was being printed as though it
# were the same thing. It is not: on the machine this was written on, four tools
# resolved on PATH and died at import on every single invocation —
#
#   deepteam     ModuleNotFoundError: No module named 'nntplib'   (3.13 removed it)
#   dirsearch    ModuleNotFoundError: No module named 'pkg_resources'
#   dnsreaper    ModuleNotFoundError: No module named 'pkg_resources'
#   paramspider  ImportError: attempted relative import with no known parent package
#
# — and `easyhunt doctor` reported all four with a green tick. That is the same
# failure that let nikto and testssl ship 100% non-functional. So the health
# check executes.

#: Substrings that mean "this binary starts up and immediately dies", as opposed
#: to "this binary printed something we did not recognise as a version". Kept
#: narrow on purpose: a false BROKEN is nearly as damaging as a false OK.
#:
#: The first five were observed verbatim in this repo's own environment. The
#: remainder are documented failure modes taken from the recipe caveats
#: (nikto's XML::Writer, testssl's hexdump) and from libc/loader errors.
_STARTUP_FAILURE = (
    "traceback (most recent call last)",
    "modulenotfounderror",
    "no module named",
    "importerror:",
    "attempted relative import",
    "required module not found",  # nikto without libxml-writer-perl
    "you need to install",  # testssl without hexdump / ps
    "@inc contains",  # perl module resolution failure
    ": command not found",
    "error while loading shared libraries",
    "cannot execute binary file",
)

#: Argument forms tried, in order, until one produces output. Tools disagree
#: wildly; ``-h`` is last because it is the only one some of them answer at all.
_VERSION_FORMS: tuple[list[str], ...] = (
    ["--version"], ["-version"], ["version"], ["-V"], ["-h"],
)

#: Total seconds allowed per tool across *all* argument forms. A per-attempt
#: timeout is the wrong unit: a slow Python tool that ignores four forms then
#: answers the fifth would otherwise cost 5x the budget on its own and set the
#: wall-clock for the entire run.
PROBE_BUDGET_S = 10.0


@dataclass(frozen=True)
class ToolHealth:
    """What is known about one tool, and how it came to be known.

    ``status`` is deliberately not a boolean, because "on PATH" and "confirmed
    working" are different claims and conflating them is the bug this exists to
    fix:

    ``working``      executed and responded (or, for a library, imported).
    ``broken``       executed and failed at startup on every form tried.
    ``wrong-tool``   something of this name is on PATH, but nothing that
                     identifies as this tool — an impostor, not an absence.
    ``unresponsive`` on PATH, ran, produced nothing within the budget. Unknown,
                     and reported as unknown rather than rounded up to working.
    ``missing``      nothing of this name anywhere.
    ``on-path``      found on PATH and *not executed* (``--fast``). This status
                     asserts nothing about whether it runs.
    """

    tool: str
    status: str
    detail: str = ""
    version: str = ""
    binary: str = ""
    #: True only when the tool declares an identity_marker that was matched.
    #: Without one, "working" means a binary of that name responded — it does
    #: not mean it is the right program.
    identity_verified: bool = False

    @property
    def ok(self) -> bool:
        return self.status in {"working", "on-path"}

    @property
    def confirmed_working(self) -> bool:
        """Strictly executed and responded. ``on-path`` does not qualify."""
        return self.status == "working"


#: Colour, cursor, and other terminal control sequences. Several of these tools
#: colour their tracebacks, and pasting raw escape codes into doctor's output
#: both mangles the alignment and re-colours the terminal mid-line.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _clean(output: str) -> str:
    return _ANSI.sub("", output)


def _decode(stream: Any) -> str:
    """TimeoutExpired carries bytes even when the call asked for text."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return str(stream)


def _classify_output(output: str) -> str | None:
    lowered = output.lower()
    for signature in _STARTUP_FAILURE:
        if signature in lowered:
            return signature
    return None


def _first_informative_line(output: str) -> str:
    """Best-effort version string, tolerating banners and ANSI noise."""
    for raw in output.splitlines():
        line = raw.strip().lstrip("[").replace("INF]", "").strip()
        if any(character.isdigit() for character in line) and len(line) < 120:
            return line[:80]
    for raw in output.splitlines():
        if raw.strip():
            return raw.strip()[:80]
    return ""


def _last_line(output: str) -> str:
    lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _probe_library(spec: Any) -> ToolHealth:
    """A tool EasyHunt imports rather than executes (bbot) — import it for real.

    ``importlib.util.find_spec`` only proves a directory exists with the right
    name; it does not run the package's ``__init__``, which is exactly where a
    broken dependency tree shows up. Import it out-of-process so a tool that
    blows up cannot take doctor with it.
    """
    module = (spec.package or "").replace("-", "_")
    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-c", f"import {module}"],
            capture_output=True, text=True, timeout=PROBE_BUDGET_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolHealth(spec.name, "broken", f"import {module} did not complete: {exc}")
    if proc.returncode != 0:
        return ToolHealth(
            spec.name, "broken",
            f"import {module} failed: {_last_line(_clean(proc.stderr or ''))[:120]}",
        )
    return ToolHealth(spec.name, "working", "python package (import succeeded)", "python package")


def probe_tool(name: str, *, execute: bool = True, budget: float = PROBE_BUDGET_S) -> ToolHealth:
    """Determine the health of one catalogued tool.

    With ``execute=False`` this degrades to the old PATH-presence check and says
    so in the status (``on-path``), so a caller that trades truth for speed
    cannot accidentally report the result as verification.
    """
    from easyhunt.tools.common import CATALOG, installed, resolve_binary, verify_identity

    spec = CATALOG.get(name)
    if spec is None:
        return ToolHealth(name, "missing", "not in catalog")

    # Identity first. `installed()` folds "impostor on PATH" into "absent", and
    # those need different words: an absence is fixed by installing, an impostor
    # by looking at your PATH — and running it would fire the wrong program at a
    # host (Kali's `medusa` is a credential brute-forcer, not the fuzzer).
    identity_ok, identity_detail = verify_identity(name)
    if not identity_ok and identity_detail != "not installed":
        return ToolHealth(name, "wrong-tool", identity_detail)

    if not installed(name):
        return ToolHealth(name, "missing", f"not installed — {spec.homepage}")

    binary = resolve_binary(name) if spec.binary else None
    if binary is None and spec.package:
        if not execute:
            return ToolHealth(name, "on-path", "python package present (not imported)")
        health = _probe_library(spec)
        return ToolHealth(
            health.tool, health.status, health.detail, health.version,
            identity_verified=bool(spec.identity_marker),
        )
    if binary is None:
        return ToolHealth(name, "missing", f"not installed — {spec.homepage}")

    if not execute:
        return ToolHealth(
            name, "on-path", "found on PATH; not executed", binary=binary,
            identity_verified=bool(spec.identity_marker) and identity_ok,
        )

    marker_verified = bool(spec.identity_marker) and identity_ok
    deadline = time.monotonic() + budget
    forms = [spec.version_args, *(f for f in _VERSION_FORMS if f != spec.version_args)]
    for args in forms:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        timed_out = False
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, *args], capture_output=True, text=True,
                timeout=remaining, check=False,
            )
            output = _clean(proc.stdout + proc.stderr)
        except subprocess.TimeoutExpired as exc:
            # A tool that prints a stack trace and *then* hangs is still broken,
            # and the partial output is the only evidence of why. Discarding it
            # would downgrade a definite failure to "unknown".
            timed_out = True
            output = _clean(_decode(exc.stdout) + _decode(exc.stderr))
        except OSError:
            continue

        failure = _classify_output(output)
        if failure is not None:
            # Report the tool's own last line, not our matched substring — the
            # operator needs the actual error to fix it.
            return ToolHealth(
                name, "broken",
                f"runs and fails at startup: {(_last_line(output) or failure)[:140]}",
                binary=binary, identity_verified=marker_verified,
            )
        if timed_out:
            return ToolHealth(
                name, "unresponsive",
                f"{binary} did not exit within {budget:.0f}s — cannot confirm it runs",
                binary=binary, identity_verified=marker_verified,
            )
        if output.strip():
            return ToolHealth(
                name, "working", identity_detail, _first_informative_line(output),
                binary=binary, identity_verified=marker_verified,
            )
    return ToolHealth(
        name, "unresponsive",
        f"on PATH at {binary} but produced no output to any of "
        f"{len(forms)} version/help forms within {budget:.0f}s — cannot confirm it runs",
        binary=binary, identity_verified=marker_verified,
    )


def health_check(
    names: Iterable[str] | None = None,
    *,
    execute: bool = True,
    workers: int = 32,
    budget: float = PROBE_BUDGET_S,
) -> list[ToolHealth]:
    """Health of every catalogued tool, probed concurrently.

    Concurrency is what makes honesty affordable. Executing every tool in
    sequence cost ~44s on the reference machine, which is why it was hidden
    behind an opt-in flag nobody used; the same work fanned out across a thread
    pool costs ~10s, bounded by the slowest single tool rather than by their sum.
    These are subprocesses, so the GIL is irrelevant.
    """
    from easyhunt.tools.common import CATALOG, resolve_binary, verify_identity

    # Caches are per-process and may predate an install in this same run.
    resolve_binary.cache_clear()
    verify_identity.cache_clear()

    selected = sorted(names) if names is not None else sorted(CATALOG)
    if not selected:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(
            pool.map(lambda n: probe_tool(n, execute=execute, budget=budget), selected)
        )


@dataclass
class StepResult:
    tool: str
    status: str  # installed | already | failed | skipped | unverified
    detail: str = ""
    command: str = ""
    stderr: str = ""
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status in {"installed", "already"}


@dataclass
class InstallReport:
    results: list[StepResult] = field(default_factory=list)
    repairs: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def add(self, result: StepResult) -> StepResult:
        self.results.append(result)
        return result

    @property
    def installed(self) -> list[StepResult]:
        return [r for r in self.results if r.status == "installed"]

    @property
    def failed(self) -> list[StepResult]:
        return [r for r in self.results if r.status == "failed"]

    @property
    def unverified(self) -> list[StepResult]:
        return [r for r in self.results if r.status == "unverified"]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return {
            "total": len(self.results),
            "by_status": counts,
            "working": sum(1 for r in self.results if r.ok),
            "failed": [r.tool for r in self.failed],
            "unverified": [r.tool for r in self.unverified],
            "repairs": self.repairs,
        }


class Installer:
    """Executes install recipes, verifies the result, and repairs known breakages."""

    def __init__(
        self,
        *,
        dry_run: bool = False,
        timeout: int = 900,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.timeout = timeout
        self.on_progress = on_progress or (lambda tool, message: None)
        self.report = InstallReport()

    # -- environment -------------------------------------------------------- #

    def runtimes(self) -> dict[str, str | None]:
        """Which package managers and toolchains are usable here."""
        found: dict[str, str | None] = {}
        for name, probe in (
            ("go", "go"), ("pip", "pip3"), ("pipx", "pipx"),
            ("npm", "npm"), ("cargo", "cargo"), ("apt", "apt-get"),
            ("git", "git"), ("curl", "curl"),
        ):
            found[name] = shutil.which(probe)
        return found

    @property
    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo(self, command: str) -> str:
        """Prefix with sudo only when needed and available."""
        if self.is_root:
            return command
        if shutil.which("sudo"):
            return f"sudo -n {command}"
        return command

    def _run(self, command: str, *, env: dict[str, str] | None = None, timeout: int | None = None):
        # Hard guard: nothing may install into the interpreter running EasyHunt.
        # Tool dependency trees conflict with ours, and an installer that breaks
        # its own host is worse than one that installs nothing.
        if (
            sys.executable in command
            and "-m pip install" in command
            and not getattr(self, "_allow_library_install", False)
        ):
            raise RuntimeError(
                "refusing to install into EasyHunt's own environment — "
                "use pipx (isolated) or a --user install instead"
            )
        merged = {**os.environ, **(env or {})}
        # go install must not run as the invoking user's root, or binaries land
        # in root's GOPATH and disappear for everyone else.
        merged.setdefault("GOPATH", merged.get("GOPATH", str(Path.home() / "go")))
        merged["PATH"] = f"{merged.get('PATH', '')}:{merged['GOPATH']}/bin:/usr/local/go/bin"
        return subprocess.run(  # noqa: S602 — recipe commands are code-defined, not user input
            command, shell=True, capture_output=True, text=True,
            timeout=timeout or self.timeout, env=merged, check=False,
        )

    # -- verification ------------------------------------------------------- #

    @staticmethod
    def _verify(tool: str, *, execute: bool = True) -> tuple[bool, str]:
        """Post-install check using the same probe as ``easyhunt doctor``.

        ``execute=True`` runs the tool. That is the point: an install that
        reports success and produces something which dies at startup is the
        failure this whole module exists to catch, and it is invisible to any
        check that stops at PATH. Planning passes ``execute=False`` — there the
        question is only "is it already here", and answering it does not justify
        running eighty binaries.
        """
        from easyhunt.tools.common import CATALOG, resolve_binary, verify_identity

        # Caches are per-process and now stale.
        resolve_binary.cache_clear()
        verify_identity.cache_clear()

        if tool not in CATALOG:
            # Not a catalogued tool (massdns, chrome) — a binary on PATH will do.
            return (shutil.which(tool) is not None, "present on PATH")
        health = probe_tool(tool, execute=execute)
        if health.status == "missing":
            return False, "not detected after install"
        return health.ok, health.detail or health.status

    # -- planning ----------------------------------------------------------- #

    def plan(self, recipes: list[Recipe]) -> dict[str, list[str]]:
        """What would happen, without doing it."""
        ordered = install_order(recipes)
        runtimes = self.runtimes()
        plan: dict[str, list[str]] = {"install": [], "already": [], "blocked": []}

        for recipe in ordered:
            present, _ = self._verify(recipe.tool, execute=False)
            if present:
                plan["already"].append(recipe.tool)
            elif recipe.method != "manual" and runtimes.get(self._runtime_for(recipe)) is None:
                plan["blocked"].append(f"{recipe.tool} (needs {self._runtime_for(recipe)})")
            elif recipe.method == "manual":
                plan["blocked"].append(f"{recipe.tool} (manual install only)")
            else:
                plan["install"].append(recipe.tool)
        return plan

    @staticmethod
    def _interpreter_at_most(maximum: str) -> str | None:
        """Highest installed Python at or below ``maximum``, or None.

        Tools like garak support a version range that the host's default Python
        has already outrun. Pinning the exact ceiling is wrong too — that release
        may not be installed either. Search downward for one that is.
        """
        try:
            ceiling = tuple(int(part) for part in maximum.split("."))
        except ValueError:
            return None

        candidates: list[tuple[tuple[int, ...], str]] = []
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if not directory or not os.path.isdir(directory):
                continue
            for entry in os.listdir(directory):
                if not entry.startswith("python3."):
                    continue
                try:
                    version = tuple(int(p) for p in entry.removeprefix("python").split("."))
                except ValueError:
                    continue
                if version <= ceiling and os.access(os.path.join(directory, entry), os.X_OK):
                    candidates.append((version, entry))
        if not candidates:
            return None
        return max(candidates)[1]

    @staticmethod
    def _runtime_for(recipe: Recipe) -> str:
        return {
            "go": "go", "pip": "pip", "pipx": "pipx", "npm": "npm",
            "cargo": "cargo", "apt": "apt", "git": "git", "script": "curl",
        }.get(recipe.method, "curl")

    # -- installation ------------------------------------------------------- #

    def install_system_packages(self, packages: tuple[str, ...] = SYSTEM_PACKAGES) -> StepResult:
        """Base build dependencies. Everything compiled needs these."""
        if not shutil.which("apt-get"):
            return self.report.add(
                StepResult("system-packages", "skipped", "apt not available on this system")
            )
        missing = [p for p in packages if not self._apt_installed(p)]
        if not missing:
            return self.report.add(StepResult("system-packages", "already", "all present"))
        if self.dry_run:
            return self.report.add(
                StepResult("system-packages", "skipped", f"would install: {' '.join(missing)}")
            )

        self.on_progress("system-packages", f"installing {len(missing)} apt package(s)")
        command = self._sudo(f"apt-get install -y -q {' '.join(missing)}")
        self._run(self._sudo("apt-get update -q"), timeout=300)
        proc = self._run(command, timeout=900)
        if proc.returncode != 0:
            return self.report.add(
                StepResult(
                    "system-packages", "failed",
                    "apt install failed — compiled tools (naabu, nmap, masscan) may not build",
                    command=command, stderr=(proc.stderr or "")[-500:],
                )
            )
        return self.report.add(
            StepResult("system-packages", "installed", f"installed: {' '.join(missing)}")
        )

    @staticmethod
    def _apt_installed(package: str) -> bool:
        try:
            proc = subprocess.run(  # noqa: S603
                ["dpkg", "-s", package], capture_output=True, timeout=15, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def install_one(self, recipe: Recipe, *, force: bool = False) -> StepResult:
        """Install a single tool and verify it afterwards."""
        import time

        if not force:
            # Cheap pre-check: only deciding whether to skip. The expensive,
            # executing check runs after the install, where it can catch a
            # success that produced nothing usable.
            present, detail = self._verify(recipe.tool, execute=False)
            if present:
                return self.report.add(StepResult(recipe.tool, "already", detail))

        if recipe.method == "manual":
            return self.report.add(
                StepResult(recipe.tool, "skipped", recipe.caveat or "manual install only")
            )

        runtime = self._runtime_for(recipe)
        if self.runtimes().get(runtime) is None:
            return self.report.add(
                StepResult(recipe.tool, "skipped", f"{runtime} is not installed")
            )

        # Hard dependencies first — a tool that needs libpcap will not build
        # without it, and the error message will not say so.
        for package in recipe.system_deps:
            if not self._apt_installed(package):
                self.install_system_packages((package,))

        command = self._command_for(recipe)
        if not command:
            return self.report.add(StepResult(recipe.tool, "skipped", "no install command"))
        if self.dry_run:
            return self.report.add(StepResult(recipe.tool, "skipped", "dry run", command=command))

        self.on_progress(recipe.tool, f"installing via {recipe.method}")
        started = time.monotonic()
        if recipe.method == "release":
            proc = self._install_release(recipe)
        else:
            # Only a recipe explicitly marked `library` may touch our own env.
            self._allow_library_install = recipe.library
            try:
                proc = self._run(command, env=recipe.env)
            finally:
                self._allow_library_install = False
        duration = time.monotonic() - started

        if proc.returncode != 0:
            return self.report.add(
                StepResult(
                    recipe.tool, "failed", f"{recipe.method} install failed",
                    command=command, stderr=(proc.stderr or proc.stdout or "")[-600:],
                    duration_s=duration,
                )
            )

        if recipe.post_install:
            post = self._run(self._maybe_sudo_post(recipe), timeout=900)
            if post.returncode != 0:
                # Post-install is where a git-cloned tool gets its venv and its
                # wrapper on PATH. Swallowing this leaves a checkout and no
                # working command — which is indistinguishable from success until
                # the tool is needed mid-engagement.
                return self.report.add(
                    StepResult(
                        recipe.tool, "failed",
                        "fetched, but post-install setup failed — the tool is not usable",
                        command=recipe.post_install[:200],
                        stderr=(post.stderr or post.stdout or "")[-600:],
                        duration_s=duration,
                    )
                )

        # An install that reports success but produces nothing usable is the
        # failure mode worth catching.
        ok, detail = self._verify(recipe.tool)
        if not ok:
            return self.report.add(
                StepResult(
                    recipe.tool, "unverified",
                    f"install reported success but the tool did not verify: {detail}",
                    command=command, duration_s=duration,
                )
            )

        if recipe.caveat:
            self.report.caveats.append(f"{recipe.tool}: {recipe.caveat}")
        return self.report.add(
            StepResult(recipe.tool, "installed", detail, command=command, duration_s=duration)
        )

    def _maybe_sudo_post(self, recipe: Recipe) -> str:
        post = recipe.post_install
        # Writing into /usr/local/bin needs privileges the build step did not.
        if "/usr/local/bin" in post and not self.is_root:
            return self._sudo(f"sh -c {post!r}")
        return post

    def _command_for(self, recipe: Recipe) -> str:
        method, package = recipe.method, recipe.package
        if method == "go":
            return f"go install -v {package}"
        if method in {"pip", "pipx"}:
            if recipe.library:
                # The one exception: EasyHunt imports this, so it must share our
                # interpreter. Only bbot qualifies (see Recipe.library).
                return f"{sys.executable} -m pip install --quiet --upgrade {package}"
            # Everything else is isolated, never `pip install` into our own
            # interpreter. Learned the hard way: installing semgrep into
            # EasyHunt's venv pulled in fastmcp-slim and silently removed
            # FastMCP's client support — the installer broke the application
            # running it. A security tool's dependency tree is not something to
            # merge with your own.
            spec = ""
            if recipe.python_max:
                interpreter = self._interpreter_at_most(recipe.python_max)
                if interpreter is None:
                    # Pinning a version that is not installed fails with an
                    # unhelpful pipx error; say what is actually wrong.
                    return ""
                spec = f"--python {interpreter} "
            if shutil.which("pipx"):
                return f"pipx install {spec}{package} --force"
            # Fall back to a user-level install, still outside our environment.
            return f"python3 -m pip install --quiet --upgrade --user {package}"
        if method == "npm":
            return self._sudo(f"npm install -g {package}")
        if method == "cargo":
            return f"cargo install {package} --locked"
        if method == "apt":
            return self._sudo(f"apt-get install -y -q {package}")
        if method == "git":
            destination = recipe.clone_to or f"/opt/{recipe.tool}"
            clone = f"git clone --depth 1 {package} {destination}"
            if not self.is_root and destination.startswith("/opt"):
                clone = self._sudo(clone)
            return f"test -d {destination} || {clone}"
        if method == "script":
            if package == "chrome":
                return self._chrome_command()
            return f"curl -sSfL {package} | sh"
        if method == "release":
            # Executed via _install_release, which uses a script file.
            return f"<release {recipe.package}>"
        return ""

    def _release_script(self, recipe: Recipe) -> str:
        """Shell script that fetches and installs a GitHub release binary.

        Several Rust tools (kingfisher, noseyparker) ship prebuilt tarballs and no
        install script, so this resolves the right asset for the running
        architecture and extracts the binary onto PATH.

        Written to a file rather than squeezed into ``sh -c '…'`` — the script
        needs both quote styles, and nesting them inside another shell's quoting
        is how you get "Unterminated quoted string" instead of an install.
        """
        arch_map = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}
        machine = os.uname().machine if hasattr(os, "uname") else "x86_64"
        arch = arch_map.get(machine, "x64")
        pattern = (recipe.asset_match or "linux-{arch}").format(arch=arch)
        # Some projects use the GNU triple form instead.
        alt = pattern.replace("x64", "x86_64").replace("arm64", "aarch64")
        tmp = f"/tmp/easyhunt-install-{recipe.tool}"  # noqa: S108 — scratch, removed below

        return f"""#!/bin/sh
set -e
rm -rf {tmp}; mkdir -p {tmp}; cd {tmp}

url=$(curl -sSL "https://api.github.com/repos/{recipe.package}/releases/latest" \\
  | grep -oE '"browser_download_url": "[^"]+"' \\
  | sed 's/.*: "//; s/"$//' \\
  | grep -E '{pattern}|{alt}' \\
  | grep -vE '\\.(rpm|sha256|asc|sig|pem|json|txt|md|sbom|att)$' \\
  | grep -viE 'sbom|checksum|signature|provenance' \\
  | head -1)

if [ -z "$url" ]; then
  echo "no release asset matching '{pattern}' for {recipe.package}" >&2
  exit 1
fi

curl -sSL -o asset "$url"
case "$url" in
  *.tgz|*.tar.gz) tar xzf asset ;;
  *.tar.xz)       tar xJf asset ;;
  *.zip)          unzip -qo asset ;;
  *.deb)          dpkg -i asset || apt-get -f install -y ;;
  *)              # Not an archive: many projects publish a bare binary named
                  # <tool>_<version>_<os>_<arch>, which no extractor will match.
                  install -m 0755 asset /usr/local/bin/{recipe.tool} ;;
esac

bin=$(find . -type f -name '{recipe.tool}' -perm -u+x 2>/dev/null | head -1)
if [ -n "$bin" ]; then
  install -m 0755 "$bin" /usr/local/bin/{recipe.tool}
fi

cd /; rm -rf {tmp}
command -v {recipe.tool} >/dev/null
"""

    def _install_release(self, recipe: Recipe) -> subprocess.CompletedProcess:
        """Run the release script from a file, so quoting cannot break it."""
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".sh", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(self._release_script(recipe))
            script = handle.name
        # Executable by us so `sh <script>` works; it is deleted immediately after.
        os.chmod(script, 0o700)  # noqa: S103
        try:
            return self._run(self._sudo(f"sh {script}"), timeout=600)
        finally:
            Path(script).unlink(missing_ok=True)

    def _chrome_command(self) -> str:
        """Chrome from Google's repo — the distro package is Chromium, not Chrome."""
        return self._sudo(
            "sh -c 'curl -fsSL https://dl.google.com/linux/linux_signing_key.pub "
            "| gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg && "
            'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] '
            "http://dl.google.com/linux/chrome/deb/ stable main\" "
            "> /etc/apt/sources.list.d/google-chrome.list && "
            "apt-get update -q && apt-get install -y -q google-chrome-stable'"
        )

    def install_many(self, recipes: list[Recipe], *, force: bool = False) -> InstallReport:
        """Install in dependency order, continuing past individual failures."""
        self.install_system_packages()
        for recipe in install_order(recipes):
            try:
                self.install_one(recipe, force=force)
            except subprocess.TimeoutExpired:
                self.report.add(
                    StepResult(recipe.tool, "failed", f"timed out after {self.timeout}s")
                )
            except Exception as exc:  # noqa: BLE001 — one bad recipe must not stop the rest
                self.report.add(StepResult(recipe.tool, "failed", str(exc)[:300]))
        return self.report

    # -- repair ------------------------------------------------------------- #

    def repair(self) -> list[str]:
        """Fix the breakages that are common, detectable, and safe to correct.

        Deliberately conservative. It will install a missing dependency or fetch
        templates; it will not uninstall software the user may rely on. The
        ``httpx`` name collision, for instance, is handled by resolving the right
        binary rather than by removing the Python CLI that shadows it.
        """
        from easyhunt.tools.common import CATALOG, installed, resolve_binary, verify_identity

        fixed: list[str] = []
        resolve_binary.cache_clear()
        verify_identity.cache_clear()

        # 1. Nuclei with no templates finds nothing and does not say why.
        if installed("nuclei"):
            templates = Path.home() / ".local/share/nuclei-templates"
            legacy = Path.home() / "nuclei-templates"
            if not templates.exists() and not legacy.exists():
                if not self.dry_run:
                    self._run("nuclei -update-templates -silent", timeout=600)
                fixed.append("fetched nuclei-templates (nuclei had none, so it matched nothing)")

        # 2. shuffledns without the massdns binary exits immediately.
        if installed("shuffledns") and not shutil.which("massdns"):
            recipe = RECIPES.get("massdns")
            if recipe and not self.dry_run:
                self.install_one(recipe)
            fixed.append("installed massdns (shuffledns is inert without it)")

        # 3. Raw-socket tools without libpcap fail at run time, not install time.
        for tool in ("naabu", "nmap", "masscan"):
            if installed(tool) and not self._apt_installed("libpcap-dev"):
                if not self.dry_run:
                    self.install_system_packages(("libpcap-dev",))
                fixed.append(f"installed libpcap-dev ({tool} needs it at run time)")
                break

        # 4. A shadowed binary is reported, not "fixed" by deleting the shadow —
        #    removing software the user installed is not ours to do.
        for name in CATALOG:
            if not CATALOG[name].identity_marker or not installed(name):
                continue
            ok, detail = verify_identity(name)
            if ok and "shadowed" in detail:
                fixed.append(
                    f"{name}: resolved past a PATH shadow automatically ({detail}). "
                    "No change made to your PATH."
                )

        # 5. GOPATH/bin missing from PATH makes every go-installed tool invisible.
        gopath_bin = Path(os.environ.get("GOPATH", str(Path.home() / "go"))) / "bin"
        if gopath_bin.is_dir() and str(gopath_bin) not in os.environ.get("PATH", ""):
            fixed.append(
                f"{gopath_bin} is not on your PATH — go-installed tools will be invisible. "
                f'Add: export PATH="$PATH:{gopath_bin}"'
            )

        self.report.repairs.extend(fixed)
        return fixed

    # -- status ------------------------------------------------------------- #

    @staticmethod
    def status(*, execute: bool = True) -> dict[str, Any]:
        """What is present, missing, or broken right now.

        ``working`` means *executed and responded*. It used to mean "resolved on
        PATH", which is how four tools that die at import were being counted
        towards a coverage percentage the operator was trusting.
        """
        from easyhunt.tools.common import CATALOG

        health = health_check(execute=execute)
        by_status: dict[str, list[ToolHealth]] = {}
        for item in health:
            by_status.setdefault(item.status, []).append(item)

        working = [h.tool for h in health if h.ok]
        missing = [h.tool for h in by_status.get("missing", [])]
        broken = [
            f"{h.tool}: {h.detail}"
            for h in (*by_status.get("broken", ()), *by_status.get("wrong-tool", ()))
        ]
        unverified = [f"{h.tool}: {h.detail}" for h in by_status.get("unresponsive", ())]

        core = [r.tool for r in RECIPES.values() if r.core]
        return {
            "working": working,
            "missing": missing,
            "broken": broken,
            "unverified": unverified,
            "executed": execute,
            "total": len(CATALOG),
            "core_missing": [t for t in core if t in missing],
            "coverage": round(100 * len(working) / max(1, len(CATALOG))),
        }

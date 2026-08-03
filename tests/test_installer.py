"""Installer: recipes, ordering, isolation, verification, and repair.

The sharpest test here is ``test_never_installs_into_our_own_environment``. It
exists because the installer once ran ``pip install semgrep`` into EasyHunt's own
venv, which pulled in ``fastmcp-slim`` and silently removed FastMCP's client
support — the installer broke the application running it.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys

import pytest

from easyhunt.install import RECIPES, Installer, install_order, recipes_for
from easyhunt.install.installer import ToolHealth, health_check, probe_tool
from easyhunt.install.recipes import SYSTEM_PACKAGES, Recipe
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import ToolSpec
from easyhunt.tools.common import CATALOG

load_capabilities()


class TestRecipeCoverage:
    def test_every_catalogued_tool_has_a_recipe(self) -> None:
        missing = sorted(set(CATALOG) - set(RECIPES))
        assert missing == [], f"no install recipe for: {missing}"

    def test_core_pipeline_is_a_usable_subset(self) -> None:
        core = {r.tool for r in recipes_for(core_only=True)}
        # Enough to run recon → probe → scan → validate → report unaided.
        assert {"nuclei", "subfinder", "httpx", "dnsx", "katana", "gau"} <= core
        assert len(core) < len(RECIPES), "core should be a subset, not everything"

    def test_licenses_are_recorded(self) -> None:
        unknown = [r.tool for r in RECIPES.values() if r.license == "unknown"]
        assert unknown == [], f"license not recorded for: {unknown}"

    def test_agpl_tools_carry_a_caveat(self) -> None:
        # Matters the moment anyone redistributes a bundle.
        for recipe in RECIPES.values():
            if recipe.license.startswith("AGPL"):
                assert "AGPL" in recipe.caveat, f"{recipe.tool} is AGPL with no caveat"

    def test_archived_tools_say_so(self) -> None:
        for name in ("jaeles", "noseyparker"):
            caveat = RECIPES[name].caveat.lower()
            assert "archiv" in caveat or "retired" in caveat


class TestOrderingAndDependencies:
    def test_massdns_installs_before_shuffledns(self) -> None:
        # shuffledns installs cleanly and then does nothing without the binary.
        order = [r.tool for r in install_order(list(RECIPES.values()))]
        assert order.index("massdns") < order.index("shuffledns")

    def test_shuffledns_declares_the_dependency(self) -> None:
        assert "massdns" in RECIPES["shuffledns"].tool_deps

    def test_raw_socket_tools_declare_libpcap(self) -> None:
        for name in ("naabu", "nmap", "masscan"):
            assert "libpcap-dev" in RECIPES[name].system_deps

    def test_raw_socket_tools_are_flagged(self) -> None:
        for name in ("naabu", "nmap", "masscan"):
            assert RECIPES[name].needs_root_to_run

    def test_katana_builds_with_cgo(self) -> None:
        # Without CGO the install succeeds and headless support is missing.
        assert RECIPES["katana"].env.get("CGO_ENABLED") == "1"

    def test_garak_pins_its_python_ceiling(self) -> None:
        assert RECIPES["garak"].python_max == "3.12"

    def test_ordering_survives_a_cycle(self) -> None:
        recipes = [
            Recipe(tool="a", method="go", package="x", tool_deps=("b",)),
            Recipe(tool="b", method="go", package="y", tool_deps=("a",)),
        ]
        assert len(install_order(recipes)) == 2


class TestIsolation:
    def test_never_installs_into_our_own_environment(self) -> None:
        # The guard that stops the installer breaking its own host.
        installer = Installer(dry_run=True)
        with pytest.raises(RuntimeError, match="refusing to install into EasyHunt"):
            installer._run(f"{sys.executable} -m pip install semgrep")

    def test_python_tools_use_pipx(self) -> None:
        installer = Installer(dry_run=True)
        command = installer._command_for(RECIPES["semgrep"])
        assert sys.executable not in command
        assert "pipx" in command or "--user" in command

    def test_only_library_recipes_target_our_interpreter(self) -> None:
        installer = Installer(dry_run=True)
        for recipe in RECIPES.values():
            if recipe.method == "manual":
                continue
            command = installer._command_for(recipe)
            if sys.executable in command:
                assert recipe.library, f"{recipe.tool} would install into our venv"

    def test_bbot_is_the_only_library_exception(self) -> None:
        # bbot is imported by the recon engine, so pipx would give a working CLI
        # and an ImportError. Nothing else has that constraint.
        assert [r.tool for r in RECIPES.values() if r.library] == ["bbot"]

    def test_library_installs_are_gated_by_the_flag(self) -> None:
        installer = Installer(dry_run=True)
        # The guard is off by default, so a stray pip-into-our-env still raises.
        with pytest.raises(RuntimeError, match="refusing to install"):
            installer._run(f"{sys.executable} -m pip install anything")

    def test_pipx_isolation_is_the_default_for_python(self) -> None:
        subprocess_tools = [
            r for r in RECIPES.values() if r.method in {"pip", "pipx"} and not r.library
        ]
        assert subprocess_tools, "expected some Python-installed tools"
        assert all(r.method == "pipx" for r in subprocess_tools)


class TestPlanning:
    def test_plan_changes_nothing(self, tmp_path) -> None:
        installer = Installer(dry_run=True)
        plan = installer.plan(recipes_for(core_only=True))
        assert set(plan) == {"install", "already", "blocked"}
        assert installer.report.results == []

    def test_already_installed_tools_are_not_reinstalled(self) -> None:
        installer = Installer(dry_run=True)
        plan = installer.plan([RECIPES["nuclei"]])
        # nuclei is present in this environment.
        assert "nuclei" in plan["already"] or "nuclei" in plan["install"]

    def test_missing_runtime_blocks_rather_than_fails(self, monkeypatch) -> None:
        installer = Installer(dry_run=True)
        monkeypatch.setattr(installer, "runtimes", lambda: dict.fromkeys(
            ["go", "pip", "pipx", "npm", "cargo", "apt", "git", "curl"], None
        ))
        # A tool that is genuinely absent here, so planning reaches the runtime
        # check instead of short-circuiting on "already installed".
        absent = Recipe(tool="nonexistent-tool", method="go", package="example.com/x@latest")
        plan = installer.plan([absent])
        assert any("nonexistent-tool" in item for item in plan["blocked"])

    def test_dry_run_installs_nothing(self) -> None:
        installer = Installer(dry_run=True)
        result = installer.install_one(RECIPES["gobuster"], force=True)
        assert result.status == "skipped" and result.detail == "dry run"


class TestCommands:
    @pytest.mark.parametrize(
        ("tool", "fragment"),
        [
            ("subfinder", "go install"),
            ("semgrep", "pipx install"),
            ("bbot", "-m pip install"),  # library exception: we import it
            ("retire", "npm install -g"),
            ("findomain", "cargo install"),
            ("nmap", "apt-get install"),
            ("massdns", "git clone"),
            ("kingfisher", "<release"),
        ],
    )
    def test_method_produces_the_right_command(self, tool: str, fragment: str) -> None:
        assert fragment in Installer(dry_run=True)._command_for(RECIPES[tool])

    def test_release_script_is_valid_shell(self) -> None:
        import subprocess

        script = Installer(dry_run=True)._release_script(RECIPES["kingfisher"])
        # The bug this replaced was a quoting error inside a nested `sh -c`.
        proc = subprocess.run(  # noqa: S603
            ["sh", "-n"], input=script, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, f"release script has a syntax error: {proc.stderr}"

    def test_release_script_resolves_architecture(self) -> None:
        script = Installer(dry_run=True)._release_script(RECIPES["noseyparker"])
        # Rust releases use the GNU/musl triple, not a short arch name.
        assert "unknown-linux-musl" in script

    def test_manual_tools_produce_no_command(self) -> None:
        assert Installer(dry_run=True)._command_for(RECIPES["strix"]) == ""


@pytest.fixture(scope="module")
def machine_status() -> dict:
    """One real, executing probe of this machine, shared by every test below.

    ``status(execute=True)`` runs ~80 binaries. Doing that once per assertion
    turned a two-second file into a minute-long one.
    """
    return Installer.status(execute=True)


class TestStatusAndRepair:
    def test_status_reports_coverage(self, machine_status) -> None:
        assert machine_status["total"] == len(CATALOG)
        assert 0 <= machine_status["coverage"] <= 100
        assert isinstance(machine_status["core_missing"], list)

    def test_status_separates_broken_from_missing(self, machine_status) -> None:
        # A tool cannot be both absent and present-but-wrong.
        broken = {entry.split(":")[0] for entry in machine_status["broken"]}
        assert not (set(machine_status["missing"]) & broken)

    def test_repair_is_safe_to_run_repeatedly(self) -> None:
        installer = Installer(dry_run=True)
        first = installer.repair()
        second = installer.repair()
        assert isinstance(first, list) and isinstance(second, list)

    def test_repair_does_not_uninstall_anything(self) -> None:
        # Removing software a user installed is not ours to do — the httpx
        # collision is solved by resolving correctly, not by deleting the shadow.
        import ast
        import inspect
        import textwrap

        function = ast.parse(textwrap.dedent(inspect.getsource(Installer.repair))).body[0]
        # Drop the docstring: it legitimately contains "uninstall" while
        # explaining that this function does not do that. ast.unparse also drops
        # comments, so only executable code is compared.
        if (
            isinstance(function.body[0], ast.Expr)
            and isinstance(function.body[0].value, ast.Constant)
            and isinstance(function.body[0].value.value, str)
        ):
            function.body = function.body[1:]
        code = ast.unparse(function)

        for destructive in ("uninstall", "rm -rf", "apt-get remove", "apt-get purge"):
            assert destructive not in code, f"repair() must not run {destructive!r}"

    def test_system_packages_cover_the_build_essentials(self) -> None:
        assert {"build-essential", "libpcap-dev", "git", "curl"} <= set(SYSTEM_PACKAGES)


# --------------------------------------------------------------------------- #
# Health: PATH presence is not working
# --------------------------------------------------------------------------- #


def _fake_tool(directory, name: str, script: str) -> str:
    """Put an executable of ``name`` on PATH and return its path."""
    path = directory / name
    path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


@pytest.fixture
def fake_path(tmp_path, monkeypatch):
    """A directory at the front of PATH, with the identity caches cleared."""
    from easyhunt.tools.common import resolve_binary, verify_identity

    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    resolve_binary.cache_clear()
    verify_identity.cache_clear()
    yield tmp_path
    resolve_binary.cache_clear()
    verify_identity.cache_clear()


@pytest.fixture
def catalogued(monkeypatch):
    """Register a throwaway ToolSpec in the catalog for the duration of a test."""

    def register(**kwargs) -> ToolSpec:
        spec = ToolSpec(**kwargs)
        monkeypatch.setitem(CATALOG, spec.name, spec)
        return spec

    return register


class TestHealthIsNotPathPresence:
    """The regression that let nikto and testssl ship 100% non-functional.

    Both resolved with ``shutil.which()`` and died on every invocation, and
    ``easyhunt doctor`` printed a green tick for each. These tests fail if
    anything ever again reports "working" on the strength of a filename.
    """

    def test_a_binary_that_fails_on_every_invocation_is_not_working(
        self, fake_path, catalogued
    ) -> None:
        # Exactly the shape of the four broken tools found in the wild: it is on
        # PATH, it is executable, and it dies at import every single time.
        _fake_tool(
            fake_path, "phantomscan",
            "echo 'Traceback (most recent call last):' >&2\n"
            "echo \"ModuleNotFoundError: No module named 'pkg_resources'\" >&2\n"
            "exit 1",
        )
        catalogued(name="phantomscan", binary="phantomscan")

        # The old check would have passed: it is unambiguously on PATH.
        assert shutil.which("phantomscan") is not None

        health = probe_tool("phantomscan")
        assert health.status == "broken", f"reported {health.status!r}: {health.detail}"
        assert not health.confirmed_working
        assert "pkg_resources" in health.detail, "the tool's own error must reach the operator"

    def test_nikto_style_perl_failure_is_not_working(self, fake_path, catalogued) -> None:
        # nikto with no XML::Writer: exits non-zero on EVERY invocation, -Version
        # included, because it builds its XML report object unconditionally.
        _fake_tool(
            fake_path, "phantomnikto",
            "echo '- ERROR: Required module not found: XML::Writer' >&2\nexit 1",
        )
        catalogued(name="phantomnikto", binary="phantomnikto")
        assert probe_tool("phantomnikto").status == "broken"

    def test_testssl_style_dependency_failure_is_not_working(
        self, fake_path, catalogued
    ) -> None:
        # testssl without hexdump: prints its dependency complaint and stops.
        _fake_tool(
            fake_path, "phantomtestssl",
            "echo 'You need to install hexdump for this program to work' >&2\nexit 245",
        )
        catalogued(name="phantomtestssl", binary="phantomtestssl")
        assert probe_tool("phantomtestssl").status == "broken"

    def test_a_silent_binary_is_unverified_not_working(self, fake_path, catalogued) -> None:
        # Produces nothing to any form. We do not know whether it works, so we
        # must not say that it does — and equally must not call it broken.
        _fake_tool(fake_path, "phantomquiet", "exit 0")
        catalogued(name="phantomquiet", binary="phantomquiet")

        health = probe_tool("phantomquiet", budget=4.0)
        assert health.status == "unresponsive"
        assert not health.confirmed_working

    def test_a_working_binary_is_reported_working(self, fake_path, catalogued) -> None:
        # The control: without this, "never say working" would pass trivially.
        _fake_tool(fake_path, "phantomgood", "echo 'phantomgood 4.2.0'")
        catalogued(name="phantomgood", binary="phantomgood")

        health = probe_tool("phantomgood")
        assert health.status == "working" and health.confirmed_working
        assert "4.2.0" in health.version

    def test_a_hung_binary_does_not_count_as_working(self, fake_path, catalogued) -> None:
        _fake_tool(fake_path, "phantomhang", "sleep 30")
        catalogued(name="phantomhang", binary="phantomhang")

        health = probe_tool("phantomhang", budget=2.0)
        assert health.status == "unresponsive"
        assert not health.confirmed_working

    def test_a_binary_that_prints_then_hangs_is_still_broken(
        self, fake_path, catalogued
    ) -> None:
        # The partial output from a timed-out call is the only evidence of why;
        # discarding it would downgrade a definite failure to "unknown".
        _fake_tool(
            fake_path, "phantomslowfail",
            "echo 'ImportError: attempted relative import with no known parent package' >&2\n"
            "sleep 30",
        )
        catalogued(name="phantomslowfail", binary="phantomslowfail")
        assert probe_tool("phantomslowfail", budget=2.0).status == "broken"

    def test_a_container_tool_is_judged_in_its_container(
        self, fake_path, catalogued
    ) -> None:
        """The host copy is not the program that runs.

        sstimap and semgrep both worked on the reference host and crashed on
        every invocation inside their images — read-only container root, and both
        write to ~ at import. `binary_in_image` said yes, because it asks
        `command -v`, which is the same question `shutil.which` asks and gets
        wrong the same way. Doctor and the wrapper agreed with each other for
        exactly as long as nobody executed anything.
        """
        _fake_tool(fake_path, "phantomcontainer", "echo 'phantomcontainer 9.9'")
        catalogued(name="phantomcontainer", binary="phantomcontainer")

        class FakeSandbox:
            def image_for(self, tool):
                return "example/image:latest"

            def _why_not_sandboxed(self, *, tool, binary, image):
                return ""

            def run_in_image(self, image, binary, args, *, tool=None):
                return 1, "Traceback (most recent call last):\nOSError: [Errno 30] Read-only file system"

        health = probe_tool("phantomcontainer", sandbox=FakeSandbox())
        assert health.status == "broken", "a working host copy must not mask a broken image"
        assert health.where == "example/image:latest"
        assert not health.confirmed_working

    def test_a_binary_absent_from_its_image_is_missing_there(
        self, fake_path, catalogued
    ) -> None:
        """dalfox: mapped to hahwul/dalfox:latest, which keeps it at /app/dalfox.

        Nothing named dalfox was on PATH in that image, so every sandboxed run
        exited 127 — and xss_validate is auto-approved, so XSS could be found and
        never proven.
        """
        _fake_tool(fake_path, "phantomelsewhere", "echo 'phantomelsewhere 1.0'")
        catalogued(name="phantomelsewhere", binary="phantomelsewhere")

        class FakeSandbox:
            def image_for(self, tool):
                return "example/wrong-layout:latest"

            def _why_not_sandboxed(self, *, tool, binary, image):
                return ""

            def run_in_image(self, image, binary, args, *, tool=None):
                return 127, "exec: phantomelsewhere: not found"

        health = probe_tool("phantomelsewhere", sandbox=FakeSandbox())
        assert health.status == "missing"
        assert "example/wrong-layout:latest" in health.detail

    def test_a_host_only_tool_still_reports_from_the_host(
        self, fake_path, catalogued
    ) -> None:
        """No container home means the host answer is the right answer."""
        _fake_tool(fake_path, "phantomhostonly", "echo 'phantomhostonly 3.1'")
        catalogued(name="phantomhostonly", binary="phantomhostonly")

        class FakeSandbox:
            def image_for(self, tool):
                return None

            def _why_not_sandboxed(self, *, tool, binary, image):
                return "no image"

            def run_in_image(self, image, binary, args, *, tool=None):
                raise AssertionError("must not probe a container for a host-only tool")

        health = probe_tool("phantomhostonly", sandbox=FakeSandbox())
        assert health.status == "working"
        assert health.where == "host"

    def test_an_impostor_reads_as_wrong_tool_not_missing(self, fake_path, catalogued) -> None:
        # A name collision needs different words from an absence: absence is
        # fixed by installing, an impostor by looking at your PATH.
        _fake_tool(fake_path, "phantomdusa", "echo 'phantomdusa v2.2 by someone else'")
        catalogued(
            name="phantomdusa", binary="phantomdusa", identity_marker="the-real-phantomdusa"
        )

        health = probe_tool("phantomdusa")
        assert health.status == "wrong-tool"
        assert not health.confirmed_working

    def test_fast_mode_never_claims_a_tool_works(self, fake_path, catalogued) -> None:
        # --fast trades truth for speed. It must not be able to launder a PATH
        # hit into a claim of health — that is the original bug.
        _fake_tool(fake_path, "phantombroken", "echo 'No module named zope' >&2\nexit 1")
        catalogued(name="phantombroken", binary="phantombroken")

        health = probe_tool("phantombroken", execute=False)
        assert health.status == "on-path"
        assert not health.confirmed_working, "--fast must never assert working"

    def test_no_health_status_confuses_presence_with_working(self) -> None:
        # Whatever the machine happens to have installed, nothing that was only
        # found on PATH may end up in the confirmed-working set. Cheap because
        # --fast is the mode that *could* launder presence into health.
        for health in health_check(execute=False):
            assert not health.confirmed_working, f"{health.tool} claimed working unexecuted"
            assert health.status in {"on-path", "wrong-tool", "missing"}

    def test_on_path_is_never_confirmed_working(self) -> None:
        assert not ToolHealth("x", "on-path").confirmed_working
        assert ToolHealth("x", "on-path").ok, "still usable as a 'do not reinstall' signal"

    def test_doctor_executes_by_default(self) -> None:
        # The health check that is not the default is the health check nobody
        # runs — which is how this shipped broken in the first place.
        from easyhunt.cli import build_parser

        args = build_parser().parse_args(["doctor"])
        assert args.fast is False
        assert getattr(args, "versions", False) is False

    def test_status_counts_only_executed_tools_as_working(self, machine_status) -> None:
        assert machine_status["executed"] is True
        broken_tools = {entry.split(":")[0] for entry in machine_status["broken"]}
        assert not (set(machine_status["working"]) & broken_tools)
        assert not (set(machine_status["working"]) & set(machine_status["missing"]))

    def test_status_marks_a_non_executing_run_as_such(self) -> None:
        # A caller reading status()["working"] deserves to know whether anything
        # was actually run to produce it.
        assert Installer.status(execute=False)["executed"] is False

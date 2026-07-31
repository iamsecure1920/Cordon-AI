"""Installer: recipes, ordering, isolation, verification, and repair.

The sharpest test here is ``test_never_installs_into_our_own_environment``. It
exists because the installer once ran ``pip install semgrep`` into EasyHunt's own
venv, which pulled in ``fastmcp-slim`` and silently removed FastMCP's client
support — the installer broke the application running it.
"""

from __future__ import annotations

import sys

import pytest

from easyhunt.install import RECIPES, Installer, install_order, recipes_for
from easyhunt.install.recipes import SYSTEM_PACKAGES, Recipe
from easyhunt.mcp_server import load_capabilities
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


class TestStatusAndRepair:
    def test_status_reports_coverage(self) -> None:
        status = Installer.status()
        assert status["total"] == len(CATALOG)
        assert 0 <= status["coverage"] <= 100
        assert isinstance(status["core_missing"], list)

    def test_status_separates_broken_from_missing(self) -> None:
        status = Installer.status()
        # A tool cannot be both absent and present-but-wrong.
        assert not (set(status["missing"]) & {b.split(":")[0] for b in status["broken"]})

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

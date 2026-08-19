"""Binary resolution by identity, and BBOT 3.0 API compatibility.

Both cover the same failure mode: something that looks installed and working but
silently produces nothing. A shadowed `httpx` exits zero with no output; a stale
BBOT config key aborts the scan. Neither is visible without checking.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cordon.mcp_server import load_capabilities
from cordon.tools.common import CATALOG, installed, resolve_binary, verify_identity

load_capabilities()


@pytest.fixture
def fake_path(tmp_path, monkeypatch):
    """Two directories on PATH, each with a binary of the same name."""
    impostor_dir = tmp_path / "impostor"
    real_dir = tmp_path / "real"
    impostor_dir.mkdir()
    real_dir.mkdir()

    def write(directory: Path, name: str, body: str) -> Path:
        script = directory / name
        script.write_text(f"#!/bin/sh\n{body}\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return script

    # The impostor is FIRST on PATH, exactly like the Python httpx CLI.
    write(impostor_dir, "toolx", 'echo "Usage: toolx [OPTIONS] URL"')
    real = write(real_dir, "toolx", 'echo "toolx v1.2.3 - projectdiscovery.io"')

    monkeypatch.setenv("PATH", f"{impostor_dir}{os.pathsep}{real_dir}{os.pathsep}/usr/bin")
    resolve_binary.cache_clear()
    verify_identity.cache_clear()
    return {"impostor": impostor_dir / "toolx", "real": real}


@pytest.fixture
def toolx_spec(fake_path):
    from cordon.tools.base import ToolSpec
    from cordon.tools.common import register_spec

    spec = register_spec(
        ToolSpec(
            name="toolx",
            binary="toolx",
            identity_marker="projectdiscovery",
            version_args=["-version"],
        )
    )
    yield spec
    CATALOG.pop("toolx", None)
    resolve_binary.cache_clear()
    verify_identity.cache_clear()


class TestIdentityResolution:
    def test_resolves_past_a_shadowing_impostor(self, toolx_spec, fake_path) -> None:
        # shutil.which would return the impostor; we must not.
        import shutil

        assert shutil.which("toolx") == str(fake_path["impostor"])
        assert resolve_binary("toolx") == str(fake_path["real"])

    def test_verify_reports_the_shadowing(self, toolx_spec, fake_path) -> None:
        ok, detail = verify_identity("toolx")
        assert ok
        assert "shadowed on PATH by" in detail

    def test_installed_means_the_correct_binary(self, toolx_spec) -> None:
        assert installed("toolx") is True

    def test_only_an_impostor_counts_as_not_installed(self, tmp_path, monkeypatch) -> None:
        from cordon.tools.base import ToolSpec
        from cordon.tools.common import register_spec

        only_impostor = tmp_path / "bin"
        only_impostor.mkdir()
        script = only_impostor / "tooly"
        script.write_text('#!/bin/sh\necho "Usage: tooly [OPTIONS]"\n')
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("PATH", str(only_impostor))
        resolve_binary.cache_clear()
        verify_identity.cache_clear()

        register_spec(
            ToolSpec(name="tooly", binary="tooly", identity_marker="projectdiscovery")
        )
        try:
            # Running an impostor is worse than reporting the tool absent: it
            # returns nothing and looks like a clean result.
            assert resolve_binary("tooly") is None
            assert installed("tooly") is False
            ok, detail = verify_identity("tooly")
            assert not ok and "none of the" in detail
        finally:
            CATALOG.pop("tooly", None)
            resolve_binary.cache_clear()
            verify_identity.cache_clear()

    def test_tools_without_a_marker_resolve_normally(self, tmp_path, monkeypatch) -> None:
        """A spec with no marker falls back to PATH order.

        This used to assert against `nuclei`, which was marker-less at the time
        and is not any more — PyPI publishes an unrelated "nuclei" (a 2018
        Kaggle package), so it earned one. A test whose premise is another
        module's configuration breaks when that configuration is corrected, and
        the breakage says nothing about the behaviour under test. Synthetic spec
        instead.
        """
        from cordon.tools.base import ToolSpec
        from cordon.tools.common import register_spec

        directory = tmp_path / "plain"
        directory.mkdir()
        script = directory / "toolz"
        script.write_text("#!/bin/sh\necho 'toolz 1.0'\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("PATH", str(directory))
        resolve_binary.cache_clear()
        verify_identity.cache_clear()

        try:
            register_spec(ToolSpec(name="toolz", binary="toolz", version_args=["--version"]))
            assert verify_identity("toolz")[1] == "no identity marker declared"
            assert resolve_binary("toolz") == str(script)
        finally:
            CATALOG.pop("toolz", None)
            resolve_binary.cache_clear()
            verify_identity.cache_clear()

    def test_guarded_run_uses_the_resolved_path(self, toolx_spec, fake_path, engagement) -> None:
        from cordon.control_plane.sanitize import ArgPolicy, register_policy

        register_policy(ArgPolicy(tool="toolx", allowed_flags=set(), allow_positional=False))
        plan = engagement.sandbox.plan(
            tool="toolx", binary=resolve_binary("toolx") or "toolx", argv=[]
        )
        assert plan.argv[0] == str(fake_path["real"])


class TestRealHttpx:
    """The concrete case that motivated all of the above."""

    def test_httpx_resolves_to_projectdiscovery_when_present(self) -> None:
        resolved = resolve_binary("httpx")
        if resolved is None:
            pytest.skip("ProjectDiscovery httpx is not installed on this machine")
        ok, _ = verify_identity("httpx")
        assert ok
        assert installed("httpx")


class TestBbotThreeCompat:
    """BBOT 3.0 renamed the scope kwargs and two config keys."""

    def test_bbot_importable(self) -> None:
        pytest.importorskip("bbot")
        from bbot.scanner import Scanner

        assert hasattr(Scanner, "async_start")

    def test_config_uses_keys_that_validate(self, engagement) -> None:
        pytest.importorskip("bbot")
        from bbot.scanner import Scanner

        from cordon.engines.bbot_engine import _bbot_config

        # BBOT validates config keys and *raises* on unknown ones, so a stale
        # name aborts the scan rather than being quietly ignored.
        scanner = Scanner(
            "example.com",
            seeds=["example.com"],
            presets=["subdomain-enum"],
            config=_bbot_config(engagement),
            force_start=True,
        )
        assert scanner.config["web"]["http_rate_limit"] == int(engagement.scope.rules.max_rps)
        assert scanner.config["web"]["user_agent"] == engagement.scope.rules.user_agent

    def test_scope_is_handed_to_the_engine(self, engagement) -> None:
        pytest.importorskip("bbot")
        from bbot.scanner import Scanner

        from cordon.engines.bbot_engine import _bbot_config

        scanner = Scanner(
            *engagement.scope.bbot_whitelist(),
            seeds=["example.com"],
            blacklist=engagement.scope.bbot_blacklist(),
            presets=["subdomain-enum"],
            config=_bbot_config(engagement),
            force_start=True,
        )
        # The engine must never generate work the scope artifact forbids.
        assert scanner.in_scope("api.example.com")
        assert not scanner.in_scope("blog.example.com")
        assert not scanner.in_scope("someone-else.net")

    def test_bbot_state_stays_in_the_workspace(self, engagement) -> None:
        from cordon.engines.bbot_engine import _bbot_config

        config = _bbot_config(engagement)
        # Not the user's ~/.bbot: an engagement is self-contained and disposable.
        assert str(engagement.workspace) in config["home"]


class TestImpostorsThatActuallyExist:
    """Markers added because a same-named impostor is published, not because a
    name looked generic.

    Each of these has a real package a `pip install` or `apt install` would land
    on PATH, checked against PyPI and apt-file rather than guessed:

      forge       PyPI "forge" is a Django scaffolding tool; Debian's `snap`
                  package ships /usr/bin/forge; Atlassian's @forge/cli takes the
                  same command. Three impostors for one name.
      slither     PyPI "slither" is a PyGame module bringing Scratch-like
                  features to Python — a children's programming toy.
      katana      PyPI "katana" soft-clips sequencing reads by primer location.
      kingfisher  PyPI "kingfisher" downloads biological FASTA/Q read data.
      amass       PyPI "amass" vendors libraries from cdnjs.
      nuclei      PyPI "nuclei" is a 2018 Kaggle Data Science Bowl package.

    The parametrised marker strings are the contract. Two of these tools print
    nothing identifying from their documented version flag — `slither --version`
    is a bare "0.11.6" and `amass -version` a bare "v5.1.1" — so the marker has
    to come from the `-h` fallback that `_identifies_as` also tries. A marker
    that matches nothing turns a working tool into a permanent "wrong-tool",
    which is worse than declaring none, so these were read off real output
    before being written down.
    """

    MARKERS = {
        "forge": "deploy solidity contracts",
        "slither": "crytic",
        "katana": "projectdiscovery",
        "kingfisher": "detect and validate secrets",
        "amass": "owasp amass",
        "nuclei": "nuclei engine",
    }

    @pytest.mark.parametrize("tool", sorted(MARKERS))
    def test_the_marker_is_declared(self, tool: str) -> None:
        assert CATALOG[tool].identity_marker == self.MARKERS[tool]

    @pytest.mark.parametrize("tool", sorted(MARKERS))
    def test_the_real_binary_still_satisfies_its_marker(self, tool: str) -> None:
        """The half that a wrong marker silently breaks.

        Adding a marker is not free: `resolve_binary` returns None when nothing
        on PATH matches, and the tool then reads as absent. Where the tool is
        installed here, it must still verify.
        """
        resolve_binary.cache_clear()
        verify_identity.cache_clear()
        if resolve_binary(tool) is None and not CATALOG[tool].identity_marker:
            pytest.skip(f"{tool} not installed on this machine")
        import shutil

        if shutil.which(CATALOG[tool].binary) is None:
            pytest.skip(f"{tool} not installed on this machine")
        ok, detail = verify_identity(tool)
        assert ok, f"{tool} is installed but no longer matches {self.MARKERS[tool]!r}: {detail}"

    @pytest.mark.parametrize("tool", sorted(MARKERS))
    def test_an_impostor_of_this_name_is_refused(
        self, tool: str, tmp_path, monkeypatch
    ) -> None:
        """A binary of the right name printing the wrong thing must not be used.

        This is the whole point: the impostors above are installable, and each
        would otherwise be handed a target and produce a confident empty result.
        """
        impostor_dir = tmp_path / f"impostor-{tool}"
        impostor_dir.mkdir()
        binary = CATALOG[tool].binary or tool
        script = impostor_dir / binary
        # Plausible impostor output: it answers, it names itself, it says nothing
        # that identifies it as the security tool.
        script.write_text(f"#!/bin/sh\necho '{binary} 2.0.1 - a completely different program'\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

        monkeypatch.setenv("PATH", str(impostor_dir))
        resolve_binary.cache_clear()
        verify_identity.cache_clear()

        assert resolve_binary(tool) is None, f"an impostor {binary} was accepted as {tool}"
        ok, _ = verify_identity(tool)
        assert not ok
        assert not installed(tool)

        resolve_binary.cache_clear()
        verify_identity.cache_clear()

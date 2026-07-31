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

from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.common import CATALOG, installed, resolve_binary, verify_identity

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
    from easyhunt.tools.base import ToolSpec
    from easyhunt.tools.common import register_spec

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
        from easyhunt.tools.base import ToolSpec
        from easyhunt.tools.common import register_spec

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

    def test_tools_without_a_marker_resolve_normally(self) -> None:
        # nuclei declares no marker; resolution falls back to PATH order.
        assert verify_identity("nuclei")[1] == "no identity marker declared"

    def test_guarded_run_uses_the_resolved_path(self, toolx_spec, fake_path, engagement) -> None:
        from easyhunt.control_plane.sanitize import ArgPolicy, register_policy

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

        from easyhunt.engines.bbot_engine import _bbot_config

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

        from easyhunt.engines.bbot_engine import _bbot_config

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
        from easyhunt.engines.bbot_engine import _bbot_config

        config = _bbot_config(engagement)
        # Not the user's ~/.bbot: an engagement is self-contained and disposable.
        assert str(engagement.workspace) in config["home"]

"""Tests for port/service scanning wiring.

The chain is ``ports -> services``: port_scan discovers open ports, service_scan
fingerprints them. The regression this file guards: service_scan used to default
to ``ports="80,443"`` regardless of what port_scan found, so any estate running
on 3000/8080/8443 reported \"no services\" — the exact case port_scan exists to
surface. It now inherits the open_port assets from the store.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from easyhunt.config import Config
from easyhunt.control_plane.context import Engagement, set_engagement
from easyhunt.control_plane.scope import Scope

NMAP = shutil.which("nmap")


@pytest.fixture(scope="module")
def engagement(tmp_path_factory: pytest.TempPathFactory):
    """Engagement that approves service_scan (aggressive) and redirects memory."""
    from easyhunt.control_plane.approval import PolicyBackend
    from tests.conftest import scope_dict

    root = Path(tmp_path_factory.mktemp("ports"))
    sd = scope_dict()
    sd["in_scope"]["cidrs"].append("203.0.113.7/32")
    config = Config({
        "workspace": {"root": str(root / "engagements")},
        "approval": {"backend": "deny"},
        "sandbox": {"mode": "none"},
        "memory": {
            "poc_store": str(root / "poc-memory.jsonl"),
            "brain_store": str(root / "neuron-brain.jsonl"),
            "brain_activity": str(root / "brain-activity.jsonl"),
        },
    }, source=str(root / "config.yaml"))
    eng = Engagement(Scope(sd, source="<test>"), config, workspace=root / "ws")
    eng.approval.backend = PolicyBackend(auto_approve=["service_scan"])
    set_engagement(eng)
    yield eng
    set_engagement(None)


class TestPortInheritance:
    """service_scan must consume what port_scan produced (no nmap required)."""

    def test_inherits_open_ports_from_store(self, engagement, monkeypatch) -> None:
        import easyhunt.tools.ports  # noqa: F401
        from easyhunt.control_plane.context import get_engagement
        from easyhunt.knowledge.findings import Asset
        from easyhunt.tools.base import REGISTRY

        # Simulate port_scan's output for juice-shop-style non-web ports on a
        # host inside the fixture scope (203.0.113.0/24).
        store = get_engagement().assets
        store.add_many([
            Asset(
                value="203.0.113.7:3000", kind="open_port", source="naabu",
                host="203.0.113.7", attributes={"host": "203.0.113.7", "port": 3000},
            ),
            Asset(
                value="203.0.113.7:8080", kind="open_port", source="naabu",
                host="203.0.113.7", attributes={"host": "203.0.113.7", "port": 8080},
            ),
        ])

        # Capture the argv nmap would have been called with; do not run nmap.
        captured: dict[str, object] = {}

        async def fake_run_one(binary: str, argv: list[str], **kwargs: object):
            captured["argv"] = argv
            import types

            run = types.SimpleNamespace(
                ran=False, error="fake", exit_code=0, values=[], stdout="",
            )
            run.to_dict = lambda: {"binary": "nmap", "argv": argv, "ran": False}
            return run

        monkeypatch.setattr("easyhunt.tools.ports.run_one", fake_run_one)
        result = asyncio.run(REGISTRY["service_scan"].fn(target="203.0.113.7"))
        assert result["ok"] is True
        argv = captured["argv"]
        # nmap must be pointed at BOTH discovered ports, not the old 80,443.
        assert "-p" in argv
        ports_flag = argv[argv.index("-p") + 1]
        assert ports_flag == "3000,8080", f"expected discovered ports, got {ports_flag!r}"

    def test_explicit_ports_win_over_store(self, engagement, monkeypatch) -> None:
        import easyhunt.tools.ports  # noqa: F401
        from easyhunt.control_plane.context import get_engagement
        from easyhunt.knowledge.findings import Asset
        from easyhunt.tools.base import REGISTRY

        store = get_engagement().assets
        store.add(
            Asset(
                value="203.0.113.7:3000", kind="open_port", source="naabu",
                host="203.0.113.7", attributes={"host": "203.0.113.7", "port": 3000},
            )
        )
        captured: dict[str, object] = {}

        async def fake_run_one(binary: str, argv: list[str], **kwargs: object):
            captured["argv"] = argv
            import types

            run = types.SimpleNamespace(
                ran=False, error="fake", exit_code=0, values=[], stdout="",
            )
            run.to_dict = lambda: {"binary": "nmap", "argv": argv, "ran": False}
            return run

        monkeypatch.setattr("easyhunt.tools.ports.run_one", fake_run_one)
        asyncio.run(REGISTRY["service_scan"].fn(target="203.0.113.7", ports="443"))
        argv = captured["argv"]
        assert argv[argv.index("-p") + 1] == "443"

    def test_empty_store_falls_back_to_web_ports(self, engagement, monkeypatch) -> None:
        import easyhunt.tools.ports  # noqa: F401
        from easyhunt.tools.base import REGISTRY

        captured: dict[str, object] = {}

        async def fake_run_one(binary: str, argv: list[str], **kwargs: object):
            captured["argv"] = argv
            import types

            run = types.SimpleNamespace(
                ran=False, error="fake", exit_code=0, values=[], stdout="",
            )
            run.to_dict = lambda: {"binary": "nmap", "argv": argv, "ran": False}
            return run

        # A host with no open_port assets in the store (module-scoped
        # engagement retains earlier tests' assets for 203.0.113.7).
        monkeypatch.setattr("easyhunt.tools.ports.run_one", fake_run_one)
        asyncio.run(REGISTRY["service_scan"].fn(target="203.0.113.8"))
        argv = captured["argv"]
        assert argv[argv.index("-p") + 1] == "80,443"

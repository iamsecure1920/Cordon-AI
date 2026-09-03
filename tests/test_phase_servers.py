"""Phase-sliced MCP servers and the `connect` helper.

The slicing promise: every phase tool name resolves to a real registered
tool, every phase server carries the shared control surface, and the full
server stays a superset of every slice.
"""

from __future__ import annotations

import pytest

from cordon.phase_servers import (
    PHASE_SERVERS,
    SHARED_CONTROL_TOOLS,
    describe_servers,
    phase_server_names,
    tools_for_phase,
)


def _registry_names() -> set[str]:
    from cordon.mcp_server import load_capabilities, registered_tools

    load_capabilities()
    return {t.name for t in registered_tools()}


@pytest.fixture(scope="module")
def registry() -> set[str]:
    return _registry_names()


def test_every_phase_tool_is_registered(registry: set[str]) -> None:
    missing: list[tuple[str, str]] = []
    for phase, spec in PHASE_SERVERS.items():
        for tool in spec["tools"]:
            if tool not in registry:
                missing.append((phase, tool))
    assert not missing, f"phase manifest names unregistered tools: {missing}"


def test_every_registered_tool_is_reachable_from_some_server(registry: set[str]) -> None:
    # Six tools were silently full-server-only (strix_deep, burp_send, the
    # session/account tools, job_status) — an agent driving a phase server
    # could never reach them, and the docs table could not either. Every
    # registered tool must appear in at least one phase server (job_status
    # and the shared control surface live in SHARED_CONTROL_TOOLS).
    reachable = set(SHARED_CONTROL_TOOLS)
    for spec in PHASE_SERVERS.values():
        reachable.update(spec["tools"])
    # Tools registered by other test modules (t_passive, sec_passive, ...)
    # are fixtures, not shipped capabilities — only real cordon tools must
    # be reachable.
    orphaned = sorted(n for n in registry - reachable if not n.startswith(("t_", "sec_")))
    assert not orphaned, f"registered tools unreachable from any phase server: {orphaned}"


def test_every_phase_has_tools_and_a_description() -> None:
    for phase, spec in PHASE_SERVERS.items():
        assert spec["tools"], phase
        assert spec["description"], phase


def test_unknown_phase_returns_none() -> None:
    assert tools_for_phase("not-a-phase") is None


def test_shared_control_tools_are_appended_once() -> None:
    for phase in PHASE_SERVERS:
        tools = tools_for_phase(phase)
        assert tools is not None
        # no duplicates from spec + shared overlap
        assert len(tools) == len(set(tools)), phase
        for control in SHARED_CONTROL_TOOLS:
            assert control in tools, f"{phase} missing {control}"


def test_phase_servers_are_disjoint_enough_to_be_useful() -> None:
    # A phase server that equals the full surface would defeat the slicing.
    recon = set(tools_for_phase("recon") or [])
    exploit = set(tools_for_phase("exploit") or [])
    assert recon != exploit
    assert "subdomain_enum" in recon and "subdomain_enum" not in exploit
    assert "sqli_validate" in exploit and "sqli_validate" not in recon


def test_describe_servers_reports_counts() -> None:
    described = {d["name"] for d in describe_servers()}
    assert described == set(PHASE_SERVERS)
    assert phase_server_names() == sorted(PHASE_SERVERS)


def test_probe_carries_fingerprinting_and_review() -> None:
    probe = set(tools_for_phase("probe") or [])
    assert {"http_probe", "waf_detect", "recon_review", "tls_audit", "cors_audit"} <= probe


def test_connect_command_formats_every_agent(capsys: pytest.CaptureFixture[str]) -> None:
    import argparse

    from cordon.cli import cmd_connect

    for agent in ("claude", "cursor", "windsurf", "gemini", "copilot", "generic"):
        args = argparse.Namespace(
            agent=agent, phase="probe", scope=None, print_only=True,
        )
        assert cmd_connect(args) == 0
        out = capsys.readouterr().out
        assert "cordon.mcp_server" in out, agent
        assert "--phase probe" in out, agent

"""OAuth 2.1 + PKCE on the remote transport.

The tests that matter here are the refusals: an unauthenticated public bind, a
token minted for another audience, and — the sharpest one — an agent token trying
to answer its own approval prompt.
"""

from __future__ import annotations

import pytest

from cordon.control_plane.auth import (
    ALL_SCOPES,
    MODE_SCOPES,
    TOOL_SCOPE_OVERRIDES,
    AuthConfig,
    assert_bind_is_safe,
    auth_checks_for,
    build_auth_provider,
    describe,
    scopes_for_tool,
)
from cordon.errors import ConfigError


class TestBindSafety:
    def test_stdio_is_always_safe(self) -> None:
        # stdio is a pipe to the parent process; it is never network-exposed.
        assert_bind_is_safe("0.0.0.0", transport="stdio", auth=AuthConfig())  # noqa: S104

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.5"])
    def test_loopback_needs_no_auth(self, host: str) -> None:
        assert_bind_is_safe(host, transport="http", auth=AuthConfig())

    @pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "203.0.113.10"])  # noqa: S104
    def test_public_bind_without_auth_is_refused(self, host: str) -> None:
        with pytest.raises(ConfigError, match="remote code execution as a service"):
            assert_bind_is_safe(host, transport="http", auth=AuthConfig())

    def test_public_bind_with_auth_is_allowed(self) -> None:
        config = AuthConfig(mode="jwt", base_url="https://cordon.example.com")
        assert_bind_is_safe("0.0.0.0", transport="http", auth=config)  # noqa: S104

    def test_plaintext_base_url_on_a_public_bind_is_refused(self) -> None:
        # Bearer tokens over plaintext HTTP are recoverable by anyone on the path.
        config = AuthConfig(mode="jwt", base_url="http://cordon.example.com")
        with pytest.raises(ConfigError, match="plaintext HTTP"):
            assert_bind_is_safe("0.0.0.0", transport="http", auth=config)  # noqa: S104


class TestScopeLadder:
    def test_modes_map_to_escalating_scopes(self) -> None:
        assert MODE_SCOPES["passive"] == "cordon:recon"
        assert MODE_SCOPES["aggressive"] == "cordon:scan"
        assert MODE_SCOPES["exploit"] == "cordon:exploit"

    @pytest.mark.parametrize("mode", ["something-new", None, "", "PASSIVE"])
    def test_unclassified_tools_fail_closed_to_admin(self, mode) -> None:
        # Fail closed: a tool nobody classified is admin-only, so adding one
        # cannot accidentally expose it to every token. Note this is stricter
        # than 'exploit' — admin is the scope you grant least often.
        assert scopes_for_tool("mystery_tool", mode) == ["cordon:admin"]

    def test_approval_needs_its_own_scope(self) -> None:
        # The whole point: an agent token holding recon+scan+exploit still cannot
        # answer its own approval prompt, so human-in-the-loop stays real.
        assert scopes_for_tool("approval_respond", "passive") == ["cordon:approve"]
        assert "cordon:approve" not in {
            scopes_for_tool(n, m)[0]
            for n, m in [("nuclei_scan", "aggressive"), ("validate_findings", "exploit")]
        }

    def test_scope_loading_is_admin_only(self) -> None:
        # Repointing the authorization artifact is not a routine operation.
        assert scopes_for_tool("cordon_load_scope", "passive") == ["cordon:admin"]

    def test_read_only_tools_are_cheap_to_grant(self) -> None:
        for name in ("cordon_status", "findings_list", "scope_check", "audit_tail"):
            assert scopes_for_tool(name, "passive") == ["cordon:read"]

    def test_every_override_names_a_declared_scope(self) -> None:
        assert set(TOOL_SCOPE_OVERRIDES.values()) <= set(ALL_SCOPES)

    def test_real_tools_get_scopes_matching_their_risk(self) -> None:
        from cordon.mcp_server import load_capabilities
        from cordon.tools.base import registered_tools

        load_capabilities()
        for tool in registered_tools():
            scopes = scopes_for_tool(tool.name, tool.mode)
            assert len(scopes) == 1 and scopes[0] in ALL_SCOPES
            # An exploit tool must never be reachable with a recon-only token.
            if tool.mode == "exploit" and tool.name not in TOOL_SCOPE_OVERRIDES:
                assert scopes == ["cordon:exploit"]


class TestProviderConstruction:
    def test_disabled_returns_no_provider(self) -> None:
        assert build_auth_provider(AuthConfig()) is None

    def test_unknown_mode_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="unknown auth.mode"):
            build_auth_provider(AuthConfig(mode="magic"))

    def test_jwt_without_a_key_source_is_refused(self) -> None:
        # Half-configured auth must fail loudly at startup, not accept requests.
        config = AuthConfig(mode="jwt", authorization_servers=["https://idp.example.com"])
        with pytest.raises(ConfigError, match="no way to verify a token signature"):
            build_auth_provider(config)

    def test_jwt_without_authorization_servers_is_refused(self) -> None:
        config = AuthConfig(mode="jwt", jwks_uri="https://idp.example.com/jwks")
        with pytest.raises(ConfigError, match="authorization_servers"):
            build_auth_provider(config)

    def test_jwt_provider_builds_and_publishes_metadata(self) -> None:
        config = AuthConfig(
            mode="jwt",
            jwks_uri="https://idp.example.com/.well-known/jwks.json",
            issuer="https://idp.example.com/",
            base_url="https://cordon.example.com",
            authorization_servers=["https://idp.example.com"],
        )
        provider = build_auth_provider(config)
        assert provider is not None
        # RFC 9728 protected-resource metadata is what tells a client where to
        # get a token after a 401.
        routes = " ".join(str(r) for r in provider.get_routes())
        assert "oauth-protected-resource" in routes

    def test_oauth_proxy_requires_client_id_from_the_environment(self, monkeypatch) -> None:
        monkeypatch.delenv("CORDON_OAUTH_CLIENT_ID", raising=False)
        config = AuthConfig(
            mode="oauth_proxy",
            jwks_uri="https://idp.example.com/jwks",
            base_url="https://cordon.example.com",
            upstream_authorization_endpoint="https://idp.example.com/authorize",
            upstream_token_endpoint="https://idp.example.com/token",
        )
        with pytest.raises(ConfigError, match="CORDON_OAUTH_CLIENT_ID"):
            build_auth_provider(config)

    def test_oauth_proxy_forwards_pkce_and_resource(self, monkeypatch) -> None:
        monkeypatch.setenv("CORDON_OAUTH_CLIENT_ID", "test-client")
        monkeypatch.setenv("CORDON_OAUTH_CLIENT_SECRET", "test-secret")  # noqa: S105
        config = AuthConfig(
            mode="oauth_proxy",
            jwks_uri="https://idp.example.com/jwks",
            base_url="https://cordon.example.com",
            upstream_authorization_endpoint="https://idp.example.com/authorize",
            upstream_token_endpoint="https://idp.example.com/token",
        )
        provider = build_auth_provider(config)
        # PKCE must be generated for the upstream leg too, so fronting an IdP
        # does not weaken the flow being fronted.
        assert provider._forward_pkce is True

    def test_audience_defaults_to_base_url(self) -> None:
        config = AuthConfig(mode="jwt", base_url="https://cordon.example.com")
        assert describe(config)["audience"] == "https://cordon.example.com"


class TestPKCE:
    def test_authorize_handler_only_accepts_s256(self) -> None:
        # 'plain' PKCE is structurally impossible: the MCP SDK types the field as
        # Literal["S256"], so a downgrade attempt fails validation.
        from mcp.server.auth.handlers.authorize import AuthorizationRequest

        field = AuthorizationRequest.model_fields["code_challenge_method"]
        assert "S256" in str(field.annotation)
        assert "plain" not in str(field.annotation)

    def test_pkce_posture_is_reported(self) -> None:
        assert "S256" in describe(AuthConfig(mode="jwt"))["pkce"]
        assert "8707" in describe(AuthConfig(mode="jwt"))["resource_indicators"]


class TestToolWiring:
    def test_no_checks_when_auth_is_disabled(self) -> None:
        assert auth_checks_for("nuclei_scan", "aggressive", AuthConfig()) == []

    def test_checks_attached_when_enabled(self) -> None:
        config = AuthConfig(mode="jwt", base_url="https://cordon.example.com")
        checks = auth_checks_for("nuclei_scan", "aggressive", config)
        assert len(checks) == 1

    def test_enforcement_can_be_disabled_without_disabling_auth(self) -> None:
        config = AuthConfig(
            mode="jwt", base_url="https://cordon.example.com", enforce_tool_scopes=False
        )
        assert auth_checks_for("nuclei_scan", "aggressive", config) == []
        assert config.enabled is True

    def test_registration_documents_the_required_scope(self) -> None:
        import asyncio

        from fastmcp import FastMCP

        from cordon.mcp_server import load_capabilities, register_registry_tools

        load_capabilities()
        server = FastMCP("scope-doc-test")
        config = AuthConfig(mode="jwt", base_url="https://cordon.example.com")
        register_registry_tools(server, config)

        # _list_tools is the unfiltered internal view; list_tools() applies the
        # caller's scopes (see the next test).
        tools = {t.name: t for t in asyncio.run(server._list_tools())}
        assert "Requires OAuth scope: cordon:exploit" in tools["validate_findings"].description
        assert "Requires OAuth scope: cordon:recon" in tools["http_probe"].description

    def test_unauthenticated_callers_cannot_even_enumerate_the_tooling(self) -> None:
        import asyncio

        from fastmcp import FastMCP

        from cordon.mcp_server import load_capabilities, register_registry_tools

        load_capabilities()
        guarded = FastMCP("guarded")
        register_registry_tools(
            guarded, AuthConfig(mode="jwt", base_url="https://cordon.example.com")
        )
        open_server = FastMCP("open")
        register_registry_tools(open_server, AuthConfig())

        visible = asyncio.run(guarded.list_tools())
        everything = asyncio.run(open_server.list_tools())

        # Scope filtering applies to discovery, not just invocation: an
        # unauthenticated caller sees nothing at all, so the exploitation surface
        # is not even enumerable without a token.
        assert len(everything) > 40
        assert visible == []


class TestConfigParsing:
    def test_defaults_are_closed(self) -> None:
        config = AuthConfig.from_dict({})
        assert config.mode == "none" and not config.enabled

    def test_parses_a_jwt_section(self) -> None:
        config = AuthConfig.from_dict(
            {
                "mode": "jwt",
                "base_url": "https://cordon.example.com",
                "jwks_uri": "https://idp.example.com/jwks",
                "issuer": "https://idp.example.com/",
                "authorization_servers": ["https://idp.example.com"],
                "required_scopes": ["cordon:read"],
            }
        )
        assert config.enabled
        assert config.required_scopes == ["cordon:read"]

    def test_example_config_documents_every_scope(self) -> None:
        from pathlib import Path

        text = (Path(__file__).resolve().parents[1] / "config.example.yaml").read_text()
        for scope in ALL_SCOPES:
            assert scope in text, f"{scope} is undocumented in config.example.yaml"

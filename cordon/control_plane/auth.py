"""OAuth 2.1 + PKCE for the remote transport.

An Cordon server reachable over a network without authentication is remote code
execution as a service: it runs port scanners, exploitation tools, and arbitrary
wrapped binaries on request. So this module does two things.

**It authenticates.** Cordon acts as an OAuth 2.1 *Resource Server* (RFC 9728):
it publishes protected-resource metadata, verifies bearer tokens against an
authorization server, and rejects anything unsigned, expired, or minted for a
different audience. PKCE with ``S256`` is mandatory on the authorization-code
flow — the MCP SDK types the challenge method as ``Literal["S256"]``, so ``plain``
is structurally impossible rather than merely discouraged.

**It authorizes, against Cordon's own risk model.** This is the part worth the
effort. Every tool already declares ``passive``/``aggressive``/``exploit``, so
scopes map straight onto that ladder:

===================  ====================================================
scope                unlocks
===================  ====================================================
``cordon:read``    status, findings, scope checks — no target contact
``cordon:recon``   passive tools
``cordon:scan``    aggressive tools (ports, nuclei, brute force)
``cordon:exploit`` exploit tools (PoC validation, takeover confirmation)
``cordon:approve`` responding to approval prompts
``cordon:admin``   loading a scope, re-pinning tool definitions
===================  ====================================================

A token is a **ceiling**, checked before the human approval gate rather than
instead of it. A CI token holding only ``cordon:recon`` cannot invoke
exploitation *even if a human would have approved it*.

``cordon:approve`` is deliberately separate from everything else. If the agent's
own token could satisfy it, the agent could answer its own approval prompts and
human-in-the-loop would be decorative. Issue that scope to an operator's token
and to nothing else.

Two deployment modes:

* ``jwt`` — you already run an IdP (Auth0, Keycloak, Entra, Okta). Cordon
  verifies its JWTs via JWKS. The IdP owns login, PKCE, and consent.
* ``oauth_proxy`` — your IdP has no Dynamic Client Registration (GitHub, Google).
  FastMCP fronts it, handling DCR for MCP clients and forwarding PKCE upstream.

Default is ``none``, which is safe *because* binding a non-loopback address then
becomes a hard refusal rather than a warning.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from cordon.errors import ConfigError

log = logging.getLogger("cordon.auth")

__all__ = [
    "MODE_SCOPES",
    "AuthConfig",
    "assert_bind_is_safe",
    "build_auth_provider",
    "scopes_for_tool",
]

# Tool mode → the scope required to invoke it.
MODE_SCOPES: dict[str, str] = {
    "passive": "cordon:recon",
    "aggressive": "cordon:scan",
    "exploit": "cordon:exploit",
}

# Control-plane tools that need something other than their mode implies.
# These are the tools where the OAuth decision is doing real work: an agent token
# must not be able to grant its own approvals or repoint the scope artifact.
TOOL_SCOPE_OVERRIDES: dict[str, str] = {
    "approval_respond": "cordon:approve",
    "cordon_load_scope": "cordon:admin",
    "rules_reload": "cordon:admin",
    "cordon_finish": "cordon:admin",
    # Read-only introspection: useful to grant broadly.
    "cordon_status": "cordon:read",
    "cordon_capabilities": "cordon:read",
    "scope_check": "cordon:read",
    "audit_tail": "cordon:read",
    "findings_list": "cordon:read",
    "finding_detail": "cordon:read",
    "rules_list": "cordon:read",
    "job_status": "cordon:read",
    "job_list": "cordon:read",
    "taskgraph_next": "cordon:read",
    "approval_pending": "cordon:read",
}

ALL_SCOPES = [
    "cordon:read",
    "cordon:recon",
    "cordon:scan",
    "cordon:exploit",
    "cordon:approve",
    "cordon:admin",
]


def scopes_for_tool(name: str, mode: str | None) -> list[str]:
    """The OAuth scope a caller must hold to invoke this tool.

    Resolution order: explicit override, then the tool's risk mode, then — for a
    control-plane tool nobody classified — ``cordon:admin``. That last fallback
    is the fail-closed case: a newly added tool is privileged until someone
    deliberately says otherwise, rather than being reachable by any token.
    """
    override = TOOL_SCOPE_OVERRIDES.get(name)
    if override:
        return [override]
    if mode in MODE_SCOPES:
        return [MODE_SCOPES[mode]]
    return ["cordon:admin"]


@dataclass
class AuthConfig:
    """Parsed ``auth:`` section of config.yaml."""

    mode: str = "none"
    #: Public URL clients reach this server on. Becomes the RFC 8707 resource
    #: indicator, so tokens are bound to *this* server and cannot be replayed
    #: against another service that trusts the same IdP.
    base_url: str = "http://127.0.0.1:8765"
    jwks_uri: str | None = None
    issuer: str | None = None
    audience: str | None = None
    public_key: str | None = None
    algorithm: str | None = None
    required_scopes: list[str] = field(default_factory=list)
    authorization_servers: list[str] = field(default_factory=list)
    # oauth_proxy mode
    upstream_authorization_endpoint: str | None = None
    upstream_token_endpoint: str | None = None
    upstream_client_id_env: str = "CORDON_OAUTH_CLIENT_ID"
    # The env var *name* to read the secret from — the secret itself never
    # appears in config, which is why this is a name and not a value.
    upstream_client_secret_env: str = "CORDON_OAUTH_CLIENT_SECRET"  # noqa: S105
    allowed_client_redirect_uris: list[str] = field(default_factory=list)
    require_consent: bool = True
    #: Enforce per-tool scopes. Turning this off keeps authentication but drops
    #: the authorization ladder — authenticated then means fully privileged.
    enforce_tool_scopes: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AuthConfig:
        data = data or {}
        return cls(
            mode=str(data.get("mode") or "none").lower(),
            base_url=str(data.get("base_url") or "http://127.0.0.1:8765"),
            jwks_uri=data.get("jwks_uri"),
            issuer=data.get("issuer"),
            audience=data.get("audience"),
            public_key=data.get("public_key"),
            algorithm=data.get("algorithm"),
            required_scopes=[str(s) for s in (data.get("required_scopes") or [])],
            authorization_servers=[str(s) for s in (data.get("authorization_servers") or [])],
            upstream_authorization_endpoint=data.get("upstream_authorization_endpoint"),
            upstream_token_endpoint=data.get("upstream_token_endpoint"),
            upstream_client_id_env=str(data.get("upstream_client_id_env") or "CORDON_OAUTH_CLIENT_ID"),
            upstream_client_secret_env=str(
                data.get("upstream_client_secret_env") or "CORDON_OAUTH_CLIENT_SECRET"
            ),
            allowed_client_redirect_uris=[
                str(u) for u in (data.get("allowed_client_redirect_uris") or [])
            ],
            require_consent=bool(data.get("require_consent", True)),
            enforce_tool_scopes=bool(data.get("enforce_tool_scopes", True)),
        )

    @property
    def enabled(self) -> bool:
        return self.mode not in {"none", "", "disabled"}


# --------------------------------------------------------------------------- #
# Bind safety
# --------------------------------------------------------------------------- #


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_bind_is_safe(host: str, *, transport: str, auth: AuthConfig) -> None:
    """Refuse to expose an unauthenticated server to a network.

    A warning is not sufficient here. This process can run nmap, sqlmap, and
    arbitrary sandboxed binaries on request; unauthenticated network exposure is
    a remote-code-execution endpoint, and the failure mode of "the operator did
    not read the warning" is somebody else's incident.
    """
    if transport == "stdio":
        # stdio is a pipe to the parent process and is never network-exposed.
        return

    if _is_loopback(host):
        return

    if not auth.enabled:
        raise ConfigError(
            f"refusing to bind {host} without authentication.\n\n"
            "A network-reachable Cordon server executes security tools on "
            "request — exposing it unauthenticated is remote code execution as a "
            "service.\n\n"
            "Either:\n"
            "  • bind 127.0.0.1 and reach it through an SSH tunnel, or\n"
            "  • configure auth.mode: jwt (or oauth_proxy) in config.yaml.\n\n"
            "See `cordon doctor` for the current auth status.",
            host=host,
            transport=transport,
        )

    if auth.base_url.startswith("http://") and not _is_loopback(host):
        raise ConfigError(
            f"auth.base_url is {auth.base_url!r} but the server is binding a public "
            "address. Bearer tokens over plaintext HTTP are recoverable by anyone "
            "on the path — use https:// (terminate TLS at a reverse proxy if you "
            "prefer).",
            base_url=auth.base_url,
        )


# --------------------------------------------------------------------------- #
# Provider construction
# --------------------------------------------------------------------------- #


def build_auth_provider(config: AuthConfig) -> Any | None:
    """Build the FastMCP auth provider for the configured mode.

    Returns ``None`` when auth is disabled. Raises :class:`ConfigError` with an
    actionable message when a mode is selected but under-configured — a
    half-configured auth layer must fail loudly at startup, not silently accept
    requests.
    """
    if not config.enabled:
        return None

    if config.mode == "jwt":
        return _build_jwt_provider(config)
    if config.mode in {"oauth_proxy", "proxy"}:
        return _build_oauth_proxy(config)

    raise ConfigError(
        f"unknown auth.mode {config.mode!r}; expected none, jwt, or oauth_proxy",
        mode=config.mode,
    )


def _token_verifier(config: AuthConfig) -> Any:
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    if not (config.jwks_uri or config.public_key):
        raise ConfigError(
            "auth.mode is set but neither auth.jwks_uri nor auth.public_key is "
            "configured — there is no way to verify a token signature.",
        )

    return JWTVerifier(
        jwks_uri=config.jwks_uri,
        public_key=config.public_key,
        issuer=config.issuer,
        # RFC 8707: the audience is this server's resource identifier. A token
        # minted for another service that trusts the same IdP is rejected here,
        # which is what stops the confused-deputy replay.
        audience=config.audience or config.base_url,
        algorithm=config.algorithm,
        required_scopes=config.required_scopes or None,
        base_url=config.base_url,
        # Block SSRF via a hostile jwks_uri.
        ssrf_safe=True,
    )


def _build_jwt_provider(config: AuthConfig) -> Any:
    from fastmcp.server.auth import RemoteAuthProvider

    if not config.authorization_servers:
        raise ConfigError(
            "auth.mode 'jwt' requires auth.authorization_servers — clients need it "
            "to discover where to obtain a token (RFC 9728 protected-resource "
            "metadata).",
        )

    provider = RemoteAuthProvider(
        token_verifier=_token_verifier(config),
        authorization_servers=config.authorization_servers,
        base_url=config.base_url,
        scopes_supported=ALL_SCOPES,
        resource_name="Cordon AI",
        resource_documentation="https://github.com/sobila/EasyHunt-AI",
    )
    log.info(
        "auth: resource server for %s (issuer=%s, audience=%s)",
        config.base_url, config.issuer, config.audience or config.base_url,
    )
    return provider


def _build_oauth_proxy(config: AuthConfig) -> Any:
    from fastmcp.server.auth.oauth_proxy import OAuthProxy

    client_id = os.environ.get(config.upstream_client_id_env, "")
    client_secret = os.environ.get(config.upstream_client_secret_env, "")
    if not client_id:
        raise ConfigError(
            f"auth.mode 'oauth_proxy' requires ${config.upstream_client_id_env} in "
            "the environment. Client credentials belong in the environment, never "
            "in config.yaml — that file gets committed.",
        )
    if not (config.upstream_authorization_endpoint and config.upstream_token_endpoint):
        raise ConfigError(
            "auth.mode 'oauth_proxy' requires auth.upstream_authorization_endpoint "
            "and auth.upstream_token_endpoint.",
        )

    provider = OAuthProxy(
        upstream_authorization_endpoint=config.upstream_authorization_endpoint,
        upstream_token_endpoint=config.upstream_token_endpoint,
        upstream_client_id=client_id,
        upstream_client_secret=client_secret or None,
        token_verifier=_token_verifier(config),
        base_url=config.base_url,
        valid_scopes=ALL_SCOPES,
        allowed_client_redirect_uris=config.allowed_client_redirect_uris or None,
        # PKCE is generated for the upstream leg as well, so the proxy does not
        # weaken the flow it is fronting.
        forward_pkce=True,
        # RFC 8707 resource indicator forwarded upstream, keeping the audience
        # binding intact end to end.
        forward_resource=True,
        require_authorization_consent=config.require_consent,
    )
    log.info("auth: OAuth proxy fronting %s", config.upstream_authorization_endpoint)
    return provider


# --------------------------------------------------------------------------- #
# Per-tool authorization
# --------------------------------------------------------------------------- #


def auth_checks_for(name: str, mode: str, config: AuthConfig) -> list[Any]:
    """FastMCP ``AuthCheck``s gating one tool, or ``[]`` when auth is off."""
    if not (config.enabled and config.enforce_tool_scopes):
        return []
    from fastmcp.server.auth import require_scopes

    return [require_scopes(*scopes_for_tool(name, mode))]


async def apply_tool_auth(server: Any, config: AuthConfig, modes: dict[str, str]) -> dict[str, str]:
    """Attach scope checks to *every* tool on the server, however it was registered.

    The registry tools get their checks at registration, but the control-plane
    tools (``approval_respond``, ``cordon_load_scope``, …) are declared with a
    plain ``@mcp.tool`` decorator at import time, before any config is loaded.
    Without this pass they would carry no checks at all — meaning any
    authenticated caller could load a new scope artifact or answer an approval
    prompt, which is precisely the bypass the scope ladder exists to prevent.

    Returns ``{tool_name: scope}`` for the audit record and ``cordon doctor``.
    """
    if not (config.enabled and config.enforce_tool_scopes):
        return {}

    from fastmcp.server.auth import require_scopes

    applied: dict[str, str] = {}
    for tool in await server._list_tools():
        scopes = scopes_for_tool(tool.name, modes.get(tool.name))
        # Never widen a check another layer already set.
        if not getattr(tool, "auth", None):
            tool.auth = [require_scopes(*scopes)]
        applied[tool.name] = scopes[0]
    return applied


def describe(config: AuthConfig) -> dict[str, Any]:
    """Auth posture, for ``cordon doctor`` and ``cordon_status``."""
    return {
        "mode": config.mode,
        "enabled": config.enabled,
        "base_url": config.base_url,
        "issuer": config.issuer,
        "audience": config.audience or config.base_url,
        "authorization_servers": config.authorization_servers,
        "enforce_tool_scopes": config.enforce_tool_scopes,
        "scopes_supported": ALL_SCOPES,
        "pkce": "S256 required (plain is rejected by the MCP authorize handler)",
        "resource_indicators": "RFC 8707 — tokens must be audience-bound to base_url",
    }


def current_identity() -> dict[str, Any] | None:
    """Subject, client, and scopes of the caller, if a token is in play.

    Used to attribute audit records: with auth on, "who ran this scan" has an
    answer beyond "whoever had access to the machine".
    """
    try:
        from fastmcp.server.dependencies import get_access_token
    except ImportError:  # pragma: no cover — older fastmcp
        return None
    try:
        token = get_access_token()
    except Exception:  # noqa: BLE001 — no request context, or unauthenticated
        return None
    if token is None:
        return None
    return {
        "subject": getattr(token, "subject", None),
        "client_id": getattr(token, "client_id", None),
        "scopes": list(getattr(token, "scopes", []) or []),
        "resource": getattr(token, "resource", None),
    }

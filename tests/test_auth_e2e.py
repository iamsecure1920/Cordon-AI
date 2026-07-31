"""Live OAuth end-to-end: a real HTTP server, real signed JWTs, real refusals.

Everything else about auth can be unit-tested. What cannot is whether the wiring
actually rejects a bad token over the wire, so this starts the streamable-HTTP
transport with an RSA keypair standing in for an IdP's JWKS and drives it with an
MCP client.

The four cases that matter:

* no token           → refused
* wrong audience     → refused (RFC 8707 confused-deputy replay)
* expired            → refused
* recon-only token   → can probe, cannot exploit, cannot self-approve
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

RESOURCE = "https://easyhunt.test"
ISSUER = "https://idp.test/"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="module")
def keypair() -> Any:
    """An RSA keypair standing in for the IdP's signing key."""
    from fastmcp.server.auth.providers.jwt import RSAKeyPair

    return RSAKeyPair.generate()


@pytest.fixture(scope="module")
def server(keypair, tmp_path_factory) -> Any:
    """The real ``easyhunt.mcp_server`` entrypoint, in a subprocess, over HTTP.

    Deliberately not an in-process FastMCP built by the test: launching the
    shipped entrypoint means this exercises config loading, the bind check, the
    provider construction, the control-plane tools, and the scope-application
    pass — the things that would actually be wrong in production.
    """
    import os
    import subprocess
    import sys

    import yaml

    tmp = tmp_path_factory.mktemp("authserver")
    port = _free_port()

    (tmp / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "auth": {
                    "mode": "jwt",
                    "base_url": RESOURCE,
                    "public_key": keypair.public_key,
                    "issuer": ISSUER,
                    "audience": RESOURCE,
                    "authorization_servers": [ISSUER],
                    "enforce_tool_scopes": True,
                },
                "workspace": {"root": str(tmp / "engagements")},
                "sandbox": {"mode": "none"},
                "memory": {"poc_store": str(tmp / "memory.jsonl")},
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable, "-m", "easyhunt.mcp_server",
            "--transport", "http", "--host", "127.0.0.1", "--port", str(port),
            "--config", str(tmp / "config.yaml"), "--log-level", "ERROR",
        ],
        cwd=str(tmp),
        env={**os.environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1])},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            pytest.fail(f"auth server exited {proc.returncode}: {err.decode()[-2000:]}")
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.4):
            break
        time.sleep(0.2)
    else:  # pragma: no cover
        proc.kill()
        pytest.skip("auth test server did not start in time")

    yield {"port": port, "url": f"http://127.0.0.1:{port}/mcp", "proc": proc}

    proc.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=10)


def token(keypair, *, scopes: list[str], audience: str = RESOURCE, expires_in: int = 3600) -> str:
    return keypair.create_token(
        subject="tester",
        issuer=ISSUER,
        audience=audience,
        scopes=scopes,
        expires_in_seconds=expires_in,
    )


async def _list_tools(url: str, jwt: str | None) -> list[str]:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}
    client = Client(StreamableHttpTransport(url, headers=headers))
    async with client:
        return [t.name for t in await client.list_tools()]


async def _call(url: str, jwt: str | None, tool: str, **args: Any) -> Any:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}
    client = Client(StreamableHttpTransport(url, headers=headers))
    async with client:
        return await client.call_tool(tool, args)


class TestTokenRejection:
    def test_no_token_is_refused(self, server) -> None:
        with pytest.raises(Exception) as excinfo:
            asyncio.run(_list_tools(server["url"], None))
        assert any(m in str(excinfo.value).lower() for m in ("401", "unauthorized", "auth"))

    def test_wrong_audience_is_refused(self, server, keypair) -> None:
        # RFC 8707: a token minted for another service that trusts the same IdP
        # must not be replayable here. This is the confused-deputy case.
        other = token(keypair, scopes=["easyhunt:read"], audience="https://other.service")
        with pytest.raises(Exception) as excinfo:
            asyncio.run(_list_tools(server["url"], other))
        assert any(m in str(excinfo.value).lower() for m in ("401", "unauthorized", "auth"))

    def test_expired_token_is_refused(self, server, keypair) -> None:
        stale = token(keypair, scopes=["easyhunt:read"], expires_in=-60)
        with pytest.raises(Exception) as excinfo:
            asyncio.run(_list_tools(server["url"], stale))
        assert any(m in str(excinfo.value).lower() for m in ("401", "unauthorized", "auth"))

    def test_unsigned_garbage_is_refused(self, server) -> None:
        with pytest.raises(Exception):
            asyncio.run(_list_tools(server["url"], "not.a.jwt"))


class TestScopeLadderOverTheWire:
    def test_read_token_sees_only_read_tools(self, server, keypair) -> None:
        jwt = token(keypair, scopes=["easyhunt:read"])
        names = asyncio.run(_list_tools(server["url"], jwt))
        assert "easyhunt_status" in names
        # No recon, scanning, or exploitation is even visible.
        assert "http_probe" not in names
        assert "nuclei_scan" not in names
        assert "validate_findings" not in names

    def test_recon_token_gains_passive_tools_only(self, server, keypair) -> None:
        jwt = token(keypair, scopes=["easyhunt:read", "easyhunt:recon"])
        names = asyncio.run(_list_tools(server["url"], jwt))
        assert "http_probe" in names and "subdomain_enum" in names
        assert "nuclei_scan" not in names
        assert "validate_findings" not in names

    def test_scan_token_stops_short_of_exploitation(self, server, keypair) -> None:
        jwt = token(keypair, scopes=["easyhunt:recon", "easyhunt:scan"])
        names = asyncio.run(_list_tools(server["url"], jwt))
        assert "nuclei_scan" in names and "port_scan" in names
        # The ceiling holds: scanning does not imply exploiting.
        assert "validate_findings" not in names
        assert "takeover_confirm" not in names

    def test_exploit_token_unlocks_validation(self, server, keypair) -> None:
        jwt = token(keypair, scopes=["easyhunt:exploit"])
        names = asyncio.run(_list_tools(server["url"], jwt))
        assert "validate_findings" in names and "takeover_confirm" in names

    def test_agent_token_cannot_answer_its_own_approval(self, server, keypair) -> None:
        # The sharpest property in the whole auth layer. A token with every
        # operational scope still cannot reach approval_respond, so an agent
        # cannot approve its own aggressive actions.
        jwt = token(
            keypair,
            scopes=["easyhunt:read", "easyhunt:recon", "easyhunt:scan", "easyhunt:exploit"],
        )
        names = asyncio.run(_list_tools(server["url"], jwt))
        assert "validate_findings" in names, "sanity: this token is otherwise privileged"
        assert "approval_respond" not in names, "agent token must not be able to self-approve"

        with pytest.raises(Exception):
            asyncio.run(
                _call(server["url"], jwt, "approval_respond", token="apr_x", decision="accept")
            )

    def test_operator_token_can_approve(self, server, keypair) -> None:
        jwt = token(keypair, scopes=["easyhunt:approve"])
        assert "approval_respond" in asyncio.run(_list_tools(server["url"], jwt))

    def test_admin_scope_gates_scope_loading(self, server, keypair) -> None:
        agent = token(keypair, scopes=["easyhunt:recon", "easyhunt:scan", "easyhunt:exploit"])
        assert "easyhunt_load_scope" not in asyncio.run(_list_tools(server["url"], agent))

        admin = token(keypair, scopes=["easyhunt:admin"])
        assert "easyhunt_load_scope" in asyncio.run(_list_tools(server["url"], admin))


class TestProtectedResourceMetadata:
    def test_401_advertises_where_to_get_a_token(self, server) -> None:
        import httpx

        # RFC 9728 discovery: an unauthenticated request must come back 401 with
        # a WWW-Authenticate pointing at the metadata document. That header is
        # how a client bootstraps the whole flow without prior configuration.
        response = httpx.post(f"http://127.0.0.1:{server['port']}/mcp", json={}, timeout=10)
        assert response.status_code == 401
        challenge = response.headers.get("www-authenticate", "")
        assert challenge.startswith("Bearer ")
        assert "resource_metadata=" in challenge

    def test_metadata_document_names_the_resource_and_scopes(self, server) -> None:
        import httpx

        # Path-suffixed form, because the MCP endpoint is mounted at /mcp.
        response = httpx.get(
            f"http://127.0.0.1:{server['port']}/.well-known/oauth-protected-resource/mcp",
            timeout=10,
        )
        assert response.status_code == 200
        payload = response.json()
        # The resource identifier is what tokens must be audience-bound to.
        assert payload["resource"].startswith(RESOURCE)
        assert any(ISSUER.rstrip("/") in str(a) for a in payload["authorization_servers"])
        # Clients can discover the full privilege ladder up front.
        assert set(payload.get("scopes_supported", [])) == {
            "easyhunt:read", "easyhunt:recon", "easyhunt:scan",
            "easyhunt:exploit", "easyhunt:approve", "easyhunt:admin",
        }

    def test_advertised_metadata_url_resolves(self, server) -> None:
        import httpx

        challenge = httpx.post(
            f"http://127.0.0.1:{server['port']}/mcp", json={}, timeout=10
        ).headers["www-authenticate"]
        advertised = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
        # The server advertises its public base_url; check the path it names is
        # the one actually served locally.
        path = advertised.split(RESOURCE, 1)[-1]
        assert httpx.get(f"http://127.0.0.1:{server['port']}{path}", timeout=10).status_code == 200

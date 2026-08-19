"""Reference Python plugin: fetch and parse /.well-known/security.txt.

Shows the whole contract for a class-A plugin:

* declare the capability with ``@cordon_tool`` — that is the only way a plugin
  can expose anything, and it is what wraps the call in the control plane;
* take the target as a normal argument and let the decorator scope-check it;
* return structured data, never a raw dump.

The HTTP call here is a single GET of a well-known, deliberately public path,
which is why the manifest declares ``mode: passive``.
"""

from __future__ import annotations

import httpx

from cordon.control_plane.context import get_engagement
from cordon.tools.base import cordon_tool


@cordon_tool(
    phase="recon",
    mode="passive",
    targets_arg="target",
    name="security_txt",
    origin="plugin:example-security-txt",
    estimated_requests=1,
)
async def security_txt(target: str) -> dict:
    """Fetch /.well-known/security.txt and report the declared security contact."""
    engagement = get_engagement()
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    fields: dict[str, list[str]] = {}
    found_at = None
    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=True,
        headers={"User-Agent": engagement.scope.rules.user_agent},
    ) as client:
        for url in (
            f"https://{host}/.well-known/security.txt",
            f"https://{host}/security.txt",
        ):
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code != 200 or "html" in response.headers.get("content-type", ""):
                continue
            found_at = url
            for line in response.text.splitlines():
                if ":" not in line or line.lstrip().startswith("#"):
                    continue
                key, _, value = line.partition(":")
                fields.setdefault(key.strip().lower(), []).append(value.strip())
            break

    return {
        "ok": True,
        "host": host,
        "found_at": found_at,
        "contact": fields.get("contact", []),
        "policy": fields.get("policy", []),
        "expires": fields.get("expires", []),
        "fields": fields,
        "note": (
            "No security.txt published — worth an observation, not a finding."
            if not found_at
            else "Prefer the contact channel declared here over guessing an address."
        ),
    }

"""endpoint_discovery: archives are meaningless for an IP-literal seed.

gau/waybackurls/waymore index URLs by *domain*. For an IP they return a flood of
unrelated historical URLs — every site that was ever served from that address —
which is not the target's attack surface. Measured: a local 127.0.0.1 seed
produced 49,172 archived URLs, of which effectively none belonged to the app
under test. For an IP seed the archives are skipped and the surface is crawled
actively instead.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from easyhunt.control_plane.sanitize import sanitize_argv
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import CATALOG, ToolRun

EP = importlib.import_module("easyhunt.tools.endpoints")


@pytest.mark.parametrize(
    "value",
    ["127.0.0.1", "203.0.113.7", "10.0.0.1:8080", "::1", "[::1]", "[2001:db8::1]:443"],
)
def test_is_ip_literal_true(value: str) -> None:
    assert EP._is_ip_literal(value) is True


@pytest.mark.parametrize("value", ["example.com", "chime.com", "api.example.com", "app.example.org"])
def test_is_ip_literal_false(value: str) -> None:
    assert EP._is_ip_literal(value) is False


def _spy(monkeypatch: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        spec = CATALOG[name]
        sanitize_argv(name, list(argv), policy=spec.arg_policy)
        calls.append({"tool": name, "argv": list(argv)})
        return ToolRun(tool=name, ran=True, values=[], duration_s=0.1, exit_code=0)

    monkeypatch.setattr(EP, "run_one", fake_run_one)
    return calls


def _tools(calls: list[dict[str, Any]]) -> set[str]:
    return {c["tool"] for c in calls}


async def test_ip_literal_skips_archives_and_crawls(engagement: Any, monkeypatch: Any) -> None:
    calls = _spy(monkeypatch)
    await REGISTRY["endpoint_discovery"].fn(target="203.0.113.7:3000")

    tools = _tools(calls)
    assert "katana" in tools
    assert not ({"gau", "waybackurls", "waymore", "paramspider"} & tools), tools

    katana = next(c for c in calls if c["tool"] == "katana")
    url = katana["argv"][katana["argv"].index("-u") + 1]
    # The crawl kept the full seed (port included), not the stripped host.
    assert url == "http://203.0.113.7:3000"


async def test_domain_still_uses_archives(engagement: Any, monkeypatch: Any) -> None:
    calls = _spy(monkeypatch)
    await REGISTRY["endpoint_discovery"].fn(target="example.com")

    tools = _tools(calls)
    assert {"gau", "waybackurls", "waymore"} <= tools
    # include_crawl defaults off, so no katana for a domain seed.
    assert "katana" not in tools

"""The native HTTP validator for open redirect, CRLF, LFI and XXE.

This tool is the validator that promoted four classes from ``detect-only`` to
``auto`` in the coverage matrix, so the properties worth testing are:

1. **It is a real, registered, approval-gated tool.** The coverage row says
   ``web_injection_probe (xxe)`` — if the tool were passive or unregistered, the
   matrix would be a false promise.
2. **The injector quotes payloads for the wire without double-encoding.** The
   CRLF payload is raw CR+LF and must survive URL-quoting; a pre-encoded variant
   would arrive as the literal string ``%250d%250a``.
3. **Refusals happen before any request.** A bogus class, a missing parameter,
   or a multi-parameter URL must be refused with a named error, not tested.
4. **The approval gate is real.** An exploit-mode tool must not run unapproved.
"""

from __future__ import annotations

import httpx
import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.tools import web_injection as w
from easyhunt.tools.base import REGISTRY


def approve(engagement, tool: str) -> None:
    engagement.approval.backend = PolicyBackend(auto_approve=[tool])


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


class TestRegistration:
    def test_tool_is_registered_and_gated(self) -> None:
        spec = REGISTRY["web_injection_probe"]
        assert spec.mode == "exploit"
        assert spec.phase == "exploit"
        assert spec.estimated_requests == 20
        assert spec.risk_notes, "an approval prompt with no risk notes tells the human nothing"

    def test_upload_surface_is_passive_and_registered(self) -> None:
        spec = REGISTRY["upload_surface"]
        assert spec.mode == "passive"
        assert spec.phase == "method"

    def test_every_class_has_a_shape(self) -> None:
        assert set(w._CLASSES) == {"open-redirect", "crlf", "lfi", "xxe", "hpp"}
        for name, spec in w._CLASSES.items():
            assert spec["payloads"], name
            assert spec["where"] in {"headers", "location", "body"}, name
            assert spec["signature"].pattern, name


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


class TestInjector:
    def test_substitutes_and_quotes_a_payload(self) -> None:
        url = "https://www.example.com/next?dest=/home"
        injected = w._inject(url, "dest", "https://easyhunt-canary.invalid/x", safe="")
        # The scheme and slashes are quoted so the value survives the wire as one
        # parameter, not as path structure.
        assert injected.startswith("https://www.example.com/next?dest=https%3A%2F%2F")
        assert "easyhunt-canary.invalid" in injected

    def test_lfi_keeps_slashes_literal(self) -> None:
        url = "https://www.example.com/view?file=index.php"
        injected = w._inject(url, "file", "../../../../etc/passwd", safe="/")
        # Traversal must survive unquoted; only the slashes are kept, dots stay
        # as themselves (they are in the always-safe set).
        assert injected.endswith("file=../../../../etc/passwd")

    def test_crlf_payload_is_not_double_encoded(self) -> None:
        url = "https://www.example.com/redirect?next=home"
        injected = w._inject(url, "next", "\r\nEasyHunt-Injected: 1", safe="")
        # One layer of quoting: %0D%0A, not %250D%250A.
        assert "%0D%0A" in injected.upper()
        assert "%250D" not in injected.upper()

    def test_hpp_duplicates_instead_of_replacing(self) -> None:
        url = "https://www.example.com/search?q=original"
        injected = w._inject(url, "q", "easyhunt-hpp-canary", safe="", duplicate=True)
        # The original value is preserved and the canary is appended as a second
        # occurrence of the same parameter — the HPP primitive.
        assert injected.count("q=") == 2
        assert "q=original" in injected
        assert "easyhunt-hpp-canary" in injected


class TestSignatureHit:
    def test_header_signature_matches_header_names(self) -> None:
        resp = httpx.Response(200, headers={"easyhunt-injected": "1"})
        assert w._signature_hit(resp, "headers", w._CLASSES["crlf"]["signature"])

    def test_location_signature_reads_the_location_header(self) -> None:
        resp = httpx.Response(302, headers={"location": "https://easyhunt-canary.invalid/x"})
        assert w._signature_hit(resp, "location", w._CLASSES["open-redirect"]["signature"])

    def test_body_signature_matches_the_body(self) -> None:
        resp = httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
        assert w._signature_hit(resp, "body", w._CLASSES["lfi"]["signature"])

    def test_clean_response_is_not_a_hit(self) -> None:
        resp = httpx.Response(200, text="welcome, nothing to see here")
        assert not w._signature_hit(resp, "body", w._CLASSES["lfi"]["signature"])


# --------------------------------------------------------------------------- #
# Refusals and the approval gate
# --------------------------------------------------------------------------- #


class TestRefusals:
    @pytest.mark.asyncio
    async def test_unknown_class_is_refused(self, engagement) -> None:
        approve(engagement, "web_injection_probe")
        result = await REGISTRY["web_injection_probe"].fn(
            target="https://www.example.com/x?q=1", parameter="q", bug_class="bogus"
        )
        assert result["ok"] is False
        assert result["error"] == "unknown_class"

    @pytest.mark.asyncio
    async def test_missing_parameter_is_refused(self, engagement) -> None:
        approve(engagement, "web_injection_probe")
        result = await REGISTRY["web_injection_probe"].fn(
            target="https://www.example.com/x?q=1", parameter="nope", bug_class="lfi"
        )
        assert result["ok"] is False
        assert result["error"] == "unknown_parameter"

    @pytest.mark.asyncio
    async def test_multi_parameter_url_is_refused(self, engagement) -> None:
        approve(engagement, "web_injection_probe")
        result = await REGISTRY["web_injection_probe"].fn(
            target="https://www.example.com/x?a=1&b=2", parameter="a", bug_class="lfi"
        )
        assert result["ok"] is False
        assert result["error"] == "multi_parameter"

    @pytest.mark.asyncio
    async def test_non_http_target_is_refused(self, engagement) -> None:
        # A bare hostname passes scope (www.example.com is in scope) but has no
        # scheme, so the tool must refuse it rather than request it as a path.
        approve(engagement, "web_injection_probe")
        result = await REGISTRY["web_injection_probe"].fn(
            target="www.example.com", parameter="q", bug_class="lfi"
        )
        assert result["ok"] is False
        assert result["error"] == "bad_target"

    @pytest.mark.asyncio
    async def test_exploit_tool_cannot_run_unapproved(self, engagement) -> None:
        # Backend is "deny" by default in the test config; no approval entry.
        with pytest.raises(Exception) as excinfo:
            await REGISTRY["web_injection_probe"].fn(
                target="https://www.example.com/x?q=1", parameter="q", bug_class="lfi"
            )
        assert "approval" in str(excinfo.value).lower()

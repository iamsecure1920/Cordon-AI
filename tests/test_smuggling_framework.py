"""The operator-supplied smuggler framework, and the coverage it has to report.

This wrapper exists because of one bug, found by disbelieving a clean result.
The framework's connection pool handed out sockets it had already closed — the
victim request carries ``Connection: close`` by design — so after the ten
pre-filled connections were spent, every send raised a broken pipe into a
handler that swallowed it. The scan finished in two seconds, reported "802
payloads across 5 detectors", and called the target clean. Roughly ten requests
had left the machine.

Everything here defends the distinction that bug erased:

1. **Loaded is not sent.** ``requests_sent`` is counted at the socket. A result
   that quotes a payload count without it is quoting an intention.
2. **A skipped detector is not a clean result.** Any skip — an absent HTTP/2
   endpoint, a missing delay gadget, a delivery shortfall — makes the whole
   result ``PARTIAL`` and ``complete: False``.
3. **An absent framework is UNTESTED**, never zero findings.
4. **The argv the wrapper builds passes the wrapper's own policy**, and names
   the container path, because the host path does not exist inside the sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.sanitize import sanitize_argv
from easyhunt.tools import smuggling_framework as sf
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import ToolRun

pytestmark = pytest.mark.asyncio


def _report(**coverage: Any) -> dict[str, Any]:
    """A framework report with the coverage block under test."""
    base = {
        "payloads_loaded": {"te_obfuscations": 376, "cl_te_variants": 100},
        "payloads_total": 802,
        "requests_sent": 4572,
        "send_errors": 0,
        "phases_run": ["cl_te", "te_cl", "te_te", "chunk_extensions", "hop_by_hop"],
        "phases_skipped": [],
        "verdict": "0 finding(s) from 802 payloads (4572 requests sent)",
    }
    base.update(coverage)
    return {"results": [{"target": "http://t/", "echo_path": "/", "delay_path": None,
                         "findings": [], "coverage": base}]}


def drive(monkeypatch, engagement, report: dict[str, Any] | None, *, ran: bool = True):
    """Intercept run_one; write ``report`` where the wrapper will look for it."""
    seen: dict[str, Any] = {}

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        seen["tool"] = name
        seen["argv"] = list(argv)
        if not ran:
            return ToolRun(tool=name, ran=False, error="not installed")
        # The wrapper passes --output; honour it, so the test exercises the same
        # read path the real run does rather than a stubbed return value.
        out = Path(argv[argv.index("--output") + 1])
        if report is not None:
            out.write_text(json.dumps(report), encoding="utf-8")
        return ToolRun(tool=name, ran=True, values=[], exit_code=0)

    monkeypatch.setattr(sf, "run_one", fake_run_one)
    # The framework is operator-supplied and may genuinely be absent on the
    # machine running these tests; pin it so the tests below test the wrapper
    # rather than the developer's filesystem.
    monkeypatch.setattr(sf, "_framework_root", lambda: engagement.workspace)
    monkeypatch.setattr(sf, "_mount_framework", lambda root: None)
    # Aggressive mode: the approval gate is real and must be satisfied.
    engagement.approval.backend = PolicyBackend(auto_approve=["smuggling_canary_probe"])
    return seen


class TestRegistration:
    async def test_the_tool_is_registered(self) -> None:
        import easyhunt.mcp_server as mcp

        mcp.load_capabilities()
        assert "smuggling_canary_probe" in REGISTRY

    async def test_it_is_aggressive_not_passive(self) -> None:
        import easyhunt.mcp_server as mcp

        mcp.load_capabilities()
        entry = REGISTRY["smuggling_canary_probe"]
        # It sends deliberately malformed requests to a front-end. A "passive"
        # label here would route it past the approval gate that exists for
        # exactly this kind of traffic.
        assert entry.mode == "aggressive"


class TestArgv:
    async def test_argv_survives_its_own_sanitizer(self, engagement, monkeypatch) -> None:
        seen = drive(monkeypatch, engagement, _report())
        await sf.smuggling_canary_probe("https://www.example.com/", repeat=3)
        # A policy that rejects its own tool's call is inert: the tool never
        # runs and the surface reads as clean.
        sanitize_argv(
            "smuggler-framework", seen["argv"], policy=sf.SMUGGLER_FRAMEWORK.arg_policy
        )

    async def test_argv_names_the_container_path(self, engagement, monkeypatch) -> None:
        seen = drive(monkeypatch, engagement, _report())
        await sf.smuggling_canary_probe("https://www.example.com/")
        # The host path does not exist inside the sandbox. Passing it produced
        # "python3: can't open file ..." — a tool failure that, without the
        # coverage block, is indistinguishable from a target with no desync.
        assert seen["argv"][0] == f"{sf._CONTAINER_ROOT}/smuggler.py"
        assert f"{sf._CONTAINER_ROOT}/payloads" in seen["argv"]

    async def test_repeat_is_clamped(self, engagement, monkeypatch) -> None:
        seen = drive(monkeypatch, engagement, _report())
        await sf.smuggling_canary_probe("https://www.example.com/", repeat=999)
        # Every increment multiplies the whole payload set by two requests.
        assert seen["argv"][seen["argv"].index("--repeat") + 1] == "10"

    async def test_rate_comes_from_the_engagement(self, engagement, monkeypatch) -> None:
        seen = drive(monkeypatch, engagement, _report())
        await sf.smuggling_canary_probe("https://www.example.com/")
        # The framework runs its own pool for hundreds of iterations inside one
        # tool call, so the limiter — which charges once per call — cannot
        # throttle any of it. The pause is the only real brake.
        assert "--pause" in seen["argv"] and "--concurrency" in seen["argv"]


class TestCoverageIsReported:
    async def test_full_coverage_is_complete(self, engagement, monkeypatch) -> None:
        drive(monkeypatch, engagement, _report(
            phases_run=["cl_te", "te_cl", "te_te", "chunk_extensions",
                        "hop_by_hop", "h2_downgrade", "response_queue"],
            phases_skipped=[],
        ))
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["status"] == "COMPLETE"
        assert result["complete"] is True

    async def test_a_skipped_detector_makes_the_result_partial(
        self, engagement, monkeypatch
    ) -> None:
        drive(monkeypatch, engagement, _report(
            phases_skipped=["h2_downgrade: target does not speak HTTP/2"],
        ))
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        # Zero findings from five of seven detectors is not a clean front-end.
        assert result["status"] == "PARTIAL"
        assert result["complete"] is False
        assert "UNTESTED" in result["note"]

    async def test_requests_sent_is_reported_next_to_payloads(
        self, engagement, monkeypatch
    ) -> None:
        drive(monkeypatch, engagement, _report())
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        cov = result["coverage"]
        # The two numbers together are the point. 802 payloads and 10 requests
        # is the shape of the bug this wrapper was built to expose.
        assert cov["payloads_loaded"] == 802
        assert cov["requests_sent"] == 4572
        assert "4572 requests actually sent" in result["note"]

    async def test_a_delivery_shortfall_is_partial(self, engagement, monkeypatch) -> None:
        # This is the original bug, as the framework now reports it.
        drive(monkeypatch, engagement, _report(
            requests_sent=19,
            send_errors=1585,
            phases_skipped=[
                "delivery: only 19 of ~1604 expected requests reached the target, "
                "so most payloads were never actually sent"
            ],
        ))
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["status"] == "PARTIAL"
        assert result["complete"] is False
        assert result["coverage"]["requests_sent"] == 19
        assert result["coverage"]["send_errors"] == 1585


class TestAbsenceIsNotCleanliness:
    async def test_a_missing_framework_is_untested(self, engagement, monkeypatch) -> None:
        drive(monkeypatch, engagement, None, ran=False)
        monkeypatch.setattr(sf, "_framework_root", lambda: None)
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["ok"] is False
        assert result["status"] == "UNTESTED"
        assert result["complete"] is False
        assert result["findings"] == []

    async def test_a_tool_that_did_not_run_is_untested(self, engagement, monkeypatch) -> None:
        drive(monkeypatch, engagement, None, ran=False)
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["ok"] is False
        assert result["status"] == "UNTESTED"
        assert result["complete"] is False

    async def test_an_unparsable_report_is_not_zero_findings(
        self, engagement, monkeypatch
    ) -> None:
        drive(monkeypatch, engagement, {"results": []})
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["ok"] is False
        assert result["complete"] is False
        assert result["error"] == "no_report"


class TestFindings:
    async def test_a_desync_is_filed_as_a_candidate(self, engagement, monkeypatch) -> None:
        report = _report()
        report["results"][0]["findings"] = [
            {"type": "TE.TE", "obfuscation": "chunked\\x0b", "canary_rate": "17/20",
             "evidence": "canary"}
        ]
        drive(monkeypatch, engagement, report)
        result = await sf.smuggling_canary_probe("https://www.example.com/")
        assert result["count"] == 1
        finding = result["findings"][0]
        assert "TE.TE" in finding["title"]
        # CANDIDATE, not CONFIRMED: canary reflection is strong evidence, but
        # "no PoC, no finding" means a human reproduces it before it is called
        # confirmed.
        assert finding["status"] == "candidate"

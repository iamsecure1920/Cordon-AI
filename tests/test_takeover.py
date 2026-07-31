"""Verified subdomain takeover.

The behaviour under test is the *refusal*: a fingerprint alone, a CNAME alone, or
a claimed-but-unproven takeover must never reach 'confirmed'.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.errors import EasyHuntError
from easyhunt.knowledge.findings import Severity, Status
from easyhunt.tools import takeover as tk
from easyhunt.tools.base import REGISTRY

S3_BODY = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"


def fake_dns(mapping: dict[str, dict[str, list[str]]], monkeypatch) -> None:
    async def _dig(host: str, record: str) -> list[str]:
        return mapping.get(host, {}).get(record, [])

    monkeypatch.setattr(tk, "_dig", _dig)


def fake_http(status: int, body: str, monkeypatch) -> None:
    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = status
            self.text = body

    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...
        async def __aenter__(self) -> FakeClient:
            return self
        async def __aexit__(self, *args: Any) -> None: ...
        async def get(self, url: str) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)


class TestFingerprintMatching:
    def test_requires_both_cname_and_body(self) -> None:
        assert tk.match_service(["x.s3.amazonaws.com"], S3_BODY) is not None
        # Body alone is not enough — plenty of pages say "NoSuchBucket".
        assert tk.match_service(["cdn.example.com"], S3_BODY) is None
        # CNAME alone is not enough — the bucket may be live and simply empty.
        assert tk.match_service(["x.s3.amazonaws.com"], "<html>Welcome</html>") is None

    def test_edge_cases_are_flagged_as_not_claimable(self) -> None:
        service = tk.match_service(["d1.cloudfront.net"], "The request could not be satisfied")
        assert service["status"] == "edge-case" and service["claimable"] is False

    def test_fingerprint_file_is_well_formed(self) -> None:
        for service in tk.load_fingerprints():
            assert service["service"] and service["cname"] and service["fingerprints"]
            assert service["status"] in {"vulnerable", "edge-case", "not-vulnerable"}


class TestVerification:
    async def test_dangling_cname_with_fingerprint_verifies(self, engagement, monkeypatch) -> None:
        fake_dns({"cdn.example.com": {"CNAME": ["old-bucket.s3.amazonaws.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)

        result = await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        assert result["verified"] is True
        assert result["status"] == "needs_manual_review"

        finding = engagement.findings.get(result["finding_id"])
        # Verified is not confirmed. Confirming requires actually claiming it.
        assert finding.status is Status.NEEDS_MANUAL_REVIEW
        assert finding.poc is None

    async def test_live_resource_does_not_verify(self, engagement, monkeypatch) -> None:
        fake_dns(
            {"cdn.example.com": {"CNAME": ["live-bucket.s3.amazonaws.com"], "A": ["203.0.113.5"]}},
            monkeypatch,
        )
        fake_http(200, "<html>a real site</html>", monkeypatch)

        result = await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        assert result["verified"] is False
        assert result["status"] == "not_a_candidate"
        assert engagement.findings.all() == []

    async def test_fingerprint_without_matching_cname_does_not_verify(
        self, engagement, monkeypatch
    ) -> None:
        # The page says NoSuchBucket but the CNAME points somewhere unrelated.
        fake_dns({"cdn.example.com": {"CNAME": ["internal-lb.example.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)
        assert (await REGISTRY["takeover_verify"].fn(target="cdn.example.com"))["verified"] is False

    async def test_ns_delegation_is_graded_critical(self, engagement, monkeypatch) -> None:
        fake_dns(
            {
                "zone.example.com": {
                    "CNAME": ["ghost.io"], "A": [], "NS": ["ns1.abandoned-provider.net"],
                }
            },
            monkeypatch,
        )
        fake_http(404, "The thing you were looking for is no longer here", monkeypatch)

        result = await REGISTRY["takeover_verify"].fn(target="zone.example.com")
        assert result["verified"] and result["kind"] == "ns"
        assert result["severity"] == Severity.CRITICAL.value

    async def test_edge_case_service_is_downgraded_with_a_reason(
        self, engagement, monkeypatch
    ) -> None:
        fake_dns({"cdn.example.com": {"CNAME": ["d1.cloudfront.net"], "A": []}}, monkeypatch)
        fake_http(403, "The request could not be satisfied", monkeypatch)

        result = await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        finding = engagement.findings.get(result["finding_id"])
        assert any("edge case" in note for note in finding.triage_notes)

    async def test_out_of_scope_host_is_refused(self, engagement) -> None:
        from easyhunt.errors import OutOfScopeError

        with pytest.raises(OutOfScopeError):
            await REGISTRY["takeover_verify"].fn(target="blog.example.com")


class TestPoCPlan:
    async def test_plan_refuses_for_an_unverified_host(self, engagement) -> None:
        result = await REGISTRY["takeover_poc_plan"].fn(target="unknown.example.com")
        assert result["ok"] is False and result["error"] == "not_verified"

    async def test_plan_is_scoped_and_unique(self, engagement, monkeypatch) -> None:
        fake_dns({"cdn.example.com": {"CNAME": ["old.s3.amazonaws.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)
        await REGISTRY["takeover_verify"].fn(target="cdn.example.com")

        plan = await REGISTRY["takeover_poc_plan"].fn(target="cdn.example.com")
        assert plan["ok"]
        assert "tester" in plan["proof_path"]  # researcher handle from the scope
        assert plan["proof_path"].startswith("/.well-known/")
        assert any("Do not collect" in item for item in plan["do_not"])

    async def test_plan_does_not_claim_anything_itself(self, engagement, monkeypatch) -> None:
        fake_dns({"cdn.example.com": {"CNAME": ["old.s3.amazonaws.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)
        await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        plan = await REGISTRY["takeover_poc_plan"].fn(target="cdn.example.com")
        # Every step is an instruction to a human, and the tool is passive.
        assert REGISTRY["takeover_poc_plan"].mode == "passive"
        assert "not automated" in plan["note"]


class TestConfirmation:
    @pytest.fixture
    async def verified(self, engagement, monkeypatch):
        fake_dns({"cdn.example.com": {"CNAME": ["old.s3.amazonaws.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)
        result = await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        engagement.approval.backend = PolicyBackend(auto_approve=["takeover_confirm"])
        return engagement.findings.get(result["finding_id"])

    async def test_confirm_requires_the_proof_to_be_live(self, verified, monkeypatch) -> None:
        fake_http(404, "not found", monkeypatch)
        result = await REGISTRY["takeover_confirm"].fn(
            target="cdn.example.com", proof_url="https://cdn.example.com/.well-known/x.txt"
        )
        assert result["ok"] is False and result["error"] == "proof_not_served"
        assert verified.status is Status.NEEDS_MANUAL_REVIEW

    async def test_confirm_attaches_a_reproducible_poc(self, verified, monkeypatch) -> None:
        fake_http(200, "EasyHunt subdomain takeover proof of concept\nhost: cdn.example.com\n", monkeypatch)
        result = await REGISTRY["takeover_confirm"].fn(
            target="cdn.example.com", proof_url="https://cdn.example.com/.well-known/x.txt"
        )
        assert result["ok"] and result["status"] == "confirmed"
        assert verified.status is Status.CONFIRMED
        assert verified.poc is not None and verified.poc.is_reproducible()
        assert "released after triage" in verified.poc.impact_limit_note

    async def test_confirm_requires_a_prior_verification(self, engagement) -> None:
        engagement.approval.backend = PolicyBackend(auto_approve=["takeover_confirm"])
        with pytest.raises(EasyHuntError, match="run takeover_verify first"):
            await REGISTRY["takeover_confirm"].fn(
                target="never.example.com", proof_url="https://never.example.com/x"
            )

    async def test_confirm_is_gated(self, engagement, monkeypatch) -> None:
        from easyhunt.errors import ApprovalDenied

        fake_dns({"cdn.example.com": {"CNAME": ["old.s3.amazonaws.com"], "A": []}}, monkeypatch)
        fake_http(404, S3_BODY, monkeypatch)
        await REGISTRY["takeover_verify"].fn(target="cdn.example.com")
        with pytest.raises(ApprovalDenied):
            await REGISTRY["takeover_confirm"].fn(
                target="cdn.example.com", proof_url="https://cdn.example.com/x"
            )

    async def test_confirm_is_the_only_route_to_confirmed(self) -> None:
        assert REGISTRY["takeover_confirm"].mode == "exploit"
        assert REGISTRY["takeover_verify"].mode == "passive"

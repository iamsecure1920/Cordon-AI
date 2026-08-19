"""Two ways a scan produces output that is worse than no output.

Both found on a real engagement. A first pass over 20 hosts produced 111
findings; every one was either a false positive or a class the program had
stated in writing that it would not accept. Net reportable: zero.

**A heuristic is not a finding.** testssl's `ipv4_in_header` greps headers for
something IPv4-shaped. On that run it matched `1.0.1.1` inside a Cloudflare
bot-management cookie — 32 MEDIUM findings about a substring. "No PoC, no
finding" applies to a scanner's own pattern matches too; forwarding one
unexamined launders a guess into a severity.

**A program's exclusion list is authorization data.** Every program publishes
one, this project read none of them, and the policy that names those exclusions
usually also excludes "scanner-generated reports that are not validated to be
true-positive". Submitting that output is not neutral — it is the specific thing
the program asked researchers not to do.

Nothing here deletes a finding. Ineligible for a bounty and worthless to the
operator are different statements, and silently dropping results is the failure
this codebase has spent its life fixing.
"""

from __future__ import annotations

import pytest
import yaml

from cordon.control_plane.scope import Scope
from cordon.knowledge.findings import Finding, FindingStore, Severity
from cordon.tools.webscan import _confirms_ipv4_in_header
from tests.conftest import scope_dict


class TestIpv4InHeaderIsValidated:
    """The check exists to catch a back-end address leaking through a proxy."""

    #: The exact header that produced 32 MEDIUM findings on a live target.
    CLOUDFLARE_COOKIE = (
        "set-cookie: __cf_bm=h.N3PJ7uZSQd2HCWqsoirEmLdLcmhd658ivmhPHiNe4"
        "-1786241965.9966922-1.0.1.1-W9WzYfaG1HZgDbPMXqvsBe1Uf6896"
    )

    def test_the_real_false_positive_is_rejected(self) -> None:
        confirmed, why = _confirms_ipv4_in_header({"finding": self.CLOUDFLARE_COOKIE})
        assert confirmed is False
        assert "no internal IPv4" in why

    @pytest.mark.parametrize(
        "header",
        [
            "X-Backend-Server: 10.0.3.44",
            "Via: 1.1 192.168.1.10 (squid/5.7)",
            "X-Real-IP: 172.16.9.2",
            "X-Host: 127.0.0.1",
            "X-Origin: 169.254.169.254",
        ],
    )
    def test_a_genuine_internal_address_is_kept(self, header: str) -> None:
        confirmed, why = _confirms_ipv4_in_header({"finding": header})
        assert confirmed is True
        assert "internal address" in why

    @pytest.mark.parametrize(
        "header",
        [
            # A routable address in a header is the load balancer doing its job.
            "X-Served-By: 104.18.32.7",
            "Server: nginx/1.25.3",
            "X-Version: 8.10.2024.1",
            "Date: Fri, 09 Aug 2026 02:00:00 GMT",
        ],
    )
    def test_public_or_non_addresses_are_rejected(self, header: str) -> None:
        confirmed, _ = _confirms_ipv4_in_header({"finding": header})
        assert confirmed is False


def _scope_with(classes: list, tmp_path) -> Scope:
    doc = scope_dict()
    doc["out_of_scope"]["finding_classes"] = classes
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump(doc))
    return Scope.load(path)


def _finding(title: str, **kw) -> Finding:
    return Finding(asset="https://www.example.com", title=title,
                   severity=Severity.MEDIUM, **kw)


class TestExclusionMatching:
    def test_a_plain_string_matches_anywhere_in_the_text(self, tmp_path) -> None:
        s = _scope_with([{"match": "HSTS", "reason": "TLS best practice"}], tmp_path)
        assert s.excluded_finding(_finding("TLS: HSTS — not offered"))["reason"] == \
            "TLS best practice"

    def test_matching_is_case_insensitive(self, tmp_path) -> None:
        s = _scope_with([{"match": "clickjacking"}], tmp_path)
        assert s.excluded_finding(_finding("Clickjacking on /account"))

    def test_a_regex_is_supported(self, tmp_path) -> None:
        s = _scope_with([{"match": r"re:\bSPF\b", "reason": "email best practice"}], tmp_path)
        assert s.excluded_finding(_finding("Missing SPF record"))
        # \b matters: SPFRecordChecker is a different thing entirely.
        assert not s.excluded_finding(_finding("SPFXYZ handler crash"))

    def test_tags_and_source_tool_are_searched(self, tmp_path) -> None:
        s = _scope_with([{"match": "testssl"}], tmp_path)
        assert s.excluded_finding(_finding("Some title", source_tool="testssl"))
        s2 = _scope_with([{"match": "tabnabbing"}], tmp_path)
        assert s2.excluded_finding(_finding("Some title", tags=["tabnabbing"]))

    def test_an_unmatched_finding_is_eligible(self, tmp_path) -> None:
        s = _scope_with([{"match": "HSTS"}], tmp_path)
        assert s.excluded_finding(_finding("IDOR on /api/orders/1042")) is None

    def test_no_exclusion_list_excludes_nothing(self, tmp_path) -> None:
        s = _scope_with([], tmp_path)
        assert s.excluded_finding(_finding("TLS: HSTS")) is None

    def test_a_broken_regex_is_reported_not_silently_dropped(self, tmp_path) -> None:
        s = _scope_with([{"match": "re:[unclosed", "reason": "x"}], tmp_path)
        # An exclusion that failed to compile means findings of that class will be
        # reported as eligible — the operator has to be told.
        assert any("finding_classes" in w for w in s.validate())


class TestTheStoreMarksRatherThanDrops:
    def test_an_excluded_finding_is_kept_and_tagged(self, tmp_path) -> None:
        s = _scope_with([{"match": "HSTS", "reason": "TLS best practice"}], tmp_path)
        store = FindingStore(classifier=s.excluded_finding)
        store.add(_finding("TLS: HSTS — not offered"))

        assert len(store.all()) == 1, "the finding must not be deleted"
        assert store.reportable() == []
        excluded = store.program_excluded()
        assert len(excluded) == 1
        assert "program-excluded" in excluded[0].tags
        assert excluded[0].extra["program_exclusion"]["reason"] == "TLS best practice"

    def test_an_eligible_finding_is_untouched(self, tmp_path) -> None:
        s = _scope_with([{"match": "HSTS"}], tmp_path)
        store = FindingStore(classifier=s.excluded_finding)
        store.add(_finding("IDOR on /api/orders/1042"))
        assert len(store.reportable()) == 1
        assert store.program_excluded() == []

    def test_a_classifier_that_raises_does_not_lose_the_finding(self, tmp_path) -> None:
        def boom(_finding):  # noqa: ANN001, ANN202
            raise RuntimeError("bad pattern")

        store = FindingStore(classifier=boom)
        store.add(_finding("IDOR on /api/orders/1042"))
        # Classification is a convenience. Losing a finding to it is not acceptable.
        assert len(store.reportable()) == 1

    def test_without_a_classifier_everything_is_reportable(self) -> None:
        store = FindingStore()
        store.add(_finding("TLS: HSTS — not offered"))
        assert len(store.reportable()) == 1

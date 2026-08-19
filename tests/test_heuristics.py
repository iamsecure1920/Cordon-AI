"""A scanner's own state, filed as a fact about the target.

This is the same defect as "absence is not a clean result", stood on its head.
Usually a tool that failed to run produces a clean report; here a tool that
failed to run — or a pattern that matched the wrong thing — produces a *finding*,
which is worse, because it goes in a report over the researcher's name.

Every case below was measured against the real scanner output stored under
``engagements/`` in this workspace, or read out of the scanner's own source. The
counts are from 47 testssl reports and 4 nikto reports:

* ``QUIC / WARN / "not tested due to lack of local OpenSSL support"`` — 43
  entries. ``WARN`` maps to LOW, so 43 LOW findings whose text says the check
  never ran. The missing support is on the *scanning* host.
* ``ipv4_in_header / MEDIUM`` — 32 entries, all the same Cloudflare cookie
  substring. Already fixed; the regression test lives in
  ``test_program_exclusions.py`` and is not duplicated here.
* ``cmdline_ip-target / WARN / "Target is not a server name..."`` — testssl
  describing the argument this wrapper handed it.
* ``HTTP_status_code / WARN / "Unexpected 503 Service Unavailable @ '/'"`` —
  testssl's own HTTP GET landed on an error page, which bounds every
  header-derived check in the same run.
* nikto ``999979`` — "IP address found in the 'x-vercel-id' header. The IP is
  "ad1::b"." Extracted from a Vercel request id. nikto's own ``is_ip()`` carries
  a hard-coded ``if ($ip eq '1.0.1.1')`` guard with the comment "prevents
  Cloudflare cookies and headers from reporting": upstream met the identical
  false positive and patched it with a one-value blocklist.
* nikto ``999106`` / ``800264`` — "Recommend proxying via Burp or mitmproxy to
  avoid TLS fingerprint blocks." Advice to the operator about nikto. ``999106``
  is guarded by ``!$CLI{'useproxy'}``, so it reports nikto's configuration.
* nikto ``011799`` — "...advertising HTTP/3. ... Nikto cannot test HTTP/3 over
  QUIC." A coverage gap filed as a result.

Each validator is discriminated on the scanner's *wording*, not on the id alone.
The id narrows the blast radius to entries with measured evidence; the wording
check means a renumbered or repurposed test is kept rather than dropped. A
validator that rejects a real finding is worse than no validator, so every test
class below pins genuine positives as hard as it pins the false one.
"""

from __future__ import annotations

import pytest

from cordon.knowledge.findings import Severity
from cordon.tools.base import REGISTRY
from cordon.tools.webscan import (
    _NIKTO_VALIDATORS,
    _TESTSSL_SCAN_STATUS_IDS,
    _TESTSSL_VALIDATORS,
    _confirms_locally_tested,
    _confirms_nikto_ip_disclosure,
    _confirms_not_a_coverage_gap,
    _confirms_not_scanner_advice,
    _is_internal_address,
)
from tests.test_webscan import _approve, _spy


def _entry(finding: str, *, id: str = "QUIC", severity: str = "WARN") -> dict:  # noqa: A002
    return {"id": id, "severity": severity, "finding": finding}


def _vuln(msg: str, *, id: str, url: str = "/") -> dict:  # noqa: A002
    return {"id": id, "method": "GET", "msg": msg, "references": "", "url": url}


# --------------------------------------------------------------------------- #
# testssl: a check that did not run is not a result
# --------------------------------------------------------------------------- #


class TestQuicNotTestedLocallyIsNotAFinding:
    """43 LOW findings said, in their own text, that nothing was tested."""

    #: Verbatim from engagements/*/raw/testssl-*.json.
    NOT_TESTED = "not tested due to lack of local OpenSSL support"

    def test_the_real_false_positive_is_rejected(self) -> None:
        confirmed, why = _confirms_locally_tested(_entry(self.NOT_TESTED))
        assert confirmed is False
        assert "did not run this check on this host" in why

    @pytest.mark.parametrize("finding", ["offered", "not offered", "offered with final"])
    def test_a_real_quic_result_is_kept(self, finding: str) -> None:
        # The id is not the discriminator. If testssl starts reporting genuine
        # QUIC posture under this id, it must reach the findings store.
        confirmed, why = _confirms_locally_tested(_entry(finding))
        assert confirmed is True
        assert why == "check ran against the target"

    def test_no_finding_text_is_kept_not_dropped(self) -> None:
        # An entry this validator cannot read is an unexamined entry, not a
        # disproved one. Failing open is the only safe direction here.
        assert _confirms_locally_tested({"id": "QUIC", "severity": "WARN"})[0] is True
        assert _confirms_locally_tested({})[0] is True

    def test_the_validator_is_actually_wired_up(self) -> None:
        assert _TESTSSL_VALIDATORS["QUIC"] is _confirms_locally_tested


class TestTestsslEntriesThatDescribeTheScan:
    """Siblings of ``scanProblem``: testssl talking about testssl."""

    @pytest.mark.parametrize("check_id", ["cmdline_ip-target", "HTTP_status_code", "scanProblem"])
    def test_scan_state_ids_never_reach_the_finding_loop(self, check_id: str) -> None:
        assert check_id in _TESTSSL_SCAN_STATUS_IDS

    @pytest.mark.parametrize(
        "check_id",
        # Everything a TLS report is actually for. None of these may be
        # short-circuited as "scan state".
        ["TLS1", "TLS1_1", "TLS1_2", "cert_chain_of_trust", "cert_expirationStatus",
         "early_data", "HSTS", "security_headers", "OCSP_stapling", "FS_KEMs"],
    )
    def test_protocol_facts_are_not_treated_as_scan_state(self, check_id: str) -> None:
        assert check_id not in _TESTSSL_SCAN_STATUS_IDS


class TestTlsAuditSurfacesWhatItSuppressed:
    async def test_a_local_limitation_is_counted_not_silently_dropped(
        self, engagement, monkeypatch
    ) -> None:
        _spy(
            monkeypatch,
            report={"scanResult": [{"serverDefaults": [
                _entry("not tested due to lack of local OpenSSL support"),
                _entry("not offered", id="TLS1_2", severity="MEDIUM"),
            ]}]},
            report_flag="--jsonfile-pretty",
        )
        result = await REGISTRY["tls_audit"].fn(target="example.com")

        titles = [f["title"] for f in result["findings"]]
        assert not any("QUIC" in t for t in titles), "a check that did not run is not a finding"
        assert any("TLS1_2" in t for t in titles), "the real protocol fact must survive"
        assert any("QUIC" in u for u in result["unconfirmed_heuristics"])

    async def test_an_unexpected_http_status_becomes_a_note_not_a_finding(
        self, engagement, monkeypatch
    ) -> None:
        _spy(
            monkeypatch,
            report={"scanResult": [{"headerResponse": [
                _entry("Unexpected 503 Service Unavailable @ '/'",
                       id="HTTP_status_code", severity="WARN"),
                _entry("Target is not a server name: results may be completely wrong",
                       id="cmdline_ip-target", severity="WARN"),
            ]}]},
            report_flag="--jsonfile-pretty",
        )
        result = await REGISTRY["tls_audit"].fn(target="example.com")

        assert result["findings"] == []
        # Not a finding, but the operator has to know the header checks in this
        # run looked at a 503 page.
        notes = " ".join(result["scan_status_notes"])
        assert "503" in notes
        assert "cmdline_ip-target" in notes
        # A non-fatal note is not a failed scan.
        assert result["scan_problems"] == []
        assert result["complete"] is True


# --------------------------------------------------------------------------- #
# nikto 999979: the ipv4_in_header bug, in a second scanner
# --------------------------------------------------------------------------- #


class TestNiktoIpInHeaderIsValidated:
    """nikto reports any valid non-loopback IP, then titles it "private"."""

    #: Verbatim from engagements/rwdy-validate/raw/nikto-003448384.json. Both came
    #: out of the header value ``iad1::bom1::5kfq4-1785717297302-1e59f4d34143``.
    VERCEL_REGION = 'IP address found in the \'x-vercel-id\' header. The IP is "ad1::b".'
    VERCEL_SERIAL = 'IP address found in the \'x-vercel-id\' header. The IP is "1::5".'

    @pytest.mark.parametrize("msg", [VERCEL_REGION, VERCEL_SERIAL])
    def test_the_real_false_positive_is_rejected(self, msg: str) -> None:
        confirmed, why = _confirms_nikto_ip_disclosure(_vuln(msg, id="999979"))
        assert confirmed is False
        assert "not an internal address" in why

    @pytest.mark.parametrize(
        "msg",
        [
            'RFC-1918 IP address found in the \'x-backend\' header. The IP is "10.0.3.44".',
            'RFC-1918 IP address found in the \'via\' header. The IP is "192.168.1.10".',
            'IP address found in the \'x-origin\' header. The IP is "169.254.169.254".',
            'IP address found in the \'x-upstream\' header. The IP is "fd12:3456:789a::1".',
            'IP address found in the \'x-node\' header. The IP is "fe80::1c2d:3e4f".',
        ],
    )
    def test_a_genuine_leaked_back_end_address_is_kept(self, msg: str) -> None:
        confirmed, why = _confirms_nikto_ip_disclosure(_vuln(msg, id="999979"))
        assert confirmed is True
        assert "internal address" in why

    @pytest.mark.parametrize(
        "msg",
        [
            # The CDN edge doing its job. nikto files this identically to an
            # RFC-1918 leak; the reference it attaches says "Private IP addresses
            # disclosed" either way.
            'IP address found in the \'x-served-by\' header. The IP is "104.18.32.7".',
            'IP address found in the \'x-cache\' header. The IP is "2606:4700::6810:85e5".',
            # The value nikto's own source hard-codes a guard against.
            'IP address found in the \'set-cookie\' header. The IP is "1.0.1.1".',
        ],
    )
    def test_a_public_address_is_not_a_disclosure(self, msg: str) -> None:
        assert _confirms_nikto_ip_disclosure(_vuln(msg, id="999979"))[0] is False

    def test_a_message_with_no_quoted_address_is_kept(self) -> None:
        # No data to check is not evidence against the finding.
        confirmed, why = _confirms_nikto_ip_disclosure(_vuln("Some future wording", id="999979"))
        assert confirmed is True
        assert "kept unexamined" in why
        assert _confirms_nikto_ip_disclosure({})[0] is True


class TestInternalAddressClassification:
    """Why ``is_reserved`` is trusted for IPv4 and refused for IPv6."""

    def test_ipv6_reserved_space_is_where_opaque_identifiers_land(self) -> None:
        # ipaddress.IPv6Address("ad1::b").is_reserved is True. Trusting it would
        # confirm the exact false positive this exists to reject.
        assert _is_internal_address("ad1::b") is False
        assert _is_internal_address("1::5") is False

    @pytest.mark.parametrize("token", ["10.0.3.44", "192.168.1.10", "172.16.9.2",
                                       "127.0.0.1", "169.254.169.254",
                                       "fd00::1", "fe80::1", "::1"])
    def test_addresses_that_never_belong_in_a_public_response(self, token: str) -> None:
        assert _is_internal_address(token) is True

    @pytest.mark.parametrize("token", ["104.18.32.7", "8.8.8.8", "1.0.1.1",
                                       "2606:4700::1", "not-an-address", ""])
    def test_public_or_unparsable_tokens_are_not_internal(self, token: str) -> None:
        assert _is_internal_address(token) is False

    def test_ipv4_reserved_space_is_still_internal(self) -> None:
        # 240.0.0.0/4 is small, genuinely never routed, and does not swallow the
        # Cloudflare cookie value the way IPv6's reserved space does.
        assert _is_internal_address("240.0.0.1") is True


# --------------------------------------------------------------------------- #
# nikto: entries about nikto
# --------------------------------------------------------------------------- #


class TestNiktoProxyAdviceIsNotAFinding:
    """"Recommend proxying via Burp" is a message to the operator."""

    #: Verbatim from engagements/rwdy-validate/raw/nikto-003448384.json.
    CF_RAY = (
        "Cloudflare detected via cf-ray header. Recommend proxying via Burp or "
        "mitmproxy to avoid TLS fingerprint blocks."
    )
    CF_BANNER = (
        "cloudflare - Cloudflare detected via banner. Recommend proxying via Burp or "
        "mitmproxy to avoid TLS fingerprint blocks if not already proxying."
    )

    @pytest.mark.parametrize("msg", [CF_RAY, CF_BANNER])
    def test_the_real_false_positive_is_rejected(self, msg: str) -> None:
        confirmed, why = _confirms_not_scanner_advice(_vuln(msg, id="999106"))
        assert confirmed is False
        assert "not an observation about the target" in why

    @pytest.mark.parametrize(
        "msg",
        [
            "Server leaks inodes via ETags, header found with file /, inode: 12345",
            "Retrieved access-control-allow-origin header: \\*.",
            "The anti-clickjacking X-Frame-Options header is not present.",
        ],
    )
    def test_an_observation_about_the_target_is_kept(self, msg: str) -> None:
        # Rejection is keyed on the wording, so an id reused for a real check
        # survives. This is the direction that matters: keeping is recoverable,
        # dropping is not.
        assert _confirms_not_scanner_advice(_vuln(msg, id="999106"))[0] is True

    def test_a_message_that_is_missing_is_kept(self) -> None:
        assert _confirms_not_scanner_advice({})[0] is True
        assert _confirms_not_scanner_advice({"id": "800264", "msg": None})[0] is True


class TestNiktoCoverageGapIsNotAFinding:
    """A tool announcing what it could not reach is a coverage note."""

    #: Verbatim from engagements/rwdy-ci_20260803-125334/raw/nikto-125335424.json.
    HTTP3 = (
        "An alt-svc header was found which is advertising HTTP/3. The endpoint "
        "is: ':443'. Nikto cannot test HTTP/3 over QUIC."
    )

    def test_the_real_false_positive_is_rejected(self) -> None:
        confirmed, why = _confirms_not_a_coverage_gap(_vuln(self.HTTP3, id="011799"))
        assert confirmed is False
        assert "coverage gap" in why

    @pytest.mark.parametrize(
        "msg",
        [
            # The plugin appends the "cannot test" sentence only on the h3 branch.
            "An alt-svc header was found which is advertising HTTP/2. The endpoint is: ':443'.",
            "A CSP report-uri header was found. The URL is: https://example.com/csp",
        ],
    )
    def test_an_alt_svc_observation_without_the_claim_is_kept(self, msg: str) -> None:
        assert _confirms_not_a_coverage_gap(_vuln(msg, id="011799"))[0] is True

    def test_a_message_that_is_missing_is_kept(self) -> None:
        assert _confirms_not_a_coverage_gap({})[0] is True


class TestNiktoValidatorRegistry:
    def test_every_measured_id_is_wired_up(self) -> None:
        assert _NIKTO_VALIDATORS["999979"] is _confirms_nikto_ip_disclosure
        assert _NIKTO_VALIDATORS["999106"] is _confirms_not_scanner_advice
        assert _NIKTO_VALIDATORS["800264"] is _confirms_not_scanner_advice
        assert _NIKTO_VALIDATORS["011799"] is _confirms_not_a_coverage_gap

    @pytest.mark.parametrize(
        "check_id",
        # nikto ids with no measured false-positive behind them. An unvalidated
        # check is left alone on purpose — guessing at a validator is the same
        # error as guessing at a finding.
        ["999100", "000287", "013587", "999104", "000433"],
    )
    def test_unmeasured_checks_are_left_alone(self, check_id: str) -> None:
        assert check_id not in _NIKTO_VALIDATORS


class TestNiktoScanSurfacesWhatItSuppressed:
    async def test_the_vercel_run_files_the_target_facts_and_nothing_else(
        self, engagement, monkeypatch
    ) -> None:
        # The four suppressed entries below are the ones a real nikto run against
        # a Vercel-fronted, Cloudflare-proxied host produced, alongside two real
        # observations that must survive.
        _approve(engagement, "nikto_scan")
        _spy(
            monkeypatch,
            values=("+ Scan terminated: 0 errors and 6 items reported on the remote host",),
            report=[{"host": "example.com", "vulnerabilities": [
                _vuln(TestNiktoIpInHeaderIsValidated.VERCEL_REGION, id="999979"),
                _vuln(TestNiktoIpInHeaderIsValidated.VERCEL_SERIAL, id="999979"),
                _vuln(TestNiktoProxyAdviceIsNotAFinding.CF_RAY, id="999106"),
                _vuln(TestNiktoProxyAdviceIsNotAFinding.CF_BANNER, id="800264"),
                _vuln(TestNiktoCoverageGapIsNotAFinding.HTTP3, id="011799"),
                _vuln("Retrieved x-powered-by header: Next.js.", id="000287"),
                _vuln("Suggested security header missing: content-security-policy.",
                      id="013587"),
            ]}],
            report_flag="-output",
        )
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/")

        assert result["complete"] is True
        # Everything nikto said is still counted, so a shrinking finding list
        # cannot be mistaken for a quieter target.
        assert result["items"] == 7
        assert len(result["findings"]) == 2
        assert len(result["unconfirmed_heuristics"]) == 5
        titles = " ".join(f["title"] for f in result["findings"])
        assert "x-powered-by" in titles
        assert "content-security-policy" in titles
        assert "Recommend proxying" not in titles
        assert "ad1::b" not in titles

    async def test_a_genuine_rfc1918_leak_still_reaches_the_store(
        self, engagement, monkeypatch
    ) -> None:
        _approve(engagement, "nikto_scan")
        _spy(
            monkeypatch,
            values=("+ Scan terminated: 0 errors and 1 item reported on the remote host",),
            report=[{"host": "example.com", "vulnerabilities": [
                _vuln(
                    'RFC-1918 IP address found in the \'x-backend\' header. '
                    'The IP is "10.0.3.44".',
                    id="999979",
                ),
            ]}],
            report_flag="-output",
        )
        result = await REGISTRY["nikto_scan"].fn(target="https://example.com/")

        assert result["unconfirmed_heuristics"] == []
        assert len(result["findings"]) == 1
        stored = engagement.findings.get(result["findings"][0]["id"])
        # nikto grades nothing; the wrapper's own rating is unchanged by any of
        # this. Validation decides whether a finding exists, not how bad it is.
        assert stored.severity is Severity.INFO

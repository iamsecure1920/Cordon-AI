"""Reading a takeover detector's output without inventing takeovers.

`takeover_detect` decided a host was a candidate with `if host in line`, over
every line the detectors printed. Two bugs lived in that one expression, and
both were measured against a real 141-host estate rather than reasoned about:

**Every host became a candidate.** subjack prints one line per host it examines,
including `[Not Vulnerable] account.chime.com` for the ones that are fine. A run
in which subjack found *nothing* produced 141 takeover candidates — one per host,
each sourced from the line saying it was clean.

**Hostnames matched as substrings.** The line for `ads.arkose-client.chime.com`
also "contained" `arkose-client.chime.com` and `chime.com`, so one host's verdict
was attributed to two unrelated others.

Why this is worse than ordinary noise: a takeover report asserts that somebody
else can claim your DNS. It is a claim about a third-party provider, it is the
kind of thing a program escalates, and 141 false ones do not read as a noisy
scanner — they read as a researcher who does not check their work.

The recognisers below fail CLOSED. These tools print a line per host examined,
so treating unfamiliar wording as a positive is how a clean estate turns back
into a full-length candidate list.
"""

from __future__ import annotations

import pytest

from easyhunt.tools.takeover import _ANSI, _hosts_in, _is_takeover_hit


class TestClearedHostsAreNotHits:
    """"Not Vulnerable" contains "Vulnerable" — the exact substring trap again."""

    @pytest.mark.parametrize(
        "line",
        [
            "[Not Vulnerable] account.chime.example",
            "[NOT VULNERABLE] app.example.com",
            "app.example.com is not vulnerable",
            "[Not Found] ghost.example.com",
            "nothing found for api.example.com",
        ],
    )
    def test_a_cleared_host_is_not_a_candidate(self, line: str) -> None:
        assert _is_takeover_hit(line) is False


class TestRealHitsSurvive:
    @pytest.mark.parametrize(
        "line",
        [
            "[Vulnerable] ghost.example.com",
            "possible takeover: dangling.example.com -> unclaimed s3 bucket",
            "api.example.com CNAME dangling, can be claimed",
            "[VULNERABLE] shop.example.com (Shopify)",
        ],
    )
    def test_a_stated_takeover_is_a_candidate(self, line: str) -> None:
        assert _is_takeover_hit(line) is True


class TestItFailsClosed:
    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "scanning 141 hosts...",
            "some unrecognised wording about example.com",
            "[INF] loaded 141 targets from file",
        ],
    )
    def test_unrecognised_wording_is_not_a_hit(self, line: str) -> None:
        # A detector prints one line per host. If unknown phrasing counted as a
        # positive, the banner alone would nominate every host in the file.
        assert _is_takeover_hit(line) is False


class TestHostsAreMatchedWhole:
    def test_a_parent_domain_is_not_extracted_from_its_child(self) -> None:
        found = _hosts_in("[Vulnerable] ads.arkose-client.example.com")
        # The old `host in line` test matched all three of these.
        assert found == {"ads.arkose-client.example.com"}
        assert "example.com" not in found
        assert "arkose-client.example.com" not in found

    def test_several_hosts_on_one_line_are_all_found(self) -> None:
        found = _hosts_in("a.example.com CNAME b.cloudfront.net dangling")
        assert {"a.example.com", "b.cloudfront.net"} <= found

    def test_matching_is_case_insensitive_and_trailing_dots_are_dropped(self) -> None:
        assert _hosts_in("[Vulnerable] API.Example.COM.") == {"api.example.com"}

    def test_a_bare_word_is_not_a_host(self) -> None:
        assert _hosts_in("vulnerable takeover unclaimed") == set()


class TestAnsiIsStrippedBeforeMatching:
    def test_colour_codes_do_not_hide_the_verdict(self) -> None:
        # subjack writes terminal colour codes into whatever file it is given,
        # so "Not Vulnerable" arrives wrapped in escape sequences.
        coloured = "[\x1b[31;1mNot Vulnerable\x1b[0m] account.example.com"
        assert _is_takeover_hit(_ANSI.sub("", coloured)) is False

    def test_a_coloured_positive_still_registers(self) -> None:
        coloured = "[\x1b[32;1mVulnerable\x1b[0m] ghost.example.com"
        plain = _ANSI.sub("", coloured)
        assert _is_takeover_hit(plain) is True
        assert _hosts_in(plain) == {"ghost.example.com"}


class TestTheRegressionItself:
    #: A verbatim slice of what subjack produced against a real estate.
    CLEAN_RUN = [
        "[\x1b[31;1mNot Vulnerable\x1b[0m] ads.arkose-client.example.com",
        "[\x1b[31;1mNot Vulnerable\x1b[0m] account.example.com",
        "[\x1b[31;1mNot Vulnerable\x1b[0m] ads.example.com",
        "[\x1b[31;1mNot Vulnerable\x1b[0m] app.example.com",
    ]

    def test_a_clean_run_nominates_nobody(self) -> None:
        hosts = {
            "ads.arkose-client.example.com", "arkose-client.example.com",
            "example.com", "account.example.com", "ads.example.com",
            "app.example.com",
        }
        candidates = set()
        for raw in self.CLEAN_RUN:
            line = _ANSI.sub("", raw)
            if _is_takeover_hit(line):
                candidates |= _hosts_in(line) & hosts
        # The old code returned all six: four from the "Not Vulnerable" verdict
        # and two more from substring collisions inside the first line.
        assert candidates == set()

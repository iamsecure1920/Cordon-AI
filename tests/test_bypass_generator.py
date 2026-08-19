"""Regex-bypass generator (P0-3): 4 modes x encodings, bounded output.

Ported from HuntProxy's PayloadGenerator::RegexBypass (Apache-2.0). The
generator is pure derivation — no requests — and its contract is: unique
variants, every mode x encoding covered, bounded by max_payloads (an over-run
raises rather than truncating).
"""

from __future__ import annotations

import pytest

from cordon.knowledge.bypass import BypassError, generate_regex_bypass


class TestGenerator:
    def test_start_mode_url_encoding(self) -> None:
        out = generate_regex_bypass(
            "x", modes=("start",), encoding="url",
            bytes=(0x00, 0x09, 0x20), max_payloads=10,
        )
        assert out == ["%00x", "%09x", "%20x"]

    def test_all_modes_all_encodings_produce_output(self) -> None:
        for encoding in ("url", "unicode", "raw", "double_url"):
            out = generate_regex_bypass(
                "a.b", modes=("start", "separator", "end", "regex_metachar"),
                encoding=encoding,  # type: ignore[arg-type]
                bytes=(0x00, 0x09, 0x0A), max_payloads=200,
            )
            assert out, f"encoding {encoding} produced nothing"
            assert len(set(out)) == len(out), "output must be deduplicated"

    def test_separator_mode_hits_both_sides_of_punctuation(self) -> None:
        out = generate_regex_bypass(
            "a.b", modes=("separator",), encoding="url",
            bytes=(0x00, 0x01, 0x02, 0x03), max_payloads=20,
        )
        assert "a%00.b" in out
        assert "a.%00b" in out

    def test_regex_metachar_replaces_the_metachar(self) -> None:
        out = generate_regex_bypass(
            "a.b", modes=("regex_metachar",), encoding="url",
            bytes=(0x00,), max_payloads=10,
        )
        # The '.' metachar is replaced by the encoded byte.
        assert "a%00b" in out

    def test_encodings(self) -> None:
        unicode = generate_regex_bypass("x", modes=("start",), encoding="unicode", bytes=(65,), max_payloads=5)
        assert "\\u0041x" in unicode
        double = generate_regex_bypass("x", modes=("end",), encoding="double_url", bytes=(0,), max_payloads=5)
        assert "x%2500" in double

    def test_bound_is_enforced_not_truncated(self) -> None:
        with pytest.raises(BypassError):
            generate_regex_bypass(
                "a.b", modes=("start", "separator", "end"), encoding="url",
                bytes=tuple(range(0, 256)), max_payloads=10,
            )

    def test_empty_input_rejected(self) -> None:
        with pytest.raises(BypassError):
            generate_regex_bypass("", modes=("start",), max_payloads=10)

    def test_web_injection_narrow_byte_set_fits_the_cap(self) -> None:
        # The byte set web_injection_probe uses: control chars + space. A long
        # traversal payload must stay inside 500 variants, not explode.
        out = generate_regex_bypass(
            "../../../../etc/passwd",
            modes=("start", "separator", "end", "regex_metachar"),
            encoding="url",
            bytes=(0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B, 0x20),
            max_payloads=500,
        )
        assert len(out) <= 500
        assert out, "traversal payload should generate variants"

    def test_default_byte_range_matches_upstream_count(self) -> None:
        # Ported fixture from HuntProxy: 'ab' start mode, url encoding, full
        # byte range minus alphanumerics = 194 payloads.
        out = generate_regex_bypass("ab", modes=("start",), encoding="url", max_payloads=2000)
        assert len(out) == 194

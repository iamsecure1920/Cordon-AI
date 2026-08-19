"""Response-diff engine (P0-2): body-hash clustering + per-case deltas.

Ported from HuntProxy's FuzzResponseDiff (Apache-2.0). The properties that
matter: identical bodies cluster into one group (the soft-404 truth), a case
differs from the baseline across status/hash/length/duration/headers, sensitive
header values are never echoed, and the cache-poison signature (second response
re-serves the injected body) is detectable.
"""

from __future__ import annotations

import pytest

from cordon.tools.fuzz_diff import (
    Case,
    body_hash,
    cluster_baseline_matches,
    diff_case,
    group_cases,
    label_clusters,
)


def _case(url: str, status: int, body: str, headers=None, **kw) -> Case:
    return Case(url=url, status=status, body=body, headers=headers or {}, **kw)


class TestGroupCases:
    def test_identical_bodies_cluster(self) -> None:
        baseline = _case("http://h/404", 404, "not found page")
        cases = [
            _case("http://h/a", 404, "not found page"),
            _case("http://h/b", 404, "not found page"),
            _case("http://h/admin", 200, "real admin page"),
            _case("http://h/api", 200, "real api page"),
        ]
        clusters = group_cases(cases, baseline=baseline)
        assert len(clusters) == 3  # catch-all + two distinct
        labelled = label_clusters(clusters, baseline=baseline)
        assert labelled["counts"] == {"distinct": 2, "catch_all": 1, "unclassified": 0}
        # The catch-all cluster holds both soft-404 URLs.
        catch_all = labelled["catch_all"][0]
        assert set(catch_all["sample_urls"]) == {"http://h/a", "http://h/b"}

    def test_cluster_baseline_matches(self) -> None:
        baseline = _case("http://h/404", 404, "same body")
        clusters = group_cases([_case("http://h/x", 404, "same body")], baseline=baseline)
        assert cluster_baseline_matches(clusters[0], baseline)


class TestDiffCase:
    def test_changed_response_flags_every_delta(self) -> None:
        baseline = _case("http://h/", 200, "home", duration_ms=10)
        case = _case("http://h/?x=1", 200, "home plus admin panel", duration_ms=40)
        diff = diff_case(baseline, case)
        assert diff.changed()
        assert diff.status_changed is False
        assert diff.body_hash_equal is False
        assert diff.response_length_delta == len(case.body) - len(baseline.body)
        assert diff.duration_ratio == pytest.approx(4.0)
        assert diff.response_length_delta_percent == pytest.approx(
            diff.response_length_delta * 100.0 / len(baseline.body)
        )

    def test_identical_response_is_not_changed(self) -> None:
        baseline = _case("http://h/", 200, "same", duration_ms=10)
        case = _case("http://h/", 200, "same", duration_ms=10)
        diff = diff_case(baseline, case)
        assert diff.changed() is False
        assert diff.body_hash_equal is True

    def test_status_change_detected(self) -> None:
        baseline = _case("http://h/", 200, "ok")
        case = _case("http://h/", 403, "blocked")
        diff = diff_case(baseline, case)
        assert diff.status_changed is True

    def test_sensitive_header_values_redacted(self) -> None:
        baseline = _case("http://h/", 200, "a", headers={"set-cookie": "session=SECRET1", "x-cache": "MISS"})
        case = _case("http://h/", 200, "a", headers={"set-cookie": "session=SECRET2", "x-cache": "HIT"})
        diff = diff_case(baseline, case)
        names = {h["name"] for h in diff.header_changes}
        assert "x-cache" in names
        assert "set-cookie" not in names
        joined = str(diff.header_changes)
        assert "SECRET1" not in joined and "SECRET2" not in joined

    def test_text_diff_is_bounded(self) -> None:
        baseline = _case("http://h/", 200, "\n".join(f"line{i}" for i in range(2000)))
        case = _case("http://h/", 200, "\n".join(f"line{i}" for i in range(2000, 0, -1)))
        diff = diff_case(baseline, case, include_text=True)
        assert len(diff.text_diff) <= 64 * 1024


class TestBodyHash:
    def test_bytes_and_str_hash_identically(self) -> None:
        assert body_hash(b"abc") == body_hash("abc")

    def test_stable(self) -> None:
        assert body_hash("abc") == body_hash("abc")

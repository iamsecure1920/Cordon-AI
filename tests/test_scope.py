"""Scope engine: denylist wins, fail closed, and every matcher form works."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from easyhunt.control_plane.scope import Scope, normalize_target
from easyhunt.errors import ConfigError, OutOfScopeError, StaleScopeError

from .conftest import scope_dict


class TestNormalization:
    @pytest.mark.parametrize(
        ("raw", "host", "kind"),
        [
            ("example.com", "example.com", "domain"),
            ("EXAMPLE.COM.", "example.com", "domain"),
            ("https://sub.example.com:8443/a/b?c=1", "sub.example.com", "domain"),
            ("http://user:pw@sub.example.com/x", "sub.example.com", "domain"),
            ("sub.example.com:443", "sub.example.com", "domain"),
            ("203.0.113.7", "203.0.113.7", "ip"),
            ("[2001:db8::1]:8080", "2001:db8::1", "ip"),
        ],
    )
    def test_parses(self, raw: str, host: str, kind: str) -> None:
        target = normalize_target(raw)
        assert (target.host, target.kind) == (host, kind)

    @pytest.mark.parametrize(
        "raw",
        ["", "   ", "not a host", "ftp://example.com", "exa mple.com", "localhost", "-bad.example.com"],
    )
    def test_unparseable_is_unknown(self, raw: str) -> None:
        assert normalize_target(raw).kind == "unknown"

    def test_unicode_homoglyph_is_punycoded_not_matched(self, scope: Scope) -> None:
        # A Cyrillic 'е' must not satisfy an ASCII scope entry.
        assert not scope.check("exаmple.com").in_scope


class TestMatching:
    def test_exact_domain(self, scope: Scope) -> None:
        assert scope.check("example.com").in_scope

    def test_wildcard_subdomain_any_depth(self, scope: Scope) -> None:
        assert scope.check("a.b.c.example.com").in_scope

    def test_cidr(self, scope: Scope) -> None:
        verdict = scope.check("203.0.113.7")
        assert verdict.in_scope and verdict.matched.startswith("cidrs:")

    def test_nmap_octet_range(self, scope: Scope) -> None:
        assert scope.check("198.51.100.25").in_scope
        assert not scope.check("198.51.100.51").in_scope

    def test_regex(self, scope: Scope) -> None:
        assert scope.check("api-42.example.net").in_scope
        assert not scope.check("api-x.example.net").in_scope

    def test_url_prefix(self, scope: Scope) -> None:
        assert scope.check("https://app.example.org/v2/users").in_scope
        assert not scope.check("https://app.example.org/v1/users").in_scope


class TestDenylistWins:
    def test_denied_domain_beats_wildcard(self, scope: Scope) -> None:
        verdict = scope.check("blog.example.com")
        assert not verdict.in_scope
        assert verdict.reason == "denylisted"

    def test_denied_wildcard_beats_allow_wildcard(self, scope: Scope) -> None:
        assert not scope.check("vpn.corp.example.com").in_scope

    def test_denied_cidr_inside_allowed_cidr(self, scope: Scope) -> None:
        assert scope.check("203.0.113.7").in_scope
        assert not scope.check("203.0.113.241").in_scope

    def test_denied_regex(self, scope: Scope) -> None:
        assert not scope.check("app.staging.example.com").in_scope

    def test_forbidden_path(self, scope: Scope) -> None:
        verdict = scope.check("https://example.com/admin/delete?id=1")
        assert not verdict.in_scope
        assert verdict.reason == "forbidden_path"


class TestFailClosed:
    def test_unknown_host_refused(self, scope: Scope) -> None:
        assert not scope.check("someone-elses.com").in_scope

    def test_unparseable_refused(self, scope: Scope) -> None:
        assert scope.check("]not-a-host[").reason == "unparseable_target"

    def test_apex_not_covered_by_wildcard_by_default(self) -> None:
        data = scope_dict()
        data["in_scope"] = {"wildcards": ["*.example.com"]}
        narrow = Scope(data, source="<test>")
        assert not narrow.check("example.com").in_scope
        assert narrow.check("www.example.com").in_scope

    def test_apex_covered_when_opted_in(self) -> None:
        data = scope_dict()
        data["in_scope"] = {"wildcards": ["*.example.com"]}
        data["rules"] = {**data["rules"], "wildcard_includes_apex": True}
        wide = Scope(data, source="<test>")
        assert wide.check("example.com").in_scope

    def test_reserved_ip_refused_unless_explicitly_ranged(self) -> None:
        data = scope_dict()
        data["in_scope"] = {"regex": [r"127\.0\.0\.1"]}
        narrow = Scope(data, source="<test>")
        verdict = narrow.check("127.0.0.1")
        assert not verdict.in_scope
        assert verdict.reason == "reserved_ip_not_explicitly_scoped"

    def test_reserved_ip_allowed_when_cidr_names_it(self) -> None:
        data = scope_dict()
        data["in_scope"] = {"cidrs": ["10.0.0.0/24"]}
        lab = Scope(data, source="<test>")
        assert lab.check("10.0.0.5").in_scope

    def test_empty_allowlist_refuses_to_load(self) -> None:
        data = scope_dict()
        data["in_scope"] = {}
        with pytest.raises(ConfigError):
            Scope(data, source="<test>")

    def test_written_approval_requires_reference(self) -> None:
        data = scope_dict()
        data["engagement"] = {**data["engagement"], "authorization": "written-approval"}
        with pytest.raises(ConfigError, match="approval_ref"):
            Scope(data, source="<test>")

    def test_bad_authorization_value_refused(self) -> None:
        data = scope_dict()
        data["engagement"] = {**data["engagement"], "authorization": "vibes"}
        with pytest.raises(ConfigError, match="authorization"):
            Scope(data, source="<test>")


class TestAssertions:
    def test_assert_raises_with_details(self, scope: Scope) -> None:
        with pytest.raises(OutOfScopeError) as excinfo:
            scope.assert_in_scope("evil.example.net")
        assert excinfo.value.details["reason"] == "not_in_allowlist"

    def test_all_or_nothing(self, scope: Scope) -> None:
        with pytest.raises(OutOfScopeError, match="1 of 2"):
            scope.assert_all_in_scope(["example.com", "blog.example.com"])


class TestFreshness:
    def test_stale_scope_warns(self) -> None:
        data = scope_dict()
        data["engagement"] = {
            **data["engagement"],
            "fetched_at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
        }
        stale = Scope(data, source="<test>")
        assert "days old" in (stale.check_freshness() or "")

    def test_stale_scope_refuses_when_configured(self) -> None:
        data = scope_dict()
        data["engagement"] = {
            **data["engagement"],
            "fetched_at": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
            "refuse_when_stale": True,
        }
        with pytest.raises(StaleScopeError):
            Scope(data, source="<test>").check_freshness()

    def test_missing_timestamp_warns(self) -> None:
        data = scope_dict()
        data["engagement"] = {k: v for k, v in data["engagement"].items() if k != "fetched_at"}
        assert "fetched_at" in (Scope(data, source="<test>").check_freshness() or "")


class TestHandoff:
    def test_fingerprint_changes_with_content(self, scope: Scope) -> None:
        widened = scope_dict()
        widened["in_scope"] = {**widened["in_scope"], "domains": ["example.com", "extra.com"]}
        assert scope.fingerprint() != Scope(widened, source="<test>").fingerprint()

    def test_bbot_lists_derive_from_scope(self, scope: Scope) -> None:
        assert "example.com" in scope.bbot_whitelist()
        assert "blog.example.com" in scope.bbot_blacklist()

    def test_unparseable_deny_entry_is_surfaced_loudly(self) -> None:
        data = scope_dict()
        data["out_of_scope"] = {"regex": ["*invalid(regex"]}
        warnings = Scope(data, source="<test>").validate()
        assert any("WIDENS" in w for w in warnings)

    def test_load_from_file(self, scope_file) -> None:
        assert Scope.load(scope_file).check("example.com").in_scope

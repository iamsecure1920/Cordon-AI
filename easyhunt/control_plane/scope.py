"""Scope engine — the authorization boundary.

Matching semantics follow ``hacker-scoper``: exact domains, wildcards, CIDR
ranges, Nmap-style octet ranges, anchored regex, and URL prefixes. Two rules
govern every decision and are not configurable:

* **Denylist wins.** An out-of-scope match beats any in-scope match.
* **Fail closed.** Anything unparseable, ambiguous, or unmatched is out of scope.

The loaded scope is a *versioned artifact*: it carries a ``fetched_at`` timestamp
and a content fingerprint, both of which land in the audit log so a finding can
always be traced back to the authorization text that permitted the request.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from easyhunt.errors import ConfigError, OutOfScopeError, StaleScopeError

__all__ = ["Scope", "ScopeRules", "Target", "Verdict"]

# Hostname labels per RFC 1123, plus a leading-underscore allowance for the
# service records (_dmarc, _acme-challenge) that show up constantly in recon.
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Target:
    """A normalized target.

    ``raw`` is what the caller passed; everything else is derived. ``kind`` is one
    of ``domain``, ``ip``, or ``unknown`` — and ``unknown`` always means refusal.
    """

    raw: str
    host: str
    kind: str
    scheme: str | None = None
    port: int | None = None
    path: str = ""
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None

    @property
    def is_url(self) -> bool:
        return self.scheme is not None

    @property
    def url(self) -> str:
        if not self.is_url:
            return self.host
        netloc = self.host if self.port is None else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"


def normalize_target(raw: str) -> Target:
    """Parse a domain, IP, host:port, or URL into a :class:`Target`.

    Never raises: an unparseable input comes back as ``kind == "unknown"``, which
    the scope check treats as out of scope.
    """
    if not isinstance(raw, str):
        return Target(raw=str(raw), host="", kind="unknown")

    text = raw.strip()
    if not text:
        return Target(raw=raw, host="", kind="unknown")

    scheme: str | None = None
    port: int | None = None
    path = ""

    if "://" in text:
        parts = urlsplit(text)
        scheme = (parts.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return Target(raw=raw, host="", kind="unknown")
        netloc = parts.netloc
        # Credentials in a target string are almost always a copy/paste mistake;
        # drop them from the host but keep them out of the audit log too.
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        host_part = netloc
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
    else:
        host_part = text
        if "/" in host_part:
            host_part, _, rest = host_part.partition("/")
            path = "/" + rest

    # IPv6 literals arrive bracketed: [::1]:8080
    if host_part.startswith("["):
        close = host_part.find("]")
        if close == -1:
            return Target(raw=raw, host="", kind="unknown")
        host = host_part[1:close]
        tail = host_part[close + 1 :]
        if tail.startswith(":"):
            port = _parse_port(tail[1:])
            if port is None:
                return Target(raw=raw, host="", kind="unknown")
    else:
        host = host_part
        if host.count(":") == 1:
            host, _, port_text = host.partition(":")
            port = _parse_port(port_text)
            if port is None:
                return Target(raw=raw, host="", kind="unknown")

    host = host.strip().rstrip(".").lower()
    if not host:
        return Target(raw=raw, host="", kind="unknown")

    # Internationalized names are compared in their punycode form so a Unicode
    # homoglyph can never slip past a scope entry written in ASCII.
    if any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return Target(raw=raw, host="", kind="unknown")

    try:
        ip = ipaddress.ip_address(host)
        return Target(raw=raw, host=host, kind="ip", scheme=scheme, port=port, path=path, ip=ip)
    except ValueError:
        pass

    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return Target(raw=raw, host="", kind="unknown")

    return Target(raw=raw, host=host, kind="domain", scheme=scheme, port=port, path=path)


def _parse_port(text: str) -> int | None:
    if not text.isdigit():
        return None
    value = int(text)
    return value if 0 < value <= 65535 else None


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Verdict:
    """Result of a scope check. Always audited, whether allowed or refused."""

    target: str
    host: str
    kind: str
    in_scope: bool
    reason: str
    matched: str | None = None
    denied_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "kind": self.kind,
            "in_scope": self.in_scope,
            "reason": self.reason,
            "matched": self.matched,
            "denied_by": self.denied_by,
        }


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


@dataclass
class ScopeRules:
    """Engagement rules of engagement, as declared in ``scope.yaml``."""

    wildcard_includes_apex: bool = False
    deny_reserved_ips: bool = True
    max_rps: float = 5.0
    max_concurrency: int = 5
    allow_aggressive: bool = True
    allow_exploitation: bool = True
    no_dos: bool = True
    user_agent: str = "EasyHunt-AI/2.0 (authorized-testing)"
    forbidden_paths: list[str] = field(default_factory=list)
    #: Headers the program requires on every request, as ``Name: value`` strings.
    #: Bugcrowd and HackerOne programs commonly mandate one for attribution
    #: (``X-Bug-Bounty: Bugcrowd-<username>``). Sending traffic without it when
    #: the policy demands it is a policy violation, so these are injected on
    #: every tool that supports a header flag.
    required_headers: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ScopeRules:
        data = data or {}
        headers = [str(h).strip() for h in (data.get("required_headers") or [])]
        for header in headers:
            # A header without a colon silently becomes junk on the wire, which
            # would look like compliance while providing none.
            if ":" not in header or not header.split(":", 1)[0].strip():
                raise ValueError(
                    f"required_headers entry {header!r} is not in 'Name: value' form"
                )
        return cls(
            wildcard_includes_apex=bool(data.get("wildcard_includes_apex", False)),
            deny_reserved_ips=bool(data.get("deny_reserved_ips", True)),
            max_rps=float(data.get("max_rps", 5)),
            max_concurrency=int(data.get("max_concurrency", 5)),
            allow_aggressive=bool(data.get("allow_aggressive", True)),
            allow_exploitation=bool(data.get("allow_exploitation", True)),
            no_dos=bool(data.get("no_dos", True)),
            user_agent=str(data.get("user_agent") or cls.user_agent),
            forbidden_paths=[str(p) for p in (data.get("forbidden_paths") or [])],
            required_headers=headers,
        )


_LIST_KEYS = ("domains", "wildcards", "cidrs", "ip_ranges", "regex", "urls")


@dataclass
class _RuleSet:
    """One side of the scope (allow or deny), pre-compiled for fast matching."""

    domains: set[str] = field(default_factory=set)
    wildcards: list[str] = field(default_factory=list)
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    regex: list[re.Pattern[str]] = field(default_factory=list)
    urls: list[tuple[str, str]] = field(default_factory=list)  # (host, path prefix)
    # Anything we could not compile. Kept so validate() can surface it loudly
    # instead of silently narrowing (allowlist) or widening (denylist) the scope.
    invalid: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, side: str) -> _RuleSet:
        data = data or {}
        rs = cls()
        for entry in data.get("domains") or []:
            host = str(entry).strip().rstrip(".").lower()
            if host.startswith("*."):
                # Tolerate a wildcard filed under domains: rather than dropping it.
                rs.wildcards.append(host)
            elif host:
                rs.domains.add(host)
        for entry in data.get("wildcards") or []:
            pattern = str(entry).strip().rstrip(".").lower()
            if pattern:
                rs.wildcards.append(pattern)
        for entry in data.get("cidrs") or []:
            try:
                rs.cidrs.append(ipaddress.ip_network(str(entry).strip(), strict=False))
            except ValueError:
                rs.invalid.append(f"{side}.cidrs: {entry!r}")
        for entry in data.get("ip_ranges") or []:
            spec = str(entry).strip()
            if _valid_octet_range(spec):
                rs.ip_ranges.append(spec)
            else:
                rs.invalid.append(f"{side}.ip_ranges: {entry!r}")
        for entry in data.get("regex") or []:
            try:
                rs.regex.append(re.compile(str(entry), re.IGNORECASE))
            except re.error:
                rs.invalid.append(f"{side}.regex: {entry!r}")
        for entry in data.get("urls") or []:
            target = normalize_target(str(entry))
            if target.kind == "unknown":
                rs.invalid.append(f"{side}.urls: {entry!r}")
            else:
                rs.urls.append((target.host, target.path or "/"))
        return rs

    def is_empty(self) -> bool:
        return not any(
            (self.domains, self.wildcards, self.cidrs, self.ip_ranges, self.regex, self.urls)
        )


def _valid_octet_range(spec: str) -> bool:
    parts = spec.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if part == "*":
            continue
        for chunk in part.split(","):
            if "-" in chunk:
                low, _, high = chunk.partition("-")
                if not (low.isdigit() and high.isdigit()):
                    return False
                if not (0 <= int(low) <= int(high) <= 255):
                    return False
            elif not (chunk.isdigit() and 0 <= int(chunk) <= 255):
                return False
    return True


def _match_octet_range(ip: ipaddress.IPv4Address, spec: str) -> bool:
    """Match an Nmap-style range: ``10.0.0-255.1,5,20-30``."""
    octets = str(ip).split(".")
    for octet, part in zip(octets, spec.split("."), strict=True):
        value = int(octet)
        if part == "*":
            continue
        ok = False
        for chunk in part.split(","):
            if "-" in chunk:
                low, _, high = chunk.partition("-")
                if int(low) <= value <= int(high):
                    ok = True
                    break
            elif value == int(chunk):
                ok = True
                break
        if not ok:
            return False
    return True


def _match_wildcard(host: str, pattern: str, *, includes_apex: bool) -> bool:
    """``*.example.com`` covers any depth of subdomain; the apex only if allowed."""
    if pattern.startswith("*."):
        base = pattern[2:]
        if not base:
            return False
        if host == base:
            return includes_apex
        return host.endswith("." + base)
    # Mid-label wildcards such as api-*.example.com
    return fnmatch.fnmatchcase(host, pattern)


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


class Scope:
    """A loaded, compiled authorization artifact."""

    def __init__(self, data: dict[str, Any], *, source: str = "<dict>") -> None:
        if not isinstance(data, dict):
            raise ConfigError("scope must be a mapping", source=source)
        self.source = source
        self.raw = data
        self.engagement: dict[str, Any] = dict(data.get("engagement") or {})
        self.rules = ScopeRules.from_dict(data.get("rules"))
        self.budget: dict[str, Any] = dict(data.get("budget") or {})
        self._allow = _RuleSet.from_dict(data.get("in_scope"), side="in_scope")
        self._deny = _RuleSet.from_dict(data.get("out_of_scope"), side="out_of_scope")

        if self._allow.is_empty():
            raise ConfigError(
                "scope declares no in-scope assets; refusing to run against nothing",
                source=source,
            )
        auth = str(self.engagement.get("authorization") or "").strip()
        if auth not in {"owned", "bug-bounty", "written-approval"}:
            raise ConfigError(
                "engagement.authorization must be one of: owned, bug-bounty, written-approval",
                source=source,
                got=auth or None,
            )
        if auth == "written-approval" and not self.engagement.get("approval_ref"):
            raise ConfigError(
                "authorization 'written-approval' requires engagement.approval_ref",
                source=source,
            )

    # -- loading ----------------------------------------------------------- #

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path).expanduser()
        if not p.is_file():
            raise ConfigError(f"scope file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"scope file is not valid YAML: {exc}", path=str(p)) from exc
        return cls(data or {}, source=str(p))

    # -- identity ---------------------------------------------------------- #

    @property
    def name(self) -> str:
        return str(self.engagement.get("name") or "unnamed-engagement")

    @property
    def authorization(self) -> str:
        return str(self.engagement.get("authorization"))

    @property
    def researcher_handle(self) -> str | None:
        handle = self.engagement.get("researcher_handle")
        return str(handle) if handle else None

    def fingerprint(self) -> str:
        """Content hash of the parts that decide access. Recorded in every audit line."""
        canonical = json.dumps(
            {
                "in_scope": {k: sorted(map(str, self.raw.get("in_scope", {}).get(k, []) or []))
                             for k in _LIST_KEYS},
                "out_of_scope": {k: sorted(map(str, self.raw.get("out_of_scope", {}).get(k, []) or []))
                                 for k in _LIST_KEYS},
                "rules": self.raw.get("rules") or {},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:32]

    # -- freshness --------------------------------------------------------- #

    def age_days(self) -> float | None:
        stamp = self.engagement.get("fetched_at")
        if not stamp:
            return None
        try:
            parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return (datetime.now(UTC) - parsed).total_seconds() / 86400.0

    def check_freshness(self) -> str | None:
        """Return a warning string when the artifact is stale, else ``None``.

        Raises :class:`StaleScopeError` when the engagement set
        ``refuse_when_stale``, because a policy that has drifted is not
        authorization.
        """
        max_age = float(self.engagement.get("max_age_days") or 7)
        age = self.age_days()
        if age is None:
            message = (
                "scope has no valid engagement.fetched_at — re-pull the program policy "
                "and record when you read it"
            )
        elif age > max_age:
            message = (
                f"scope is {age:.1f} days old (max {max_age:.0f}); re-pull the program "
                "policy before running"
            )
        else:
            return None

        # Default to refusing for bug bounty work. A program's published policy
        # *is* the authorization, and scope drifts — targets get removed, rules
        # change. Continuing on a stale bug-bounty scope risks testing something
        # that is no longer in scope, which is the one failure this whole file
        # exists to prevent. Owned assets and written approvals do not expire the
        # same way, so they keep warning as the default.
        declared = self.engagement.get("refuse_when_stale")
        if declared is None:
            refuse = str(self.engagement.get("authorization", "")).lower() == "bug-bounty"
        else:
            refuse = bool(declared)

        if refuse:
            raise StaleScopeError(message, source=self.source, age_days=age, max_age_days=max_age)
        return message

    def validate(self) -> list[str]:
        """Non-fatal problems worth showing the operator before a run starts."""
        warnings: list[str] = []
        warnings.extend(f"unparseable scope entry ignored: {e}" for e in self._allow.invalid)
        warnings.extend(
            f"unparseable DENY entry ignored — this WIDENS your effective scope: {e}"
            for e in self._deny.invalid
        )
        if not self.rules.wildcard_includes_apex:
            for pattern in self._allow.wildcards:
                if pattern.startswith("*."):
                    apex = pattern[2:]
                    if apex not in self._allow.domains:
                        warnings.append(
                            f"'{pattern}' does not cover the apex '{apex}' "
                            "(add it under in_scope.domains, or set rules.wildcard_includes_apex)"
                        )
        if not self.rules.no_dos:
            warnings.append("rules.no_dos is false — EasyHunt still refuses volumetric tooling")
        stale = self.check_freshness()
        if stale:
            warnings.append(stale)
        return warnings

    # -- the check --------------------------------------------------------- #

    def check(self, target: str) -> Verdict:
        """Decide whether ``target`` may be touched. Denylist wins; fail closed."""
        parsed = normalize_target(target)
        if parsed.kind == "unknown":
            return Verdict(
                target=str(target),
                host="",
                kind="unknown",
                in_scope=False,
                reason="unparseable_target",
            )

        base = Verdict(
            target=parsed.url if parsed.is_url else parsed.host,
            host=parsed.host,
            kind=parsed.kind,
            in_scope=False,
            reason="not_in_allowlist",
        )

        # 1. Denylist first, always.
        denial = self._match(parsed, self._deny)
        if denial:
            return Verdict(**{**base.__dict__, "reason": "denylisted", "denied_by": denial})

        # 2. Program-forbidden paths.
        if parsed.path:
            path_only = parsed.path.split("?", 1)[0]
            for forbidden in self.rules.forbidden_paths:
                if path_only.startswith(forbidden):
                    return Verdict(
                        **{
                            **base.__dict__,
                            "reason": "forbidden_path",
                            "denied_by": f"rules.forbidden_paths:{forbidden}",
                        }
                    )

        # 3. Allowlist.
        allowance = self._match(parsed, self._allow)
        if not allowance:
            return base

        # 4. Reserved/private IPs need to be named explicitly, not caught by a
        #    broad regex — otherwise a scope typo becomes a pivot into infra.
        if parsed.kind == "ip" and self.rules.deny_reserved_ips and _is_reserved(parsed.ip):
            if not allowance.startswith(("cidrs:", "ip_ranges:")):
                return Verdict(
                    **{
                        **base.__dict__,
                        "reason": "reserved_ip_not_explicitly_scoped",
                        "denied_by": "rules.deny_reserved_ips",
                    }
                )

        return Verdict(**{**base.__dict__, "in_scope": True, "reason": "allowed", "matched": allowance})

    def _match(self, target: Target, rs: _RuleSet) -> str | None:
        """Return the identifier of the first matching rule, or ``None``."""
        if target.kind == "ip" and target.ip is not None:
            for net in rs.cidrs:
                if target.ip.version == net.version and target.ip in net:
                    return f"cidrs:{net}"
            if isinstance(target.ip, ipaddress.IPv4Address):
                for spec in rs.ip_ranges:
                    if _match_octet_range(target.ip, spec):
                        return f"ip_ranges:{spec}"
            if target.host in rs.domains:
                return f"domains:{target.host}"
        else:
            if target.host in rs.domains:
                return f"domains:{target.host}"
            for pattern in rs.wildcards:
                if _match_wildcard(
                    target.host, pattern, includes_apex=self.rules.wildcard_includes_apex
                ):
                    return f"wildcards:{pattern}"

        for pattern in rs.regex:
            if pattern.fullmatch(target.host) or pattern.fullmatch(target.raw.strip().lower()):
                return f"regex:{pattern.pattern}"

        for host, prefix in rs.urls:
            if target.host != host:
                continue
            if not target.path or target.path.startswith(prefix) or prefix == "/":
                return f"urls:{host}{prefix}"
        return None

    def assert_in_scope(self, target: str) -> Verdict:
        """Return the verdict, or raise :class:`OutOfScopeError`."""
        verdict = self.check(target)
        if not verdict.in_scope:
            raise OutOfScopeError(
                f"target refused: {verdict.target or target} ({verdict.reason})",
                **verdict.to_dict(),
            )
        return verdict

    def check_all(self, targets: list[str]) -> list[Verdict]:
        return [self.check(t) for t in targets]

    def assert_all_in_scope(self, targets: list[str]) -> list[Verdict]:
        """All-or-nothing: one refused target refuses the whole call.

        Partial execution would leave the operator unsure which hosts were
        actually touched, which is exactly what the audit trail exists to prevent.
        """
        verdicts = self.check_all(targets)
        refused = [v for v in verdicts if not v.in_scope]
        if refused:
            raise OutOfScopeError(
                f"{len(refused)} of {len(verdicts)} targets refused",
                refused=[v.to_dict() for v in refused],
            )
        return verdicts

    # -- handing scope down to engines ------------------------------------- #

    def bbot_whitelist(self) -> list[str]:
        """Scope entries in the form BBOT accepts, so scope is enforced twice."""
        out: list[str] = sorted(self._allow.domains)
        out += [p[2:] for p in self._allow.wildcards if p.startswith("*.")]
        out += [str(net) for net in self._allow.cidrs]
        out += [host for host, _ in self._allow.urls]
        return sorted(set(out))

    def bbot_blacklist(self) -> list[str]:
        out: list[str] = sorted(self._deny.domains)
        out += [p[2:] for p in self._deny.wildcards if p.startswith("*.")]
        out += [str(net) for net in self._deny.cidrs]
        return sorted(set(out))

    def seeds(self) -> list[str]:
        """Reasonable starting targets for recon: apexes, wildcard bases, URLs."""
        out = sorted(self._allow.domains)
        out += [p[2:] for p in self._allow.wildcards if p.startswith("*.")]
        out += [host for host, _ in self._allow.urls]
        return sorted(set(out))

    def summary(self) -> dict[str, Any]:
        return {
            "engagement": self.name,
            "authorization": self.authorization,
            "program_url": self.engagement.get("program_url"),
            "source": self.source,
            "fingerprint": self.fingerprint(),
            "age_days": self.age_days(),
            "in_scope_counts": {
                "domains": len(self._allow.domains),
                "wildcards": len(self._allow.wildcards),
                "cidrs": len(self._allow.cidrs),
                "ip_ranges": len(self._allow.ip_ranges),
                "regex": len(self._allow.regex),
                "urls": len(self._allow.urls),
            },
            "out_of_scope_counts": {
                "domains": len(self._deny.domains),
                "wildcards": len(self._deny.wildcards),
                "cidrs": len(self._deny.cidrs),
                "regex": len(self._deny.regex),
            },
            "rules": {
                "max_rps": self.rules.max_rps,
                "max_concurrency": self.rules.max_concurrency,
                "allow_aggressive": self.rules.allow_aggressive,
                "allow_exploitation": self.rules.allow_exploitation,
                "deny_reserved_ips": self.rules.deny_reserved_ips,
                "wildcard_includes_apex": self.rules.wildcard_includes_apex,
            },
        }


def _is_reserved(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> bool:
    if ip is None:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )

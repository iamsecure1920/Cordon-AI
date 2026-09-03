"""Response-diff engine: what a payload actually changed, per case.

ffuf's filters (-fl/-fw/-fs) compare a single scalar against a baseline and call
that soft-404 detection. This is the diff engine behind that — ported from
HuntProxy's ``FuzzResponseDiff`` (Apache-2.0, BehiSecc) — which compares a case
response against a baseline across status, mime, body hash, length, duration and
headers, then groups identical bodies into clusters so a catch-all page reads as
one cluster instead of a thousand findings.

Two uses:

* ``group_cases`` clusters fuzz responses by body hash and labels each cluster
  against a baseline — the soft-404 truth ``content_discovery`` needs. A cluster
  whose body matches the baseline is the catch-all; a cluster that differs is
  what the wordlist actually discovered.
* ``diff_case`` returns the per-case delta a cache-poisoning probe needs: the
  injected case's second response is diffed against the baseline, and if the
  cache served the injected body to a *different* requester, that is the poison.

Everything here is pure (bytes/dicts in, structured diff out) and never sends a
request — the callers that fetch are :mod:`cordon.tools.webscan` and the
``fuzz_compare`` MCP tool.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "MAX_DIFF_TEXT_BYTES",
    "Case",
    "Cluster",
    "FuzzResponseDiff",
    "body_hash",
    "cluster_baseline_matches",
    "diff_case",
    "group_cases",
    "label_clusters",
]

#: Bounded text diff cap, matching HuntProxy's 64 KiB. Diffing megabytes of HTML
#: for every case is the "everything at everything" anti-pattern in miniature.
MAX_DIFF_TEXT_BYTES = 64 * 1024

#: Headers that legitimately change between two requests and carry no signal.
#: ``content-length`` moves with body length, which the diff reports separately.
_VOLATILE_HEADERS = frozenset(
    {
        "date", "set-cookie", "expires", "age", "server-timing", "x-request-id",
        "x-correlation-id", "traceparent", "tracestate", "cf-ray",
        "x-amzn-trace-id", "content-length",
    }
)


@dataclass
class Case:
    """One fuzz response: what the server answered for one payload."""

    url: str
    status: int | None = None
    mime: str | None = None
    #: ``None`` = body not captured (e.g. a silent ffuf run); ``b""`` = an
    #: empty body that WAS captured. The distinction is what lets
    #: :func:`diff_case` report "cannot compare" instead of quietly calling two
    #: absent bodies identical.
    body: bytes | str | None = None
    duration_ms: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""

    @property
    def length(self) -> int:
        return len(self.body) if isinstance(self.body, (bytes, str)) else 0

    @property
    def hash(self) -> str:
        return body_hash(self.body or b"")


@dataclass
class Cluster:
    """A group of cases sharing one body hash — the soft-404 truth."""

    body_hash: str
    case_count: int
    status: int | None = None
    mime: str | None = None
    length_min: int | None = None
    length_max: int | None = None
    url: str = ""
    different_from_baseline: bool | None = None
    body_hash_matches_baseline: bool | None = None
    #: Representative URLs, so a report can point at the cluster.
    sample_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "body_hash": self.body_hash,
            "case_count": self.case_count,
            "status": self.status,
            "mime": self.mime,
            "length_min": self.length_min,
            "length_max": self.length_max,
            "different_from_baseline": self.different_from_baseline,
            "body_hash_matches_baseline": self.body_hash_matches_baseline,
            "url": self.url,
            "sample_urls": self.sample_urls[:5],
        }


@dataclass
class FuzzResponseDiff:
    """Structured delta between a baseline response and one case."""

    url: str
    status_baseline: int | None
    status_case: int | None
    status_changed: bool
    mime_baseline: str | None
    mime_case: str | None
    mime_changed: bool
    body_hash_equal: bool | None
    response_length_delta: int | None
    response_length_delta_percent: float | None
    duration_ms_delta: float | None
    duration_ratio: float | None
    header_changes: list[dict[str, Any]]
    text_diff: str = ""
    text_diff_warning: str = ""

    def changed(self) -> bool:
        """True when the case differs from baseline in any observable way."""
        return bool(
            self.status_changed
            or self.mime_changed
            or self.body_hash_equal is False
            or self.response_length_delta
            or self.duration_ms_delta
            or self.header_changes
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": f"{self.status_baseline} -> {self.status_case}",
            "status_changed": self.status_changed,
            "mime": f"{self.mime_baseline} -> {self.mime_case}",
            "mime_changed": self.mime_changed,
            "body_hash_equal": self.body_hash_equal,
            "length_delta": self.response_length_delta,
            "length_delta_percent": self.response_length_delta_percent,
            "duration_ms_delta": self.duration_ms_delta,
            "duration_ratio": self.duration_ratio,
            "header_changes": self.header_changes,
            "text_diff": self.text_diff[:MAX_DIFF_TEXT_BYTES],
            "changed": self.changed(),
        }


def body_hash(body: bytes | str) -> str:
    """Stable hash of a response body (bytes or str)."""
    raw = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    return hashlib.sha256(raw).hexdigest()[:16]


def _normalize_mime(mime: str | None) -> str | None:
    if not mime:
        return None
    value = mime.split(";")[0].strip().lower()
    return value or None


def _is_textual_mime(mime: str | None) -> bool:
    value = _normalize_mime(mime)
    if value is None:
        return True
    return bool(
        value.startswith("text/")
        or "json" in value
        or "xml" in value
        or "javascript" in value
        or value in {"application/x-www-form-urlencoded", "application/graphql"}
    )


def _group_headers(headers: dict[str, str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for name, value in headers.items():
        key = name.lower()
        if key not in _VOLATILE_HEADERS:
            grouped.setdefault(key, []).append(str(value))
    return grouped


def _header_changes(baseline: dict[str, str], case: dict[str, str]) -> list[dict[str, Any]]:
    """Added/removed/changed headers, values redacted from sensitive names.

    ``set-cookie`` and friends are volatile and excluded above; anything else
    that differs is reported with the *names* and kinds, and only the changed
    values for non-sensitive headers (a caching header like ``x-cache`` is the
    signal cache poisoning needs). The full values are not returned so a
    Set-Cookie-shaped header that slips past the volatile list cannot leak a
    session value into a report.
    """
    base = _group_headers(baseline)
    case = _group_headers(case)
    names = sorted(set(base) | set(case))
    changes: list[dict[str, Any]] = []
    for name in names:
        left = base.get(name, [])
        right = case.get(name, [])
        if left == right:
            continue
        kind = "added" if not left else ("removed" if not right else "changed")
        # Values of sensitive headers are never echoed; the names + kind are.
        if name in _VOLATILE_HEADERS or "cookie" in name or "token" in name or "auth" in name:
            changes.append({"name": name, "kind": kind})
        else:
            changes.append({"name": name, "kind": kind, "baseline": left, "case": right})
    return changes


def _bounded_text_diff(left: str, right: str) -> str:
    """First differing lines, bounded to MAX_DIFF_TEXT_BYTES."""
    output: list[str] = []
    size = 0
    left_lines = (left or "").splitlines()
    right_lines = (right or "").splitlines()
    for index in range(min(max(len(left_lines), len(right_lines)), 400)):
        left_line = left_lines[index] if index < len(left_lines) else ""
        right_line = right_lines[index] if index < len(right_lines) else ""
        if left_line == right_line:
            continue
        change = f"- {left_line}\n+ {right_line}\n"
        if size + len(change) > MAX_DIFF_TEXT_BYTES:
            output.append("… (diff truncated)")
            break
        output.append(change.rstrip("\n"))
        size += len(change)
    return "\n".join(output)


def diff_case(baseline: Case, case: Case, *, include_text: bool = True) -> FuzzResponseDiff:
    """Structured delta of ``case`` against ``baseline`` (HuntProxy algorithm).

    Length delta, duration ratio, mime change, body-hash equality, header
    changes and a bounded text diff. ``case`` is the injected request; the diff
    answers "did the payload change anything observable".
    """
    baseline_mime = _normalize_mime(baseline.mime)
    case_mime = _normalize_mime(case.mime)
    length_delta = (case.length - baseline.length) if baseline.length is not None else None
    length_percent = None
    if length_delta is not None and baseline.length:
        length_percent = length_delta * 100.0 / baseline.length
    duration_delta = None
    duration_ratio = None
    if case.duration_ms is not None and baseline.duration_ms is not None:
        duration_delta = case.duration_ms - baseline.duration_ms
        if baseline.duration_ms:
            duration_ratio = case.duration_ms / baseline.duration_ms

    text_diff = ""
    warning = ""
    if include_text and baseline.body is not None and case.body is not None and _is_textual_mime(case.mime) and _is_textual_mime(baseline.mime):
        left = baseline.body.decode("utf-8", errors="replace") if isinstance(baseline.body, bytes) else baseline.body
        right = case.body.decode("utf-8", errors="replace") if isinstance(case.body, bytes) else case.body
        text_diff = _bounded_text_diff(left, right)
    elif baseline.body is None or case.body is None:
        warning = "body not captured on one or both sides — text diff skipped"
    else:
        warning = "binary or unknown mime — text diff skipped"

    return FuzzResponseDiff(
        url=case.url,
        status_baseline=baseline.status,
        status_case=case.status,
        status_changed=baseline.status != case.status,
        mime_baseline=baseline_mime,
        mime_case=case_mime,
        mime_changed=baseline_mime != case_mime,
        body_hash_equal=(
            (baseline.hash == case.hash)
            if baseline.body is not None and case.body is not None
            else None
        ),
        response_length_delta=length_delta,
        response_length_delta_percent=round(length_percent, 2) if length_percent is not None else None,
        duration_ms_delta=duration_delta,
        duration_ratio=round(duration_ratio, 2) if duration_ratio is not None else None,
        header_changes=_header_changes(baseline.headers, case.headers),
        text_diff=text_diff,
        text_diff_warning=warning,
    )


def group_cases(cases: list[Case], baseline: Case | None = None) -> list[Cluster]:
    """Cluster cases by body hash — identical bodies are one cluster.

    This is the soft-404 truth: on a catch-all host every nonexistent path
    returns the same page, so every case shares one hash and becomes ONE cluster
    the caller can discard, instead of a thousand findings of the same page.
    """
    buckets: dict[str, list[Case]] = {}
    for case in cases:
        buckets.setdefault(case.hash, []).append(case)

    clusters: list[Cluster] = []
    for bodyhash, members in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        first = members[0]
        cluster = Cluster(
            body_hash=bodyhash,
            case_count=len(members),
            status=first.status,
            mime=_normalize_mime(first.mime),
            length_min=min(m.length for m in members),
            length_max=max(m.length for m in members),
            url=first.url,
            sample_urls=[m.url for m in members],
        )
        if baseline is not None:
            cluster.body_hash_matches_baseline = bodyhash == baseline.hash
            length_matches = cluster.length_min == baseline.length and cluster.length_max == baseline.length
            cluster.different_from_baseline = bool(
                cluster.status != baseline.status
                or _normalize_mime(cluster.mime) != _normalize_mime(baseline.mime)
                or cluster.body_hash_matches_baseline is False
                or not length_matches
            )
        clusters.append(cluster)
    return clusters


def label_clusters(
    clusters: list[Cluster], baseline: Case | None = None
) -> dict[str, Any]:
    """Summarise clusters for a fuzz run: real vs catch-all vs unclassified.

    Returns the clusters split into ``distinct`` (differ from baseline — what
    the wordlist actually found), ``catch_all`` (match the baseline — the
    soft-404 page) and ``unclassified`` (no baseline supplied), plus counts.
    """
    if baseline is None:
        return {
            "distinct": [c.to_dict() for c in clusters],
            "catch_all": [],
            "unclassified": [],
            "counts": {"distinct": len(clusters), "catch_all": 0, "unclassified": 0},
        }
    distinct = [c for c in clusters if c.different_from_baseline is True]
    catch_all = [c for c in clusters if c.different_from_baseline is False]
    unclassified = [c for c in clusters if c.different_from_baseline is None]
    return {
        "distinct": [c.to_dict() for c in distinct],
        "catch_all": [c.to_dict() for c in catch_all],
        "unclassified": [c.to_dict() for c in unclassified],
        "counts": {
            "distinct": len(distinct),
            "catch_all": len(catch_all),
            "unclassified": len(unclassified),
        },
    }


def cluster_baseline_matches(cluster: Cluster, baseline: Case) -> bool:
    """Convenience: does one cluster look like the baseline page?"""
    return bool(
        cluster.body_hash_matches_baseline is True
        or (
            cluster.status == baseline.status
            and cluster.length_min == baseline.length
            and cluster.length_max == baseline.length
        )
    )

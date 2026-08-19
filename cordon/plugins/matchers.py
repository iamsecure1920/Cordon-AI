"""Native matcher/extractor engine for rule-packs.

Lightweight regex/word/status logic over any tool's output, so a user can add a
detection without writing Python and without needing a full Nuclei template. The
vocabulary is deliberately close to Nuclei's — anyone who can write a template
can write one of these.

Nothing here evaluates user-supplied expressions. There is no DSL, no ``eval``,
no template rendering: a rule file is data, and data from ``rules/`` is treated
with the same suspicion as data from a target.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from cordon.errors import PluginError

__all__ = [
    "MatchInput",
    "MatchResult",
    "evaluate_rule",
    "validate_extractor",
    "validate_matcher",
]

MATCHER_TYPES = {"word", "regex", "status", "size", "header", "hash"}
EXTRACTOR_TYPES = {"regex", "kval", "json"}
PARTS = {"body", "header", "all", "url", "status", "raw"}

# A rule regex runs against attacker-influenced text. Cap the input rather than
# the pattern: a linear-time scan over 512 KB is bounded work, a pathological
# pattern over 50 MB is not.
MAX_SCAN_CHARS = 512 * 1024


@dataclass
class MatchInput:
    """One observation for a rule to run against."""

    url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def part(self, name: str) -> str:
        name = (name or "body").lower()
        if name == "body":
            return self.body[:MAX_SCAN_CHARS]
        if name == "header":
            return "\n".join(f"{k}: {v}" for k, v in self.headers.items())[:MAX_SCAN_CHARS]
        if name == "url":
            return self.url
        if name == "status":
            return str(self.status or "")
        if name == "raw":
            return (self.raw or self.body)[:MAX_SCAN_CHARS]
        # "all"
        joined = "\n".join(
            [self.url, str(self.status or ""), self.part("header"), self.body]
        )
        return joined[:MAX_SCAN_CHARS]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MatchInput:
        headers = data.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        return cls(
            url=str(data.get("url") or data.get("host") or ""),
            status=int(data["status"]) if str(data.get("status") or "").isdigit() else None,
            headers={str(k).lower(): str(v) for k, v in headers.items()},
            body=str(data.get("body") or ""),
            raw=str(data.get("raw") or ""),
            extra={k: v for k, v in data.items() if k not in {"url", "status", "headers", "body", "raw"}},
        )


@dataclass
class MatchResult:
    matched: bool
    rule_id: str
    matched_by: list[str] = field(default_factory=list)
    extracted: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "rule_id": self.rule_id,
            "matched_by": self.matched_by,
            "extracted": self.extracted,
        }


# --------------------------------------------------------------------------- #
# Validation (load time)
# --------------------------------------------------------------------------- #


def validate_matcher(matcher: Any, *, plugin_id: str, index: int) -> None:
    where = f"{plugin_id}.matchers[{index}]"
    if not isinstance(matcher, dict):
        raise PluginError(f"{where}: must be a mapping", plugin=plugin_id)

    kind = str(matcher.get("type") or "").lower()
    if kind not in MATCHER_TYPES:
        raise PluginError(
            f"{where}: unknown matcher type {kind!r}; expected one of {sorted(MATCHER_TYPES)}",
            plugin=plugin_id,
        )
    part = str(matcher.get("part") or "body").lower()
    if part not in PARTS:
        raise PluginError(
            f"{where}: unknown part {part!r}; expected one of {sorted(PARTS)}", plugin=plugin_id
        )
    condition = str(matcher.get("condition") or "or").lower()
    if condition not in {"and", "or"}:
        raise PluginError(f"{where}: condition must be 'and' or 'or'", plugin=plugin_id)

    if kind == "word":
        if not matcher.get("words"):
            raise PluginError(f"{where}: a word matcher needs 'words'", plugin=plugin_id)
    elif kind == "regex":
        patterns = matcher.get("regex")
        if not patterns:
            raise PluginError(f"{where}: a regex matcher needs 'regex'", plugin=plugin_id)
        for pattern in patterns if isinstance(patterns, list) else [patterns]:
            try:
                re.compile(str(pattern))
            except re.error as exc:
                raise PluginError(f"{where}: invalid regex {pattern!r}: {exc}", plugin=plugin_id) from exc
    elif kind == "status":
        statuses = matcher.get("status")
        if not statuses:
            raise PluginError(f"{where}: a status matcher needs 'status'", plugin=plugin_id)
        for code in statuses if isinstance(statuses, list) else [statuses]:
            if not str(code).isdigit():
                raise PluginError(f"{where}: status {code!r} is not numeric", plugin=plugin_id)
    elif kind == "size":
        if not matcher.get("size"):
            raise PluginError(f"{where}: a size matcher needs 'size'", plugin=plugin_id)
    elif kind == "header":
        if not matcher.get("name"):
            raise PluginError(f"{where}: a header matcher needs 'name'", plugin=plugin_id)
    elif kind == "hash":
        if not matcher.get("hashes"):
            raise PluginError(f"{where}: a hash matcher needs 'hashes'", plugin=plugin_id)


def validate_extractor(extractor: Any, *, plugin_id: str, index: int) -> None:
    where = f"{plugin_id}.extractors[{index}]"
    if not isinstance(extractor, dict):
        raise PluginError(f"{where}: must be a mapping", plugin=plugin_id)
    kind = str(extractor.get("type") or "").lower()
    if kind not in EXTRACTOR_TYPES:
        raise PluginError(
            f"{where}: unknown extractor type {kind!r}; expected {sorted(EXTRACTOR_TYPES)}",
            plugin=plugin_id,
        )
    if kind == "regex":
        patterns = extractor.get("regex")
        if not patterns:
            raise PluginError(f"{where}: a regex extractor needs 'regex'", plugin=plugin_id)
        for pattern in patterns if isinstance(patterns, list) else [patterns]:
            try:
                re.compile(str(pattern))
            except re.error as exc:
                raise PluginError(f"{where}: invalid regex {pattern!r}: {exc}", plugin=plugin_id) from exc
    elif kind == "kval" and not extractor.get("kval"):
        raise PluginError(f"{where}: a kval extractor needs 'kval'", plugin=plugin_id)
    elif kind == "json" and not extractor.get("json"):
        raise PluginError(f"{where}: a json extractor needs 'json'", plugin=plugin_id)


# --------------------------------------------------------------------------- #
# Evaluation (run time)
# --------------------------------------------------------------------------- #


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _match_one(matcher: dict[str, Any], target: MatchInput) -> bool:
    kind = str(matcher.get("type")).lower()
    part_name = str(matcher.get("part") or "body")
    condition = str(matcher.get("condition") or "or").lower()
    negative = bool(matcher.get("negative"))
    # Case-sensitive by default, matching Nuclei: someone porting a template
    # should not get quietly broader matching here than they had there.
    case_insensitive = bool(matcher.get("case_insensitive", False))
    haystack = target.part(part_name)
    if case_insensitive:
        haystack = haystack.lower()

    if kind == "word":
        words = [str(w).lower() if case_insensitive else str(w) for w in _as_list(matcher["words"])]
        hits = [w in haystack for w in words]
    elif kind == "regex":
        flags = re.IGNORECASE if case_insensitive else 0
        hits = [
            re.search(str(p), haystack, flags) is not None for p in _as_list(matcher["regex"])
        ]
    elif kind == "status":
        hits = [target.status == int(code) for code in _as_list(matcher["status"])]
    elif kind == "size":
        hits = [len(target.body) == int(size) for size in _as_list(matcher["size"])]
    elif kind == "header":
        name = str(matcher["name"]).lower()
        value = target.headers.get(name)
        wanted = _as_list(matcher.get("values"))
        if value is None:
            hits = [False]
        elif not wanted:
            hits = [True]
        else:
            compare = value.lower() if case_insensitive else value
            hits = [str(w).lower() in compare if case_insensitive else str(w) in compare for w in wanted]
    elif kind == "hash":
        import hashlib

        digest = hashlib.sha256(target.body.encode("utf-8", "replace")).hexdigest()
        hits = [digest == str(h).lower() for h in _as_list(matcher["hashes"])]
    else:
        hits = [False]

    result = all(hits) if condition == "and" else any(hits)
    return not result if negative else result


def _extract_one(extractor: dict[str, Any], target: MatchInput) -> list[str]:
    kind = str(extractor.get("type")).lower()
    part_name = str(extractor.get("part") or "body")
    out: list[str] = []

    if kind == "regex":
        group = int(extractor.get("group", 0))
        haystack = target.part(part_name)
        for pattern in _as_list(extractor["regex"]):
            for match in re.finditer(str(pattern), haystack):
                try:
                    out.append(match.group(group))
                except IndexError:
                    # Rule names a group its pattern does not have; fall back to
                    # the whole match rather than dropping the hit.
                    out.append(match.group(0))
    elif kind == "kval":
        for key in _as_list(extractor["kval"]):
            value = target.headers.get(str(key).lower())
            if value is None:
                value = target.extra.get(str(key))
            if value is not None:
                out.append(str(value))
    elif kind == "json":
        try:
            document = json.loads(target.body)
        except (json.JSONDecodeError, TypeError):
            return []
        for path in _as_list(extractor["json"]):
            node: Any = document
            for segment in str(path).split("."):
                if isinstance(node, dict) and segment in node:
                    node = node[segment]
                elif isinstance(node, list) and segment.isdigit() and int(segment) < len(node):
                    node = node[int(segment)]
                else:
                    node = None
                    break
            if node is not None:
                out.append(node if isinstance(node, str) else json.dumps(node, default=str))

    # Cap: an extractor pointed at a huge response should not blow up a finding.
    return list(dict.fromkeys(out))[:100]


def evaluate_rule(manifest: Any, target: MatchInput) -> MatchResult:
    """Run one rule-pack against one observation."""
    matched_by: list[str] = []
    outcomes: list[bool] = []
    for index, matcher in enumerate(manifest.matchers):
        hit = _match_one(matcher, target)
        outcomes.append(hit)
        if hit:
            matched_by.append(f"{matcher.get('type')}[{index}]")

    condition = getattr(manifest, "condition", "and")
    matched = all(outcomes) if condition == "and" else any(outcomes)
    if not outcomes:
        matched = False

    extracted: dict[str, list[str]] = {}
    if matched:
        for index, extractor in enumerate(manifest.extractors):
            name = str(extractor.get("name") or f"{extractor.get('type')}_{index}")
            values = _extract_one(extractor, target)
            if values:
                extracted[name] = values

    return MatchResult(
        matched=matched, rule_id=manifest.id, matched_by=matched_by, extracted=extracted
    )

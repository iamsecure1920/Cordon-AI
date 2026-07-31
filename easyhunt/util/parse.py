"""Output parsing helpers.

Tool output is never handed to a model raw. Everything lands here first to be
parsed, deduplicated, capped, and stripped of prompt-injection markers — the
tool-output-is-untrusted-input rule, implemented once so no wrapper can forget it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "cap_payload",
    "dedupe",
    "host_of",
    "iter_jsonl",
    "parse_jsonl",
    "sanitize_for_model",
    "stable_id",
]


def parse_jsonl(text: str, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Parse JSON-lines output, skipping the banner noise tools like to emit."""
    return list(iter_jsonl(text, limit=limit))


def iter_jsonl(text: str, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            yield parsed
            count += 1
        elif isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    yield item
                    count += 1
        if limit is not None and count >= limit:
            return


def host_of(value: str) -> str:
    """Best-effort hostname extraction from a URL, host:port, or bare host."""
    text = (value or "").strip()
    if "://" in text:
        text = urlsplit(text).netloc
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        return text[1 : text.find("]")] if "]" in text else text
    return text.split(":", 1)[0].rstrip(".").lower()


def dedupe(items: Iterable[Any], *, key: str | None = None) -> list[Any]:
    """Order-preserving dedupe, optionally on a dict key."""
    seen: set[Any] = set()
    out: list[Any] = []
    for item in items:
        marker = item.get(key) if key and isinstance(item, dict) else item
        try:
            hashable = marker if isinstance(marker, (str, int, float, bool, tuple, type(None))) else json.dumps(marker, sort_keys=True, default=str)
        except (TypeError, ValueError):
            hashable = str(marker)
        if hashable in seen:
            continue
        seen.add(hashable)
        out.append(item)
    return out


def stable_id(*parts: Any) -> str:
    """Deterministic short id, so re-running a scan does not duplicate findings."""
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Untrusted-output handling
# --------------------------------------------------------------------------- #

# Markers that try to talk to the model rather than describe the target. A page
# title or HTTP response can contain any of these, and it reaches our context
# window verbatim if we let it.
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions?"), "[stripped: injection marker]"),
    (re.compile(r"(?i)\bsystem\s*prompt\b"), "[stripped: injection marker]"),
    (re.compile(r"(?i)</?(system|assistant|human|user)>"), "[stripped: role tag]"),
    (re.compile(r"(?i)<\s*/?\s*(instructions?|important)\s*>"), "[stripped: directive tag]"),
    (re.compile(r"(?i)\bnew\s+instructions?\s*:"), "[stripped: injection marker]"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(a|an|the)\b"), "[stripped: persona override]"),
    (re.compile(r"(?i)\b(tool|function)_(call|result)\b\s*[:{]"), "[stripped: protocol marker]"),
    (re.compile(r"<\s*system-reminder\s*>", re.IGNORECASE), "[stripped: protocol marker]"),
]


def sanitize_for_model(text: str, *, max_lines: int = 400, max_chars: int = 60_000) -> str:
    """Neutralize prompt-injection markers and cap size before a model sees it.

    Findings keep their original text on disk and in the report — only the copy
    that enters a context window is rewritten, and every rewrite leaves a visible
    ``[stripped: ...]`` marker so a reviewer can tell something was there.
    """
    if not text:
        return ""
    out = text
    for pattern, replacement in _INJECTION_PATTERNS:
        out = pattern.sub(replacement, out)

    lines = out.splitlines()
    if len(lines) > max_lines:
        omitted = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... [{omitted} further lines omitted; use fetch_slice]"]
        out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars] + f"\n... [truncated at {max_chars} chars; use fetch_slice]"
    return out


def cap_payload(payload: Any, *, max_bytes: int = 262_144) -> tuple[Any, bool]:
    """Shrink a structured payload to fit the MCP response ceiling.

    Returns ``(payload, truncated)``. Lists are cut from the end and annotated,
    which keeps the highest-signal items (findings are sorted by severity before
    this is called) rather than an arbitrary prefix of a serialized blob.
    """
    encoded = json.dumps(payload, default=str)
    if len(encoded) <= max_bytes:
        return payload, False

    if isinstance(payload, dict):
        trimmed = dict(payload)
        # Shrink the largest list field until it fits.
        for _ in range(24):
            list_keys = [k for k, v in trimmed.items() if isinstance(v, list) and v]
            if not list_keys:
                break
            biggest = max(list_keys, key=lambda k: len(json.dumps(trimmed[k], default=str)))
            values = trimmed[biggest]
            keep = max(1, len(values) // 2)
            trimmed[biggest] = values[:keep]
            trimmed["_truncated"] = {
                "field": biggest,
                "kept": keep,
                "total": len(payload[biggest]) if isinstance(payload.get(biggest), list) else keep,
                "hint": "call fetch_slice(job_id, ...) for the full set",
            }
            if len(json.dumps(trimmed, default=str)) <= max_bytes:
                return trimmed, True
        return {
            "_truncated": {"reason": "payload too large", "hint": "use fetch_slice"},
            "summary": str(payload)[: max_bytes // 2],
        }, True

    if isinstance(payload, list):
        keep = len(payload)
        while keep > 1 and len(json.dumps(payload[:keep], default=str)) > max_bytes:
            keep //= 2
        return payload[:keep], True

    return str(payload)[:max_bytes], True

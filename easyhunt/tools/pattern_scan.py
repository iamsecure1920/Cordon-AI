"""gf pattern scan: classified sink candidates from URLs and response bodies.

``gf`` (github.com/tomnomnom/gf) is a grep wrapper whose real value is not the
binary — it is a hundred lines that pipes stdin through ``grep -oP`` — but the
*named pattern library*: per-bug-class regex packs for XSS, SSRF, open-redirect,
SQLi, LFI, RCE, SSTI, IDOR, upload and cloud-storage sinks. A human pentester
holds those shapes in their head; this module holds them as data.

Two decisions shape this module:

**The patterns are data, vetted and pinned.** They live in ``rules/gf/*.json``,
one file per class, in gf's native format — ``{"flags": "HnriP", "patterns":
[...]}`` — so the same files run under the real ``gf`` binary dropped into
``~/.gf/`` (the flags select PCRE and case-insensitive matching, which both
grep -P and Python ``re`` honour). ``rules/gf/manifest.json`` maps each file to
a bug class, a severity and the validator that would actually prove it. A bad
regex or a manifest naming a missing file fails at import, not silently at scan
time — the same reason ``scope`` keeps its uncompilable patterns in an
``invalid`` list instead of dropping them.

**This is candidate generation, not detection.** A regex that matches is a
*shape*, not a bug. ``?redirect=`` is an open-redirect candidate; whether the
server follows it is what the validator proves. Nothing here files a Finding —
it stores ``sink_candidate`` assets and reports the classified list, each entry
naming the validator that would turn it into one. That is the exact line the
rest of this codebase draws between a scanner's heuristic and a finding, and the
false-positive history (testssl's ``ipv4_in_header`` filing 32 MEDIUMs over a
cookie, ssrfmap's oracle saturating on a CDN) is why.

Nothing here sends traffic a caller did not ask for: URL strings are classified
without a request, and bodies are only fetched when ``scan_bodies`` is true,
under the engagement's rate limiter and scope checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Asset
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import targets_or_assets
from easyhunt.util.parse import host_of

__all__ = ["GF_PATTERNS", "GfPattern", "load_patterns", "pattern_scan"]

_GF_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "gf"


@dataclass(frozen=True)
class GfPattern:
    """One named pattern pack, compiled and ready to scan."""

    name: str
    klass: str
    severity: str
    validator: str
    purpose: str
    regexes: tuple[re.Pattern[str], ...]


def load_patterns(directory: Path = _GF_DIR) -> tuple[list[GfPattern], list[str]]:
    """Load and compile the pattern pack. Returns ``(patterns, problems)``.

    ``problems`` lists every malformed regex, missing file, and manifest entry
    that names nothing, so a broken pack is surfaced rather than silently
    shrinking the scan — a dropped ``ssrf`` pack makes an SSRF-shaped estate
    read as clean, which is the worst quiet failure available.
    """
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        return [], [f"no manifest at {manifest_path}"]
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], [f"{manifest_path}: invalid JSON: {exc}"]
    entries = raw.get("patterns", []) if isinstance(raw, dict) else []
    if not entries:
        return [], [f"{manifest_path}: no patterns declared"]

    problems: list[str] = []
    patterns: list[GfPattern] = []
    for entry in entries:
        name = str(entry.get("name", ""))
        file_path = directory / f"{name}.json"
        if not name:
            problems.append(f"{manifest_path}: pattern entry without a name")
            continue
        if not file_path.is_file():
            problems.append(f"{file_path}: declared in manifest but missing")
            continue
        try:
            raw_pattern = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"{file_path}: invalid JSON: {exc}")
            continue
        # gf's native format: {"flags": "HnriP", "patterns": [...]}, with a
        # single legacy {"pattern": "..."} fallback. The flags select grep
        # behaviour; only the case-insensitive (i) bit is honoured here, the
        # same way gf's `grep -i` would.
        if not isinstance(raw_pattern, dict):
            problems.append(f"{file_path}: expected a gf pattern object with a 'patterns' array")
            continue
        ignore_case = "i" in str(raw_pattern.get("flags", ""))
        regex_list = raw_pattern.get("patterns") or raw_pattern.get("pattern")
        if isinstance(regex_list, str):
            regex_list = [regex_list]
        if not isinstance(regex_list, list) or not regex_list:
            problems.append(f"{file_path}: expected a non-empty 'patterns' array")
            continue
        compiled: list[re.Pattern[str]] = []
        for i, pattern in enumerate(regex_list):
            if not isinstance(pattern, str):
                problems.append(f"{file_path}: pattern {i} is not a string")
                continue
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE if ignore_case else 0))
            except re.error as exc:
                problems.append(f"{file_path}: pattern {i} does not compile: {exc}")
        if compiled:
            patterns.append(
                GfPattern(
                    name=name,
                    klass=str(entry.get("class", name)),
                    severity=str(entry.get("severity", "medium")),
                    validator=str(entry.get("validator", "")),
                    purpose=str(entry.get("purpose", "")),
                    regexes=tuple(compiled),
                )
            )
    return patterns, problems


#: Loaded once at import. A broken pack does not crash the server — it is
#: reported by the tool as UNTESTED, which is the honest answer for "the pattern
#: library never loaded".
GF_PATTERNS, _LOAD_PROBLEMS = load_patterns()

#: Cap on how much of a body to scan. A regex never needs more than a small
#: window around a sink, and scanning megabytes of minified bundle per pattern
#: is CPU for nothing.
_BODY_SCAN_LIMIT = 2_000_000

#: A response that is an edge/origin refusing us, not application content.
#: Scanning it yields zero candidates and reads as a clean estate — the same
#: lie js_analyze refuses to tell.
_BLOCK_PAGE = re.compile(
    r"""(?i)(?:sorry,\s*you\s*have\s*been\s*blocked
        | attention\s+required!?\s*\|\s*cloudflare
        | request\s+rejected
        | access\s+denied
        | \bcf-error-details\b
        | <title>\s*4\d\d\s+forbidden)""",
    re.VERBOSE,
)


def _blocked(body: str) -> bool:
    return bool(_BLOCK_PAGE.search(body[:16_000]) or _BLOCK_PAGE.search(body[-16_000:]))


def _scan(text: str, patterns: list[GfPattern], *, limit: int = 400) -> list[dict[str, Any]]:
    """Every pattern match in ``text``, as a candidate record.

    ``matched`` is the substring the regex captured, truncated; ``evidence`` is
    surrounding context so a human can see the sink in situ. Bounded by
    ``limit`` per pattern so one noisy pattern cannot drown the rest.
    """
    hits: list[dict[str, Any]] = []
    for pack in patterns:
        seen: set[tuple[int, int]] = set()
        for pattern in pack.regexes:
            for match in pattern.finditer(text):
                key = (match.start(), match.end())
                if key in seen:
                    continue
                seen.add(key)
                value = match.group(0)
                hits.append({
                    "class": pack.klass,
                    "pattern": pack.name,
                    "matched": value[:200],
                    "evidence": text[max(0, match.start() - 60): match.end() + 60][:400],
                })
                if len(hits) >= limit:
                    return hits
    return hits


@easyhunt_tool(
    phase="method",
    mode="passive",
    targets_arg="target",
    timeout=600,
    name="pattern_scan",
    tags={"recon", "patterns", "gf"},
    estimated_requests=40,
    rationale="Classify the attack surface with vetted gf patterns: which URLs and bodies carry XSS/SSRF/redirect/SQLi/LFI/RCE/SSTI/IDOR/upload/cloud-storage shapes.",
)
async def pattern_scan(
    target: str, scan_bodies: bool = True, max_urls: int = 40
) -> dict[str, Any]:
    """Scan URLs (and optionally their response bodies) with vetted gf patterns.

    Classifies each URL by its query parameters and path segments, and — when
    ``scan_bodies`` is true — fetches it once and scans the response for sink
    shapes. Results are grouped by bug class, each candidate naming the
    validator that would prove or kill it. Nothing here files a finding: a
    pattern match is a lead, and the validators exist because leads are usually
    wrong.

    ``target`` names URLs, or "auto" to inherit the live URLs an earlier phase
    recorded. The pattern library lives in ``rules/gf/``; if it failed to load,
    this returns UNTESTED rather than an empty scan.
    """
    engagement = get_engagement()
    if not GF_PATTERNS:
        return {
            "ok": False,
            "error": "pattern_pack_unavailable",
            "status": "UNTESTED",
            "problems": _LOAD_PROBLEMS,
            "message": (
                "The gf pattern pack did not load. Zero candidates from a scan "
                "that never ran is not a clean estate — it is UNTESTED."
            ),
        }

    candidates, origin = targets_or_assets(target, kind="url", tool="pattern_scan")
    urls = [u for u in candidates if u.startswith("http")][:max_urls]
    if not urls:
        return {
            "ok": False,
            "error": "no_urls",
            "message": "pattern_scan needs http(s) URLs, or a prior phase that recorded some.",
        }

    # URL shapes are classified without any request: the query string and path
    # are already the surface. Bodies are a second, gated pass.
    grouped: dict[str, list[dict[str, Any]]] = {}
    problems = list(_LOAD_PROBLEMS)
    fetched: list[dict[str, Any]] = []

    for url in urls:
        for hit in _scan(url, GF_PATTERNS, limit=60):
            hit["url"] = url
            hit["from"] = "url"
            grouped.setdefault(hit["class"], []).append(hit)

    if scan_bodies:
        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True,
            headers={"User-Agent": engagement.scope.rules.user_agent},
        ) as client:
            for url in urls:
                async with engagement.limiter.slot(host=url):
                    try:
                        response = await client.get(url)
                    except httpx.HTTPError as exc:
                        fetched.append({"url": url, "error": str(exc)[:200]})
                        continue
                body = response.text[:_BODY_SCAN_LIMIT]
                if response.status_code >= 400 or _blocked(body):
                    fetched.append({
                        "url": url, "status": response.status_code,
                        "verdict": "blocked",
                    })
                    continue
                fetched.append({"url": url, "status": response.status_code, "bytes": len(body)})
                for hit in _scan(body, GF_PATTERNS, limit=120):
                    hit["url"] = url
                    hit["from"] = "body"
                    grouped.setdefault(hit["class"], []).append(hit)

    # Deduplicate within each class: the same URL can match several patterns,
    # and a body re-matches what the URL string already matched.
    seen_candidates: set[str] = set()
    classified: dict[str, list[dict[str, Any]]] = {}
    for klass, hits in grouped.items():
        unique: list[dict[str, Any]] = []
        for hit in hits:
            key = (hit["url"], hit["pattern"], hit["matched"][:80])
            if key in seen_candidates:
                continue
            seen_candidates.add(key)
            unique.append(hit)
        classified[klass] = unique

    # Store so a later phase can inherit them without re-deriving, tagged by
    # class. Kind is "sink_candidate", not "url": these are leads, not targets
    # to point a scanner at.
    for klass, hits in classified.items():
        engagement.assets.add_many(
            Asset(
                value=hit["url"], kind="sink_candidate", source="pattern_scan",
                host=host_of(hit["url"]), tags=[klass, "gf-candidate"],
                attributes={"pattern": hit["pattern"], "matched": hit["matched"]},
            )
            for hit in hits
        )
    engagement.assets.save(engagement.workspace / "assets.json")

    blocked = [f for f in fetched if f.get("verdict") == "blocked"]
    failed = [f for f in fetched if "error" in f]
    summary = {
        klass: {
            "count": len(hits),
            "validator": next(
                (p.validator for p in GF_PATTERNS if p.klass == klass), ""
            ),
            "candidates": hits[:40],
        }
        for klass, hits in sorted(classified.items())
    }

    return {
        "ok": True,
        "status": "PARTIAL" if (blocked or failed) else "COMPLETE",
        "complete": not (blocked or failed),
        "origin": origin,
        "urls_scanned": len(urls),
        "bodies_fetched": len(fetched) - len(blocked) - len(failed),
        "blocked": blocked[:20],
        "fetch_errors": failed[:20],
        "problems": problems,
        "classes": summary,
        "candidates_total": sum(len(h) for h in classified.values()),
        # The phase gate (phase.py 'count': 'count') reads this key — a match
        # class with zero candidates is a legitimately empty phase, but the
        # key must exist or EVERY pattern phase reports "produced nothing".
        "count": sum(len(h) for h in classified.values()),
        "note": _note(len(urls), scan_bodies, blocked, failed),
        "next_step": (
            "A pattern match is a shape, not a bug. Run the validator named in "
            "each class — xss_validate, ssrf_probe, sqli_validate, ssti_probe, "
            "cmdi_probe, authz_compare, or validate_findings — against the "
            "candidate URLs, and report only what the validator reproduces."
        ),
    }


def _note(total: int, scan_bodies: bool, blocked: list[dict[str, Any]], failed: list[dict[str, Any]]) -> str:
    bits = [f"{total} URL(s) classified."]
    if scan_bodies:
        bits.append("Response bodies were scanned for sink shapes.")
    if blocked:
        bits.append(
            f"{len(blocked)} response(s) were an edge/origin refusal — those "
            "bodies are UNTESTED, not clean."
        )
    if failed:
        bits.append(f"{len(failed)} fetch(es) failed — those bodies are UNTESTED.")
    bits.append(
        "Every result is a candidate. Nothing here is a finding until a "
        "validator reproduces it."
    )
    return " ".join(bits)

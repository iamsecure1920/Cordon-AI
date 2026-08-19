"""The OWASP Web Security Testing Guide, as data the agent can query.

Cordon has always been able to *run* things and weak at deciding what to run
next. That gap showed up concretely on a real engagement: nuclei came back clean
across a mature estate, and the next move was improvisation rather than method.

The WSTG is the profession's answer — 115 named tests grouped by phase. Indexed
by ``scripts/fetch_wstg.py`` from a pinned OWASP commit; the guide text is
CC BY-SA 4.0 and attribution travels with every record.

This is deliberately *retrieval*, not automation. A WSTG test says what to check
and why it matters; whether it applies is a judgement about the target that no
detector makes for you.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = ["WstgIndex", "load_index"]

INDEX_PATH = Path(__file__).resolve().parent.parent.parent / "knowledge" / "wstg" / "index.json"

#: Technology or observation -> WSTG categories worth reading first. Keeps the
#: agent from walking all 115 tests when http_probe already said what the stack is.
STACK_HINTS: dict[str, tuple[str, ...]] = {
    "graphql": ("APIT", "INPV", "ATHZ"),
    "rest": ("APIT", "ATHZ", "INPV"),
    "api": ("APIT", "ATHZ", "ATHN"),
    "oauth": ("ATHN", "ATHZ", "SESS"),
    "saml": ("ATHN", "ATHZ", "SESS"),
    "sso": ("ATHN", "SESS", "IDNT"),
    "jwt": ("SESS", "ATHN", "CRYP"),
    "wordpress": ("CONF", "ATHN", "INPV"),
    "java": ("INPV", "CONF", "ERRH"),
    "tomcat": ("CONF", "ATHN"),
    "php": ("INPV", "CONF"),
    "nodejs": ("INPV", "CLNT"),
    "express": ("INPV", "CLNT", "SESS"),
    "react": ("CLNT", "SESS"),
    "upload": ("BUSL", "INPV"),
    "payment": ("BUSL", "ATHZ"),
    "admin": ("ATHZ", "ATHN", "CONF"),
    "login": ("ATHN", "SESS", "IDNT"),
    "s3": ("CONF",),
    "cloudfront": ("CONF",),
    "akamai": ("CONF",),
}


class WstgIndex:
    """Search over the indexed guide."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.source: dict[str, Any] = payload.get("source", {})
        self.tests: list[dict[str, Any]] = payload.get("tests", [])
        self._by_id = {t["id"]: t for t in self.tests}

    @property
    def available(self) -> bool:
        return bool(self.tests)

    def get(self, wstg_id: str) -> dict[str, Any] | None:
        return self._by_id.get(wstg_id.upper().strip())

    def phases(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for test in self.tests:
            counts[test["phase"]] = counts.get(test["phase"], 0) + 1
        return dict(sorted(counts.items()))

    def by_phase(self, phase: str) -> list[dict[str, Any]]:
        want = phase.lower().strip()
        return [t for t in self.tests if t["phase"] == want or t["category"].lower() == want]

    def search(self, query: str, limit: int = 12) -> list[dict[str, Any]]:
        """Rank tests by term overlap. Title and objectives weigh most."""
        terms = [t for t in re.split(r"\W+", query.lower()) if len(t) > 2]
        if not terms:
            return []
        scored: list[tuple[int, dict[str, Any]]] = []
        for test in self.tests:
            title = test["title"].lower()
            objectives = " ".join(test.get("objectives", [])).lower()
            body = (test.get("summary", "") + test.get("how_to_test", "")).lower()
            score = sum(
                8 * title.count(term) + 4 * objectives.count(term) + body.count(term)
                for term in terms
            )
            if score:
                scored.append((score, test))
        scored.sort(key=lambda pair: -pair[0])
        return [test for _, test in scored[:limit]]

    def for_stack(self, technologies: list[str], limit: int = 20) -> list[dict[str, Any]]:
        """Tests worth running against an observed technology stack."""
        wanted: list[str] = []
        for tech in technologies:
            low = tech.lower()
            for key, categories in STACK_HINTS.items():
                if key in low:
                    wanted.extend(categories)
        if not wanted:
            return []
        ranked = sorted(set(wanted), key=wanted.count, reverse=True)
        out: list[dict[str, Any]] = []
        for category in ranked:
            out.extend(t for t in self.tests if t["category"] == category)
        return out[:limit]


@lru_cache(maxsize=1)
def _cached(path: str) -> WstgIndex:
    file = Path(path)
    if not file.is_file():
        return WstgIndex({})
    return WstgIndex(json.loads(file.read_text(encoding="utf-8")))


def load_index(path: Path | None = None) -> WstgIndex:
    return _cached(str(path or INDEX_PATH))

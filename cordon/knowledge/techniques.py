"""PayloadsAllTheThings as data the agent can query.

The WSTG index answers *what to check* (115 named tests by phase). This answers
*how* — the concrete techniques, bypass tables and payload shapes a human
pentester reaches for when a scanner comes back clean. It is built by
``scripts/fetch_pat.py`` from a pinned commit of swisskyrepo/PayloadsAllTheThings
(MIT), with attribution travelling on every record.

Two things this deliberately is not:

* It is **retrieval, not automation.** A record says which bug class a technique
  belongs to, which Cordon tools test it, and which vetted payload lists and
  gf pattern packs correspond to it. Whether the technique applies to *this*
  target is a judgement no detector makes for you.
* It does **not** vendor PAT's raw payload files. Those are dense attack strings
  (RCE statements, reverse shells, third-party callbacks) and are handled by the
  vetted store in ``payloads/`` instead — the index only references the list
  *names* that vetting already classified.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = ["TechniqueIndex", "load_index"]

INDEX_PATH = Path(__file__).resolve().parent.parent.parent / "knowledge" / "pat" / "index.json"

#: Words too common to signal relevance. Without them, a title like "swap the
#: order id in the basket" scores "the" against a summary that mentions it ten
#: times and out-ranks the technique that actually matters.
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was",
    "were", "has", "have", "had", "not", "but", "its", "it", "you", "your",
    "can", "via", "into", "onto", "than", "then", "them", "they", "will",
    "would", "when", "what", "which", "there", "here", "how", "all", "any",
    "each", "both", "also", "been", "being", "does", "did", "done",
}

#: Technology or observation -> technique classes worth reading first. Keeps the
#: agent from walking all 63 records when http_probe already said what the
#: stack is.
STACK_HINTS: dict[str, tuple[str, ...]] = {
    "graphql": ("graphql-injection",),
    "jwt": ("json-web-token",),
    "oauth": ("oauth-misconfiguration",),
    "saml": ("saml-injection",),
    "rails": ("mass-assignment", "insecure-direct-object-references"),
    "ruby": ("mass-assignment",),
    "php": ("type-juggling", "file-inclusion", "server-side-include-injection"),
    "wordpress": ("file-inclusion", "sql-injection"),
    "java": ("insecure-deserialization", "java-rmi"),
    "nodejs": ("prototype-pollution", "nosql-injection"),
    "express": ("prototype-pollution",),
    "mongodb": ("nosql-injection",),
    "next.js": ("server-side-request-forgery", "prototype-pollution"),
    "react": ("client-side-path-traversal", "prototype-pollution"),
    "angular": ("dom-clobbering", "xss-injection"),
    "upload": ("upload-insecure-files", "zip-slip"),
    "s3": ("api-key-leaks",),
    "aws": ("api-key-leaks", "cloud-aws-pentest"),
    "azure": ("cloud-azure-pentest",),
    "kubernetes": ("api-key-leaks", "container-kubernetes-pentest"),
    "docker": ("container-docker-pentest",),
    "websocket": ("web-sockets",),
    "deserialization": ("insecure-deserialization",),
}


class TechniqueIndex:
    """Search over the indexed technique library."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.source: dict[str, Any] = payload.get("source", {})
        self.techniques: list[dict[str, Any]] = payload.get("techniques", [])
        self._by_class = {t["class"]: t for t in self.techniques}

    @property
    def available(self) -> bool:
        return bool(self.techniques)

    def get(self, class_name: str) -> dict[str, Any] | None:
        return self._by_class.get(class_name.strip().lower())

    def classes(self) -> list[str]:
        return sorted(self._by_class)

    def by_phase(self, phase: str) -> list[dict[str, Any]]:
        want = phase.strip().lower()
        return [t for t in self.techniques if t["phase"] == want]

    def for_tool(self, tool: str, limit: int = 12) -> list[dict[str, Any]]:
        want = tool.strip().lower()
        return [t for t in self.techniques if want in t.get("tools", [])][:limit]

    def search(self, query: str, limit: int = 12) -> list[dict[str, Any]]:
        """Rank techniques by term overlap. Title weighs most, then summary."""
        terms = [
            t for t in re.split(r"\W+", query.lower())
            if len(t) > 2 and t not in _STOPWORDS
        ]
        if not terms:
            return []
        scored: list[tuple[int, dict[str, Any]]] = []
        for tech in self.techniques:
            title = tech["title"].lower()
            cls = tech["class"].lower()
            summary = tech.get("summary", "").lower()
            keywords = " ".join(tech.get("keywords", [])).lower()
            score = sum(
                8 * title.count(term)
                + 10 * keywords.count(term)
                + 6 * cls.count(term)
                + 2 * summary.count(term)
                for term in terms
            )
            if score:
                scored.append((score, tech))
        scored.sort(key=lambda pair: -pair[0])
        return [tech for _, tech in scored[:limit]]

    def for_stack(self, technologies: list[str], limit: int = 20) -> list[dict[str, Any]]:
        """Techniques worth reading against an observed technology stack."""
        wanted: list[str] = []
        for tech in technologies:
            low = tech.lower()
            for key, classes in STACK_HINTS.items():
                if key in low:
                    wanted.extend(classes)
        if not wanted:
            return []
        ranked = sorted(set(wanted), key=wanted.count, reverse=True)
        out: list[dict[str, Any]] = []
        for cls in ranked:
            tech = self._by_class.get(cls)
            if tech is not None:
                out.append(tech)
        return out[:limit]


@lru_cache(maxsize=1)
def _cached(path: str) -> TechniqueIndex:
    file = Path(path)
    if not file.is_file():
        return TechniqueIndex({})
    return TechniqueIndex(json.loads(file.read_text(encoding="utf-8")))


def load_index(path: Path | None = None) -> TechniqueIndex:
    return _cached(str(path or INDEX_PATH))

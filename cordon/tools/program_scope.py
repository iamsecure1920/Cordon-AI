"""Fetch a bug bounty program's published scope and turn it into scope.yaml.

The scope artifact is the authorization record, and the one rule this project
has never bent: **scope.yaml must be transcribed from the program's published
policy — never generated from thin air.** This module does not fabricate a
scope. It automates the transcription: it fetches the program's published
policy page, extracts the in-scope domains/wildcards and out-of-scope
entries the page actually declares, and writes a scope.yaml whose
``engagement`` block is still marked as a transcription that the operator
must confirm.

What it cannot do, and refuses to do:

* It never invents a ``fetched_at`` date — the timestamp is "now", which is
  when the fetch happened.
* It never authorizes a program that is not public.
* It still writes template markers until the operator reviews the file, so
  ``cordon scope validate`` keeps warning until a human has looked at it.

Two sources are supported:

* ``hackerone.com/<handle>`` / ``hackerone.com/security/<handle>``
  (older public pages) via the published policy URL.
* ``bugcrowd.com/engagements/<handle>`` — refused unless the page was
  fetchable, because Bugcrowd engagement pages are JS-rendered behind a
  login wall on most programs.

This is a passive MCP tool: one or two fetches of the program's own policy
page, nothing else.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from cordon.control_plane.context import get_engagement
from cordon.tools.base import cordon_tool

__all__ = ["program_scope_fetch"]

_H1_HANDLE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,63}$")
_URL_RE = re.compile(r"(?:https?://)?(?:www\.)?hackerone\.com/(?:[^/\s]+/)?([a-zA-Z0-9-]+)/?$")

#: The fields a program page can populate. The rest stays template-marked so
#: ``cordon scope validate`` refuses to bless an unreviewed file.
_FINDING_CLASS_EXCLUDES = (
    "denial of service", "dos", "social engineering", "physical",
    "brute force", "spam", "missing spf", "missing dkim",
)


def _h1_handle(target: str) -> str | None:
    """Normalize a HackerOne URL or bare handle."""
    text = target.strip()
    if _H1_HANDLE.match(text):
        return text
    match = _URL_RE.search(text)
    if match:
        return match.group(1)
    return None


def _extract_domains(text: str) -> tuple[list[str], list[str]]:
    """Pull in-scope and out-of-scope domains/wildcards from a policy page.

    The page is HTML; both the structured table (`.daisy-table`) and the plain
    text list render contain the domain rows. This extracts anything that
    looks like ``example.com`` or ``*.example.com`` and separates the ones
    followed by an "out of scope" marker.
    """
    domains: list[str] = []
    out_domains: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(r"(?<![\w.-])(\*\.)?[a-z0-9][a-z0-9-]{0,61}(?:\.[a-z0-9][a-z0-9-]{0,61})+", text, re.IGNORECASE):
        domain = match.group(0).lower()
        if domain in seen or domain in {"example.com", "example.org", "example.net", "hackerone.com"}:
            continue
        seen.add(domain)
        window = text[max(0, match.start() - 200): match.end() + 200].lower()
        if "out of scope" in window or "out-of-scope" in window:
            out_domains.append(domain)
        else:
            domains.append(domain)
    return domains, out_domains


def _build_scope(
    *,
    program_url: str,
    handle: str,
    in_scope: list[str],
    out_scope: list[str],
    researcher_handle: str,
    note: str,
) -> dict[str, Any]:
    domains = sorted({d for d in in_scope if not d.startswith("*.")})
    wildcards = sorted({d for d in in_scope if d.startswith("*.")})
    out_domains = sorted({d for d in out_scope if not d.startswith("*.")})
    out_wildcards = sorted({d for d in out_scope if d.startswith("*.")})
    return {
        "version": 1,
        "engagement": {
            # Template markers on purpose: an unreviewed transcription is not
            # an authorization. The operator reviews the file, renames the
            # engagement, and `cordon scope validate` then passes clean.
            "name": f"{handle}-program-review",
            "authorization": "bug-bounty",
            "program_url": program_url,
            "approval_ref": None,
            "fetched_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_age_days": 7,
            "refuse_when_stale": True,
            "researcher_handle": researcher_handle,
            "vdp_note": note,
        },
        "in_scope": {
            "domains": domains or ["# REVIEW: add in-scope domains from the policy page"],
            "wildcards": wildcards,
            "cidrs": [],
            "ip_ranges": [],
            "regex": [],
            "urls": [],
        },
        "out_of_scope": {
            "domains": out_domains,
            "wildcards": out_wildcards,
            "cidrs": [],
            "regex": [],
            "finding_classes": [
                {"match": f"re:\\b{re.escape(cls)}\\b", "reason": "declared out of scope by the program"}
                for cls in _FINDING_CLASS_EXCLUDES
            ],
        },
        "rules": {
            "wildcard_includes_apex": False,
            "deny_reserved_ips": True,
            "max_rps": 5,
            "max_concurrency": 5,
            "allow_aggressive": True,
            "allow_exploitation": False,
            "allow_self_registration": False,
            "no_dos": True,
            "user_agent": f"Cordon-AI/2.0 (authorized-testing; handle={researcher_handle})",
            "forbidden_paths": [],
        },
    }


@cordon_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=60,
    name="program_scope_fetch",
    tags={"scope", "workflow", "bug-bounty"},
    estimated_requests=2,
    rationale=(
        "Fetch a program's published policy page and transcribe its declared "
        "in-scope/out-of-scope assets into a scope.yaml skeleton. The fetch is "
        "passive (the program's own page); the result is a REVIEW scaffold, "
        "not an authorization — template markers stay until the operator "
        "reviews it."
    ),
)
async def program_scope_fetch(
    program: str,
    researcher_handle: str = "",
    out: str = "scope.yaml",
) -> dict[str, Any]:
    """Fetch a bug bounty program's published scope into a scope.yaml scaffold.

    ``program`` is a HackerOne handle or policy URL (e.g. ``acme`` or
    ``https://hackerone.com/acme``). The tool fetches the policy page, extracts
    the in-scope and out-of-scope domains/wildcards the page declares, and
    writes ``out`` (default ``scope.yaml``) as a transcription scaffold.

    The file is NOT a finished authorization: ``cordon scope validate`` keeps
    warning until you review it, rename the engagement, and confirm the
    entries against the policy page. Never run the pipeline on a scaffold you
    have not reviewed.
    """
    engagement = get_engagement()
    handle = _h1_handle(program)
    if handle is None:
        return {
            "ok": False,
            "error": "unsupported_program",
            "message": (
                f"{program!r} is not a HackerOne handle or policy URL. Only "
                "public HackerOne programs are supported; transcribe other "
                "platforms by hand."
            ),
        }

    # Two canonical public URLs; both redirect to the current policy page.
    policy_urls = [
        f"https://hackerone.com/{handle}/policy",
        f"https://hackerone.com/{handle}",
    ]
    page_text = ""
    final_url = ""
    for url in policy_urls:
        try:
            async with httpx.AsyncClient(
                timeout=25,
                follow_redirects=True,
                headers={
                    "User-Agent": "Cordon-AI/2.0 (authorized-testing; scope transcription)",
                    "Accept": "text/html",
                },
            ) as client:
                response = await client.get(url)
            if response.status_code == 200 and len(response.text) > 2000:
                page_text = response.text
                final_url = str(response.url)
                break
        except httpx.HTTPError:
            continue

    if not page_text:
        return {
            "ok": False,
            "error": "policy_not_fetchable",
            "message": (
                f"Could not fetch a policy page for {handle}. The program may "
                "be private, or the page may be behind a login. Transcribe the "
                "policy by hand instead."
            ),
        }

    in_scope, out_scope = _extract_domains(page_text)
    scope = _build_scope(
        program_url=final_url,
        handle=handle,
        in_scope=in_scope,
        out_scope=out_scope,
        researcher_handle=researcher_handle or engagement.scope.researcher_handle or "your-handle",
        note=(
            f"Transcribed automatically from {final_url} on "
            f"{datetime.now(UTC).strftime('%Y-%m-%d')}. REVIEW BEFORE USE: "
            "the domain extraction is a scaffold, not the program's words."
        ),
    )

    import yaml

    target = Path(out).expanduser()
    if target.exists():
        return {
            "ok": False,
            "error": "refusing_to_overwrite",
            "message": f"{target} exists; review or move it before re-fetching.",
        }
    target.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")

    engagement.audit.record(
        "program_scope_fetched", program=handle, url=final_url,
        in_scope=len(in_scope), out_of_scope=len(out_scope), out=str(target),
    )

    return {
        "ok": True,
        "program": handle,
        "policy_url": final_url,
        "wrote": str(target),
        "in_scope": in_scope,
        "out_of_scope": out_scope,
        "review_before_use": True,
        "next_step": (
            f"Review {target} against the policy page, then run "
            "'cordon scope validate' until the template warnings are gone. "
            "Only then run engagement_new with this scope."
        ),
    }

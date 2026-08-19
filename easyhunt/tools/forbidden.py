"""403 access-control bypass testing via unKover (BruteLogic).

``forbidden_bypass`` runs unKover against a URL that returned 403 and files a
finding when one of its twelve proven bypass techniques turns it into a 2xx —
IP-header spoofing, method tampering/case, protocol headers, Referer trust,
path-normalization and encoding tricks, HTTP/1.0 downgrade, hop-by-hop header
smuggling, path suffix injection, and API version prefix/swap. unKover
calibrates against a wildcard baseline so a soft-404 isn't read as a bypass,
stops at the first success, and returns a ready-to-run curl PoC.

When to use it (the agent's cue): any URL that came back 403 from
``http_probe``, ``content_discovery``, or a nuclei hit. A 403 is an access
decision, and access decisions are the class of bug that reads as "not
vulnerable" until someone finds the route around them — which is exactly what
these techniques do. The companion ``forbidden_candidates`` pre-checks URLs so
you only feed real 403s (unKover refuses anything else).

The finding is filed ``needs_manual_review``: the technique is proven (2xx on
a 403 path, wildcard-calibrated), but whether it is a *vulnerability* depends
on what the path protects, so a human decides impact. Severity starts at
medium and escalates to high for admin-flavoured paths.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import URL_PATTERN, register_spec, run_one

log = logging.getLogger("easyhunt.tools.forbidden")

__all__ = ["forbidden_bypass", "forbidden_candidates"]

UNKOVER = register_spec(
    ToolSpec(
        name="unkover", binary="unkover", license="MIT",
        homepage="https://github.com/BruteLogic/unKover",
        version_args=["-q"],
        identity_marker="unKover",
        arg_policy=ArgPolicy(
            tool="unkover",
            allowed_flags={"--prefix", "-j", "--json", "-q", "--quiet"},
            boolean_flags={"-j", "--json", "-q", "--quiet"},
            # Version/API prefixes like /v2 or /api/v1 — path-ish, never a URL.
            value_patterns={"--prefix": re.compile(r"/[A-Za-z0-9._~/-]{0,64}")},
            allow_positional=True,
            positional_pattern=URL_PATTERN,
        ),
    )
)

#: Technique -> severity escalation. Base is medium; admin-flavoured targets
#: and methods that bypass real authz (not just WAF quirks) go up.
_TECHNIQUE_WEIGHT = {
    "ip_header_spoof": 1,   # trusting client-supplied IP headers is a real authz gap
    "header_override": 1,   # X-Original-URL / X-Rewrite-URL rewriting
    "api_version": 1,       # version prefix/swap reaching code that skipped authz
    "method_tampering": 0,  # method quirks are often framework behaviour
    "method_case": 0,
    "http10_bypass": 0,
}

_ADMIN_HINTS = (
    "admin", "dashboard", "internal", "console", "config", "debug",
    "manage", "panel", "staff", "backoffice", "api/v1", "api/v2", ".git",
)

_BRAIN_CLASS = "access-control-bypass"


def _parse_unkover_output(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse unKover's single-JSON-object stdout.

    Returns ``(parsed, None)`` on success or ``(None, error_key)`` where
    ``error_key`` is ``"unparseable_output"`` or ``"not_forbidden"`` (the
    tool's own preflight refusal).
    """
    try:
        parsed = json.loads(raw or "{}")
    except ValueError:
        return None, "unparseable_output"
    if not isinstance(parsed, dict):
        return None, "unparseable_output"
    if parsed.get("error"):
        return None, "not_forbidden"
    return parsed, None


def _escalate(url: str, technique: str) -> Severity:
    """Medium base; high when the technique is authz-relevant AND the path is admin-ish."""
    lower = url.lower()
    authz_relevant = _TECHNIQUE_WEIGHT.get(technique, 0) == 1
    admin_path = any(h in lower for h in _ADMIN_HINTS)
    if authz_relevant and admin_path:
        return Severity.HIGH
    return Severity.MEDIUM


@easyhunt_tool(
    phase="scan",
    mode="aggressive",
    targets_arg="url",
    timeout=300,
    name="forbidden_bypass",
    spec=UNKOVER,
    tags={"authz", "bypass", "access-control"},
    estimated_requests=120,
    rationale=(
        "Test a URL that returned 403 against twelve proven access-bypass "
        "techniques (unKover); a 2xx on a 403 path is a broken-access-control "
        "candidate with a ready PoC."
    ),
    risk_notes=(
        "Sends ~40-120 crafted requests (header spoofing, method and path "
        "variants) to the URL. 403-bypass testing is the access-control "
        "equivalent of a login bypass check — authorization state, not data.",
    ),
)
async def forbidden_bypass(url: str, prefix: str | None = None) -> dict[str, Any]:
    """Test a URL that returned 403 against twelve access-bypass techniques.

    ``url`` must be a URL that actually returned 403 (run ``forbidden_candidates``
    or check the probe result first — unKover refuses anything else).
    ``prefix`` optionally adds an API version prefix (``/v2``) that the server
    may not protect. Returns the first working technique with a curl PoC, or a
    clean report when nothing bypasses.
    """
    engagement = get_engagement()
    argv = [url, "-j"]
    if prefix:
        argv += ["--prefix", prefix]

    run = await run_one(
        "unkover", argv, timeout=240,
        # unKover emits one JSON object on stdout; keep it whole.
        extract=lambda r: [r.stdout],
    )
    if not run.ran:
        return {
            "ok": False,
            "error": "tool_unavailable",
            "message": f"unkover is not installed: {run.error}",
            "hint": "Install it with the unkover recipe ('easyhunt install'), then retry.",
        }

    parsed, parse_error = _parse_unkover_output(run.values[0] if run.values else "")
    if parse_error == "unparseable_output":
        return {
            "ok": False,
            "error": "unparseable_output",
            "message": f"unkover returned non-JSON output (exit {run.exit_code}): "
                        f"{(run.values[0] if run.values else '')[:300]}",
        }
    if parse_error == "not_forbidden":
        return {
            "ok": False,
            "error": "not_forbidden",
            "message": parsed.get("error") if parsed else "target did not return 403",
            "hint": "Feed forbidden_bypass only URLs that returned 403 — run "
                    "forbidden_candidates first.",
        }
    if parsed is None:
        return {"ok": False, "error": "unparseable_output",
                "message": "unkover returned no usable output."}

    bypass = bool(parsed.get("bypass"))
    findings = parsed.get("findings") or []
    technique = str(findings[0].get("technique") or "") if findings else ""
    baseline = parsed.get("baseline") or {}
    poc = parsed.get("poc")

    # The brain learns from every outcome — a bypass is a hit on this stack,
    # a clean pass is evidence the 403 is enforced properly.
    techs = [str(t) for t in engagement.assets.values("technology")][:10]
    engagement.brain.learn(
        vuln_class=_BRAIN_CLASS,
        technique="forbidden_bypass",
        outcome="hit" if bypass else "clean",
        technologies=techs,
        engagement=engagement.scope.name,
    )

    if not bypass:
        coverage = getattr(engagement, "coverage", None)
        if coverage is not None:
            coverage.record(_BRAIN_CLASS, "disproven", tool="forbidden_bypass",
                            note=f"12 techniques clean on {url}")
        return {
            "ok": True,
            "bypass": False,
            "url": url,
            "message": "No access-bypass technique worked — the 403 held against all 12.",
            "techniques_tested": 12,
            "baseline": baseline,
        }

    finding = Finding(
        asset=url,
        title=f"403 access-control bypass via {technique} ({_TECHNIQUE_LABEL(technique)})",
        phase="scan",
        severity=_escalate(url, technique),
        status=Status.NEEDS_MANUAL_REVIEW,
        description=(
            f"{url} returns 403 by default, but the '{technique}' bypass technique "
            f"turned it into HTTP {findings[0].get('result', {}).get('status')} "
            f"(wildcard-calibrated, so this is not a soft-404). If the path protects "
            "sensitive functionality, the access-control decision is bypassable — "
            "an attacker can reach it without authorization. "
            f"Request that worked: {findings[0].get('request', {})}."
        ),
        how_found=(
            "forbidden_bypass: unKover baseline 403, wildcard calibration done, "
            f"first successful technique '{technique}' returned "
            f"{findings[0].get('result', {}).get('status')}."
        ),
        source_tool="forbidden_bypass",
        rule_id=f"forbidden-bypass.{technique or 'unknown'}",
        confidence=0.75,
        evidence=[
            Evidence(
                kind="http",
                description=f"baseline HTTP {baseline.get('status')} on {url}",
                excerpt=f"size {baseline.get('size')} bytes",
            ),
            Evidence(
                kind="poc",
                description=f"bypass technique: {technique}",
                excerpt=poc or "",
            ),
        ],
        remediation=(
            "Enforce the authorization decision server-side from the authenticated "
            "identity, not from path normalization, method, or client-supplied "
            "headers (X-Forwarded-For/X-Original-URL must never grant access). "
            "Normalize paths and HTTP methods before routing, and reject unknown "
            "methods explicitly. Re-test with unKover after the fix."
        ),
        references=["https://github.com/BruteLogic/unKover"],
        tags=["access-control", "403-bypass", technique or "bypass"],
        extra={
            "technique": technique,
            "request": findings[0].get("request", {}),
            "baseline": baseline,
            "poc": poc,
        },
    )
    engagement.findings.add(finding)
    engagement.findings.save()

    coverage = getattr(engagement, "coverage", None)
    if coverage is not None:
        coverage.record(_BRAIN_CLASS, "detected", tool="forbidden_bypass",
                        note=f"{technique} bypassed {url}")

    return {
        "ok": True,
        "bypass": True,
        "url": url,
        "technique": technique,
        "poc": poc,
        "baseline": baseline,
        "result": findings[0].get("result", {}),
        "finding_id": finding.id,
        "severity": finding.severity.value,
        # feeds the audit's finding count (the dashboard's Tools view)
        "count": 1,
        "note": (
            "Technique proven (2xx on a 403 path) but impact depends on what the "
            "path protects — filed needs_manual_review for a human to confirm."
        ),
    }


def _TECHNIQUE_LABEL(technique: str) -> str:
    return technique.replace("_", " ")


@easyhunt_tool(
    phase="scan",
    mode="passive",
    targets_arg="urls",
    timeout=120,
    name="forbidden_candidates",
    tags={"authz", "discovery"},
    # One HEAD per URL in the batch — a pre-check still costs requests.
    estimated_requests=25,
    rationale=(
        "Which URLs are 403 and therefore worth feeding to forbidden_bypass — "
        "read-only, pre-checks URLs with a single HEAD each."
    ),
)
async def forbidden_candidates(urls: list[str]) -> dict[str, Any]:
    """Pre-check a list of URLs and return the ones that actually return 403.

    ``forbidden_bypass`` refuses anything that is not 403, so this is the
    pre-filter: one cheap HEAD per URL, returns the 403s. Give it URLs from
    ``http_probe`` or content discovery that looked interesting; it tells you
    which are worth the bypass pass. Read-only.
    """
    if not urls:
        return {"ok": True, "candidates": [], "checked": 0, "count": 0}

    import httpx as _httpx  # the Python client — this tool's own HTTP, not a catalog binary

    checked: list[dict[str, Any]] = []
    async with _httpx.AsyncClient(
        timeout=10.0, follow_redirects=False,
        # Deliberate: pre-checking may hit self-signed lab or internal hosts,
        # exactly like unkover's own curl -sk.
        verify=False,  # noqa: S501
    ) as client:
        for url in urls:
            try:
                r = await client.head(url)
            except Exception as exc:  # noqa: BLE001 — a dead URL is not a candidate
                log.debug("forbidden_candidates HEAD %s failed: %s", url, exc)
                continue
            checked.append({"url": url, "status": r.status_code})
    candidates = [c for c in checked if c["status"] == 403]
    return {
        "ok": True,
        "checked": len(checked),
        "count": len(candidates),
        "candidates": candidates,
        "note": "Feed these to forbidden_bypass — it refuses anything that is not 403.",
    }

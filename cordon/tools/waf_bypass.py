"""WAF identification and bypass payload lookup as MCP tools.

``waf_detect`` (wafw00f) names the vendor in front of a host and stops —
identifying a WAF is context, not a step toward evasion. These two tools are the
read-only other half: given a vendor (or a raw response to fingerprint), they
return the *ordered* bypass payload set for a vulnerability class, basic →
advanced, plus the encoding strategies that fit.

Nothing here sends a request. ``fingerprint_waf`` analyses a response the caller
already has; ``waf_bypass`` is a pure lookup against the tables in
:mod:`cordon.knowledge.waf`. The exploit chain consumes the result to re-fire
sqlmap/dalfox with vendor-tailored payloads *only when the base pass came back
clean* — the boundary between "look up what might work" (this module) and
"sending attack payloads" (the validators, behind the exploit gate) stays where
it has always been.
"""

from __future__ import annotations

from typing import Any, Literal

from cordon.knowledge import waf
from cordon.tools.base import cordon_tool

__all__ = ["waf_bypass", "fingerprint_waf", "waf_vendors"]


@cordon_tool(
    phase="exploit",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="waf_bypass",
    tags={"knowledge", "bypass"},
    estimated_requests=0,
    budget_exempt=True,
    rationale=(
        "Look up vendor-specific WAF bypass payloads for a vulnerability class — "
        "read-only knowledge, the data half of the exploit chain's bypass pass."
    ),
)
async def waf_bypass(
    vendor: str,
    vuln_class: Literal["xss", "sqli", "cmdi", "ssti", "ssrf", "path_traversal"] = "xss",
    level: Literal["all", "basic", "intermediate", "advanced"] = "all",
    max_payloads: int = 50,
) -> dict[str, Any]:
    """Ordered WAF-bypass payloads for (vendor, vuln_class), basic → advanced.

    ``vendor`` is a wafw00f display name ("Cloudflare", "Amazon Web Services
    (AWS) WAF") or a canonical key ("cloudflare", "aws_waf", "modsecurity").
    ``vuln_class`` is one of ``xss``, ``sqli``, ``cmdi``, ``ssti``, ``ssrf``,
    ``path_traversal``. ``level`` filters to ``basic`` / ``intermediate`` /
    ``advanced`` / ``all``.

    Read-only: returns text payloads tagged with technique + level, nothing is
    sent. Payloads are the *data* the exploit chain feeds its validators when a
    base pass was clean; calling this tool does not fire anything at a target.
    """
    vendor = (vendor or "").strip()
    vuln_class = (vuln_class or "").strip().lower()
    if not vendor:
        return {"ok": False, "error": "no_vendor", "message": "vendor is required"}
    known = set(waf.WAF_BYPASSES) | set(waf.VENDOR_ALIASES)
    if waf._normalize_vendor(vendor) not in waf.WAF_BYPASSES and vendor.lower() not in known:
        return {
            "ok": False,
            "error": "unknown_vendor",
            "message": f"{vendor!r} is not a known WAF vendor; use '_generic' for "
            "universal bypasses. Known: " + ", ".join(sorted(waf.WAF_BYPASSES)),
        }
    payloads = waf.bypass_payloads(vendor, vuln_class, level, max_payloads=max_payloads)
    if not payloads:
        return {
            "ok": True,
            "vendor": vendor,
            "vuln_class": vuln_class,
            "level": level,
            "count": 0,
            "payloads": [],
            "encodings": waf.encoding_strategies(vuln_class),
            "note": (
                f"No payloads for {vuln_class!r} — try 'xss', 'sqli', 'cmdi', "
                "'ssti', 'ssrf' or 'path_traversal'."
            ),
        }
    return {
        "ok": True,
        "vendor": vendor,
        "vuln_class": vuln_class,
        "level": level,
        "count": len(payloads),
        "payloads": payloads,
        "encodings": waf.encoding_strategies(vuln_class),
        "note": (
            "Ordered basic → advanced. Try the basic set first; escalate to "
            "intermediate/advanced with an encoding strategy only when the base "
            "pass was blocked. Feeding these to a validator is exploitation and "
            "stays behind the exploit gate."
        ),
    }


@cordon_tool(
    phase="exploit",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="fingerprint_waf",
    tags={"knowledge", "bypass"},
    estimated_requests=0,
    budget_exempt=True,
    rationale=(
        "Identify the WAF vendor from a response the caller already captured — "
        "header/body/status signature matching, no request is made."
    ),
)
async def fingerprint_waf(
    headers: dict[str, str],
    body: str = "",
    status_code: int = 403,
) -> dict[str, Any]:
    """Identify the WAF vendor from response headers, body, and status code.

    ``headers`` is a dict of response headers (``{"server": "...", "cf-ray": ...}``).
    Pass the block page as ``body`` when you have one — the markers there are
    often the only signal. Returns matches sorted by confidence; an empty list
    means no signature reached threshold (no WAF, an unknown one, or a
    transparent one that never modifies responses).
    """
    matches = waf.fingerprint_waf(headers or {}, body or "", int(status_code))
    return {
        "ok": True,
        "count": len(matches),
        "matches": matches,
        "primary": matches[0]["waf"] if matches else None,
        "note": (
            "Matches are scored by evidence weight (headers/Server = 3, body "
            "pattern = 2, block marker = 1, status = 1). Below ~37 confidence "
            "is block-page noise, not a vendor call. Feed the primary vendor to "
            "waf_bypass to get its payload set."
        ),
    }


@cordon_tool(
    phase="exploit",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="waf_vendors",
    tags={"knowledge"},
    estimated_requests=0,
    budget_exempt=True,
    rationale="List the WAF vendors the fingerprint DB and bypass tables cover.",
)
async def waf_vendors() -> dict[str, Any]:
    """List supported WAF vendors with the classes each has bypass payloads for."""
    rows: list[dict[str, Any]] = []
    for vendor in sorted(waf.WAF_BYPASSES):
        if vendor == "_generic":
            continue
        classes = sorted(waf.WAF_BYPASSES[vendor])
        rows.append({"vendor": vendor, "classes": classes})
    return {
        "ok": True,
        "count": len(rows),
        "vendors": rows,
        "aliases": waf.vendor_aliases(),
        "note": (
            "Use waf_bypass(vendor, vuln_class) to get the ordered payload set. "
            "Vendors without a class entry fall back to the generic table."
        ),
    }

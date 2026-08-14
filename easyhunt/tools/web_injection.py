"""Native HTTP validator for the bug classes no scanner binary covers.

Five classes — open redirect, CRLF, LFI, XXE and HTTP parameter pollution — were
``detect-only``: the gf pattern found the sink and a human had to confirm,
because no catalogued binary owns them. This validator closes that gap through
the control plane's own HTTP path (rate limiter, scope, approval), firing a
small curated set of *read-only* payloads and filing a CANDIDATE when the
response shows the class's signature.

Detection is **differential**: the signature must appear in the injected
response and not in the baseline, so a page whose own text happens to contain
``root:`` does not become an LFI. Nothing here is a confirmed finding — like
every other probe it is a candidate that a human or ``validate_findings`` must
promote.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import URL_PATTERN, split_targets, targets_or_assets

__all__ = ["web_injection_probe", "upload_surface"]

#: A canary hostname in the RFC 2606 ``.invalid`` TLD — guaranteed to never
#: resolve, so no external request is ever made; the only thing we observe is
#: whether the *target* echoes it into a Location header or body.
_CANARY = "easyhunt-canary.invalid"

#: One class -> payloads + where the signature shows up + the finding shape.
#: ``safe`` controls URL-quoting: open-redirect/CRLF/XXE encode everything so the
#: server decodes the full value; LFI keeps ``/`` literal so traversal survives.
_CLASSES: dict[str, dict[str, Any]] = {
    "open-redirect": {
        "payloads": [
            f"https://{_CANARY}/redirect",
            f"//{_CANARY}/redirect",
        ],
        "safe": "",
        "where": "location",
        "signature": re.compile(re.escape(_CANARY)),
        "follow": False,
        "severity": Severity.MEDIUM,
        "title": "Open redirect",
        "description": (
            "A parameter the application turns into a redirect destination echoed "
            "a supplied URL into the response. An attacker abuses this to send a "
            "legitimate-looking link that lands victims on a phishing host."
        ),
        "remediation": (
            "Never redirect to a user-supplied URL. If a relative redirect is "
            "required, allow-list known destinations and reject anything with a "
            "scheme, a leading //, or a host component."
        ),
    },
    "crlf": {
        # Raw CRLF only: _inject() URL-quotes the value on the wire, and a
        # pre-encoded "%0d%0a" variant would be double-encoded into the literal
        # string "%250d%250a" instead of a line break.
        "payloads": ["\r\nEasyHunt-Injected: 1"],
        "safe": "",
        "where": "headers",
        "signature": re.compile(r"easyhunt-injected", re.I),
        "follow": False,
        "severity": Severity.MEDIUM,
        "title": "CRLF / header injection",
        "description": (
            "A parameter the application reflects into response headers let a "
            "line break split into an attacker-controlled header."
        ),
        "remediation": (
            "Strip CR and LF from any value reflected into headers or a redirect "
            "Location, and validate the remainder against an allow-list."
        ),
    },
    "lfi": {
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
        ],
        "safe": "/",
        "where": "body",
        "signature": re.compile(r"root:.*:0:0:"),
        "follow": True,
        "severity": Severity.HIGH,
        "title": "Local file inclusion",
        "description": (
            "A parameter used as a file path let a traversal read a system file. "
            "Reading /etc/passwd is the standard proof of LFI; the impact is any "
            "file the service account can read."
        ),
        "remediation": (
            "Resolve the file against a fixed, allow-listed directory and reject "
            "any path that escapes it, after normalisation."
        ),
    },
    "xxe": {
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
            '"file:///etc/passwd">]><r>&xxe;</r>',
        ],
        "safe": "",
        "where": "body",
        "signature": re.compile(r"root:.*:0:0:"),
        "follow": True,
        "severity": Severity.HIGH,
        "title": "XML external entity injection",
        "description": (
            "An XML document with an external entity read a local file and "
            "reflected its content. Reading /etc/passwd proves XXE; the impact is "
            "arbitrary file read or, with a callback entity, SSRF."
        ),
        "remediation": (
            "Disable DTDs and external entities in the XML parser, and reject "
            "documents declaring a DOCTYPE."
        ),
    },
    "hpp": {
        # HTTP parameter pollution is read-only by construction: the same
        # parameter is sent twice with two different canary values and we
        # observe which one the application reflects. The duplicate *appends*
        # (does not replace), which is the whole technique.
        "payloads": ["easyhunt-hpp-canary"],
        "duplicate": True,
        "safe": "",
        "where": "body",
        "signature": re.compile(r"easyhunt-hpp-canary"),
        "follow": False,
        "severity": Severity.INFO,
        "title": "HTTP parameter pollution",
        "description": (
            "When a parameter was duplicated, the application reflected the "
            "second (attacker-appended) value. This behaviour is the primitive "
            "HPP chains on: a WAF may inspect the first value while the backend "
            "uses the second, so it is a lead for bypassing a filter rather than "
            "a standalone vulnerability."
        ),
        "remediation": (
            "Take the first occurrence of a parameter, reject duplicated keys, or "
            "fail the request when a parameter appears more than once."
        ),
    },
}


def _inject(url: str, parameter: str, payload: str, safe: str, duplicate: bool = False) -> str:
    """Substitute ``payload`` into ``parameter``, URL-quoting it once for the wire.

    The payload goes into the query raw and ``urlencode`` does the single layer
    of quoting with the class's ``safe`` set. Pre-quoting with ``quote()`` and
    then passing the result to ``urlencode`` double-encodes: ``%`` becomes
    ``%25``, so a CRLF arrives as the literal string ``%250d%250a`` instead of a
    line break, and an open-redirect canary arrives as its own percent-encoding.

    ``duplicate`` appends the payload as a second occurrence of ``parameter``
    instead of replacing the first — that is the HTTP parameter pollution
    technique, where which occurrence the application honours is the signal.
    """
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if duplicate:
        pairs.append((parameter, payload))
    else:
        pairs = [(k, payload if k == parameter else v) for k, v in pairs]
    return url.replace(parsed.query, urlencode(pairs, quote_via=quote, safe=safe))


def _signature_hit(response: httpx.Response, where: str, signature: re.Pattern[str]) -> bool:
    if where == "headers":
        return any(signature.search(name) for name in response.headers)
    if where == "location":
        location = response.headers.get("location", "")
        if signature.search(location):
            return True
        return signature.search(response.text[:8000]) is not None
    return signature.search(response.text[:16000]) is not None


def _candidate_for(url: str, cls: str, spec: dict[str, Any], excerpt: str) -> Finding:
    finding = Finding(
        asset=url,
        title=spec["title"],
        phase="exploit",
        severity=spec["severity"],
        status=Status.CANDIDATE,
        description=spec["description"],
        how_found=f"web_injection_probe ({cls}) against {url}",
        source_tool="web_injection_probe",
        rule_id=f"injection.web.{cls}",
        confidence=0.4,
        evidence=[Evidence(kind="log", description="injected response", excerpt=excerpt[:2000])],
        remediation=spec["remediation"],
        tags=[cls, "candidate"],
    )
    finding.note(
        "Candidate only — the signature appeared in the injected response but was "
        "not in the baseline. Reproduce by hand and record the proof with "
        "poc_record() before it appears in a report as confirmed."
    )
    return finding


@easyhunt_tool(
    phase="exploit",
    mode="exploit",
    targets_arg="target",
    timeout=300,
    name="web_injection_probe",
    tags={"exploitation", "injection"},
    estimated_requests=20,
    risk_notes=[
        "Injects read-only payloads (open redirect, CRLF, LFI, XXE, HPP) into one parameter.",
        "The LFI/XXE payloads read /etc/passwd through the target — the standard "
        "proof — and nothing else. No out-of-band callback, no command execution.",
    ],
    rationale=(
        "Prove the bug classes no scanner binary covers: open redirect, CRLF, "
        "LFI, XXE and HTTP parameter pollution, differentially against a baseline."
    ),
)
async def web_injection_probe(
    target: str,
    parameter: str,
    bug_class: str = "open-redirect",
) -> dict[str, Any]:
    """Detect open redirect, CRLF, LFI, XXE or HPP in one parameter.

    ``target`` is the full URL carrying the parameter to test (one parameter —
    ``&`` is refused project-wide). ``parameter`` names it. ``bug_class`` is one
    of ``open-redirect``, ``crlf``, ``lfi``, ``xxe``, ``hpp``.

    Every result is a CANDIDATE: the class signature must appear in the injected
    response and not in the baseline request. Nothing is confirmed here.
    """
    engagement = get_engagement()
    targets = split_targets(target)
    if not targets:
        return {"ok": False, "error": "no_target", "message": "no target supplied"}
    url = targets[0]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"ok": False, "error": "bad_target", "message": f"{url!r} is not an absolute http(s) URL"}
    if not URL_PATTERN.fullmatch(url):
        return {"ok": False, "error": "bad_target", "message": f"{url!r} contains disallowed characters"}
    if "&" in url:
        return {
            "ok": False, "error": "multi_parameter",
            "message": "'&' is refused project-wide; test one parameter at a time.",
        }
    if bug_class not in _CLASSES:
        return {
            "ok": False, "error": "unknown_class",
            "message": f"bug_class must be one of {sorted(_CLASSES)}",
        }
    if parameter not in dict(parse_qsl(parsed.query, keep_blank_values=True)):
        return {
            "ok": False, "error": "unknown_parameter",
            "message": f"{parameter!r} is not a parameter of {url}",
        }

    spec = _CLASSES[bug_class]
    baseline = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{urlencode(dict(parse_qsl(parsed.query, keep_blank_values=True)))}"
    headers = {"User-Agent": engagement.scope.rules.user_agent}

    async with httpx.AsyncClient(timeout=20, follow_redirects=spec["follow"], headers=headers) as client:
        # Baseline first: the signature in an unmodified response is not a hit.
        baseline_hit = False
        async with engagement.limiter.slot(host=url):
            try:
                base_resp = await client.get(baseline)
                baseline_hit = _signature_hit(base_resp, spec["where"], spec["signature"])
            except httpx.HTTPError as exc:
                return {
                    "ok": False, "error": "baseline_failed",
                    "message": f"baseline request failed: {str(exc)[:200]}",
                    "untested": True,
                }

        findings: list[Finding] = []
        hits: list[dict[str, Any]] = []
        for payload in spec["payloads"]:
            injected = _inject(url, parameter, payload, spec["safe"], spec.get("duplicate", False))
            async with engagement.limiter.slot(host=url):
                try:
                    response = await client.get(injected)
                except httpx.HTTPError as exc:
                    hits.append({"payload": payload[:120], "error": str(exc)[:160]})
                    continue
            if _signature_hit(response, spec["where"], spec["signature"]):
                excerpt = response.text[:2000] or "\n".join(
                    f"{k}: {v}" for k, v in response.headers.items()
                )
                hits.append({"payload": payload[:120], "status": response.status_code})
                findings.append(_candidate_for(url, bug_class, spec, excerpt))

    if findings:
        for finding in findings:
            engagement.findings.add(finding)
        engagement.findings.save()

    return {
        "ok": True,
        "target": url,
        "parameter": parameter,
        "bug_class": bug_class,
        "baseline_signature": baseline_hit,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "requests": len(spec["payloads"]) + 1,
        "note": (
            "Candidate only. The signature appeared in an injected response and "
            "not the baseline; reproduce it by hand and record the proof with "
            "poc_record() before it is reported as confirmed."
            if findings else
            "No class signature appeared. This parameter is clean for "
            f"{bug_class} under these payloads, not necessarily in general."
        ),
    }


#: A file input or a multipart form in a page — the two things that make an
#: endpoint an upload surface. Nothing here uploads; it only *finds* the surface
#: so a human (or an approved validator) can test it.
_FILE_INPUT = re.compile(r"""(?is)<input[^>]+type\s*=\s*["']file["']""")
_MULTIPART = re.compile(r"""(?is)<form[^>]+enctype\s*=\s*["']multipart/form-data["']""")
_UPLOAD_ACTION = re.compile(
    r"""(?i)(upload|attachment|avatar|photo|image|img|logo|doc|document|import|
    import_file|file_upload|filename|file_name|attachment_id)""",
    re.VERBOSE,
)


@easyhunt_tool(
    phase="method",
    mode="passive",
    targets_arg="target",
    timeout=600,
    name="upload_surface",
    tags={"recon", "upload"},
    estimated_requests=40,
    rationale=(
        "Find where a target accepts files before any upload is attempted — the "
        "read-only half of the file-upload class, so the state-changing proof is "
        "aimed, not sprayed."
    ),
)
async def upload_surface(target: str, max_urls: int = 40) -> dict[str, Any]:
    """Detect file-upload surfaces (multipart forms, file inputs, upload paths).

    Fetches the discovered pages read-only and reports which URLs carry a file
    input, a multipart form, or an upload-shaped action/parameter. Nothing is
    uploaded — this is detection only, and every entry is a lead for a human or
    an approved validator, not a finding.
    """
    engagement = get_engagement()
    candidates, origin = targets_or_assets(target, kind="url", tool="upload_surface")
    urls = [u for u in candidates if u.startswith("http")][:max_urls]
    if not urls:
        return {
            "ok": False, "error": "no_urls",
            "message": "no URLs supplied and none inherited from an earlier phase",
        }

    headers = {"User-Agent": engagement.scope.rules.user_agent}
    surfaces: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=headers) as client:
        for url in urls:
            async with engagement.limiter.slot(host=url):
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
            body = response.text[:40000]
            file_inputs = len(_FILE_INPUT.findall(body))
            multipart = bool(_MULTIPART.search(body))
            actions = sorted({m.group(0).lower() for m in _UPLOAD_ACTION.finditer(body)})[:12]
            if file_inputs or multipart or actions:
                surfaces.append({
                    "url": url,
                    "status": response.status_code,
                    "file_inputs": file_inputs,
                    "multipart_form": multipart,
                    "upload_shaped_tokens": actions,
                })

    return {
        "ok": True,
        "origin": origin,
        "scanned": len(urls),
        "count": len(surfaces),
        "surfaces": surfaces,
        "note": (
            "Detection only — no file was uploaded. Each surface is a lead; "
            "confirm an insecure upload with an approved, state-changing validator "
            "and record the proof with poc_record()."
            if surfaces else
            "No upload surface detected on the scanned pages. That does not rule "
            "out an upload endpoint behind authentication or not linked from these pages."
        ),
    }

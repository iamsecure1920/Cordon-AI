"""Vulnerability-class coverage: what EasyHunt can find, confirm, and bypass.

The one question a client asks before a test is "will you find the thing that
hurts me". The WSTG index answers *what to check* and the technique index
answers *how to check it*; this answers *is the path actually wired end to
end* — detection → validation → payloads → bypass — for every bug class.

Each row states a status, deliberately in three honest grades:

* ``auto``        — a validator binary actually confirms the bug (sqlmap proves
  the injection, dalfox proves the XSS). A scanner hit can be turned into a
  reproducible PoC without leaving the tool.
* ``detect-only`` — the class is *found* (gf pattern, content discovery, a
  technique) but nothing here proves it. A hit is a lead that a human must
  confirm, or a validator still needs building.
* ``manual``      — the class is inherently judgement-shaped (IDOR, business
  logic, cache poisoning, race conditions). Detection is model-driven via
  ``hunt_plan``/``authz_compare`` and a human decides; no scanner can own it.

This is the honest version of "are we complete". A class listed ``detect-only``
or ``manual`` is not missing — it is *named*, with what would close the gap, so
it cannot be silently skipped.
"""

from __future__ import annotations

from typing import Any

__all__ = ["CoverageIndex", "COVERAGE", "load_coverage"]

#: One row per bug class a client engagement is expected to cover. ``class``
#: matches the technique index slug where the two overlap; ``payloads`` names
#: vetted-store filenames; ``bypass`` names the PAT technique holding the
#: bypass tables for that class.
COVERAGE: list[dict[str, Any]] = [
    {
        "class": "sql-injection", "title": "SQL Injection", "phase": "input_validation",
        "detection": "gf:sqli + pattern_scan", "validation": "sqli_validate (sqlmap)",
        "payloads": ["allsqli.txt", "blindsqli.txt"], "gf": ["sqli"], "status": "auto",
        "bypass": "sql-injection",
        "note": "Payload lists are vetted tier B but sqlmap takes no wordlist, so they are reference-only.",
    },
    {
        "class": "xss-injection", "title": "Cross-Site Scripting", "phase": "client_side",
        "detection": "gf:xss + pattern_scan", "validation": "xss_validate (dalfox, xsstrike)",
        "payloads": ["xsspollygots.txt", "xsswafbypss.txt", "vulJs.txt"], "gf": ["xss"], "status": "auto",
        "bypass": "xss-injection",
        "note": "dalfox consumes the three payload lists via --custom-payload. DOM XSS needs chromium, which the image ships.",
    },
    {
        "class": "server-side-request-forgery", "title": "SSRF", "phase": "input_validation",
        "detection": "gf:ssrf + pattern_scan", "validation": "ssrf_probe (ssrfmap)",
        "payloads": ["ssrf.txt"], "gf": ["ssrf"], "status": "auto",
        "bypass": "server-side-request-forgery",
    },
    {
        "class": "server-side-template-injection", "title": "SSTI", "phase": "input_validation",
        "detection": "gf:ssti + pattern_scan", "validation": "ssti_probe (sstimap)",
        "payloads": ["ssti.txt"], "gf": ["ssti"], "status": "auto",
        "bypass": "server-side-template-injection",
    },
    {
        "class": "command-injection", "title": "Command Injection", "phase": "input_validation",
        "detection": "gf:rce + pattern_scan", "validation": "cmdi_probe (commix)",
        "payloads": [], "gf": ["rce"], "status": "auto",
        "bypass": "command-injection",
    },
    {
        "class": "nosql-injection", "title": "NoSQL Injection", "phase": "input_validation",
        "detection": "technique + parameter review", "validation": "nosqli_probe (nosqli)",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "nosql-injection",
    },
    {
        "class": "request-smuggling", "title": "HTTP Request Smuggling", "phase": "session",
        "detection": "technique", "validation": "smuggling_probe + smuggling_canary_probe (smuggler)",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "request-smuggling",
        "note": "Desync probes are malformed by construction; never run outside the authorised window.",
    },
    {
        "class": "subdomain-takeover", "title": "Subdomain Takeover", "phase": "recon",
        "detection": "takeover_detect (subzy, subjack, subdominator, dnsreaper)",
        "validation": "takeover_verify + takeover_confirm",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "virtual-hosts",
    },
    {
        "class": "cors-misconfiguration", "title": "CORS Misconfiguration", "phase": "configuration",
        "detection": "cors_audit (corscanner)", "validation": "cors_audit (reachability to authed data is the proof)",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "cors-misconfiguration",
    },
    {
        "class": "json-web-token", "title": "JWT Attacks", "phase": "session",
        "detection": "jwt_inspect (decode)", "validation": "jwt_inspect (jwt_tool forge modes)",
        "payloads": ["jwt-secrets.txt"], "gf": [], "status": "auto",
        "bypass": "json-web-token",
        "note": "Decode is detection; --forge/--replay are exploitation and sit behind the approval gate.",
    },
    {
        "class": "graphql-injection", "title": "GraphQL Abuse", "phase": "api",
        "detection": "graphql_audit (graphql-cop)", "validation": "graphql_audit",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "graphql-injection",
    },
    {
        "class": "web-sockets", "title": "WebSocket Testing", "phase": "api",
        "detection": "websocket_probe (websocat)", "validation": "websocket_probe",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "web-sockets",
    },
    {
        "class": "secrets", "title": "API Keys / Token Leaks", "phase": "recon",
        "detection": "secret_scan (trufflehog, gitleaks, noseyparker, kingfisher)",
        "validation": "secret_validate (is the key live and what does it reach)",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "api-key-leaks",
    },
    {
        "class": "tls", "title": "TLS / SSL", "phase": "configuration",
        "detection": "tls_audit (testssl)", "validation": "tls_audit",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "insecure-randomness",
    },
    {
        "class": "insecure-direct-object-references", "title": "IDOR / Broken Access Control", "phase": "authorization",
        "detection": "gf:idor + hunt_plan (object-reference candidates)",
        "validation": "authz_compare (two identities) — model-driven",
        "payloads": [], "gf": ["idor"], "status": "manual",
        "bypass": "insecure-direct-object-references",
        "note": "Needs two authenticated identities of different privilege; hunt_plan names the candidates, a human or the agent drives authz_compare.",
    },
    {
        "class": "business-logic-errors", "title": "Business Logic (coupons, money movement, step bypass)", "phase": "business_logic",
        "detection": "hunt_plan + auth_crawl (multi-step flow mapping)",
        "validation": "manual / model-driven — no scanner owns this",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "business-logic-errors",
    },
    {
        "class": "xxe-injection", "title": "XXE", "phase": "input_validation",
        "detection": "technique + parameter review", "validation": "web_injection_probe (xxe)",
        "payloads": ["xml.txt"], "gf": [], "status": "auto",
        "bypass": "xxe-injection",
        "note": "Native read-only probe: a DOCTYPE entity reading /etc/passwd, reflected. No out-of-band callback.",
    },
    {
        "class": "crlf-injection", "title": "CRLF Injection", "phase": "input_validation",
        "detection": "technique + parameter review", "validation": "web_injection_probe (crlf)",
        "payloads": ["crlf.txt"], "gf": [], "status": "auto",
        "bypass": "crlf-injection",
        "note": "Native probe: an injected CRLF header must appear in the response headers.",
    },
    {
        "class": "file-inclusion", "title": "LFI / Path Traversal", "phase": "input_validation",
        "detection": "gf:lfi + ffuf (traversal-unix/win)", "validation": "web_injection_probe (lfi)",
        "payloads": ["directory_traversal_unix.txt", "directory_traversal_win.txt", "lfi.txt"], "gf": ["lfi"], "status": "auto",
        "bypass": "file-inclusion",
        "note": "Native probe reads /etc/passwd through a traversal, differentially against a baseline.",
    },
    {
        "class": "open-redirect", "title": "Open Redirect", "phase": "input_validation",
        "detection": "gf:redirect + pattern_scan", "validation": "web_injection_probe (open-redirect)",
        "payloads": [], "gf": ["redirect"], "status": "auto",
        "bypass": "open-redirect",
        "note": "Native probe: a .invalid canary URL must appear in the Location header or body.",
    },
    {
        "class": "http-parameter-pollution", "title": "HTTP Parameter Pollution", "phase": "input_validation",
        "detection": "param_discovery (arjun) + gf", "validation": "web_injection_probe (hpp)",
        "payloads": [], "gf": [], "status": "auto",
        "bypass": "http-parameter-pollution",
        "note": "Native read-only probe: the parameter is duplicated with a canary and the app reflecting the second value is the HPP primitive.",
    },
    {
        "class": "upload-insecure-files", "title": "File Upload", "phase": "input_validation",
        "detection": "gf:upload + upload_surface (live form/field detection)", "validation": "manual — proof requires uploading a file",
        "payloads": [], "gf": ["upload"], "status": "manual",
        "bypass": "upload-insecure-files",
        "note": "Detecting the upload surface is now read-only and automatic; confirming an insecure upload is state-changing and stays behind the approval gate.",
    },
    {
        "class": "insecure-deserialization", "title": "Insecure Deserialization", "phase": "input_validation",
        "detection": "technique + stack fingerprint", "validation": "none — ysoserial-class payloads not integrated",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "insecure-deserialization",
    },
    {
        "class": "cross-site-request-forgery", "title": "CSRF", "phase": "session",
        "detection": "auth_crawl (token presence/absence)", "validation": "manual",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "cross-site-request-forgery",
    },
    {
        "class": "web-cache-deception", "title": "Web Cache Poisoning / Deception", "phase": "session",
        "detection": "technique + header review", "validation": "none — no validator",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "web-cache-deception",
    },
    {
        "class": "race-condition", "title": "Race Condition", "phase": "business_logic",
        "detection": "hunt_plan (multi-step flows)", "validation": "none — no concurrency harness",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "race-condition",
    },
    {
        "class": "mass-assignment", "title": "Mass Assignment", "phase": "authorization",
        "detection": "hunt_plan (API schema review)", "validation": "manual / model-driven",
        "payloads": [], "gf": [], "status": "manual",
        "bypass": "mass-assignment",
    },
]


class CoverageIndex:
    """Query the coverage matrix."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self._by_class = {r["class"]: r for r in rows}

    @property
    def available(self) -> bool:
        return bool(self.rows)

    def all(self) -> list[dict[str, Any]]:
        return list(self.rows)

    def get(self, class_name: str) -> dict[str, Any] | None:
        return self._by_class.get(class_name.strip().lower())

    def by_status(self, status: str) -> list[dict[str, Any]]:
        want = status.strip().lower()
        return [r for r in self.rows if r["status"] == want]

    def gaps(self) -> list[dict[str, Any]]:
        """Classes that are not auto-validated — the ones to watch for."""
        return [r for r in self.rows if r["status"] != "auto"]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return dict(sorted(counts.items()))


def load_coverage() -> CoverageIndex:
    """The coverage matrix is static, curated data — no file to fetch."""
    return CoverageIndex(COVERAGE)

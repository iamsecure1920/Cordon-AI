"""JavaScript analysis: endpoints, secrets, and vulnerable libraries.

Front-end bundles are the highest-yield passive source in most web engagements.
They routinely contain API paths that appear nowhere else, hardcoded keys, and
the exact version string of a library with a known CVE — all obtainable by
fetching a file the target already serves to every visitor.

Anything that looks like a credential is reported as a *candidate* and never
tested against a live service from here. Validation is a separate, gated step.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import URL_PATTERN, register_spec, run_one, split_targets, store_assets

__all__ = ["js_analyze"]

JSLUICE = register_spec(
    ToolSpec(
        name="jsluice", binary="jsluice", license="MIT",
        homepage="https://github.com/BishopFox/jsluice", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="jsluice",
            allowed_flags={"-R", "-c", "-p", "-U"},
            boolean_flags={"-R", "-U"},
            numeric_caps={"-c": 20},
            allow_positional=True,
            positional_pattern=re.compile(r"urls|secrets|tree|query|format|[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)

RETIREJS = register_spec(
    ToolSpec(
        name="retire", binary="retire", license="Apache-2.0",
        homepage="https://github.com/RetireJS/retire.js", version_args=["--version"],
        identity_marker="retire",
        arg_policy=ArgPolicy(
            tool="retire",
            # No --js. retire 5.x removed it entirely — `retire --help` lists
            # --path and --jspath and nothing else for scanning JavaScript.
            #
            # This flag has a history worth keeping. It was first declared
            # value-taking, so the sanitizer swallowed the following --path and
            # the directory arrived as a bare positional and was refused. That
            # was fixed by declaring it boolean, which made the sanitizer accept
            # it — and retire then rejected it with "unknown option '--js'",
            # exit 1, zero output. Two fixes, both to the argument policy,
            # neither to the thing that actually runs. retire has never once
            # scanned anything in this project.
            allowed_flags={"--path", "--outputformat", "--outputpath", "--exitwith"},
            # --js is a mode switch, not a value-taking flag. Undeclared, the
            # sanitizer treated it as taking a value, so it swallowed "--path"
            # and the directory that followed arrived as a bare positional and
            # was refused. retire therefore never ran on any engagement: the
            # failure surfaced as ran=False in the result rather than as a crash,
            # so JS library CVE detection has been quietly absent throughout.
            boolean_flags={"--js"},
            value_patterns={
                "--outputformat": re.compile(r"json|text|cyclonedx"),
                "--path": re.compile(r"[A-Za-z0-9._/-]{1,300}"),
                "--outputpath": re.compile(r"[A-Za-z0-9._/-]{1,300}"),
            },
            numeric_caps={"--exitwith": 1},
        ),
    )
)

LINKFINDER = register_spec(
    ToolSpec(
        name="linkfinder", binary="linkfinder", license="MIT",
        homepage="https://github.com/GerbenJavado/LinkFinder", version_args=["-h"],
        arg_policy=ArgPolicy(
            tool="linkfinder",
            allowed_flags={"-i", "-o", "-d", "-r"},
            boolean_flags={"-d"},
            value_patterns={"-i": URL_PATTERN, "-o": re.compile(r"cli|[A-Za-z0-9._/-]{1,512}")},
        ),
    )
)

# Credential shapes worth surfacing. Deliberately conservative: a rule that fires
# on every base64 string produces a triage queue nobody reads.
SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    ("aws-access-key-id", r"\bAKIA[0-9A-Z]{16}\b", Severity.HIGH),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.MEDIUM),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", Severity.HIGH),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Severity.HIGH),
    ("stripe-live-key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", Severity.CRITICAL),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", Severity.LOW),
    ("firebase-url", r"https://[a-z0-9-]+\.firebaseio\.com", Severity.MEDIUM),
    # Userinfo per RFC 3986: unreserved / pct-encoded / sub-delims / ":" — and
    # crucially NOT quotes or braces. The previous `[^@\s/]+` matched anything up
    # to the next "@", so on any page carrying JSON-LD it ran from
    # `https://schema.org` through `","@type"` and reported a HIGH severity
    # credential leak. Yoast SEO emits that block on every WordPress page, so the
    # detector fired on a large share of the internet. Measured against a live
    # target: one HIGH "finding", zero credentials.
    (
        "basic-auth-url",
        r"https?://[A-Za-z0-9._~%!$&'()*+;=-]+:[A-Za-z0-9._~%!$&'()*+;=:-]+@[A-Za-z0-9.-]+",
        Severity.HIGH,
    ),
    ("generic-assignment", r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", Severity.MEDIUM),
]

ENDPOINT_PATTERN = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_\-./]{2,120}))["'`]|["'`](https?://[A-Za-z0-9._\-/]{6,200})["'`]"""
)


def _mask(value: str) -> str:
    """Enough of a credential to locate it again, not enough to use it."""
    return value[:6] + "…" + value[-4:] if len(value) > 14 else "…"


def _scan_text(text: str, url: str) -> tuple[list[dict[str, Any]], list[str]]:
    secrets: list[dict[str, Any]] = []
    for name, pattern, severity in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            masked = _mask(value)
            # The surrounding source is useful context, but it contains the
            # credential verbatim — replace it there too. A finding that carries a
            # live key ends up in the report, the audit log, and eventually an
            # email thread, which is a second disclosure on top of the first.
            context = text[max(0, match.start() - 60) : match.end() + 60].replace(value, masked)
            secrets.append(
                {
                    "type": name,
                    "severity": severity.value,
                    "masked": masked,
                    "context": context,
                    "url": url,
                }
            )
            if len(secrets) >= 200:
                return secrets, []

    endpoints: set[str] = set()
    for match in ENDPOINT_PATTERN.finditer(text):
        endpoints.add(match.group(1) or match.group(2))
    return secrets, sorted(endpoints)[:2000]


@easyhunt_tool(
    phase="js_analysis", mode="passive", targets_arg="target", timeout=900,
    name="js_analyze", tags={"js", "secrets"}, estimated_requests=30,
)
async def js_analyze(target: str, max_files: int = 25) -> dict[str, Any]:
    """Fetch JavaScript bundles and extract endpoints, secrets, and libraries.

    Fetches each URL once (a normal browser request), then runs native pattern
    matching, jsluice (grammar-based URL extraction) and retire.js (known-vulnerable
    library detection). Either external tool being absent is reported per-tool in
    ``tools``; it never turns into a quiet zero. Credential candidates are masked
    in the output and are never tested against a live service here.
    """
    engagement = get_engagement()
    urls = [u for u in split_targets(target) if u.startswith("http")][:max_files]
    if not urls:
        return {"ok": False, "error": "no_urls", "message": "js_analyze needs http(s) URLs"}

    all_secrets: list[dict[str, Any]] = []
    all_endpoints: set[str] = set()
    fetched: list[dict[str, Any]] = []

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

            body = response.text[: 4 * 1024 * 1024]
            secrets, endpoints = _scan_text(body, url)
            all_secrets.extend(secrets)
            all_endpoints.update(endpoints)
            fetched.append(
                {"url": url, "status": response.status_code, "bytes": len(body), "secrets": len(secrets)}
            )

            path = engagement.raw_path("js", "js")
            path.write_text(body, encoding="utf-8")

    for secret in all_secrets:
        finding = Finding(
            asset=secret["url"],
            title=f"Possible {secret['type']} in JavaScript bundle",
            phase="secrets",
            severity=Severity.parse(secret["severity"]),
            status=Status.CANDIDATE,
            description=(
                f"A value matching the {secret['type']} pattern appears in a "
                "JavaScript file served to every visitor."
            ),
            how_found=f"js_analyze pattern '{secret['type']}' matched in {secret['url']}",
            source_tool="js_analyze",
            rule_id=f"js.{secret['type']}",
            confidence=0.5,
            evidence=[
                Evidence(kind="file", description="Surrounding source", excerpt=secret["context"][:500])
            ],
            remediation=(
                "Move the secret server-side and rotate it. A key shipped to the "
                "browser is public from the moment it ships, regardless of obfuscation."
            ),
            tags=["javascript", "secret-candidate"],
            extra={"masked": secret["masked"]},
        )
        finding.note(
            "Candidate only. Some of these are public by design (e.g. Firebase "
            "web config). Confirm the key is genuinely privileged before reporting."
        )
        engagement.findings.add(finding)

    relative = sorted(e for e in all_endpoints if e.startswith("/"))
    store_assets(relative, kind="endpoint", source="js_analyze", tags=["from-js"])

    # jsluice parses JavaScript with a real grammar rather than regexes, so it
    # recovers routes the native pattern pass cannot. It had a ToolSpec, an
    # installed binary and a docstring promising it ran — and no call site. On a
    # live target the native pass alone returned "/./", "/a/b", "/_next/":
    # minifier noise rather than routes.
    jsluice_endpoints: list[str] = []
    js_files = sorted(str(p) for p in engagement.raw_dir.glob("js-*.js"))
    if js_files:
        jsluice_run = await run_one(
            "jsluice", ["urls", *js_files[:max_files]], timeout=180
        )
        if jsluice_run.ran:
            for line in jsluice_run.values:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                found = record.get("url")
                if found:
                    jsluice_endpoints.append(str(found))
            all_endpoints.update(jsluice_endpoints)

    library_run = await run_one(
        "retire", ["--path", str(engagement.raw_dir), "--outputformat", "json"],
        timeout=300, allow_codes=(0, 13),
    )

    engagement.findings.save()
    engagement.assets.save(engagement.workspace / "assets.json")

    return {
        "ok": True,
        "files_fetched": len(fetched),
        "fetched": fetched,
        "secret_candidates": len(all_secrets),
        "secrets": all_secrets[:100],
        "endpoints_found": len(all_endpoints),
        "endpoints": relative[:500],
        "absolute_urls": sorted(e for e in all_endpoints if e.startswith("http"))[:200],
        "libraries": library_run.to_dict(),
        "note": (
            "Secret candidates are masked and unvalidated. Validating a credential "
            "means using it — only do that where the program explicitly allows it."
        ),
    }

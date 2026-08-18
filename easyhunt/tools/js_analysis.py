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
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import (
    ToolRun,
    register_spec,
    run_one,
    store_assets,
    targets_or_assets,
)
from easyhunt.util.parse import host_of

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

#: linkfinder -i accepts either a URL or a local file. The native pass fetches
#: URLs; linkfinder runs over the bundles already saved to the workspace, so -i
#: has to accept a filesystem path too. The URL-only pattern that was here would
#: have made the call site refuse its own argument — the wrapper would report
#: `ran: false` forever and read as a tool that finds no extra endpoints.
_LINKFINDER_INPUT = re.compile(
    r"(?:https?://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]{1,2000}|[A-Za-z0-9._/-]{1,1024})"
)

LINKFINDER = register_spec(
    ToolSpec(
        name="linkfinder", binary="linkfinder", license="MIT",
        homepage="https://github.com/GerbenJavado/LinkFinder", version_args=["-h"],
        network="none",
        arg_policy=ArgPolicy(
            tool="linkfinder",
            allowed_flags={"-i", "-o", "-d", "-r"},
            boolean_flags={"-d"},
            value_patterns={"-i": _LINKFINDER_INPUT, "-o": re.compile(r"cli|[A-Za-z0-9._/-]{1,512}")},
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

#: The character class carries `?`, `&`, `=` and `%` deliberately. Without them
#: this pattern could not match a single URL with a query string — `"/api/x?id=1"`
#: did not match *at all*, because the class stopped at `?` and the closing quote
#: was then in the wrong place.
#:
#: That is not a small omission. Parameters are the thing worth finding: they are
#: what `hunt_plan` groups into object-reference and server-side-sink candidates,
#: and what every injection class needs as an entry point. The endpoint miner has
#: been feeding the planner a view of the application with all its inputs removed.
#:
#: Measured against a real engagement's stored bundles: the narrow class found
#: 210 endpoints where LinkFinder found 422, and every one of the 210 was in
#: LinkFinder's set — a strict subset, missing exactly the parameterised ones.
ENDPOINT_PATTERN = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_\-./]{2,120}(?:\?[A-Za-z0-9_\-./%&=+,:]{0,160})?))["'`]"""
    r"""|["'`](https?://[A-Za-z0-9._\-/]{6,200}(?:\?[A-Za-z0-9_\-./%&=+,:]{0,160})?)["'`]"""
    r"""|\}(/(?:[A-Za-z0-9_\-./]{2,120})(?:\?[A-Za-z0-9_\-./%&=+,:]{0,160})?)(?=\$\{)"""
)


def _mask(value: str) -> str:
    """Enough of a credential to locate it again, not enough to use it."""
    return value[:6] + "…" + value[-4:] if len(value) > 14 else "…"


#: Escape sequences a minifier or JSON-encoder leaves in a bundle, normalised
#: back to the characters a browser would decode (HuntProxy's page_analyzer
#: technique, Apache-2.0). ``https:\/\/host`` and ``\u002Fapi`` are the two that
#: hide real endpoints: without normalisation they read as ``https:\/\/host``
#: and the endpoint pattern never matches them, so a bundle full of JSON-string
#: URLs yields zero endpoints. Normalise BEFORE regexing, never after — the
#: pattern expects the decoded form.
_ESCAPE_NORMALIZATIONS = (
    (re.compile(r"\\/"), "/"),
    (re.compile(r"\\u002[fF]"), "/"),
    (re.compile(r"\\u003[aA]"), ":"),
    (re.compile(r"\\u002[eE]"), "."),
    (re.compile(r"\\u005[bB]"), "["),
    (re.compile(r"\\u005[dD]"), "]"),
)

#: A backslash-escaped URL character (``\?``, ``\=``, ``\&``, ``\%``…) left by
#: a string-encoder. Only URL-safe characters are decoded — a blanket
#: backslash-strip would turn ``\n`` inside a template literal into a newline
#: and corrupt the source before the pattern scans it.
_ESCAPED_URL_CHAR = re.compile(r"\\([?=&%.+#~])")


def _normalize_escapes(text: str) -> str:
    """Decode the escape sequences minified bundles use for URL characters."""
    for pattern, replacement in _ESCAPE_NORMALIZATIONS:
        text = pattern.sub(replacement, text)
    return _ESCAPED_URL_CHAR.sub(r"\1", text)


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

    normalized = _normalize_escapes(text)
    endpoints: set[str] = set()
    for match in ENDPOINT_PATTERN.finditer(normalized):
        endpoints.add(match.group(1) or match.group(2) or match.group(3))
    return secrets, sorted(endpoints)[:2000]


#: Bodies that are an edge or origin refusing us, not application JavaScript.
#: Matched on the response body because the status code alone is not enough —
#: an interstitial is sometimes served with HTTP 200.
_BLOCK_PAGE = re.compile(
    r"""(?i)(?:sorry,\s*you\s*have\s*been\s*blocked
        | attention\s+required!?\s*\|\s*cloudflare
        | request\s+rejected
        | access\s+denied
        | \bcf-error-details\b
        | \b__cf\$cv\$params\b
        | you\s+are\s+unable\s+to\s+access
        | <title>\s*4\d\d\s+forbidden)""",
    re.VERBOSE,
)


def _block_marker(body: str) -> bool:
    """Search both ends of the body, not just the head.

    Cloudflare's interstitial is ~437 KB and puts "Sorry, you have been blocked"
    at byte 436488 — everything before it is inline CSS and challenge script. A
    head-only window reported that page as ordinary content, which is the same
    mistake as the bug this function exists to catch, made one layer up.
    """
    return bool(_BLOCK_PAGE.search(body[:16_000]) or _BLOCK_PAGE.search(body[-16_000:]))

#: A document, not a script. Anything served as HTML where JavaScript was asked
#: for is either an error page, a login redirect, or a shell — none of which
#: contain the bundle we came for.
_LOOKS_LIKE_HTML = re.compile(r"""(?is)\A\s*(?:<!doctype\s+html|<html\b|<head\b)""")


#: A ``<script src=...>`` in an HTML shell. The SPA index page is not a bundle,
#: but it names the bundles that are — and the routes live in those, not in the
#: shell. Without following these, js_analyze fetched exactly the shell URL it
#: was handed, saw "served as HTML, not a script", and extracted nothing from
#: the 22 chunk files the application actually runs.
_SCRIPT_SRC = re.compile(r"""(?is)<script[^>]+src=["']([^"']+)["']""")
#: ES module preloads, which SPA shells also use to name their bundles.
_MODULE_PRELOAD = re.compile(r"""(?is)<link[^>]+rel=["']modulepreload["'][^>]+href=["']([^"']+)["']""")


def _script_urls(body: str, base: str) -> list[str]:
    """The bundle URLs an HTML shell references, resolved against the page.

    Absolute only, http(s) only, deduplicated. Relative ``src="main.js"`` is
    resolved with urljoin so a shell served from a path resolves correctly.
    """
    seen: set[str] = set()
    out: list[str] = []
    for match in _SCRIPT_SRC.finditer(body):
        out.append(urljoin(base, match.group(1)))
    for match in _MODULE_PRELOAD.finditer(body):
        out.append(urljoin(base, match.group(1)))
    for url in out:
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc and url not in seen:
            seen.add(url)
            yield url


def _fetch_verdict(status: int, body: str, content_type: str) -> tuple[str, str]:
    """What did we actually receive? Returns ``(verdict, why)``.

    This exists because `js_analyze` once reported a successful phase over six
    hosts while receiving a 437 KB Cloudflare "Sorry, you have been blocked"
    page from each of them. It extracted zero endpoints and zero secrets from
    those bodies — which is exactly what a genuinely clean bundle produces — and
    the phase returned ``ok: True``. Minutes earlier `http_probe` had pulled 864
    KB of real content from the same hosts, so the surface was there and simply
    never read.

    Zero findings from a body we were refused is not a result about the target.
    """
    if status >= 400:
        return "blocked", f"HTTP {status}"
    if _block_marker(body):
        return "blocked", "response body is an edge/WAF interstitial"
    if "html" in content_type.lower() or _LOOKS_LIKE_HTML.match(body):
        # Not necessarily a failure: an SPA shell is a legitimate thing to fetch
        # and mine for script tags. But it is not a bundle, and counting it as
        # one inflates coverage.
        return "not_javascript", "served as HTML, not a script"
    return "ok", ""


@easyhunt_tool(
    phase="js_analysis", mode="passive", targets_arg="target", timeout=900,
    name="js_analyze", tags={"js", "secrets"}, estimated_requests=30,
)
async def js_analyze(target: str, max_files: int = 25) -> dict[str, Any]:
    """Fetch JavaScript bundles and extract endpoints, secrets, and libraries.

    Fetches each URL once (a normal browser request), then runs native pattern
    matching, jsluice (grammar-based URL extraction), linkfinder (regex-based
    endpoint recovery over the saved files) and retire.js (known-vulnerable
    library detection). Either external tool being absent is reported per-tool in
    ``tools``; it never turns into a quiet zero. Credential candidates are masked
    in the output and are never tested against a live service here.
    """
    engagement = get_engagement()
    # No target means "the live URLs http_probe recorded". Passing a bare
    # hostname here used to give `no_urls` in 0.0 seconds, which the pipeline
    # then printed a green tick over.
    candidates, origin = targets_or_assets(target, kind="url", tool="js_analyze")
    urls = [u for u in candidates if u.startswith("http")][:max_files]
    if not urls:
        return {"ok": False, "error": "no_urls", "message": "js_analyze needs http(s) URLs"}

    all_secrets: list[dict[str, Any]] = []
    all_endpoints: set[str] = set()
    #: Endpoint -> origin host (``app.example.com``). A route recovered from a
    #: bundle belongs to the host that served that bundle; without this binding
    #: the exploit chain resolves every endpoint against every live host and
    #: spends its validator budget on ``app.example.com``'s routes aimed at
    #: ``legacy.example.com`` (a host that does not even resolve).
    endpoint_origins: dict[str, str] = {}
    #: Saved bundle file -> URL it was fetched from. jsluice/linkfinder run over
    #: the saved files, whose timestamped names carry no URL; this map is how
    #: their discoveries get attributed to the host that served them.
    saved_urls: dict[str, str] = {}
    #: Fetched URL -> the page that referenced it (``<script src>``). Routes
    #: found in a bundle belong to the app that loaded it, NOT the CDN that
    #: stored it: an app's bundles live on a ``*.example-cdn.net`` asset host while
    #: their routes (``/account/transfer``, ``/api/graphql``) are served by
    #: ``app.example.com``. Attributing to the bundle URL pinned 102 routes to a
    #: CDN that is not even in the live host set — the exploit chain then had
    #: nothing to aim them at. Seeds reference themselves.
    page_urls: dict[str, str] = {}
    fetched: list[dict[str, Any]] = []
    #: Hosts that refused us. Their JavaScript is UNTESTED, not empty.
    blocked: list[dict[str, Any]] = []
    #: Fetched, but a document rather than a bundle.
    not_js: list[dict[str, Any]] = []

    # A shell names its bundles via <script src>, and the routes live in those
    # bundles, not in the shell. Fetch the shell, then follow what it names —
    # bounded by max_files so an SPA that references a thousand chunks is still
    # capped, not followed without limit.
    queue: deque[str] = deque(urls)
    seen: set[str] = set()
    #: Seed pages are their own referrer; anything the queue follows inherits
    #: the page that named it.
    for seed in urls:
        page_urls[seed] = seed

    async with httpx.AsyncClient(
        timeout=20,
        follow_redirects=True,
        headers={"User-Agent": engagement.scope.rules.user_agent},
    ) as client:
        while queue and len(fetched) < max_files * 4:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            async with engagement.limiter.slot(host=url):
                try:
                    response = await client.get(url)
                except httpx.HTTPError as exc:
                    fetched.append({"url": url, "error": str(exc)[:200]})
                    continue

            body = response.text[: 4 * 1024 * 1024]
            verdict, why = _fetch_verdict(
                response.status_code, body, response.headers.get("content-type", "")
            )
            record = {
                "url": url, "status": response.status_code,
                "bytes": len(body), "verdict": verdict,
            }
            if verdict == "blocked":
                # Do not scan it and do not count it as covered. Scanning a
                # block page yields zero of everything, which reads as a clean
                # bundle.
                record["why"] = why
                blocked.append(record)
                fetched.append(record)
                continue

            secrets, endpoints = _scan_text(body, url)
            all_secrets.extend(secrets)
            origin = host_of(page_urls.get(url, url))
            for endpoint in endpoints:
                all_endpoints.add(endpoint)
                endpoint_origins.setdefault(endpoint, origin)
            record["secrets"] = len(secrets)
            if verdict == "not_javascript":
                record["why"] = why
                not_js.append(record)
                # An HTML shell's value is the bundles it names. A bundle
                # inherits the page that referenced it as its origin — see
                # ``page_urls``.
                for script_url in _script_urls(body, url):
                    if script_url not in seen and len(fetched) < max_files * 4:
                        queue.append(script_url)
                        page_urls.setdefault(script_url, url)
            fetched.append(record)

            path = engagement.raw_path("js", "js")
            path.write_text(body, encoding="utf-8")
            saved_urls[str(path)] = url

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

    # jsluice parses JavaScript with a real grammar rather than regexes, so it
    # recovers routes the native pattern pass cannot. It had a ToolSpec, an
    # installed binary and a docstring promising it ran — and no call site. On a
    # live target the native pass alone returned "/./", "/a/b", "/_next/":
    # minifier noise rather than routes.
    jsluice_endpoints: list[str] = []
    js_files = sorted(str(p) for p in engagement.raw_dir.glob("js-*.js"))
    # jsluice runs per file, not over the batch, so each discovery can be
    # attributed to the host that served that bundle. It costs no network and is
    # sub-second per file; the batch form silently lost the origin host.
    for js_file in js_files[:max_files]:
        origin = host_of(page_urls.get(saved_urls.get(js_file, ""), saved_urls.get(js_file, "")))
        jsluice_run = await run_one("jsluice", ["urls", js_file], timeout=180)
        if jsluice_run.ran:
            for line in jsluice_run.values:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                found = record.get("url")
                if found:
                    found = str(found)
                    jsluice_endpoints.append(found)
                    if origin:
                        endpoint_origins.setdefault(found, origin)
    all_endpoints.update(jsluice_endpoints)

    # linkfinder recovers parameterised routes the native regex pass cannot.
    # Measured against 12 real bundles: 422 endpoints to the native pass's 210,
    # and a strict superset — it missed nothing either of the others found.
    # It runs over the files already saved to the workspace, so it costs no
    # extra requests and needs no network (`network: none` on the spec).
    #
    # linkfinder was catalogued with a spec, a binary and no caller for the
    # whole life of the project: its exemption in test_wiring.py was marked
    # "WIRING PROPOSED". This is the call site that lands it.
    linkfinder_endpoints: list[str] = []
    linkfinder_runs: list[ToolRun] = []
    for js_file in js_files[:max_files]:
        origin = host_of(page_urls.get(saved_urls.get(js_file, ""), saved_urls.get(js_file, "")))
        lf_run = await run_one(
            "linkfinder", ["-i", js_file, "-o", "cli"], timeout=180
        )
        linkfinder_runs.append(lf_run)
        if lf_run.ran:
            for value in lf_run.values:
                # `-o cli` prints one candidate per line; keep the URL-shaped ones.
                if value.startswith(("/", "http")):
                    linkfinder_endpoints.append(value)
                    if origin:
                        endpoint_origins.setdefault(value, origin)
    all_endpoints.update(linkfinder_endpoints)

    # Endpoint snapshot is taken AFTER jsluice and linkfinder have contributed.
    # Taken earlier (as it once was), their discoveries were counted in
    # `endpoints_found` but absent from `endpoints` and from the asset store — a
    # tool that visibly ran, whose output was silently dropped on the floor.
    relative = sorted(e for e in all_endpoints if e.startswith("/"))
    store_assets(
        relative,
        kind="endpoint",
        source="js_analyze",
        tags=["from-js"],
        hosts={e: endpoint_origins.get(e, "") for e in relative},
    )

    library_run = await run_one(
        "retire", ["--path", str(engagement.raw_dir), "--outputformat", "json"],
        timeout=300, allow_codes=(0, 13),
    )

    engagement.findings.save()
    engagement.assets.save(engagement.workspace / "assets.json")

    scanned = len(fetched) - len(blocked)
    return {
        # A phase that was refused by half its targets did not succeed at those.
        "ok": not blocked,
        "status": "PARTIAL" if blocked else "COMPLETE",
        "complete": not blocked,
        "files_fetched": len(fetched),
        "files_scanned": scanned,
        "blocked": blocked,
        "not_javascript": not_js,
        "coverage_note": (
            f"{len(blocked)} of {len(fetched)} responses were an edge or origin "
            "refusing the request, not JavaScript. Those hosts' bundles are "
            "UNTESTED — zero secrets and zero endpoints from a block page is not "
            "a statement about the target. Re-run them, or report them as uncovered."
            if blocked else
            f"{scanned} of {len(fetched)} responses were scanned."
        ),
        "fetched": fetched,
        "secret_candidates": len(all_secrets),
        "secrets": all_secrets[:100],
        "endpoints_found": len(all_endpoints),
        "endpoints": relative[:500],
        "absolute_urls": sorted(e for e in all_endpoints if e.startswith("http"))[:200],
        "libraries": library_run.to_dict(),
        "linkfinder": {
            "ran": bool(linkfinder_runs),
            "files": len(linkfinder_runs),
            "endpoints_found": len(linkfinder_endpoints),
            "tools": [r.to_dict() for r in linkfinder_runs],
        },
        "note": (
            "Secret candidates are masked and unvalidated. Validating a credential "
            "means using it — only do that where the program explicitly allows it."
        ),
    }

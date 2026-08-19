"""Browser-driven vulnerability confirmation with Playwright.

Scanner output is a lead; a browser can turn it into evidence. ``browser_verify``
drives a real headless Chromium (via the ``playwright`` Python package and the
system's Chrome — no browser download) to a URL and reports what actually
happened when the page rendered:

* **reflection** — did a supplied payload come back into the DOM *unescaped*
  (a reflected-XSS candidate) or only HTML-encoded (escaped, not vulnerable)?
* **execution** — did the payload actually run (alert/confirm dialog, page
  error, or console message containing it)? An executed payload is the PoC a
  report needs, not a heuristic.
* **redirect** — did navigation land on a different host than the one asked
  for (open-redirect candidate)?
* **console / page errors** — the browser's own view of what broke.
* **screenshot + DOM excerpt** — saved into the workspace ``evidence/`` dir so
  the report carries a real picture, not a description.

Why this exists as a tool rather than a job for the agent: the evidence has to
be *captured at render time*. A human triager wants the screenshot, the exact
DOM window where the payload landed, and the console trace; that is what this
produces, and it is what makes a ``needs_manual_review`` candidate promotable.

When to use it (the agent's cue): a scanner (nuclei, dalfox, ``web_injection_probe``)
reports reflected XSS / open redirect / DOM sink, or a parameter reflects input
with no encoding in sight. Payloads pass through **unescaped** — this tool
builds the URL itself and never hands the payload to a subprocess, so a payload
like ``<svg onload=alert(1)>`` is legitimate data here.

The browser is launched per call and torn down after: no persistent profile, no
cookies, no state between calls.
"""

from __future__ import annotations

import html as _html
import logging
import re
import time
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import easyhunt_tool

log = logging.getLogger("easyhunt.tools.browser_verify")

__all__ = ["browser_verify"]

#: How much DOM context to keep around the first reflection point.
_SNIPPET_RADIUS = 200

#: Characters that make a payload HTML-significant. A plain token reflected
#: back verbatim ("hello-world") is not an XSS candidate; a payload carrying
#: any of these could change how the browser parses the page.
_HTML_SIGNIFICANT = set("<>\"'&")


class Reflection:
    """Reflection classification results."""

    #: The exact payload (or its HTML-significant form) appears unescaped in
    #: the rendered DOM — a reflected-XSS candidate.
    RAW = "raw"
    #: The payload appears verbatim but contains no HTML-significant characters
    #: (a plain token echoed back — interesting, not vulnerable on its own).
    PLAIN = "plain"
    #: Only the HTML-escaped form appears (``&lt;script&gt;``) — the sink encodes.
    ESCAPED = "escaped"
    NONE = "none"


#: Chrome binary candidates, in preference order.
_CHROME_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "headless_shell",
)


def _chrome_binary() -> str | None:
    """Locate a usable Chrome/Chromium binary.

    Order: explicit env (``CHROME_BIN``/``CHROME_PATH``), then PATH candidates.
    Playwright can also launch its own bundled chromium, but that needs
    ``playwright install`` — the system browser is the zero-download path.
    """
    import os
    import shutil

    for env in ("CHROME_BIN", "CHROME_PATH", "PUPPETEER_EXECUTABLE_PATH"):
        path = os.environ.get(env)
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    for name in _CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _playwright_available() -> bool:
    try:  # pragma: no cover - import probe, exercised implicitly
        import playwright  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def build_target_url(url: str, param: str, payload: str) -> str:
    """Inject ``payload`` into ``param`` of ``url`` (replacing an existing one).

    Pure function so the URL construction is unit-testable without a browser.
    If no ``param`` is given the URL is returned unchanged.
    """
    if not param:
        return url
    parts = urlsplit(url)
    query = parts.query
    if query:
        kept = [kv for kv in query.split("&") if not kv.startswith(f"{param}=")]
        query = "&".join(kept + [f"{param}={urlencode({'': payload})[1:]}"])
    else:
        query = f"{param}={urlencode({'': payload})[1:]}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def classify_reflection(html_doc: str, payload: str) -> str:
    """Is ``payload`` reflected unescaped, only escaped, or absent?

    Returns ``Reflection.RAW`` (an HTML-significant payload appears unescaped —
    an XSS candidate), ``Reflection.PLAIN`` (the payload appears verbatim but
    carries no HTML-significant characters — echoed back, not injectable),
    ``Reflection.ESCAPED`` (only the HTML-escaped form appears), or
    ``Reflection.NONE``.

    Note the DOM is re-serialized after parse, so a payload whose markup the
    browser normalised (``<svg onload=alert(1)>`` → ``<svg onload="alert(1)">``)
    may match neither raw nor escaped. Execution detection (dialog/console)
    is the signal that covers that case — see :func:`browser_verify`.
    """
    if not payload:
        return Reflection.NONE
    html_significant = any(ch in payload for ch in _HTML_SIGNIFICANT)
    if payload in html_doc:
        return Reflection.RAW if html_significant else Reflection.PLAIN
    escaped = _html.escape(payload)
    if escaped and escaped in html_doc:
        return Reflection.ESCAPED
    return Reflection.NONE


def reflection_snippet(html_doc: str, payload: str, radius: int = _SNIPPET_RADIUS) -> str:
    """A DOM window around the first occurrence of ``payload`` (or its escaped form)."""
    needle = payload if payload in html_doc else _html.escape(payload)
    idx = html_doc.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(html_doc), idx + len(needle) + radius)
    return html_doc[start:end]


def _payload_token(payload: str) -> str:
    """A stable substring of the payload to match against console/error text.

    Prefers an alphanumeric run (a function name, an id) so the match is robust
    to quoting differences between the payload and the console render.
    """
    runs = re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", payload)
    if runs:
        return max(runs, key=len)
    return payload[:12]


@easyhunt_tool(
    phase="exploit",
    mode="aggressive",
    targets_arg="url",
    timeout=180,
    name="browser_verify",
    tags={"browser", "xss", "redirect", "evidence", "playwright"},
    estimated_requests=8,
    rationale=(
        "Drive a real headless browser to a URL (optionally with a payload in a "
        "parameter) and capture what actually renders: unescaped reflection, "
        "payload execution (dialog/console), open redirect, console errors, and "
        "a screenshot + DOM excerpt saved as evidence. Converts scanner leads "
        "into promotable findings."
    ),
    risk_notes=(
        "Loads the target page in a real browser engine — executes the page's "
        "own JavaScript, and executes the supplied payload if it is crafted to "
        "run (that is the point: it is proof-of-concept confirmation, alert()-"
        "level, never data access). A handful of requests per call.",
    ),
    text_args=("payload", "param"),
)
async def browser_verify(
    url: str,
    payload: str = "",
    param: str = "",
    screenshot: bool = True,
) -> dict[str, Any]:
    """Verify a candidate in a real browser and capture evidence.

    ``url`` is the target URL. ``param`` names a query parameter and ``payload``
    is what to put in it (an XSS payload, a canary token, a URL for open
    redirect — passed **unescaped**; this tool builds the URL itself). The
    browser loads the page and reports:

    * ``reflection`` — ``raw`` / ``escaped`` / ``none`` (unescaped reflection
      of the payload is a reflected-XSS candidate),
    * ``executed`` — whether the payload ran (dialog, page error, or console
      message containing it) — the strongest signal,
    * ``redirect`` — ``final_url`` host differing from the requested host
      (open-redirect candidate),
    * console messages and page errors,
    * ``screenshot`` / ``dom_excerpt`` — saved to the workspace ``evidence/``
      dir and referenced from the filed finding.

    A finding is filed for raw reflection (MEDIUM), execution (HIGH), or a
    host-changing redirect (LOW) — all ``needs_manual_review`` with the
    screenshot as evidence.
    """
    if not _playwright_available():
        return {
            "ok": False,
            "error": "dependency_missing",
            "message": (
                "The 'playwright' Python package is not installed. "
                "Install it with: .venv/bin/pip install 'playwright>=1.40' "
                "(uses the system Chrome — no 'playwright install' needed)."
            ),
        }
    chrome = _chrome_binary()
    if chrome is None:
        return {
            "ok": False,
            "error": "browser_unavailable",
            "message": (
                "No Chrome/Chromium binary found on PATH or via CHROME_BIN. "
                "Install a browser (e.g. google-chrome-stable) or point "
                "CHROME_BIN at an existing one."
            ),
        }

    request_url = build_target_url(url, param, payload)
    token = _payload_token(payload)
    started_host = urlsplit(url).hostname or ""

    engagement = get_engagement()
    evidence_dir = engagement.workspace / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    from playwright.async_api import async_playwright  # lazy: optional dependency

    console_msgs: list[str] = []
    page_errors: list[str] = []
    dialogs: list[str] = []
    final_url = ""
    status_code: int | None = None

    def _on_console(msg: Any) -> None:
        text = msg.text or ""
        if text and len(console_msgs) < 30:
            console_msgs.append(f"{msg.type}: {text}")

    def _on_pageerror(err: Any) -> None:
        text = str(err)
        if len(page_errors) < 10:
            page_errors.append(text)

    def _on_dialog(dlg: Any) -> None:
        try:
            dialogs.append(f"{dlg.type}({dlg.message})")
        finally:
            # Dialogs would block the page; dismiss every one.
            import asyncio as _asyncio

            _asyncio.ensure_future(dlg.dismiss())

    browser = None
    screenshot_path = None
    html_doc = ""
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                executable_path=chrome,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page()
            page.on("console", _on_console)
            page.on("pageerror", _on_pageerror)
            page.on("dialog", _on_dialog)
            response = await page.goto(request_url, wait_until="domcontentloaded", timeout=45_000)
            if response is not None:
                status_code = response.status
                final_url = response.url
            # Give late onload handlers / dialogs a moment to fire.
            await page.wait_for_timeout(800)
            html_doc = await page.content()
            if screenshot:
                try:
                    path = evidence_dir / f"browser_verify_{int(time.time() * 1000)}.png"
                    await page.screenshot(path=str(path), full_page=False)
                    screenshot_path = str(path)
                except Exception as exc:  # noqa: BLE001
                    log.debug("screenshot capture failed: %s", exc)
    except Exception as exc:  # noqa: BLE001 — a browser failure is a clean report
        return {
            "ok": False,
            "error": "browser_failed",
            "message": f"Browser navigation failed: {exc}",
            "url": request_url,
        }
    finally:
        if browser is not None:
            try:
                await browser.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("browser close failed: %s", exc)

    reflection = classify_reflection(html_doc, payload) if payload else Reflection.NONE
    snippet = (
        reflection_snippet(html_doc, payload)
        if reflection in (Reflection.RAW, Reflection.PLAIN)
        else ""
    )
    executed = False
    for msg in console_msgs + page_errors:
        if token and token in msg:
            executed = True
    executed = executed or bool(dialogs)

    final_host = urlsplit(final_url or request_url).hostname or ""
    redirected = bool(
        started_host
        and final_host
        and started_host != final_host
        and started_host not in final_host
        and final_host not in started_host
    )

    result: dict[str, Any] = {
        "ok": True,
        "url": request_url,
        "status": status_code,
        "final_url": final_url or request_url,
        "reflection": reflection,
        "executed": executed,
        "redirected": redirected,
        "console": console_msgs[-12:],
        "page_errors": page_errors[-6:],
        "dialogs": dialogs[-6:],
        "screenshot": screenshot_path,
    }
    if reflection in (Reflection.RAW, Reflection.PLAIN):
        result["dom_excerpt"] = snippet[:1200]

    # Brain + coverage learn from every render, hit or clean.
    techs = [str(t) for t in engagement.assets.values("technology")][:10]
    classes = []
    if reflection == Reflection.RAW or executed:
        classes.append("xss-injection")
    if redirected:
        classes.append("open-redirect")
    for cls in classes:
        engagement.brain.learn(
            vuln_class=cls,
            technique="browser_verify",
            outcome="hit",
            technologies=techs,
            engagement=engagement.scope.name,
        )
        coverage = getattr(engagement, "coverage", None)
        if coverage is not None:
            coverage.record(
                cls,
                "detected",
                tool="browser_verify",
                note=f"reflection={reflection}, executed={executed}",
            )

    # A finding is filed when the payload EXECUTED (dialog/console — the DOM
    # re-serialisation may hide the exact payload string, so execution is the
    # authoritative signal) or when an HTML-significant payload rendered
    # unescaped (RAW). A PLAIN echo ("hello-world" reflected back) is not a
    # finding — it is interesting, not injectable.
    findings_filed = 0
    if reflection == Reflection.RAW or executed:
        if executed:
            title = "Reflected XSS — payload executed in the browser"
            severity = Severity.HIGH
            rule_id = "browser-verify.xss.executed"
        else:
            title = "Reflected XSS candidate — payload rendered unescaped"
            severity = Severity.MEDIUM
            rule_id = "browser-verify.xss.reflected"
        render_note = (
            "and executes it (alert/console)" if executed else "unescaped in the rendered DOM"
        )
        finding = Finding(
            asset=url,
            title=title,
            phase="exploit",
            severity=severity,
            status=Status.NEEDS_MANUAL_REVIEW,
            description=(
                f"The parameter {param or '(page)'!r} of {url} reflects the "
                f"supplied payload {render_note} "
                f"(verified in a real headless Chrome). This is a reflected-XSS "
                f"candidate: an attacker who controls the value can run script "
                f"in the victim's browser. Detection is render-time — the "
                f"payload ran (or rendered) exactly as submitted."
            ),
            how_found=(
                f"browser_verify: headless Chrome loaded {request_url} — "
                f"reflection={reflection}, executed={executed}, "
                f"status={status_code}, final={final_url}"
            ),
            source_tool="browser_verify",
            rule_id=rule_id,
            confidence=0.8 if executed else 0.6,
            evidence=[
                Evidence(
                    kind="screenshot",
                    description="headless-Chrome capture of the rendered page",
                    excerpt=screenshot_path or "screenshot capture failed",
                ),
                Evidence(
                    kind="dom",
                    description="DOM window around the reflection point",
                    excerpt=snippet[:1200] or "(payload re-serialised by the DOM)",
                ),
            ]
            + (
                [
                    Evidence(
                        kind="console",
                        description="browser console/page-error trace showing execution",
                        excerpt=" | ".join(dialogs or page_errors or console_msgs)[:500],
                    )
                ]
                if executed
                else []
            ),
            remediation=(
                "Encode the reflected value for its HTML context (context-aware "
                "output encoding, CSP, and a trusted sanitizer). Never insert "
                "user input into HTML without encoding; treat reflected values "
                "as data, never markup."
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
            tags=["xss", "reflected-xss", "browser-verified", "candidate"],
            extra={
                "reflection": reflection,
                "executed": executed,
                "payload": payload,
                "parameter": param,
                "final_url": final_url,
                "screenshot": screenshot_path,
            },
        )
        engagement.findings.add(finding)
        findings_filed += 1

    if redirected:
        finding = Finding(
            asset=url,
            title="Open-redirect candidate — navigation left the requested host",
            phase="exploit",
            severity=Severity.LOW,
            status=Status.NEEDS_MANUAL_REVIEW,
            description=(
                f"Loading {url} in a browser landed on {final_url} — a different "
                f"host. If the destination is influenced by the payload "
                f"({'present in ' + param if param else 'page input'}), this is an "
                f"open redirect; Chime-style programs require an additional "
                f"security impact (OAuth token theft) before it is reportable."
            ),
            how_found=(f"browser_verify: requested host {started_host} → final host {final_host}"),
            source_tool="browser_verify",
            rule_id="browser-verify.open-redirect",
            confidence=0.5,
            evidence=[
                Evidence(
                    kind="http",
                    description="request URL → final URL",
                    excerpt=f"{request_url} → {final_url}",
                ),
            ],
            remediation=(
                "Only redirect to allow-listed destinations (relative paths or "
                "an explicit host list); validate the next parameter server-side."
            ),
            references=["https://portswigger.net/web-security/ssrf/open-redirect"],
            tags=["open-redirect", "candidate"],
            extra={"request_url": request_url, "final_url": final_url},
        )
        engagement.findings.add(finding)
        findings_filed += 1

    if findings_filed:
        engagement.findings.save()

    result["count"] = findings_filed
    result["findings"] = findings_filed
    if reflection == Reflection.RAW or executed:
        result["note"] = (
            "Reflection/execution confirmed in a real browser — file as a "
            "reflected-XSS candidate; reproduce the PoC by hand to promote it."
        )
    return result

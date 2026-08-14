"""Session registration and the two-identity differ.

`authz_compare` is the reason this module exists. The core authorization test in
every methodology is the same three steps: perform a request as user A, replay it
byte-for-byte as user B, and see whether B receives A's data. That single pattern
covers most of WSTG's Authorization category and much of Business Logic — 15
tests that had no tool behind them because nothing here could hold two identities
at once.

It is deliberately a *comparison*, not a verdict. Two responses differing proves
the server distinguishes the callers. Two responses matching proves it does not —
which is a finding only when the resource belongs to someone. The tool reports
what it observed and what would make it a finding; a human decides.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.knowledge.sessions import Session, mask
from easyhunt.tools.base import easyhunt_tool
from easyhunt.tools.common import split_targets

__all__ = ["account_register", "authz_compare", "session_list", "session_register"]


def _parse_pairs(raw: str | None) -> dict[str, str]:
    """`a=1; b=2` or `Name: value` lines into a dict. Rejects nothing silently."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for chunk in raw.replace("\n", ";").split(";"):
        item = chunk.strip()
        if not item:
            continue
        if ":" in item and "=" not in item.split(":", 1)[0]:
            key, _, value = item.partition(":")
        else:
            key, _, value = item.partition("=")
        if key.strip():
            out[key.strip()] = value.strip()
    return out


@easyhunt_tool(
    phase="method", mode="passive", targets_arg=None, timeout=30,
    name="session_register", tags={"auth", "session"}, estimated_requests=0,
    rationale="Register an authenticated session so later phases can test as a real user.",
)
async def session_register(
    name: str,
    host: str,
    cookies: str | None = None,
    headers: str | None = None,
    role: str = "user",
    note: str = "",
) -> dict[str, Any]:
    """Register an authenticated session for later phases to use.

    ``cookies`` takes ``sid=abc; csrf=def``. ``headers`` takes
    ``Authorization: Bearer xyz`` (semicolon or newline separated).

    ``host`` is mandatory and is enforced: a session is only ever attached to
    that host or its subdomains. Sending an operator's cookie to a host it was
    not issued for is a credential leak, and guessing is how that happens.

    ``role`` is free text — "admin", "user-a", "user-b". Register **two**
    accounts of differing privilege and `authz_compare` can test authorization
    properly; one account only tests that the application works.

    Nothing here creates an account. Self-registration is a policy question:
    some programs invite it, others are silent, and silence is not permission.
    Read the program's rules, register by hand, then bring the session here.

    Values are masked in every result, log and audit entry. The store lives in
    the engagement workspace, which is gitignored, mode 0600.
    """
    engagement = get_engagement()
    clean_host = (host or "").strip().lower()
    if not clean_host:
        return {
            "ok": False,
            "error": "host_required",
            "message": (
                "A session must name the host it belongs to. Without one it "
                "cannot be attached safely, and attaching it by guess would send "
                "your credentials somewhere they were not issued for."
            ),
        }

    verdict = engagement.scope.check(clean_host)
    if not verdict.in_scope:
        return {
            "ok": False,
            "error": "scope_denied",
            "message": (
                f"{clean_host} is not in scope ({verdict.reason}). A session for an "
                "out-of-scope host would be attached to requests this engagement "
                "may not make."
            ),
        }

    session = Session(
        name=name,
        role=role,
        host=clean_host,
        cookies=_parse_pairs(cookies),
        headers=_parse_pairs(headers),
        note=note,
    )
    if not session.cookies and not session.headers:
        return {
            "ok": False,
            "error": "empty_session",
            "message": "No cookies and no headers — there is nothing to authenticate with.",
        }

    engagement.sessions.add(session)
    engagement.sessions.save(engagement.workspace / "sessions.json")
    engagement.audit.record(
        "session_registered", name=name, role=role, host=clean_host,
        cookie_names=sorted(session.cookies), header_names=sorted(session.headers),
    )

    roles = engagement.sessions.counts()
    return {
        "ok": True,
        "session": session.safe(),
        "registered": engagement.sessions.names(),
        "roles": roles,
        "next_step": (
            "Register a second account with a different role, then run "
            "authz_compare to test whether the server distinguishes them."
            if len(roles) < 2
            else "Two or more roles registered — authz_compare can now test authorization."
        ),
    }


@easyhunt_tool(
    phase="method",
    mode="aggressive",
    targets_arg="host",
    timeout=60,
    name="account_register",
    tags={"auth", "session"},
    estimated_requests=4,
    risk_notes=[
        "Creates a test account on the target. This is a state change — the "
        "account persists after the scan and is someone else's data to hold.",
        "Refused outright unless scope.rules.allow_self_registration is true, "
        "which is only ever true because the program's published policy says "
        "self-registration is permitted. Silence is not permission.",
    ],
    rationale="Create a test account where the program's policy permits it.",
)
async def account_register(
    host: str,
    signup_url: str,
    username_field: str,
    password_field: str,
    email_field: str | None = None,
    username: str | None = None,
    password: str | None = None,
    email: str | None = None,
    role: str = "user",
    name: str = "",
) -> dict[str, Any]:
    """Create a test account and register the resulting session.

    This is the one action in the authenticated toolchain that *creates* state
    rather than reading it, so it is refused unless the program said it may
    happen: ``rules.allow_self_registration`` in ``scope.yaml``, which is
    transcribed from the program's published policy and defaults to false.

    ``signup_url`` is the form's action (where the signup POST goes).
    ``username_field``/``password_field``/``email_field`` name the form fields.
    Credentials default to generated values; pass them to register a specific
    account. The session that comes back (cookies + headers) is registered
    under ``name`` so ``authz_compare`` can use it immediately.

    The response is masked; the generated credentials are returned once so the
    operator can store them, and never logged.
    """
    import secrets

    import httpx

    engagement = get_engagement()
    if not engagement.scope.rules.allow_self_registration:
        return {
            "ok": False,
            "error": "self_registration_not_permitted",
            "message": (
                "rules.allow_self_registration is false, so no account will be "
                "created. Creating an account is a state change on the target, and "
                "silence in the program's policy is not permission. If the policy "
                "actually permits self-registration, set it true in scope.yaml — "
                "otherwise register by hand and bring the session back via "
                "session_register."
            ),
        }

    clean_host = (host or "").strip().lower()
    verdict = engagement.scope.check(clean_host)
    if not verdict.in_scope:
        return {
            "ok": False, "error": "scope_denied",
            "message": f"{clean_host} is not in scope ({verdict.reason}).",
        }

    parsed = urlsplit(signup_url)
    if parsed.hostname != clean_host:
        return {
            "ok": False, "error": "signup_host_mismatch",
            "message": (
                f"signup_url is on {parsed.hostname or 'no host'} but the session was "
                f"declared for {clean_host}. The signup POST would send credentials "
                "somewhere the operator did not name."
            ),
        }

    user = username or f"easyhunt_{secrets.token_hex(6)}"
    pw = password or secrets.token_urlsafe(18)
    mail = email or f"{user}@example.com"
    data = {username_field: user, password_field: pw}
    if email_field:
        data[email_field] = mail

    session_name = name or f"{role}-{user}"
    rules = engagement.scope.rules
    async with httpx.AsyncClient(
        timeout=30, follow_redirects=True,
        headers={"User-Agent": rules.user_agent},
    ) as client:
        try:
            async with engagement.limiter.slot(host=clean_host):
                response = await client.post(signup_url, data=data)
        except httpx.HTTPError as exc:
            return {
                "ok": False, "error": "signup_failed",
                "message": f"signup POST to {signup_url} failed: {type(exc).__name__}",
            }

    session = Session(
        name=session_name,
        role=role,
        host=clean_host,
        cookies=dict(response.cookies),
        note=f"created by account_register at {signup_url}",
    )
    if not session.cookies and not session.headers:
        return {
            "ok": False, "error": "no_session_returned",
            "status": response.status_code,
            "message": (
                f"The signup POST returned HTTP {response.status_code} with no session "
                "cookies. The account may have been created but the session could not "
                "be captured — log in by hand and use session_register."
            ),
        }

    engagement.sessions.add(session)
    engagement.sessions.save(engagement.workspace / "sessions.json")
    engagement.audit.record(
        "account_registered",
        host=clean_host, role=role, signup_url=signup_url,
        session=session_name, status=response.status_code,
    )

    return {
        "ok": True,
        "status": response.status_code,
        "session": session.safe(),
        # The generated credentials are returned once — the operator needs them
        # to log in again if the session expires. Never written to the audit log.
        "credentials": {
            "username": user,
            "password": pw,
            **({"email": mail} if email_field else {}),
        },
        "next_step": (
            "Register a second account with a different role, then authz_compare "
            "can test whether the server distinguishes them."
        ),
    }


@easyhunt_tool(
    phase="method", mode="passive", targets_arg=None, timeout=30,
    name="session_list", tags={"auth", "session"}, estimated_requests=0,
    rationale="Show which authenticated identities this engagement holds.",
)
async def session_list() -> dict[str, Any]:
    """List registered sessions. Values are masked."""
    engagement = get_engagement()
    sessions = engagement.sessions.safe_list()
    return {
        "ok": True,
        "count": len(sessions),
        "sessions": sessions,
        "roles": engagement.sessions.counts(),
        "note": (
            "No sessions registered. Everything behind a login is untestable — "
            "which is 42 of 115 WSTG tests, including all of Authorization and "
            "Business Logic."
            if not sessions
            else "Registered. Wrappers attach these only to the host each was issued for."
        ),
    }


@easyhunt_tool(
    phase="exploit", mode="exploit", targets_arg="target", timeout=120,
    name="authz_compare", tags={"authz", "idor"}, estimated_requests=3,
    risk_notes=[
        "Sends the same request under two identities and compares the responses.",
        "Read-only by construction: GET and HEAD only. A state-changing method "
        "would modify another user's data, which every program forbids.",
    ],
    rationale="Test whether the server distinguishes callers — the core IDOR check.",
)
async def authz_compare(
    target: str, session_a: str, session_b: str, method: str = "GET"
) -> dict[str, Any]:
    """Fetch one URL as two identities and report whether the server told them apart.

    The core authorization test. If A can read A's resource and B can read it
    too, the server is not checking ownership — that is an IDOR. If B is refused,
    it is.

    Restricted to GET and HEAD on purpose. Proving broken access control never
    requires writing: reading another user's record is the proof, and writing to
    it modifies data that is not yours, which every program in this space
    forbids outright.

    Reports a CANDIDATE, never a confirmed finding. Two identical responses can
    also mean the resource is public, or that neither session is actually
    authenticated. The result says which checks would settle it.
    """
    import httpx

    engagement = get_engagement()
    if method.upper() not in {"GET", "HEAD"}:
        return {
            "ok": False,
            "error": "method_not_permitted",
            "message": (
                f"{method.upper()} is not permitted here. Proving broken access "
                "control requires reading another user's data, never writing to it."
            ),
        }

    url = split_targets(target)[0]
    host = urlsplit(url).hostname or ""
    a = engagement.sessions.get(session_a)
    b = engagement.sessions.get(session_b)
    missing = [n for n, s in ((session_a, a), (session_b, b)) if s is None]
    if missing:
        return {
            "ok": False, "error": "unknown_session",
            "message": f"No session named {missing}. Register with session_register first.",
            "registered": engagement.sessions.names(),
        }

    wrong_host = [s.name for s in (a, b) if s not in engagement.sessions.for_host(host)]
    if wrong_host:
        return {
            "ok": False, "error": "session_host_mismatch",
            "message": (
                f"Session(s) {wrong_host} were not issued for {host}. Refusing to "
                "send them — attaching a credential to the wrong host leaks it."
            ),
        }

    # Two copies of one identity always compare IDENTICAL, and that is not a
    # finding — it is the test being run against itself. Caught on the first
    # live run: a SQL-injection login bypass returned the same admin token for
    # two different email addresses, so both "identities" were one account and
    # the tool reported a HIGH severity IDOR candidate about nothing.
    if a.as_headers() == b.as_headers():
        return {
            "ok": False,
            "error": "identical_sessions",
            "message": (
                f"{a.name} and {b.name} carry the same credentials, so they are one "
                "identity. Comparing a session with itself always reports IDENTICAL "
                "and proves nothing. Register two genuinely separate accounts."
            ),
        }

    rules = engagement.scope.rules
    results = {}
    async with httpx.AsyncClient(
        timeout=20, follow_redirects=False, verify=True
    ) as client:
        for label, session in (("a", a), ("b", b)):
            headers = {"User-Agent": rules.user_agent, **session.as_headers()}
            try:
                r = await client.request(method.upper(), url, headers=headers)
                body = r.text or ""
                results[label] = {
                    "session": session.name, "role": session.role,
                    "status": r.status_code, "length": len(body),
                    "body_sha": __import__("hashlib").sha256(body.encode()).hexdigest()[:16],
                    "excerpt": body[:300],
                }
            except Exception as exc:  # noqa: BLE001
                results[label] = {"session": session.name, "error": f"{type(exc).__name__}: {exc}"}

    if any("error" in r for r in results.values()):
        return {
            "ok": False, "error": "request_failed", "detail": results,
            "message": "One identity's request did not complete — UNTESTED, not authorized.",
        }

    same_status = results["a"]["status"] == results["b"]["status"]
    same_body = results["a"]["body_sha"] == results["b"]["body_sha"]
    both_ok = results["a"]["status"] < 400 and results["b"]["status"] < 400
    indistinguishable = same_status and same_body and both_ok

    findings: list[Finding] = []
    if indistinguishable:
        findings.append(
            Finding(
                asset=url,
                title=f"Server does not distinguish callers on {urlsplit(url).path or '/'}",
                phase="exploit",
                severity=Severity.HIGH,
                status=Status.CANDIDATE,
                description=(
                    f"{method.upper()} {url} returned an identical response "
                    f"(status {results['a']['status']}, same body hash) to two different "
                    f"authenticated identities: {a.name} (role {a.role}) and "
                    f"{b.name} (role {b.role}). If this resource belongs to one of them, "
                    "the server is not checking ownership."
                ),
                how_found="authz_compare: same request under two sessions",
                source_tool="authz_compare",
                confidence=0.5,
                tags=["idor", "access-control", "candidate"],
                evidence=[Evidence(
                    kind="response",
                    description=f"identical under {mask(a.name, keep=8)} and {mask(b.name, keep=8)}",
                    excerpt=results["a"]["excerpt"],
                )],
                remediation=(
                    "Authorize on the server for every request that returns a "
                    "user-scoped resource — check that the authenticated principal "
                    "owns the object, not merely that they are logged in."
                ),
            )
        )
        for f in findings:
            engagement.findings.add(f)
        engagement.findings.save()

    return {
        "ok": True,
        "target": url,
        "method": method.upper(),
        "identities": {"a": f"{a.name}/{a.role}", "b": f"{b.name}/{b.role}"},
        "responses": results,
        "distinguished": not indistinguishable,
        "findings": [f.to_dict() for f in findings],
        "verdict": (
            "IDENTICAL — the server did not tell these identities apart."
            if indistinguishable
            else "Different responses: the server distinguished the callers."
        ),
        "next_step": (
            "Before reporting: confirm the resource actually belongs to one identity "
            "and not the other, and confirm BOTH sessions are genuinely authenticated "
            "— two logged-out sessions also produce identical responses. A public "
            "resource is not an IDOR."
            if indistinguishable
            else "No difference to chase here. Try a resource owned by A specifically."
        ),
    }

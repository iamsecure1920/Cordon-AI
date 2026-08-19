"""Authenticated sessions — the primitive 36% of WSTG needs and this tool lacked.

Measured against the OWASP WSTG index this project already ships: 42 of 115
tests have no tool behind them, and they are not scattered. They are every test
in Authentication (11), Session management (11), Business logic (10),
Authorization (5) and Identity management (5).

Every *covered* category is something testable without an account. Every
uncovered one requires being logged in — and the authorization tests require
being logged in **twice, as different people**. That is not 42 features to
build. It is one missing primitive.

What this is
------------
A named store of credentials-in-flight: cookies, headers, bearer tokens. Not a
login automation — the operator supplies the session, or a future capture tool
does, and every wrapper that speaks HTTP can then attach it.

Two sessions at once is the point. The core authorization test is: perform a
request as A, replay it byte-for-byte as B, and see whether B gets A's data.
That single pattern is most of ATHZ and much of BUSL, and it is mechanically
simple once two sessions can coexist.

What this deliberately is NOT
-----------------------------
It does not create accounts. Self-registration is a **policy** question, not a
technical one: of four bug bounty programs read during this project, two
explicitly permitted self-registration and two said nothing — and silence is not
permission. Account creation belongs behind an explicit scope rule, the way
exploitation already is.

Secrets handling
----------------
Session values are credentials. They are stored in the engagement workspace,
which is gitignored, and they are **masked in every result and audit entry**.
A cookie that reaches a report is a cookie in someone's ticketing system.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = ["Session", "SessionStore", "mask"]


def mask(value: str, *, keep: int = 4) -> str:
    """A credential, rendered so it identifies itself without being usable.

    Reports get read by triagers, pasted into tickets and mailed around. A
    session cookie that survives that journey is a live credential in a system
    nobody threat-modelled for it.
    """
    text = str(value)
    if len(text) <= keep * 2:
        return "…" * 3
    return f"{text[:keep]}…{text[-keep:]}"


@dataclass
class Session:
    """One authenticated identity.

    ``role`` is free text the operator chooses — "admin", "user-a", "user-b".
    It exists so a two-identity differ can say *which* identity saw what,
    because "the request succeeded" means nothing without knowing who sent it.
    """

    name: str
    role: str = "user"
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    #: Host this session is valid for. A cookie sent to the wrong host is a
    #: credential leak, so attachment checks this before sending anything.
    host: str = ""
    note: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def as_headers(self) -> dict[str, str]:
        """Everything this session contributes to a request."""
        out = dict(self.headers)
        if self.cookies:
            out["Cookie"] = self.cookie_header()
        return out

    def safe(self) -> dict[str, Any]:
        """The version that may appear in a result, a log, or a report."""
        return {
            "name": self.name,
            "role": self.role,
            "host": self.host,
            "note": self.note,
            "created_at": self.created_at,
            "cookies": {k: mask(v) for k, v in self.cookies.items()},
            "headers": {
                k: (mask(v) if _is_secret_header(k) else v) for k, v in self.headers.items()
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


#: Headers whose value is a credential rather than metadata.
_SECRET_HEADERS = {
    "authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token",
    "x-xsrf-token", "authentication", "proxy-authorization", "x-session-token",
}


def _is_secret_header(name: str) -> bool:
    return name.strip().lower() in _SECRET_HEADERS


class SessionStore:
    """Named sessions for one engagement, persisted alongside its findings."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def add(self, session: Session) -> Session:
        with self._lock:
            self._sessions[session.name] = session
            return session

    def get(self, name: str) -> Session | None:
        return self._sessions.get(name)

    def names(self) -> list[str]:
        return sorted(self._sessions)

    def by_role(self, role: str) -> list[Session]:
        return [s for s in self._sessions.values() if s.role == role]

    def for_host(self, host: str) -> list[Session]:
        """Sessions valid for this host. Never guesses — an empty host matches nothing.

        A session captured on `app.example.com` must not be attached to a
        request for `evil.example.com`, and a session with no recorded host is
        not attached anywhere. Failing closed here costs a little convenience;
        failing open sends the operator's credentials to a third party.
        """
        target = (host or "").strip().lower()
        if not target:
            return []
        return [
            s for s in self._sessions.values()
            if s.host and (target == s.host.lower() or target.endswith("." + s.host.lower()))
        ]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self._sessions.values():
            out[s.role] = out.get(s.role, 0) + 1
        return dict(sorted(out.items()))

    def safe_list(self) -> list[dict[str, Any]]:
        return [s.safe() for s in self._sessions.values()]

    def __len__(self) -> int:
        return len(self._sessions)

    def save(self, path: Path) -> None:
        """Persist. The workspace is gitignored; these are live credentials."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([s.to_dict() for s in self._sessions.values()], indent=2),
            encoding="utf-8",
        )
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def load(self, path: Path) -> int:
        if not path.exists():
            return 0
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return 0
        before = len(self._sessions)
        for item in raw if isinstance(raw, list) else []:
            try:
                self.add(Session(**item))
            except TypeError:
                continue
        return len(self._sessions) - before

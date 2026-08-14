"""Append-only audit log.

One JSONL line per *attempt* — refusals included, because "EasyHunt declined to
touch that host" is exactly the record an engagement needs when a program asks
what you did. Lines are hash-chained: each carries the previous line's digest, so
a deletion or edit anywhere in the file is detectable with :meth:`AuditLog.verify`.

The log is the engagement's evidence. It is never rewritten, never truncated, and
credential-shaped values are redacted on the way in so it can be attached to a
report without leaking what you found.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = ["AuditLog", "redact"]

_GENESIS = "0" * 64

# Values shaped like credentials get replaced before they are ever written.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_\-]{16,}\b"), "<redacted:api-key>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted:aws-access-key-id>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "<redacted:github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<redacted:slack-token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "<redacted:jwt>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<redacted:private-key>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S{6,}"), r"\1=<redacted>"),
]

# Argument names whose values are always sensitive regardless of shape.
_SECRET_KEYS = {
    "api_key", "apikey", "token", "password", "passwd", "secret", "authorization",
    "cookie", "cookies", "session", "sessions", "aws_secret_access_key",
    "private_key", "bearer", "headers", "auth", "credential", "credentials",
    # account_register accepts these as arguments and returns them once to the
    # operator; they are the test account's login pair, not public data. An
    # email is PII and a username plus password is the credential. Keeping them
    # out of the hash-chained, kept-forever audit log is the same rule that
    # already applies to ``password`` — and ``password`` is redacted here while
    # ``username``/``email`` are not, which is a leak of two thirds of the pair.
    "email", "username",
}

# Name fragments that mark a value as a credential. The patterns above catch
# things that *look* like secrets, which is most of them — but a session cookie
# is `sid=a1b2c3` and looks like nothing at all. Only the argument's name says
# what it is, so a name carrying any of these is redacted whatever its shape.
#
# Found by a test asserting the audit log did not contain a token that had just
# been registered. It did: `session_register` takes `cookies` and `headers`, the
# decorator records every tool argument verbatim, and the log is hash-chained and
# kept forever. Over-redacting an audit field costs a little debuggability;
# under-redacting writes live credentials into a permanent record.
_SECRET_KEY_FRAGMENTS = (
    "password", "passwd", "secret", "token", "cookie", "apikey", "api_key",
    "credential", "authorization",
)


def _is_secret_key(key: Any) -> bool:
    name = str(key).lower()
    return name in _SECRET_KEYS or any(f in name for f in _SECRET_KEY_FRAGMENTS)


def redact(value: Any) -> Any:
    """Recursively redact credential-shaped content from a value."""
    if isinstance(value, str):
        out = value
        for pattern, replacement in _SECRET_PATTERNS:
            out = pattern.sub(replacement, out)
        return out
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if _is_secret_key(k) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


class AuditLog:
    """Hash-chained JSONL writer.

    Thread-safe and process-append-safe: each record is one ``write`` of a single
    line, flushed and fsynced before the call returns.
    """

    def __init__(self, path: str | Path, *, hash_chain: bool = True, scope_fingerprint: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.hash_chain = hash_chain
        self.scope_fingerprint = scope_fingerprint
        self._lock = threading.Lock()
        self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Continue an existing chain so a resumed run does not fork the log."""
        if not self.path.exists():
            return 0, _GENESIS
        seq, prev = 0, _GENESIS
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = int(record.get("seq", seq)) + 1
                prev = str(record.get("hash") or prev)
        return seq, prev

    @staticmethod
    def _digest(record: dict[str, Any]) -> str:
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """Write one line. Returns the record as written (including its digest)."""
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **{k: redact(v) for k, v in fields.items()},
        }
        with self._lock:
            entry["seq"] = self._seq
            if self.hash_chain:
                entry["prev_hash"] = self._prev
                entry["hash"] = self._digest(entry)
            line = json.dumps(entry, default=str, ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._seq += 1
            if self.hash_chain:
                self._prev = entry["hash"]
        return entry

    # -- convenience writers ----------------------------------------------- #

    def tool_call(
        self,
        *,
        tool: str,
        phase: str,
        mode: str,
        targets: list[str],
        args: dict[str, Any] | None = None,
        command: str | None = None,
        scope_verdicts: list[dict[str, Any]] | None = None,
        approval: dict[str, Any] | None = None,
        outcome: str = "ok",
        error: str | None = None,
        error_code: str | None = None,
        exit_code: int | None = None,
        duration_ms: int | None = None,
        rate_wait_ms: int | None = None,
        output_hash: str | None = None,
        output_bytes: int | None = None,
        job_id: str | None = None,
        findings: int | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "tool_call",
            tool=tool,
            phase=phase,
            mode=mode,
            targets=targets,
            args=args or {},
            command=command,
            scope_verdicts=scope_verdicts or [],
            approval=approval,
            outcome=outcome,
            error=error,
            error_code=error_code,
            exit_code=exit_code,
            duration_ms=duration_ms,
            rate_wait_ms=rate_wait_ms,
            output_hash=output_hash,
            output_bytes=output_bytes,
            job_id=job_id,
            findings=findings,
            scope_fingerprint=self.scope_fingerprint,
        )

    def llm_call(
        self,
        *,
        tier: str,
        model: str,
        phase: str,
        prompt_tokens: int,
        completion_tokens: int,
        usd: float,
        purpose: str = "",
        fallback_used: str | None = None,
        cached_tokens: int = 0,
        cache_discount: float = 0.0,
    ) -> dict[str, Any]:
        return self.record(
            "llm_call",
            tier=tier,
            model=model,
            phase=phase,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            usd=round(usd, 6),
            purpose=purpose,
            fallback_used=fallback_used,
            cached_tokens=cached_tokens,
            cache_discount=round(cache_discount, 6),
        )

    # -- reading ----------------------------------------------------------- #

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return out

    def tail(self, count: int = 20) -> list[dict[str, Any]]:
        return self.read_all()[-count:]

    def verify(self) -> tuple[bool, str]:
        """Re-walk the chain. Returns ``(ok, message)``."""
        if not self.hash_chain:
            return True, "hash chain disabled"
        prev = _GENESIS
        for index, record in enumerate(self.read_all()):
            if record.get("prev_hash") != prev:
                return False, f"chain break at line {index + 1}: prev_hash mismatch"
            claimed = record.get("hash")
            recomputed = self._digest({k: v for k, v in record.items() if k != "hash"})
            if claimed != recomputed:
                return False, f"tampered line {index + 1}: digest mismatch"
            prev = str(claimed)
        return True, "chain intact"

    def stats(self) -> dict[str, Any]:
        records = self.read_all()
        calls = [r for r in records if r.get("event") == "tool_call"]
        refusals = [r for r in calls if r.get("outcome") == "refused"]
        by_tool: dict[str, int] = {}
        for record in calls:
            by_tool[str(record.get("tool"))] = by_tool.get(str(record.get("tool")), 0) + 1
        return {
            "path": str(self.path),
            "records": len(records),
            "tool_calls": len(calls),
            "refusals": len(refusals),
            "llm_calls": sum(1 for r in records if r.get("event") == "llm_call"),
            "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])),
            "chain_ok": self.verify()[0],
        }

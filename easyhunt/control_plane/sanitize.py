"""Argument sanitizer — reject, never "clean and run".

Two layers, both enforced server-side:

1. **Global rules.** Characters that could break out of an argument, and flags
   whose purpose is to write, execute, or disrupt, are refused for every tool.
   There is no relaxation path for shell control characters.
2. **Per-tool allowlists.** Each wrapped tool registers an :class:`ArgPolicy`
   naming the flags it may use, the shape of each value, and numeric ceilings.
   A flag that is not on the list is refused even if it is harmless.

Commands are executed with an argv list, never a shell string, so the character
rules are defense in depth rather than the only barrier — which is the point.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from easyhunt.errors import SanitizeError

__all__ = [
    "ArgPolicy",
    "get_policy",
    "register_policy",
    "sanitize_argv",
    "sanitize_path",
    "sanitize_text",
    "sanitize_value",
]

# Never permitted in any argument value, under any policy. These are the
# characters that let one command become two.
HARD_DENY_CHARS = frozenset(";|&\n\r\x00\v\f")
HARD_DENY_SUBSTRINGS = ("$(", "`", "${", "&&", "||", ">>", "<<", "\\x00")

# Permitted only when a tool's policy explicitly relaxes them (e.g. a tool that
# takes a regex needs parentheses; nothing needs a backtick).
SOFT_DENY_CHARS = frozenset("$()<>'\"\\")

# Flags refused for every tool, regardless of what its policy says. Grouped by
# what they do rather than by tool, because the same footgun keeps recurring.
GLOBAL_DENIED_FLAGS: dict[str, str] = {
    # Remote command execution / shells
    "--os-shell": "spawns an OS shell on the target",
    "--os-pwn": "attempts OOB shell / Meterpreter on the target",
    "--os-cmd": "executes an OS command on the target",
    "--os-bof": "buffer-overflow exploitation",
    "--sql-shell": "interactive SQL shell on the target",
    "--priv-esc": "privilege escalation on the target",
    "--eval": "evaluates arbitrary code",
    # Note: short flags like -c are deliberately NOT here. Their meaning is
    # per-tool (-c is concurrency for nuclei, a command for a shell), and since
    # argv never reaches a shell, the per-tool allowlist is the correct control.
    # A global list should only hold flags that are dangerous in every tool.
    # Writing to the target
    "--file-write": "writes a file to the target host",
    "--file-dest": "writes a file to the target host",
    "--file-upload": "uploads a file to the target host",
    # Destructive local/remote operations
    "--delete": "destructive operation",
    "--purge": "destructive operation",
    "--overwrite": "destructive operation",
    # Disruption
    "--flood": "volumetric disruption",
    "--dos": "volumetric disruption",
    # Scope / safety evasion. Refused on principle: building an evasion path is
    # out of bounds for this project even when a tool offers one.
    "--random-agent": "defeats the tagged user-agent the program uses to identify us",
    "--tor": "anti-attribution",
    "--proxy-chain": "anti-attribution",
    "--check-tor": "anti-attribution",
}

# Substring markers inside a *value* that indicate the same problems as above.
DENIED_VALUE_MARKERS: dict[str, str] = {
    "/etc/shadow": "credential file read",
    "/etc/passwd": "credential file read attempt (use a dedicated LFI PoC instead)",
    "id_rsa": "private key exfiltration",
}

_FLAG_RE = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass
class ArgPolicy:
    """What one tool is allowed to be asked to do.

    ``allowed_flags`` is an allowlist: anything absent is refused. ``value_patterns``
    maps a flag to a regex its value must fully match. ``numeric_caps`` maps a flag
    to an inclusive maximum — this is where request-rate and thread ceilings live,
    so a tool cannot be talked into out-running the program's rate limit.
    """

    tool: str
    allowed_flags: set[str] = field(default_factory=set)
    denied_flags: set[str] = field(default_factory=set)
    boolean_flags: set[str] = field(default_factory=set)
    value_patterns: dict[str, re.Pattern[str]] = field(default_factory=dict)
    numeric_caps: dict[str, float] = field(default_factory=dict)
    denied_values: dict[str, set[str]] = field(default_factory=dict)
    allow_positional: bool = False
    positional_pattern: re.Pattern[str] | None = None
    max_argv: int = 64
    # Soft-deny characters this tool genuinely needs (e.g. regex parentheses).
    relaxed_chars: frozenset[str] = frozenset()

    def describe(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "allowed_flags": sorted(self.allowed_flags),
            "denied_flags": sorted(self.denied_flags),
            "numeric_caps": self.numeric_caps,
            "allow_positional": self.allow_positional,
        }


_POLICIES: dict[str, ArgPolicy] = {}


def register_policy(policy: ArgPolicy) -> ArgPolicy:
    """Register (or replace) a tool's argument policy."""
    _POLICIES[policy.tool] = policy
    return policy


def get_policy(tool: str) -> ArgPolicy | None:
    return _POLICIES.get(tool)


def known_policies() -> list[str]:
    return sorted(_POLICIES)


# --------------------------------------------------------------------------- #
# Value-level checks
# --------------------------------------------------------------------------- #


def sanitize_value(
    value: Any,
    *,
    name: str = "value",
    tool: str | None = None,
    relaxed_chars: frozenset[str] = frozenset(),
    max_length: int = 4096,
) -> str:
    """Validate a single scalar argument value. Returns it unchanged or raises.

    Deliberately does not modify the value: a caller that quietly strips a
    semicolon teaches the agent that malformed input sometimes works.
    """
    if value is None:
        raise SanitizeError(f"{name}: value is required", tool=tool, arg=name)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        raise SanitizeError(
            f"{name}: expected a string, got {type(value).__name__}", tool=tool, arg=name
        )

    if len(value) > max_length:
        raise SanitizeError(
            f"{name}: value exceeds {max_length} characters", tool=tool, arg=name, length=len(value)
        )

    bad = sorted(set(value) & HARD_DENY_CHARS)
    if bad:
        raise SanitizeError(
            f"{name}: shell control character(s) {bad!r} are never permitted",
            tool=tool,
            arg=name,
            chars=bad,
        )
    for marker in HARD_DENY_SUBSTRINGS:
        if marker in value:
            raise SanitizeError(
                f"{name}: substring {marker!r} is never permitted", tool=tool, arg=name
            )

    soft = sorted((set(value) & SOFT_DENY_CHARS) - set(relaxed_chars))
    if soft:
        raise SanitizeError(
            f"{name}: character(s) {soft!r} are not permitted for this tool "
            "(a tool that needs them must declare relaxed_chars in its ArgPolicy)",
            tool=tool,
            arg=name,
            chars=soft,
        )

    lowered = value.lower()
    for marker, why in DENIED_VALUE_MARKERS.items():
        if marker in lowered:
            raise SanitizeError(f"{name}: refused — {why}", tool=tool, arg=name, marker=marker)

    return value


def sanitize_text(value: Any, *, name: str = "text", max_length: int = 20_000) -> str:
    """Validate a free-form text argument that never reaches a subprocess.

    PoC steps, triage notes, and report prose legitimately contain quotes,
    parentheses, and ``$`` — applying shell rules to them blocks real content for
    no benefit, because these values are stored as JSON and rendered into
    Markdown, never executed.

    What *is* enforced: a length cap, and rejection of NUL and control characters
    that would corrupt the audit log or the report. Prompt-injection markers are
    handled separately, at the point where text enters a model's context
    (``util.parse.sanitize_for_model``), because stripping them here would mangle
    a legitimate finding about prompt injection.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if len(value) > max_length:
        raise SanitizeError(
            f"{name}: text exceeds {max_length} characters", arg=name, length=len(value)
        )
    bad = sorted({c for c in value if ord(c) < 32 and c not in "\n\r\t"} | ({"\x00"} & set(value)))
    if bad:
        raise SanitizeError(
            f"{name}: control character(s) {bad!r} are not permitted in text", arg=name
        )
    return value


def sanitize_path(value: str, *, workspace: Path, name: str = "path", must_exist: bool = False) -> Path:
    """Confine a filesystem argument to the engagement workspace.

    Blocks traversal and absolute escapes, so a tool cannot be pointed at
    ``/root/.ssh`` by way of an innocuous-looking ``-o`` flag.
    """
    sanitize_value(value, name=name)
    if "\x00" in value:
        raise SanitizeError(f"{name}: NUL byte in path", arg=name)
    candidate = Path(value).expanduser()
    root = workspace.resolve()
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not resolved.is_relative_to(root):
        raise SanitizeError(
            f"{name}: path escapes the engagement workspace",
            arg=name,
            path=str(resolved),
            workspace=str(root),
        )
    if must_exist and not resolved.exists():
        raise SanitizeError(f"{name}: path does not exist", arg=name, path=str(resolved))
    return resolved


# --------------------------------------------------------------------------- #
# argv-level checks
# --------------------------------------------------------------------------- #


def sanitize_argv(tool: str, argv: list[str], *, policy: ArgPolicy | None = None) -> list[str]:
    """Validate a full argument vector against the tool's policy.

    The vector must not include the binary name — pass only its arguments. Returns
    the vector unchanged on success; raises :class:`SanitizeError` otherwise.
    """
    policy = policy or get_policy(tool)
    if policy is None:
        raise SanitizeError(
            f"no argument policy registered for tool {tool!r}; refusing to execute it",
            tool=tool,
        )
    if not isinstance(argv, list):
        raise SanitizeError("argv must be a list of strings", tool=tool)
    if len(argv) > policy.max_argv:
        raise SanitizeError(
            f"argv too long ({len(argv)} > {policy.max_argv})", tool=tool, length=len(argv)
        )

    index = 0
    while index < len(argv):
        item = argv[index]
        if not isinstance(item, str):
            raise SanitizeError(
                f"argv[{index}]: expected a string, got {type(item).__name__}", tool=tool
            )

        if _FLAG_RE.match(item):
            flag = item
            if flag in GLOBAL_DENIED_FLAGS:
                raise SanitizeError(
                    f"{flag} is globally denied: {GLOBAL_DENIED_FLAGS[flag]}",
                    tool=tool,
                    flag=flag,
                )
            if flag in policy.denied_flags:
                raise SanitizeError(f"{flag} is denied for {tool}", tool=tool, flag=flag)
            if flag not in policy.allowed_flags:
                raise SanitizeError(
                    f"{flag} is not on the allowlist for {tool}",
                    tool=tool,
                    flag=flag,
                    allowed=sorted(policy.allowed_flags),
                )
            if flag in policy.boolean_flags:
                index += 1
                continue

            if index + 1 >= len(argv):
                raise SanitizeError(f"{flag} requires a value", tool=tool, flag=flag)
            raw_value = argv[index + 1]
            value = sanitize_value(
                raw_value, name=flag, tool=tool, relaxed_chars=policy.relaxed_chars
            )
            _check_flag_value(tool, policy, flag, value)
            index += 2
            continue

        # Positional argument.
        if not policy.allow_positional:
            raise SanitizeError(
                f"positional argument {item!r} not permitted for {tool}", tool=tool, value=item
            )
        value = sanitize_value(
            item, name=f"argv[{index}]", tool=tool, relaxed_chars=policy.relaxed_chars
        )
        if policy.positional_pattern and not policy.positional_pattern.fullmatch(value):
            raise SanitizeError(
                f"positional argument {item!r} does not match the permitted shape for {tool}",
                tool=tool,
                value=item,
                pattern=policy.positional_pattern.pattern,
            )
        index += 1

    return argv


def _check_flag_value(tool: str, policy: ArgPolicy, flag: str, value: str) -> None:
    denied = policy.denied_values.get(flag)
    if denied:
        # Comma-separated lists are the norm for tags/severities/methods.
        for part in (p.strip().lower() for p in value.split(",")):
            if part in denied:
                raise SanitizeError(
                    f"{flag}={part!r} is denied for {tool}", tool=tool, flag=flag, value=part
                )

    pattern = policy.value_patterns.get(flag)
    if pattern and not pattern.fullmatch(value):
        raise SanitizeError(
            f"{flag}: value {value!r} does not match the permitted shape",
            tool=tool,
            flag=flag,
            pattern=pattern.pattern,
        )

    cap = policy.numeric_caps.get(flag)
    if cap is not None:
        try:
            numeric = float(value)
        except ValueError as exc:
            raise SanitizeError(
                f"{flag}: expected a number, got {value!r}", tool=tool, flag=flag
            ) from exc
        if numeric > cap:
            raise SanitizeError(
                f"{flag}={numeric:g} exceeds the ceiling of {cap:g} for {tool}",
                tool=tool,
                flag=flag,
                value=numeric,
                cap=cap,
            )
        if numeric < 0:
            raise SanitizeError(f"{flag}: negative values are not permitted", tool=tool, flag=flag)


def render_command(binary: str, argv: list[str]) -> str:
    """Shell-quoted rendering of a command, for the audit log and the report.

    Display only — execution always uses the argv list.
    """
    return " ".join(shlex.quote(part) for part in [binary, *argv])

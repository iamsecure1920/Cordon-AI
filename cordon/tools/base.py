"""The universal tool decorator and registry.

Every capability Cordon exposes — engine, atomic wrapper, or plugin — is
declared with :func:`cordon_tool`. The decorator runs a fixed sequence around
the function body, and there is no argument, flag, or debug mode that skips any
step of it:

    scope → sanitize → budget → rate-limit → approval → sandbox exec
          → parse/normalize → audit → structured return

Because the sequence lives here rather than in each wrapper, adding the fortieth
tool cannot accidentally add the first unguarded one. A wrapper that forgets to
call the scope engine is still scope-checked; a wrapper that returns 400 MB is
still capped; a wrapper that raises is still audited.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cordon.control_plane.approval import ApprovalRequest
from cordon.control_plane.context import Engagement, get_engagement
from cordon.control_plane.sandbox import ExecPlan
from cordon.control_plane.sanitize import (
    ArgPolicy,
    register_policy,
    sanitize_argv,
    sanitize_text,
    sanitize_value,
)
from cordon.errors import CordonError, ToolUnavailable
from cordon.util.parse import cap_payload, sanitize_for_model
from cordon.util.run import ProcResult, run_process

__all__ = [
    "REGISTRY",
    "RegisteredTool",
    "ToolSpec",
    "cordon_tool",
    "guarded_run",
    "registered_tools",
]

Mode = Literal["passive", "aggressive", "exploit"]


@dataclass
class ToolSpec:
    """Static facts about an underlying binary or library.

    ``license`` is recorded because several tools in this space are AGPL-3.0
    (TruffleHog, PMapper) or OSS-core with proprietary backends, and that matters
    the moment anyone redistributes an Cordon bundle.
    """

    name: str
    binary: str | None = None
    package: str | None = None
    image: str | None = None
    license: str = "unknown"
    homepage: str = ""
    version_args: list[str] = field(default_factory=lambda: ["-version"])
    #: Substring expected in the binary's version output. Several security tools
    #: share a name with something else on PATH — ``httpx`` is both
    #: ProjectDiscovery's prober and the Python HTTP library's CLI — and running
    #: the wrong one produces confusing empty results rather than a clear error.
    identity_marker: str | None = None
    capabilities: list[str] = field(default_factory=list)
    network: str | None = None
    # Flag through which the engagement's tagged user-agent is injected.
    user_agent_flag: str | None = None
    arg_policy: ArgPolicy | None = None

    def __post_init__(self) -> None:
        if self.arg_policy is not None:
            # `guarded_run` injects the engagement user-agent through this flag,
            # so the policy must expect a header value there. Declaring it here
            # rather than in ~20 individual policies means the rule cannot drift
            # from the code that actually builds the argument: the flag that
            # carries a header is, by construction, the flag checked as one.
            if self.user_agent_flag:
                self.arg_policy.header_flags.add(self.user_agent_flag)
            register_policy(self.arg_policy)


@dataclass
class RegisteredTool:
    """A tool as the MCP server sees it."""

    name: str
    fn: Callable[..., Awaitable[Any]]
    phase: str
    mode: Mode
    description: str
    targets_arg: str | None
    timeout: float
    spec: ToolSpec | None
    tags: set[str]
    estimated_requests: int | None
    risk_notes: list[str]
    origin: str = "builtin"

    def definition(self) -> dict[str, Any]:
        """Canonical description, hashed for supply-chain pinning (Stage 16)."""
        signature = inspect.signature(self.fn)
        return {
            "name": self.name,
            "phase": self.phase,
            "mode": self.mode,
            "description": (self.description or "").strip(),
            "targets_arg": self.targets_arg,
            "timeout": self.timeout,
            "params": [
                {
                    "name": p.name,
                    "annotation": str(p.annotation),
                    "default": "<required>" if p.default is inspect.Parameter.empty else repr(p.default),
                }
                for p in signature.parameters.values()
                if p.name not in {"ctx", "self"}
            ],
            "binary": self.spec.binary if self.spec else None,
            "image": self.spec.image if self.spec else None,
            "license": self.spec.license if self.spec else "unknown",
        }


REGISTRY: dict[str, RegisteredTool] = {}


def registered_tools(*, phase: str | None = None, mode: str | None = None) -> list[RegisteredTool]:
    tools = list(REGISTRY.values())
    if phase:
        tools = [t for t in tools if t.phase == phase]
    if mode:
        tools = [t for t in tools if t.mode == mode]
    return sorted(tools, key=lambda t: (t.phase, t.name))


def _collect_targets(value: Any) -> list[str]:
    """Flatten whatever a caller passed into the targets argument."""
    if value is None:
        return []
    if isinstance(value, str):
        # Agents habitually pass comma- or newline-separated lists.
        parts = [p.strip() for p in value.replace("\n", ",").split(",")]
        return [p for p in parts if p]
    if isinstance(value, Sequence):
        out: list[str] = []
        for item in value:
            out.extend(_collect_targets(item))
        return out
    return [str(value)]


def cordon_tool(
    *,
    phase: str,
    mode: Mode = "passive",
    targets_arg: str | None = "target",
    timeout: float = 1800.0,
    name: str | None = None,
    spec: ToolSpec | None = None,
    tags: set[str] | None = None,
    estimated_requests: int | None = None,
    risk_notes: Sequence[str] = (),
    rationale: str = "",
    origin: str = "builtin",
    text_args: Sequence[str] = (),
    budget_exempt: bool = False,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a capability in the control plane and register it.

    ``mode`` decides whether a human is consulted:

    * ``passive``    — read-only or observational; runs automatically.
    * ``aggressive`` — state-touching, noisy, or high request volume; gated.
    * ``exploit``    — proves a vulnerability; gated, and additionally refused
      outright when the engagement's rules disallow exploitation.

    ``text_args`` names arguments that carry free-form prose (PoC steps, notes)
    and are never used to build a command line. They skip shell-character
    sanitization — which would otherwise reject an apostrophe in a sentence — and
    get length and control-character validation instead. Only list an argument
    here if it genuinely never reaches a subprocess.

    ``budget_exempt`` skips the spend ceiling for tools that consume no external
    resource — report generation and findings inspection. Those are precisely the
    tools you need *after* a budget ceiling has fired, so gating them would turn a
    clean abort into a run with nothing to show for it. Never set it on anything
    that sends a request or calls a model.
    """
    text_arg_names = set(text_args)

    def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        tool_name = name or fn.__name__
        description = inspect.cleandoc(fn.__doc__ or "")

        @functools.wraps(fn)
        async def wrapper(*args: Any, ctx: Any = None, **kwargs: Any) -> Any:
            engagement = get_engagement()
            started = time.monotonic()

            bound = _bind(fn, args, kwargs)
            targets = _collect_targets(bound.get(targets_arg)) if targets_arg else []

            audit_base: dict[str, Any] = {
                "tool": tool_name,
                "phase": phase,
                "mode": mode,
                "targets": targets,
                "args": {k: v for k, v in bound.items() if k != "ctx"},
            }
            # With OAuth enabled, "who ran this scan" has an answer beyond
            # "whoever had access to the machine".
            identity = _caller_identity()
            if identity:
                audit_base["caller"] = identity

            def refuse(exc: Exception, verdicts: list[dict[str, Any]] | None = None) -> None:
                engagement.audit.tool_call(
                    **audit_base,
                    scope_verdicts=verdicts or [],
                    outcome="refused",
                    error=str(exc),
                    error_code=getattr(exc, "code", exc.__class__.__name__),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )

            # 1. Scope. Every target, denylist first, fail closed.
            verdicts: list[dict[str, Any]] = []
            try:
                if targets_arg is not None:
                    # "auto"/""/"-" are the inherit-from-asset-store sentinels
                    # (see tools.common.targets_or_assets). They are not
                    # targets: scope-checking them literally would refuse the
                    # call before the tool can resolve them against the
                    # engagement's discovered assets — and the resolved
                    # targets are themselves scope-checked inside the wrapper.
                    sentinel = {t.strip().lower() for t in targets if t.strip().lower() in {"auto", "-"}}
                    checkable = [t for t in targets if t.strip().lower() not in {"auto", "-"}]
                    if not targets:
                        raise CordonError(
                            f"{tool_name}: no target supplied to a scope-checked tool",
                            tool=tool_name,
                        )
                    if checkable:
                        verdicts = [v.to_dict() for v in engagement.scope.assert_all_in_scope(checkable)]
                    elif not sentinel:
                        raise CordonError(
                            f"{tool_name}: no target supplied to a scope-checked tool",
                            tool=tool_name,
                        )
            except Exception as exc:
                refuse(exc, getattr(exc, "details", {}).get("refused"))
                raise

            # 2. Sanitize every string the caller supplied. Tool-specific argv
            #    checks happen again inside guarded_run.
            relaxed = spec.arg_policy.relaxed_chars if spec and spec.arg_policy else frozenset()
            try:
                for key, value in bound.items():
                    if key in {"ctx", targets_arg}:
                        continue
                    for item in value if isinstance(value, (list, tuple)) else [value]:
                        if not isinstance(item, str):
                            continue
                        if key in text_arg_names:
                            # Free-form prose: never reaches a subprocess, so shell
                            # rules would only block legitimate content.
                            sanitize_text(item, name=key)
                        else:
                            sanitize_value(item, name=key, tool=tool_name, relaxed_chars=relaxed)
            except Exception as exc:
                refuse(exc, verdicts)
                raise

            # 3. Budget, before any work is issued. Tools that spend nothing are
            #    exempt: report_generate and the findings inspectors are how an
            #    operator recovers from an exhausted budget, so gating them would
            #    make "abort cleanly with a partial report" impossible.
            if not budget_exempt:
                try:
                    engagement.budget.check(need_requests=estimated_requests or 0)
                except Exception as exc:
                    refuse(exc, verdicts)
                    raise

            # 4/5. Rate limit, then approval. Approval is inside the concurrency
            #      slot so a queue of pending prompts cannot bypass the ceiling.
            host = targets[0] if targets else None
            # The declared request count is the price of the call. `slot()` has
            # accepted a `cost` since it was written and no caller ever passed
            # one, so every tool was charged a single token: `ssrf_probe`, which
            # sends 8,283 requests, cost exactly what one `dig` cost. The limiter
            # then reported a compliant engagement on traffic three orders of
            # magnitude past the ceiling.
            #
            # Tools that declare nothing still cost 1. That is the honest floor —
            # a call was made — and it keeps every existing wrapper working while
            # the estimates are filled in.
            cost = float(estimated_requests or 1)
            try:
                async with engagement.limiter.slot(
                    host=host, cost=cost, tool=tool_name
                ) as waited:
                    approval_record: dict[str, Any] | None = None
                    if mode != "passive":
                        why = rationale or (description.splitlines()[0] if description else "")
                        decision = await engagement.approval.require(
                            ApprovalRequest(
                                tool=tool_name,
                                phase=phase,
                                mode=mode,
                                targets=targets,
                                rationale=why,
                                risk_notes=list(risk_notes),
                                estimated_requests=estimated_requests,
                            ),
                            ctx,
                        )
                        approval_record = decision.to_dict()

                    # 6. The tool body (which runs the sandboxed process).
                    if _wants_ctx(fn):
                        kwargs["ctx"] = ctx
                    result = await fn(*args, **kwargs)
            except Exception as exc:
                engagement.audit.tool_call(
                    **audit_base,
                    scope_verdicts=verdicts,
                    outcome="refused" if isinstance(exc, CordonError) else "error",
                    error=str(exc),
                    error_code=getattr(exc, "code", exc.__class__.__name__),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                raise

            # 7. Normalize, defang, and cap. Never return raw megabytes over MCP,
            #    and never return target-controlled text that reads as instructions.
            duration = time.monotonic() - started
            if engagement.config.get("hardening.sanitize_tool_output", True):
                result = _defang(result)
            payload, truncated = cap_payload(result, max_bytes=engagement.max_payload_bytes)
            if isinstance(payload, dict):
                payload.setdefault("tool", tool_name)
                payload.setdefault("phase", phase)
                if truncated:
                    payload["truncated"] = True

            # 8. Audit the success too.
            engagement.budget.charge_tool(seconds=duration, requests=estimated_requests or 1)
            engagement.audit.tool_call(
                **audit_base,
                scope_verdicts=verdicts,
                approval=approval_record,
                outcome="ok",
                duration_ms=int(duration * 1000),
                rate_wait_ms=int(waited * 1000),
                findings=_count_findings(result),
            )
            return payload

        # Expose ctx to FastMCP without forcing every tool body to accept it.
        _add_ctx_parameter(wrapper, fn)

        REGISTRY[tool_name] = RegisteredTool(
            name=tool_name,
            fn=wrapper,
            phase=phase,
            mode=mode,
            description=description,
            targets_arg=targets_arg,
            timeout=timeout,
            spec=spec,
            tags=set(tags or ()),
            estimated_requests=estimated_requests,
            risk_notes=list(risk_notes),
            origin=origin,
        )
        return wrapper

    return decorator


def _bind(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Resolve positional and keyword arguments into a name→value mapping."""
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        return dict(kwargs)


def _wants_ctx(fn: Callable[..., Any]) -> bool:
    return "ctx" in inspect.signature(fn).parameters


def _add_ctx_parameter(wrapper: Callable[..., Any], fn: Callable[..., Any]) -> None:
    """Give the wrapper a ``ctx`` parameter so FastMCP can inject the session.

    FastMCP excludes Context-annotated parameters from the JSON schema, so this
    stays invisible to the calling agent.
    """
    from fastmcp import Context

    signature = inspect.signature(fn)
    params = [p for p in signature.parameters.values() if p.name != "ctx"]
    params.append(
        inspect.Parameter(
            "ctx", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=Context | None
        )
    )
    wrapper.__signature__ = signature.replace(parameters=params)  # type: ignore[attr-defined]
    annotations = dict(getattr(fn, "__annotations__", {}))
    annotations["ctx"] = Context | None
    wrapper.__annotations__ = annotations


# Keys whose values are our own generated guidance, not target-controlled text.
# Defanging them would mangle the instructions we wrote for the agent.
_TRUSTED_KEYS = frozenset(
    {"note", "next_step", "notes", "warning", "message", "hint", "coverage_note",
     "reminder", "impact_limit", "do_not", "steps", "proof_content"}
)

# Below this length, a string cannot plausibly carry an injection payload and
# scanning it wastes time on large result sets.
_DEFANG_MIN_LENGTH = 24


def _defang(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Neutralize prompt-injection markers in target-controlled strings.

    Applied to every tool result before it reaches the agent. A page title, an
    HTTP response, or a DNS TXT record is data the target controls, and it lands
    verbatim in a context window if nothing strips it first.

    Values under our own trusted keys are left alone — those are the guidance
    strings this codebase wrote, and rewriting them would defeat the point.
    """
    if depth > 12:
        return value
    if isinstance(value, str):
        if key in _TRUSTED_KEYS or len(value) < _DEFANG_MIN_LENGTH:
            return value
        return sanitize_for_model(value, max_lines=10_000, max_chars=len(value) + 1)
    if isinstance(value, dict):
        return {k: _defang(v, key=str(k), depth=depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_defang(v, key=key, depth=depth + 1) for v in value]
    return value


def _caller_identity() -> dict[str, Any] | None:
    """Authenticated caller, when the remote transport is in use. None on stdio."""
    try:
        from cordon.control_plane.auth import current_identity

        return current_identity()
    except Exception:  # noqa: BLE001 — identity is never worth failing a call over
        return None


def _count_findings(result: Any) -> int | None:
    if isinstance(result, dict):
        for key in ("findings", "results", "events", "assets"):
            value = result.get(key)
            if isinstance(value, list):
                return len(value)
        count = result.get("count")
        if isinstance(count, int):
            return count
    return None


# --------------------------------------------------------------------------- #
# Sandboxed execution helper
# --------------------------------------------------------------------------- #

#: Host directories to expose, read-only, to the container that runs each tool,
#: as ``tool -> [(host path, container path)]``.
#:
#: Containers ship the binary and nothing else. Without these mounts a
#: containerised subfinder finds no config and no API keys, and a containerised
#: nuclei finds none of the 13,391 templates on the host — and because
#: ``-disable-update-check`` stops it fetching them, it exits with "no templates
#: provided for scan". Both failures are quiet enough to read as "this estate is
#: clean" rather than "the tool never ran".
_CONTAINER_MOUNTS: dict[str, list[tuple[str, str]]] = {
    "subfinder": [("~/.config/subfinder", "/root/.config/subfinder")],
    "amass": [("~/.config/amass", "/root/.config/amass")],
    "nuclei": [
        ("~/.config/nuclei", "/root/.config/nuclei"),
        # The template library is the tool. Without it nuclei is an empty shell.
        ("~/nuclei-templates", "/root/nuclei-templates"),
        # nuclei initialises uncover's provider config even when uncover is unused.
        ("~/.config/uncover", "/root/.config/uncover"),
    ],
    "httpx": [("~/.config/httpx", "/root/.config/httpx")],
    "katana": [("~/.config/katana", "/root/.config/katana")],
    "naabu": [("~/.config/naabu", "/root/.config/naabu")],
    "dnsx": [("~/.config/dnsx", "/root/.config/dnsx")],
    "uncover": [("~/.config/uncover", "/root/.config/uncover")],
    "notify": [("~/.config/notify", "/root/.config/notify")],
}


def register_container_mount(tool: str, host_path: str | Path, container_path: str) -> None:
    """Declare a read-only mount for a tool whose data lives outside the image.

    The table above is static because those paths are fixed. An
    operator-supplied tool is not: its location comes from an environment
    variable or a search path resolved at runtime, so it registers itself at
    import time instead of being hard-coded here.

    It still goes through the same chokepoint and is still mounted read-only.
    The alternative — letting such a tool run unsandboxed because the image does
    not contain it — is how a wrapper quietly stops being governed.
    """
    entry = (str(host_path), container_path)
    existing = _CONTAINER_MOUNTS.setdefault(tool, [])
    if entry not in existing:
        existing.append(entry)


def _config_mounts(tool: str) -> list[tuple[Path, str, str]]:
    """Read-only mounts carrying a tool's host config and data into its container.

    Read-only on purpose: a tool must not be able to rewrite the operator's
    credentials, and nothing in a scan should mutate configuration or templates.

    Absent host paths are skipped rather than mounted. Mounting a non-existent
    path makes Docker create an empty directory, which looks configured and
    behaves as if it were not.
    """
    mounts: list[tuple[Path, str, str]] = []
    for host_path, container_path in _CONTAINER_MOUNTS.get(tool, []):
        host = Path(host_path).expanduser()
        if host.is_dir():
            mounts.append((host, container_path, "ro"))
    return mounts


async def guarded_run(
    spec: ToolSpec,
    argv: list[str],
    *,
    timeout: float = 900.0,
    stdin: str | None = None,
    output_name: str | None = None,
    engagement: Engagement | None = None,
    allow_codes: tuple[int, ...] = (0,),
    check: bool = True,
) -> ProcResult:
    """Sanitize, sandbox, and execute one command.

    Wrappers call this instead of touching :mod:`subprocess`. The argv is
    re-checked against the tool's own policy here, so a wrapper that builds
    arguments from parsed tool output (a very easy way to reintroduce injection)
    is still covered.
    """
    engagement = engagement or get_engagement()
    if spec.binary is None and spec.image is None:
        raise ToolUnavailable(f"{spec.name}: no binary or image declared", tool=spec.name)

    sanitize_argv(spec.name, argv, policy=spec.arg_policy)

    # Inject the engagement's tagged user-agent where the tool supports one, so
    # the target can attribute the traffic and the program can allowlist it.
    #
    # A generic header flag (-H/--header) needs full 'Name: value' syntax. Passing
    # the bare agent string there produces a malformed header, which looks like
    # attribution while sending none — so the two flag styles are distinguished.
    final_argv = list(argv)
    rules = engagement.scope.rules
    if spec.user_agent_flag and spec.user_agent_flag not in final_argv:
        header_style = spec.user_agent_flag in {"-H", "--header", "-header"}
        final_argv += [
            spec.user_agent_flag,
            f"User-Agent: {rules.user_agent}" if header_style else rules.user_agent,
        ]
        # Headers the program mandates for attribution. Only tools that take a
        # generic header flag can carry them; the rest are reported by
        # `scope validate` so the gap is visible rather than silent.
        if header_style:
            for header in rules.required_headers:
                if header not in final_argv:
                    final_argv += [spec.user_agent_flag, header]

    # Two different questions, and they had one answer between them.
    #
    # `binary` is the NAME the tool is known by. Inside a container that is all
    # that means anything: the image has its own layout and PATH.
    #
    # `host_binary` is the identity-resolved absolute path, used only when the
    # tool falls back to host execution — that is where "which of the three
    # things called httpx is the right one" matters.
    #
    # Conflating them sent an absolute host path into the container check, so
    # `command -v /usr/bin/amass` ran inside an image that keeps amass in
    # /usr/local/bin, reported it absent, and fell back to the host. amass,
    # cloud_enum, commix, garak and jaeles all escaped the sandbox this way; the
    # rest passed only because their host and image paths happened to match.
    # Found by running the toolchain against a live target, not by any test.
    binary = spec.binary or spec.name
    host_binary: str | None = None
    if spec.identity_marker:
        from cordon.tools.common import resolve_binary

        host_binary = resolve_binary(spec.name)

    plan: ExecPlan = engagement.sandbox.plan(
        tool=spec.name,
        binary=binary,
        host_binary=host_binary,
        argv=final_argv,
        network=spec.network,
        capabilities=spec.capabilities,
        extra_mounts=_config_mounts(spec.name),
    )
    output_path = engagement.raw_path(output_name or spec.name) if output_name else None
    result = await run_process(plan, timeout=timeout, stdin=stdin, output_path=output_path)
    # The audit already records the wrapper call (``tool_call``). Record which
    # *binary* actually executed too: the report's tool inventory lists catalog
    # entries (subfinder, testssl, sqlmap...) while the audit records wrappers
    # (subdomain_enum, tls_audit, sqli_validate...), so a run where every
    # wrapper succeeded showed most tools as "no" — half the installed fleet
    # looked unused while driving the entire engagement.
    engagement.audit.record(
        "binary_run", tool=spec.name, ran=True,
        exit_code=result.exit_code, timed_out=result.timed_out,
    )
    if check:
        result.raise_for_status(tool=spec.name, allow_codes=allow_codes)
    return result

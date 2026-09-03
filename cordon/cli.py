"""Cordon command line: doctor, scope validation, and engagement inspection.

The CLI is deliberately small. Running a scan is the agent's job through MCP —
what you need on the command line is the ability to answer "is this installed
correctly", "is my scope file sane", and "what did the last run actually do".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cordon import __version__
from cordon.errors import CordonError

GREEN, YELLOW, RED, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"


def _color(enabled: bool) -> tuple[str, str, str, str, str]:
    return (GREEN, YELLOW, RED, DIM, RESET) if enabled else ("", "", "", "", "")


def _terse_version(version: str) -> str:
    """A short version string, or a plain statement that the tool ran.

    Never invent a version: if what the tool printed is not recognisably one,
    say "responds" rather than passing off the first line of its help text as a
    release number.
    """
    if not version:
        return "responds"
    if version == "python package":
        return version
    if len(version) <= 34 and re.search(r"\d+\.\d+", version):
        return version
    return "responds"


def _print_tool_health(args: argparse.Namespace, palette: tuple[str, ...]) -> dict[str, list[str]]:
    """Execute every catalogued tool and print what each one actually did.

    The old version asked ``shutil.which()`` and printed "installed", which is a
    claim about a filename, not about a program. Four tools on the reference
    machine passed that check and died at import on every invocation; two more
    (nikto, testssl) shipped 100% non-functional for days behind the same tick.
    Execution is now the default and ``--fast`` is the opt-out, rather than the
    other way round — an honest check nobody runs protects nobody.
    """
    green, yellow, red, dim, reset = palette

    from cordon.config import Config
    from cordon.install.installer import health_check
    from cordon.tools.common import CATALOG

    execute = not args.fast

    # Probe each tool where the engagement will actually invoke it. A tool with a
    # container home is a container program; the host copy is a different file
    # that happens to share a name, and reporting on it is how sstimap passed
    # every check while crashing on every call.
    sandbox = None
    if execute:
        try:
            config = Config.load(args.config)
            if config.get("sandbox.mode", "none") == "docker":
                import tempfile

                from cordon.control_plane.sandbox import Sandbox, SandboxConfig

                # A throwaway workspace: nothing is mounted for a version probe,
                # and doctor must not create or touch an engagement directory.
                sandbox = Sandbox(
                    SandboxConfig.from_dict(config.section("sandbox")),
                    workspace=Path(tempfile.mkdtemp(prefix="cordon-doctor-")),
                )
                if not sandbox.runtime_available():
                    sandbox = None
        except CordonError:
            sandbox = None

    started = time.monotonic()
    report = health_check(execute=execute, sandbox=sandbox)
    elapsed = time.monotonic() - started

    print("External tools")
    buckets: dict[str, list[str]] = {
        "working": [], "broken": [], "wrong-tool": [],
        "unresponsive": [], "missing": [], "on-path": [],
    }
    unmarked = 0
    for health in report:
        buckets.setdefault(health.status, []).append(health.tool)
        license_name = CATALOG[health.tool].license if health.tool in CATALOG else "unknown"
        if health.ok and not health.identity_verified:
            unmarked += 1

        if health.status == "working":
            # The version was obtained anyway, so show it — but only when it
            # actually looks like one. Half these tools answer --version with a
            # usage banner, and a column of truncated help text is worse than a
            # plain statement that the thing ran.
            note = health.version if args.versions else _terse_version(health.version)
            home = "" if health.where == "host" else f" {dim}@{health.where}{reset}"
            print(
                f"  {green}✓{reset} {health.tool:18} {dim}{note}{reset}{home}"
                f"  {dim}[{license_name}]{reset}"
            )
        elif health.status == "on-path":
            print(
                f"  {yellow}?{reset} {health.tool:18} {yellow}on PATH, NOT VERIFIED{reset}"
                f"  {dim}[{license_name}]{reset}"
            )
        elif health.status == "broken":
            print(f"  {red}✗{reset} {health.tool:18} {red}BROKEN{reset} {dim}— {health.detail}{reset}")
        elif health.status == "wrong-tool":
            print(f"  {red}✗{reset} {health.tool:18} {red}WRONG TOOL{reset} {dim}— {health.detail}{reset}")
        elif health.status == "unresponsive":
            print(
                f"  {yellow}?{reset} {health.tool:18} {yellow}UNVERIFIED{reset}"
                f" {dim}— {health.detail}{reset}"
            )
        else:
            print(f"  {red}✗{reset} {health.tool:18} {dim}{health.detail}{reset}")

    total = len(report)
    if execute:
        print(
            f"\n  {green}{len(buckets['working'])} working{reset} "
            f"{dim}(executed, not just found on PATH){reset} / {total} catalogued"
        )
    else:
        print(
            f"\n  {yellow}{len(buckets['on-path'])} on PATH — NOT VERIFIED{reset} / "
            f"{total} catalogued"
        )
        print(f"    {dim}--fast skipped execution. Nothing here is a claim that a tool works.{reset}")
    for label, colour, key in (
        ("broken (runs, fails at startup)", red, "broken"),
        ("wrong tool on PATH", red, "wrong-tool"),
        ("unverified (no response)", yellow, "unresponsive"),
        ("not installed", dim, "missing"),
    ):
        if buckets[key]:
            print(f"  {colour}{len(buckets[key])} {label}{reset}: {dim}{', '.join(buckets[key])}{reset}")
    if buckets["wrong-tool"]:
        print(
            f"    {dim}A different program of the same name is on your PATH. Those "
            f"return nothing rather than erroring.{reset}"
        )
    if execute and unmarked:
        # The residual, and the reason `identity_marker` matters: running a
        # binary proves *a* program of that name responds, not that it is ours.
        print(
            f"    {dim}{unmarked} of those declare no identity_marker — execution proves "
            f"a binary of that name responds, not that it is the right program.{reset}"
        )
    print(f"    {dim}checked in {elapsed:.1f}s{reset}\n")
    return buckets


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what is installed, what is configured, and what is missing."""
    palette = _color(sys.stdout.isatty() and not args.no_color)
    green, yellow, red, dim, reset = palette

    from cordon.config import Config, find_scope
    from cordon.mcp_server import load_capabilities
    from cordon.tools.base import REGISTRY

    print(f"Cordon AI {__version__}\n")

    print("Capability modules")
    statuses = load_capabilities()
    for module, status in statuses.items():
        name = module.split(".")[-1]
        mark = f"{green}✓{reset}" if status == "loaded" else f"{yellow}!{reset}"
        detail = "" if status == "loaded" else f" {dim}{status}{reset}"
        print(f"  {mark} {name}{detail}")
    print(f"  {len(REGISTRY)} MCP tools registered\n")

    buckets = _print_tool_health(args, palette)
    missing = buckets["missing"]
    unhealthy = buckets["broken"] + buckets["wrong-tool"]

    print("Configuration")
    config = Config.load(args.config)
    print(f"  config: {config.source}")
    scope_path = find_scope(args.scope)
    if scope_path is None:
        print(f"  {yellow}!{reset} no scope.yaml found — Cordon refuses to run without one")
    else:
        try:
            from cordon.control_plane.scope import Scope

            scope = Scope.load(scope_path)
            print(f"  {green}✓{reset} scope: {scope_path} ({scope.name}, {scope.authorization})")
            for warning in scope.validate():
                print(f"    {yellow}!{reset} {warning}")
        except CordonError as exc:
            print(f"  {red}✗{reset} scope invalid: {exc}")

    sandbox_mode = config.get("sandbox.mode", "none")
    docker_ok = bool(shutil.which(config.get("sandbox.runtime", "docker")))
    if sandbox_mode == "docker" and not docker_ok:
        print(f"  {yellow}!{reset} sandbox.mode is 'docker' but the runtime is not installed")
    else:
        print(f"  {green}✓{reset} sandbox: {sandbox_mode}")

    from cordon.control_plane.auth import AuthConfig
    from cordon.control_plane.auth import describe as describe_auth

    auth_config = AuthConfig.from_dict(config.section("auth"))
    if not auth_config.enabled:
        print(
            f"  {green}✓{reset} auth: disabled {dim}(stdio only — a non-loopback bind "
            f"is refused){reset}"
        )
    else:
        posture = describe_auth(auth_config)
        print(f"  {green}✓{reset} auth: {posture['mode']} at {posture['base_url']}")
        print(f"    {dim}audience: {posture['audience']}{reset}")
        print(f"    {dim}{posture['pkce']}{reset}")
        if not auth_config.enforce_tool_scopes:
            print(
                f"    {yellow}!{reset} enforce_tool_scopes is false — any authenticated "
                "caller is fully privileged"
            )
        if auth_config.base_url.startswith("http://") and "127.0.0.1" not in auth_config.base_url:
            print(f"    {red}✗{reset} base_url is plaintext HTTP; bearer tokens are exposed")

    approval_backend = config.get("approval.backend", "deny")
    if approval_backend == "policy" and config.get("approval.policy.auto_approve"):
        print(
            f"  {yellow}!{reset} approval.backend is 'policy' with an auto_approve list — "
            "aggressive actions will run without a human"
        )
    else:
        print(f"  {green}✓{reset} approval backend: {approval_backend}")

    print("\nRules")
    from cordon.plugins.loader import load_all

    dirs = config.get("rules.dirs") or ["./rules"]
    registry = load_all(dirs, import_python=False)
    summary = registry.report.summary()
    print(f"  {green}✓{reset} {summary['loaded']} rule(s) loaded: {summary['by_kind']}")
    print(f"    custom nuclei templates: {len(registry.nuclei_paths())}")
    if summary["rejected"]:
        print(f"  {red}✗{reset} {summary['rejected']} rejected:")
        for rejection in registry.report.rejected[:10]:
            print(f"      {rejection['path']}: {rejection['error']}")

    if registry.nuclei_paths() and shutil.which("nuclei"):
        result = registry.validate_nuclei_templates()
        if result.get("problems"):
            print(f"  {red}✗{reset} nuclei -validate found problems:")
            for problem in result["problems"][:5]:
                print(f"      {problem['path']}: {problem['error'][:200]}")
        else:
            print(f"  {green}✓{reset} nuclei -validate passed on custom templates")

    print("\nLLM (OpenRouter)")
    key_env = str(config.get("llm.api_key_env", "OPENROUTER_API_KEY"))

    # The key being set is not the same as the client being able to run. The
    # `openai` package is an optional dependency, and without it every LLM path
    # — triage, report synthesis, hunt_plan — raises at call time, not at start.
    # Doctor reported the key was present and said nothing about the import, so
    # a machine with a configured key and no package looked fully working right
    # up until the first triage call failed mid-engagement.
    try:
        import openai  # noqa: F401

        client_ready = True
    except ImportError:
        client_ready = False

    if not client_ready:
        print(f"  {red}✗{reset} the 'openai' package is missing — every LLM path will")
        print(f"    {dim}raise at call time, not at startup. Install with:{reset}")
        print(f"    {dim}  pip install 'cordon-ai[llm]'{reset}")
        print(f"    {dim}Scanning and rule-based detection are unaffected.{reset}")
    elif not os.environ.get(key_env):
        print(f"  {yellow}!{reset} ${key_env} not set — triage and report synthesis are unavailable")
        print(f"    {dim}Passive recon, scanning, and rule-based detection work without it.{reset}")
    elif args.probe:
        print(f"  {dim}probing available models…{reset}")
        report = asyncio.run(_probe_models(config))
        if not report.get("ok"):
            print(f"  {red}✗{reset} {report.get('reason')}")
        else:
            print(f"  {green}✓{reset} {report['models_listed']} models available")
            for tier, info in report["tiers"].items():
                mark = green + "✓" + reset if info["model_available"] else yellow + "!" + reset
                print(f"    {mark} {tier}: {info['model']}")
                if info["dead_slugs"]:
                    print(f"      {red}dead slugs: {info['dead_slugs']}{reset}")
    else:
        print(f"  {green}✓{reset} ${key_env} is set  {dim}(--probe to verify model slugs){reset}")

    print("\nMCP registration")
    claude = shutil.which("claude")
    if not claude:
        print(f"  {yellow}!{reset} no agent CLI found; run `cordon connect` for copy-paste registration")
    else:
        try:
            proc = subprocess.run(  # noqa: S603
                [claude, "mcp", "list"], capture_output=True, text=True, timeout=20, check=False
            )
            if "cordon" in proc.stdout:
                print(f"  {green}✓{reset} cordon connected")
            else:
                print(f"  {yellow}!{reset} cordon not registered. Run:")
                print(f"      {dim}claude mcp add cordon -- python -m cordon.mcp_server{reset}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  {yellow}!{reset} could not query the claude CLI: {exc}")

    if getattr(args, "fix", False):
        print("\nRepairs")
        from cordon.install import Installer

        repairs = Installer().repair()
        if repairs:
            for item in repairs:
                print(f"  {green}✓{reset} {item}")
        else:
            print(f"  {dim}nothing to repair{reset}")
        if missing:
            print(f"  {dim}{len(missing)} tool(s) absent — run `cordon install` to add them{reset}")
    elif missing or unhealthy:
        print(f"\n  {dim}Run `cordon install` to add missing tools, "
              f"or `cordon doctor --fix` to repair what is already here.{reset}")

    print()
    if scope_path is None:
        print(f"{yellow}Doctor finished with warnings. Create a scope.yaml before running.{reset}")
        return 1
    if unhealthy:
        # A tool that resolves and then fails on every invocation is worse than
        # an absent one: absence degrades a wrapper honestly, whereas this looks
        # like a clean run that found nothing. Exit non-zero so it is not missed.
        print(
            f"{red}Doctor finished with {len(unhealthy)} tool(s) that resolve but do not "
            f"work:{reset} {', '.join(unhealthy)}"
        )
        return 1
    print(f"{green}Doctor finished.{reset} {len(missing)} optional tool(s) not installed.")
    return 0


async def _probe_models(config: Any) -> dict[str, Any]:
    """Probe model availability without needing a full engagement."""
    from cordon.llm.openrouter import LLMClient

    stub = type("Stub", (), {"config": config, "budget": None, "audit": None})()
    return await LLMClient(stub).probe()


def cmd_install(args: argparse.Namespace) -> int:
    """Install, verify, and repair the tool suite."""
    green, yellow, red, dim, reset = _color(sys.stdout.isatty() and not args.no_color)

    from cordon.install import Installer, recipes_for
    from cordon.mcp_server import load_capabilities

    load_capabilities()

    if args.category:
        selected = recipes_for(category=args.category)
        if not selected:
            from cordon.install.recipes import categories

            print(f"{red}unknown category {args.category!r}{reset}; try: {', '.join(categories())}")
            return 2
    else:
        selected = recipes_for(core_only=not args.all)

    installer = Installer(
        dry_run=args.dry_run,
        timeout=args.timeout,
        on_progress=lambda tool, message: print(f"  {dim}→ {tool}: {message}{reset}", flush=True),
    )

    runtimes = installer.runtimes()
    absent = [name for name, path in runtimes.items() if path is None]
    print(f"Cordon AI — installing {len(selected)} tool(s)")
    print(f"  runtimes: {', '.join(n for n, p in runtimes.items() if p) or 'none'}")
    if absent:
        print(f"  {yellow}!{reset} unavailable: {', '.join(absent)} — tools needing them are skipped")
    if not installer.is_root and not shutil.which("sudo"):
        print(f"  {yellow}!{reset} not root and no sudo — apt packages will be skipped")
    print()

    # Show the plan before changing anything.
    plan = installer.plan(selected)
    print(f"  already working : {len(plan['already'])}")
    print(f"  to install      : {len(plan['install'])}")
    if plan["blocked"]:
        print(f"  {yellow}blocked{reset}         : {len(plan['blocked'])}")
        for item in plan["blocked"][:8]:
            print(f"      {dim}{item}{reset}")

    if args.dry_run:
        print(f"\n{dim}Dry run — nothing was changed. Would install:{reset}")
        for tool in plan["install"]:
            print(f"    {tool}")
        return 0

    if not plan["install"] and not args.force:
        print(f"\n{green}Everything already installed.{reset} Running repairs…")
    else:
        print()

    report = installer.install_many(selected, force=args.force)
    repairs = installer.repair()

    print("\n" + "─" * 60)
    for result in report.results:
        if result.status == "installed":
            print(f"  {green}✓{reset} {result.tool:22} installed ({result.duration_s:.0f}s)")
        elif result.status == "already":
            print(f"  {dim}·{reset} {result.tool:22} already present")
        elif result.status == "skipped":
            print(f"  {dim}–{reset} {result.tool:22} {dim}{result.detail}{reset}")
        elif result.status == "unverified":
            print(f"  {yellow}!{reset} {result.tool:22} {yellow}{result.detail}{reset}")
        else:
            print(f"  {red}✗{reset} {result.tool:22} {result.detail}")
            if result.stderr:
                print(f"      {dim}{result.stderr.strip().splitlines()[-1][:120]}{reset}")

    if repairs:
        print(f"\n{green}Repairs:{reset}")
        for item in repairs:
            print(f"  • {item}")

    if report.caveats:
        print(f"\n{yellow}Worth knowing:{reset}")
        for item in report.caveats:
            print(f"  • {item}")

    status = Installer.status()
    summary = report.summary()
    print("\n" + "─" * 60)
    print(f"  {status['coverage']}% coverage — {len(status['working'])}/{status['total']} tools verified working")
    if status["core_missing"]:
        print(f"  {yellow}core tools still missing: {', '.join(status['core_missing'])}{reset}")
    if summary["failed"]:
        print(f"  {red}failed: {', '.join(summary['failed'])}{reset}")
        print(f"  {dim}re-run to retry; installs are idempotent{reset}")

    print(f"\n{dim}Next: cordon doctor{reset}")
    return 1 if summary["failed"] else 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Validate a scope file and test targets against it.

    With ``--transcribe POLICY_SOURCE``, emits a fresh scope.yaml skeleton whose
    fields are filled with the policy text the operator pasted — the operator
    still writes the in-scope entries by hand, but the engagement block, the
    out-of-scope table, and every stale/placeholder field are pre-populated from
    the source instead of being copy-pasted from the example template.
    """
    green, yellow, red, dim, reset = _color(sys.stdout.isatty() and not args.no_color)

    if getattr(args, "targets", None) and args.targets and args.targets[0] == "transcribe":
        policy_text = " ".join(args.targets[1:]).strip()
        if not policy_text:
            policy_text = sys.stdin.read().strip()
        args.transcribe = policy_text
        return _cmd_scope_transcribe(args, (green, yellow, red, dim, reset))

    from cordon.config import find_scope
    from cordon.control_plane.scope import Scope

    path = find_scope(args.scope)
    if path is None:
        print(f"{red}no scope.yaml found{reset}")
        return 2
    try:
        scope = Scope.load(path)
    except CordonError as exc:
        print(f"{red}invalid scope: {exc}{reset}")
        return 2

    print(json.dumps(scope.summary(), indent=2, default=str))
    for warning in scope.validate():
        print(f"{yellow}warning:{reset} {warning}")

    # `cordon scope validate` is what README, CLAUDE.md, docs/BOOTSTRAP.md and
    # bootstrap.sh all tell people to run. It was being parsed as a TARGET named
    # "validate", which then failed the scope check and printed
    # "REFUSED validate (unparseable_target)" — a documented command producing an
    # error that looks like the scope is broken. Treat it as the verb it reads as.
    targets = [t for t in (args.targets or []) if t.lower() != "validate"]

    if targets:
        print("\nTarget checks:")
        exit_code = 0
        for target in targets:
            verdict = scope.check(target)
            if verdict.in_scope:
                print(f"  {green}✓ IN SCOPE {reset} {target}  {dim}({verdict.matched}){reset}")
            else:
                exit_code = 1
                detail = verdict.denied_by or verdict.reason
                print(f"  {red}✗ REFUSED  {reset} {target}  {dim}({detail}){reset}")
        return exit_code
    return 0


def _cmd_scope_transcribe(args: argparse.Namespace, palette: tuple[str, ...]) -> int:
    """Write a hand-transcription scaffold, never a completed scope.

    The output still carries the shipped-template markers (example-bbp etc.)
    so ``cordon scope validate`` will refuse to bless it as an authorization
    until the operator finishes the transcription. The difference from copying
    ``scope.example.yaml`` is that everything the policy text can fill is
    already filled — engagement name, program URL, fetched_at (now), and the
    policy text itself preserved in a comment block for provenance.
    """
    from datetime import UTC, datetime

    import yaml

    policy_text = (args.transcribe or "").strip()
    if not policy_text:
        print(f"{palette[2]}transcribe needs the program policy text{palette[4]}")
        print(f"{palette[3]}Usage: cordon scope transcribe --program-url https://... \"$(cat policy.txt)\"{palette[4]}")
        return 2

    if not getattr(args, "program_url", None):
        print(f"{palette[1]}!{palette[4]} no --program-url given; using the placeholder — "
              "fill it in before validating")
    program_url = getattr(args, "program_url", None) or "https://REPLACE-ME.example/policy"

    target = Path(args.out or "scope.yaml").expanduser()
    if target.exists():
        print(f"{palette[2]}refusing to overwrite {target}{palette[4]}")
        return 2

    skeleton = {
        "version": 1,
        "engagement": {
            "name": "example-bbp",  # deliberately still the template marker
            "authorization": "bug-bounty",
            "program_url": program_url,
            "approval_ref": None,
            "fetched_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_age_days": 7,
            "refuse_when_stale": True,
            "researcher_handle": "your-handle",  # deliberately still the template marker
        },
        "in_scope": {
            "domains": ["# TRANSCRIBE: in-scope domains from the policy"],
            "wildcards": [],
            "cidrs": [],
            "ip_ranges": [],
            "regex": [],
            "urls": [],
        },
        "out_of_scope": {"domains": [], "wildcards": [], "cidrs": [], "finding_classes": []},
        "rules": {
            "wildcard_includes_apex": False,
            "deny_reserved_ips": True,
            "max_rps": 5,
            "max_concurrency": 5,
            "allow_aggressive": True,
            "allow_exploitation": False,
            "allow_self_registration": False,
            "no_dos": True,
            "user_agent": "Cordon-AI/2.0 (authorized-testing; handle=your-handle)",
            "forbidden_paths": [],
        },
    }

    lines = [
        "# Cordon AI — engagement scope (TRANSCRIPTION SCAFFOLD — NOT AN AUTHORIZATION)",
        "#",
        "# Generated by `cordon scope transcribe`. The fields below that can be",
        "# derived from the pasted policy are filled; every authorization field",
        "# still carries its template marker so `cordon scope validate` refuses",
        "# to bless this file until you finish transcribing it by hand.",
        "#",
        "# Pasted policy text (for provenance):",
    ]
    lines += [f"#   {line}" for line in policy_text.splitlines()[:200]]
    lines += ["#", yaml.safe_dump(skeleton, sort_keys=False)]

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{palette[0]}✓{palette[4]} wrote transcription scaffold to {target}")
    print(f"{palette[3]}  Fill in in_scope by hand from the policy, then run "
          f"`cordon scope validate` until the template warnings are gone.{palette[4]}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Show a summary of a finished engagement workspace."""
    workspace = Path(args.workspace)
    findings_file = workspace / "findings.json"
    if not findings_file.exists():
        print(f"no findings.json in {workspace}")
        return 2
    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    print(json.dumps(payload.get("stats", {}), indent=2))

    from cordon.control_plane.audit import AuditLog

    audit = AuditLog(workspace / "audit.jsonl")
    ok, message = audit.verify()
    print(f"\naudit chain: {'intact' if ok else 'BROKEN — ' + message}")
    print(json.dumps(audit.stats(), indent=2))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """List and validate detection rules."""
    from cordon.config import Config
    from cordon.plugins.loader import load_all

    config = Config.load(args.config)
    registry = load_all(config.get("rules.dirs") or ["./rules"], import_python=False)
    print(json.dumps(registry.summary(), indent=2, default=str))
    return 1 if registry.report.rejected else 0


def _brain_path(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    env = os.environ.get("CORDON_BRAIN_ACTIVITY")
    if env:
        return Path(env)
    return Path.home() / ".cordon" / "brain-activity.jsonl"


def _brain_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("kind") == "activity":
                events.append(record)
    except OSError:
        pass
    return events


def cmd_brain_watch(args: argparse.Namespace) -> int:
    from cordon.tools.brain_watch import brain_watch as _watch

    return _watch(args)


def cmd_brain_state(args: argparse.Namespace) -> int:
    path = _brain_path(getattr(args, "path", None))
    events = _brain_events(path)
    if not events:
        print(f"brain: no activity recorded at {path}")
        return 2
    last = events[-1]
    by_tool: dict[str, int] = {}
    findings_total = 0
    for event in events:
        tool = str(event.get("tool") or "?")
        by_tool[tool] = by_tool.get(tool, 0) + 1
        findings_total += int(event.get("findings") or 0)
    print(f"brain: sensing {len(events)} event(s) — {findings_total} finding(s) filed")
    print(f"  last: phase={last.get('phase')} tool={last.get('tool')} "
          f"outcome={last.get('outcome')}")
    print(f"  tools: {', '.join(sorted(by_tool, key=by_tool.get, reverse=True)[:8])}")
    return 0


def cmd_brain_export(args: argparse.Namespace) -> int:
    from cordon.tools.brain_export import brain_export as _export

    return _export(args)


def cmd_brain_history(args: argparse.Namespace) -> int:
    path = _brain_path(getattr(args, "path", None))
    events = _brain_events(path)
    if getattr(args, "phase", None):
        events = [e for e in events if e.get("phase") == args.phase]
    if getattr(args, "tool", None):
        events = [e for e in events if e.get("tool") == args.tool]
    if getattr(args, "outcome", None):
        events = [e for e in events if e.get("outcome") == args.outcome]
    events = events[-max(1, int(getattr(args, "limit", 30))):]
    if not events:
        print(f"brain: no matching history at {path}")
        return 2
    for event in events:
        findings = int(event.get("findings") or 0)
        mark = "★" * min(findings, 3) if findings else "·"
        ts = str(event.get("ts") or "")[11:19]
        print(f"  {ts} {str(event.get('phase') or '?'):<10} "
              f"{str(event.get('tool') or '?'):<26} {mark} {event.get('outcome')}")
    return 0

def cmd_dashboard(args: argparse.Namespace) -> int:
    from cordon.tools.dashboard import dashboard as _dashboard

    return _dashboard(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cordon",
        description="Cordon AI — agentic VAPT orchestrator (authorized testing only)",
    )
    parser.add_argument("--version", action="version", version=f"cordon {__version__}")

    # Accepted on either side of the subcommand — people type it both ways.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-color", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser(
        "doctor", parents=[common], help="check installation, config, rules, and MCP status"
    )
    doctor.add_argument("--config")
    doctor.add_argument("--scope")
    # Every tool is executed by default now, so --versions no longer changes
    # *what* is checked — only how much of the answer is printed. Kept because
    # it is in the docs and in muscle memory, and because the version string is
    # genuinely useful noise to suppress by default.
    doctor.add_argument(
        "--versions", action="store_true",
        help="print each tool's version string (tools are executed either way)",
    )
    doctor.add_argument(
        "--fast", action="store_true",
        help="skip execution: report PATH presence only, clearly marked as unverified",
    )
    doctor.add_argument("--probe", action="store_true", help="verify OpenRouter model slugs")
    doctor.add_argument(
        "--fix", action="store_true",
        help="repair what can be repaired (templates, missing deps, PATH advice)",
    )
    doctor.set_defaults(func=cmd_doctor)

    install = sub.add_parser(
        "install", parents=[common], help="install and verify the security tool suite"
    )
    install.add_argument("--all", action="store_true", help="every tool, not just the core pipeline")
    install.add_argument("--category", help="one category only (recon, dns, http, ports, …)")
    install.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    install.add_argument("--force", action="store_true", help="reinstall even if already present")
    install.add_argument("--timeout", type=int, default=900, help="per-tool timeout in seconds")
    install.set_defaults(func=cmd_install)

    connect = sub.add_parser(
        "connect", parents=[common],
        help="print the exact MCP registration for an AI CLI of your choice",
    )
    connect.add_argument(
        "--agent", default="auto",
        choices=["auto", "claude", "cursor", "windsurf", "gemini", "copilot", "generic"],
        help="which agent CLI to generate the registration for",
    )
    connect.add_argument(
        "--phase",
        choices=["full", *_phase_server_choices()],
        default="full",
        help="connect one phase server, or the full surface (default)",
    )
    connect.add_argument("--scope", help="pin scope.yaml into the registration")
    connect.add_argument(
        "--print-only", action="store_true",
        help="just print the commands; never touch any agent config",
    )
    connect.set_defaults(func=cmd_connect)

    scope = sub.add_parser("scope", parents=[common], help="validate scope.yaml and test targets against it")
    scope.add_argument("--scope")
    scope.add_argument("targets", nargs="*", help="targets to check, or 'transcribe' + policy text")
    scope.add_argument("--program-url", help="the program policy page the text came from")
    scope.add_argument("--out", default="scope.yaml", help="scaffold output path")
    scope.set_defaults(func=cmd_scope)

    report = sub.add_parser("report", parents=[common], help="summarize a finished engagement workspace")
    report.add_argument("workspace")
    report.set_defaults(func=cmd_report)

    rules = sub.add_parser("rules", parents=[common], help="list and validate detection rules")
    rules.add_argument("--config")
    rules.set_defaults(func=cmd_rules)

    brain = sub.add_parser(
        "brain", parents=[common],
        help="the neuron brain: live neural animation, sensing, and memory",
    )
    brain_sub = brain.add_subparsers(dest="brain_command", required=True)

    watch = brain_sub.add_parser(
        "watch", help="live neural pop-up: pulses travel from the brain to the active phase"
    )
    watch.add_argument("--path", help="activity feed path (default ~/.cordon/brain-activity.jsonl)")
    watch.add_argument("--once", action="store_true", help="render one frame and exit")
    watch.set_defaults(func=cmd_brain_watch)

    state = brain_sub.add_parser(
        "state", help="one-shot snapshot of what the brain senses right now"
    )
    state.add_argument("--path", help="activity feed path")
    state.set_defaults(func=cmd_brain_state)

    history = brain_sub.add_parser(
        "history",
        help="episodic memory: what happened before — failures, successes, findings",
    )
    history.add_argument("--path", help="activity feed path")
    history.add_argument("--phase")
    history.add_argument("--tool")
    history.add_argument("--outcome")
    history.add_argument("--limit", type=int, default=30)
    history.set_defaults(func=cmd_brain_history)

    dash = sub.add_parser(
        "dashboard", parents=[common],
        help="live engagement dashboard: phases, findings, assets, coverage, activity",
    )
    dash.add_argument("--out", default="dashboard.html", help="output path")
    dash.add_argument("--serve", action="store_true",
                      help="run a live local server; serves the React UI (or legacy page)")
    dash.add_argument("--build", action="store_true",
                      help="build the React dashboard (npm ci + vite build)")
    dash.add_argument("--port", default="8765", help="serve port (default 8765)")
    dash.add_argument("--workspace", help="pin a workspace by name (default: newest)")
    dash.set_defaults(func=cmd_dashboard)

    # Phase-sliced MCP servers: one surface per engagement phase, same control
    # plane. `cordon serve` (full surface) is registered by the cordon-mcp
    # entry point; these narrow it.
    serve = sub.add_parser(
        "serve", parents=[common],
        help="run the full MCP server (add --phase for a phase-sliced surface)",
    )
    serve.add_argument("--phase", choices=_phase_server_choices(),
                       help="slice the surface to one phase server")
    serve.add_argument("--scope", default=None, help="scope.yaml path")
    serve.add_argument("--config", default=None, help="config.yaml path")
    serve.add_argument("--workspace", default=None, help="engage an existing workspace")
    serve.set_defaults(func=cmd_serve)

    export = brain_sub.add_parser(
        "export",
        help="self-contained HTML neural animation of the brain's sensed activity",
    )
    export.add_argument("--path", help="activity feed path")
    export.add_argument("--out", help="output base name (default ./brain.html)")
    export.add_argument("--open", action="store_true", help="open the page after writing")
    export.set_defaults(func=cmd_brain_export)

    return parser


def _phase_server_choices() -> list[str]:
    from cordon.phase_servers import phase_server_names

    return phase_server_names()


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the MCP server, optionally phase-sliced."""
    from cordon.mcp_server import build_server

    server = build_server(
        scope_path=getattr(args, "scope", None),
        config_path=getattr(args, "config", None),
        workspace=getattr(args, "workspace", None),
        phase=getattr(args, "phase", None),
    )
    phase = getattr(args, "phase", None)
    if phase:
        print(f"cordon: serving phase surface '{phase}' over stdio", file=sys.stderr)
    server.run(transport="stdio", show_banner=False)
    return 0


def _mcp_command(phase: str | None, scope: str | None) -> str:
    """The exact server command an agent registration should run.

    python -m works inside the venv the agent's PATH already resolves; the
    absolute interpreter is the fallback when the agent launches with a
    clean environment.
    """
    argv = [sys.executable if sys.prefix != sys.base_prefix else "python", "-m", "cordon.mcp_server"]
    if phase and phase != "full":
        argv += ["--phase", phase]
    if scope:
        argv += ["--scope", str(Path(scope).expanduser().resolve())]
    return " ".join(argv)


def cmd_connect(args: argparse.Namespace) -> int:
    """Print the exact MCP registration for the agent CLI the user picks.

    The same phase servers, the same stdio transport — this just formats the
    registration for each agent's own CLI, so a user can run the tool inside
    Claude Code, Cursor, Windsurf, Gemini CLI, GitHub Copilot, or any other
    stdio-speaking agent without translating the command by hand.
    """
    from cordon.phase_servers import describe_servers

    dim = "\033[2m"
    reset = "\033[0m"
    green = "\033[32m"

    phase = getattr(args, "phase", "full")
    scope = getattr(args, "scope", None)
    cmd = _mcp_command(phase, scope)

    if phase == "full":
        label = "cordon (full surface)"
    else:
        label = f"cordon-{phase}"

    print(f"{label} — server command:\n")
    print(f"    {cmd}\n")

    def _stdio_json() -> dict[str, Any]:
        parts = cmd.split()
        return {"command": parts[0], "args": parts[1:]}

    registrations: dict[str, str] = {
        "claude": f"claude mcp add {label} -- {cmd}",
        "cursor": (
            '# ~/.cursor/mcp.json — add to the "mcpServers" object:\n'
            + json.dumps({"mcpServers": {label: _stdio_json()}}, indent=2)
        ),
        "windsurf": (
            "# ~/.codeium/windsurf/mcp_config.json — add:\n"
            + json.dumps({"mcpServers": {label: _stdio_json()}}, indent=2)
        ),
        "gemini": (
            '# .gemini/settings.json — add to "mcpServers":\n'
            + json.dumps({"mcpServers": {label: _stdio_json()}}, indent=2)
        ),
        "copilot": (
            "# .vscode/mcp.json or Copilot chat /mcp — add a server:\n"
            + json.dumps({"servers": {label: _stdio_json()}}, indent=2)
        ),
        "generic": cmd,
    }

    detected: str | None = None
    if args.agent == "auto":
        for name in ("claude", "cursor", "windsurf", "gemini", "copilot"):
            if shutil.which(name):
                detected = name
                break
        if detected:
            print(f"{green}detected: {detected}{reset}\n")
            print(registrations[detected])
        else:
            print(f"{dim}no known agent CLI found — here is the generic stdio "
                  f"command any MCP client can use:{reset}\n")
            print(registrations["generic"])
    else:
        detected = args.agent
        print(registrations[args.agent])

    # Non-print mode actually registers when the target agent has a one-line
    # CLI for it. Only claude mcp add qualifies; every other agent edits a
    # config file by hand, so for those we print and stop.
    if not args.print_only and detected == "claude":
        proc = subprocess.run(  # noqa: S603
            ["claude", "mcp", "add", label, "--"] + cmd.split(),
            capture_output=True, text=True, timeout=60, check=False,
        )
        if proc.returncode == 0:
            print(f"{green}registered with the claude CLI{reset}")
        else:
            print(f"{dim}claude CLI declined registration:{reset}\n{proc.stderr.strip()[:400]}")
    elif getattr(args, "print_only", False):
        print(f"{dim}--print-only: nothing was changed{reset}")

    if phase == "full":
        print(f"\n{dim}Phase servers available (add --phase <name>):{reset}")
        for entry in describe_servers():
            print(f"  {dim}{entry['name']:12} {entry['tools']} tools — {entry['description']}{reset}")
    print(f"\n{dim}Scope lives in the engagement, not the registration — "
          f"pass --scope to pin it, or load it from the agent with cordon_load_scope.{reset}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "no_color"):
        args.no_color = False
    try:
        return int(args.func(args))
    except CordonError as exc:
        print(f"cordon: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

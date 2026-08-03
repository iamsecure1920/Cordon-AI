"""EasyHunt command line: doctor, scope validation, and engagement inspection.

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

from easyhunt import __version__
from easyhunt.errors import EasyHuntError

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

    from easyhunt.install.installer import health_check
    from easyhunt.tools.common import CATALOG

    execute = not args.fast
    started = time.monotonic()
    report = health_check(execute=execute)
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
            print(f"  {green}✓{reset} {health.tool:18} {dim}{note}{reset}  {dim}[{license_name}]{reset}")
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

    from easyhunt.config import Config, find_scope
    from easyhunt.mcp_server import load_capabilities
    from easyhunt.tools.base import REGISTRY

    print(f"EasyHunt AI {__version__}\n")

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
        print(f"  {yellow}!{reset} no scope.yaml found — EasyHunt refuses to run without one")
    else:
        try:
            from easyhunt.control_plane.scope import Scope

            scope = Scope.load(scope_path)
            print(f"  {green}✓{reset} scope: {scope_path} ({scope.name}, {scope.authorization})")
            for warning in scope.validate():
                print(f"    {yellow}!{reset} {warning}")
        except EasyHuntError as exc:
            print(f"  {red}✗{reset} scope invalid: {exc}")

    sandbox_mode = config.get("sandbox.mode", "none")
    docker_ok = bool(shutil.which(config.get("sandbox.runtime", "docker")))
    if sandbox_mode == "docker" and not docker_ok:
        print(f"  {yellow}!{reset} sandbox.mode is 'docker' but the runtime is not installed")
    else:
        print(f"  {green}✓{reset} sandbox: {sandbox_mode}")

    from easyhunt.control_plane.auth import AuthConfig
    from easyhunt.control_plane.auth import describe as describe_auth

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
    from easyhunt.plugins.loader import load_all

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
    if not os.environ.get(key_env):
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
        print(f"  {yellow}!{reset} claude CLI not found; register manually (see README)")
    else:
        try:
            proc = subprocess.run(  # noqa: S603
                [claude, "mcp", "list"], capture_output=True, text=True, timeout=20, check=False
            )
            if "easyhunt" in proc.stdout:
                print(f"  {green}✓{reset} easyhunt connected")
            else:
                print(f"  {yellow}!{reset} easyhunt not registered. Run:")
                print(f"      {dim}claude mcp add easyhunt -- python -m easyhunt.mcp_server{reset}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  {yellow}!{reset} could not query the claude CLI: {exc}")

    if getattr(args, "fix", False):
        print("\nRepairs")
        from easyhunt.install import Installer

        repairs = Installer().repair()
        if repairs:
            for item in repairs:
                print(f"  {green}✓{reset} {item}")
        else:
            print(f"  {dim}nothing to repair{reset}")
        if missing:
            print(f"  {dim}{len(missing)} tool(s) absent — run `easyhunt install` to add them{reset}")
    elif missing or unhealthy:
        print(f"\n  {dim}Run `easyhunt install` to add missing tools, "
              f"or `easyhunt doctor --fix` to repair what is already here.{reset}")

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
    from easyhunt.llm.openrouter import LLMClient

    stub = type("Stub", (), {"config": config, "budget": None, "audit": None})()
    return await LLMClient(stub).probe()


def cmd_install(args: argparse.Namespace) -> int:
    """Install, verify, and repair the tool suite."""
    green, yellow, red, dim, reset = _color(sys.stdout.isatty() and not args.no_color)

    from easyhunt.install import Installer, recipes_for
    from easyhunt.mcp_server import load_capabilities

    load_capabilities()

    if args.category:
        selected = recipes_for(category=args.category)
        if not selected:
            from easyhunt.install.recipes import categories

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
    print(f"EasyHunt AI — installing {len(selected)} tool(s)")
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

    print(f"\n{dim}Next: easyhunt doctor{reset}")
    return 1 if summary["failed"] else 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Validate a scope file and test targets against it."""
    green, yellow, red, dim, reset = _color(sys.stdout.isatty() and not args.no_color)
    from easyhunt.config import find_scope
    from easyhunt.control_plane.scope import Scope

    path = find_scope(args.scope)
    if path is None:
        print(f"{red}no scope.yaml found{reset}")
        return 2
    try:
        scope = Scope.load(path)
    except EasyHuntError as exc:
        print(f"{red}invalid scope: {exc}{reset}")
        return 2

    print(json.dumps(scope.summary(), indent=2, default=str))
    for warning in scope.validate():
        print(f"{yellow}warning:{reset} {warning}")

    if args.targets:
        print("\nTarget checks:")
        exit_code = 0
        for target in args.targets:
            verdict = scope.check(target)
            if verdict.in_scope:
                print(f"  {green}✓ IN SCOPE {reset} {target}  {dim}({verdict.matched}){reset}")
            else:
                exit_code = 1
                detail = verdict.denied_by or verdict.reason
                print(f"  {red}✗ REFUSED  {reset} {target}  {dim}({detail}){reset}")
        return exit_code
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

    from easyhunt.control_plane.audit import AuditLog

    audit = AuditLog(workspace / "audit.jsonl")
    ok, message = audit.verify()
    print(f"\naudit chain: {'intact' if ok else 'BROKEN — ' + message}")
    print(json.dumps(audit.stats(), indent=2))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """List and validate detection rules."""
    from easyhunt.config import Config
    from easyhunt.plugins.loader import load_all

    config = Config.load(args.config)
    registry = load_all(config.get("rules.dirs") or ["./rules"], import_python=False)
    print(json.dumps(registry.summary(), indent=2, default=str))
    return 1 if registry.report.rejected else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="easyhunt",
        description="EasyHunt AI — agentic VAPT orchestrator (authorized testing only)",
    )
    parser.add_argument("--version", action="version", version=f"easyhunt {__version__}")

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

    scope = sub.add_parser("scope", parents=[common], help="validate scope.yaml and test targets against it")
    scope.add_argument("--scope")
    scope.add_argument("targets", nargs="*", help="targets to check")
    scope.set_defaults(func=cmd_scope)

    report = sub.add_parser("report", parents=[common], help="summarize a finished engagement workspace")
    report.add_argument("workspace")
    report.set_defaults(func=cmd_report)

    rules = sub.add_parser("rules", parents=[common], help="list and validate detection rules")
    rules.add_argument("--config")
    rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "no_color"):
        args.no_color = False
    try:
        return int(args.func(args))
    except EasyHuntError as exc:
        print(f"easyhunt: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

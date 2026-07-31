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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from easyhunt import __version__
from easyhunt.errors import EasyHuntError

GREEN, YELLOW, RED, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"


def _color(enabled: bool) -> tuple[str, str, str, str, str]:
    return (GREEN, YELLOW, RED, DIM, RESET) if enabled else ("", "", "", "", "")


def _tool_version(spec: Any) -> str:
    """Best-effort version string. Tools disagree wildly on how to report one."""
    if not spec.binary:
        return "python package"
    binary = shutil.which(spec.binary)
    if not binary:
        return ""
    for args in (spec.version_args, ["--version"], ["-version"], ["version"], ["-V"]):
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, *args], capture_output=True, text=True, timeout=8, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout + proc.stderr).strip()
        if not output:
            continue
        for line in output.splitlines():
            line = line.strip().lstrip("[").replace("INF]", "").strip()
            if any(ch.isdigit() for ch in line) and len(line) < 120:
                return line[:80]
        return output.splitlines()[0][:80]
    return "installed"


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what is installed, what is configured, and what is missing."""
    green, yellow, red, dim, reset = _color(sys.stdout.isatty() and not args.no_color)

    from easyhunt.config import Config, find_scope
    from easyhunt.mcp_server import load_capabilities
    from easyhunt.tools.base import REGISTRY
    from easyhunt.tools.common import CATALOG, installed, verify_identity

    print(f"EasyHunt AI {__version__}\n")

    print("Capability modules")
    statuses = load_capabilities()
    for module, status in statuses.items():
        name = module.split(".")[-1]
        mark = f"{green}✓{reset}" if status == "loaded" else f"{yellow}!{reset}"
        detail = "" if status == "loaded" else f" {dim}{status}{reset}"
        print(f"  {mark} {name}{detail}")
    print(f"  {len(REGISTRY)} MCP tools registered\n")

    print("External tools")
    present: list[str] = []
    missing: list[str] = []
    wrong: list[str] = []
    for name, spec in sorted(CATALOG.items()):
        if installed(name):
            identity_ok, detail = verify_identity(name)
            if not identity_ok:
                # A name collision on PATH is worse than a missing tool: the
                # wrong binary returns empty results and no error.
                wrong.append(name)
                print(f"  {red}✗{reset} {name:18} {red}WRONG TOOL{reset} {dim}— {detail}{reset}")
                continue
            present.append(name)
            version = _tool_version(spec) if args.versions else "installed"
            print(f"  {green}✓{reset} {name:18} {dim}{version}{reset}  {dim}[{spec.license}]{reset}")
        else:
            missing.append(name)
    for name in missing:
        spec = CATALOG[name]
        print(f"  {red}✗{reset} {name:18} {dim}not installed — {spec.homepage}{reset}")
    print(f"\n  {len(present)}/{len(CATALOG)} installed")
    if wrong:
        print(
            f"  {red}{len(wrong)} name collision(s): {', '.join(wrong)}{reset}\n"
            f"    {dim}A different program of the same name is earlier on your PATH. "
            f"Those tools will return nothing rather than erroring.{reset}"
        )
    print()

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
    elif missing or wrong:
        print(f"\n  {dim}Run `easyhunt install` to add missing tools, "
              f"or `easyhunt doctor --fix` to repair what is already here.{reset}")

    blocking = scope_path is None
    print()
    if blocking:
        print(f"{yellow}Doctor finished with warnings. Create a scope.yaml before running.{reset}")
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
    doctor.add_argument("--versions", action="store_true", help="query each tool's version")
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

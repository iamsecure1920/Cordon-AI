"""Smart-contract analysis: Slither, Aderyn, Foundry.

A different domain from the rest of EasyHunt, sharing the same control plane.
Nothing here touches a network target — analysis is local, on source or on a
forked chain — so these tools are ``passive`` and take no scope-checked target.

The invariant that replaces scope here comes from Immunefi's rules and every
other platform's: **testing happens on a local fork, never against a live
protocol.** A PoC that executes against mainnet is theft, not research, and it
is the one thing that must be impossible rather than discouraged.

Findings from static analysis are CANDIDATES. Slither's precision is good but
its high-impact detectors still fire on safe code, and a detector hit without a
runnable PoC is not a report on any platform that pays.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import register_spec, run_one

__all__ = ["contract_static_scan", "contract_toolchain"]

#: Paths under the workspace only. A repo path is the "target" here, and letting
#: an agent name an arbitrary filesystem path is how an audit tool becomes a
#: file-read primitive.
REPO_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,300}")

SLITHER = register_spec(
    ToolSpec(
        name="slither", binary="slither", license="AGPL-3.0",
        homepage="https://github.com/crytic/slither",
        version_args=["--version"],
        # PyPI ships an unrelated "slither": a PyGame module that brings
        # Scratch-like features to Python. `pip install slither` lands a
        # children's programming toy on PATH, and this spec would then hand it a
        # Solidity contract and report no findings.
        #
        # The marker cannot come from --version, which prints a bare "0.11.6"
        # and identifies nothing. `_identifies_as` also tries -h, whose usage
        # text carries the crytic-compile URL — crytic is Trail of Bits' org and
        # no toy prints it.
        identity_marker="crytic",
        arg_policy=ArgPolicy(
            tool="slither",
            allowed_flags={
                "--json", "--exclude-informational", "--exclude-optimization",
                "--exclude-low", "--exclude-dependencies", "--solc-remaps",
                "--filter-paths", "--checklist", "--markdown-root", "--print",
                "--detect", "--exclude", "--compile-force-framework", "--fail-none",
            },
            boolean_flags={
                "--exclude-informational", "--exclude-optimization", "--exclude-low",
                "--exclude-dependencies", "--checklist", "--fail-none",
            },
            value_patterns={
                "--json": re.compile(r"-|" + REPO_PATTERN.pattern),
                "--detect": re.compile(r"[a-z0-9,_-]{1,400}"),
                "--exclude": re.compile(r"[a-z0-9,_-]{1,400}"),
                "--filter-paths": re.compile(r"[A-Za-z0-9._/|-]{1,200}"),
            },
            allow_positional=True,
            positional_pattern=REPO_PATTERN,
            max_argv=24,
        ),
    )
)

ADERYN = register_spec(
    ToolSpec(
        name="aderyn", binary="aderyn", license="MIT",
        homepage="https://github.com/Cyfrin/aderyn",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="aderyn",
            allowed_flags={"--output", "-o", "--src", "--path-includes", "--path-excludes", "--skip-update-check"},
            boolean_flags={"--skip-update-check"},
            value_patterns={"--output": REPO_PATTERN, "-o": REPO_PATTERN},
            allow_positional=True,
            positional_pattern=REPO_PATTERN,
            max_argv=16,
        ),
    )
)

FORGE = register_spec(
    ToolSpec(
        name="forge", binary="forge", license="Apache-2.0 OR MIT",
        homepage="https://github.com/foundry-rs/foundry",
        version_args=["--version"],
        # The most-shadowed name in this catalogue: Debian's `snap` package ships
        # /usr/bin/forge, PyPI's "forge" is a Django scaffolding tool, and
        # Atlassian's @forge/cli takes the same command. Three impostors, and
        # this spec's denied_flags exist to stop `forge script`/`create` sending
        # real transactions — a guard that means nothing if the binary is not
        # Foundry in the first place.
        #
        # --version prints "forge Version: 1.7.1", which a Django tool could
        # plausibly match. -h prints the tagline instead.
        identity_marker="deploy solidity contracts",
        arg_policy=ArgPolicy(
            tool="forge",
            allowed_flags={
                "test", "build", "--match-test", "--match-contract", "--match-path",
                "--fork-url", "--fork-block-number", "--json", "-vvvv", "-vvv", "-vv",
                "--no-match-test", "--gas-report", "--root", "--offline", "--silent",
            },
            boolean_flags={"--json", "-vvvv", "-vvv", "-vv", "--gas-report", "--offline", "--silent"},
            # A PoC runs against a local fork. A broadcast sends real transactions;
            # a private key on the command line is how a research tool becomes an
            # incident. Neither is reachable.
            denied_flags={
                "--broadcast", "--private-key", "--unlocked", "--mnemonic",
                "--interactives", "--ledger", "--trezor", "--keystore", "--rpc-url",
                "script", "create", "send",
            },
            value_patterns={
                "--match-test": re.compile(r"[A-Za-z0-9_]{1,80}"),
                "--match-contract": re.compile(r"[A-Za-z0-9_]{1,80}"),
                "--fork-url": re.compile(r"https?://127\.0\.0\.1(:\d+)?(/.*)?|http://localhost(:\d+)?(/.*)?"),
            },
            numeric_caps={"--fork-block-number": 99_999_999},
            allow_positional=True,
            positional_pattern=re.compile(r"test|build"),
            max_argv=24,
        ),
    )
)

#: Trail of Bits' smart-contract fuzzer shares its name with Medusa the password
#: brute-forcer, which ships in Kali at /usr/bin/medusa. Running the wrong one
#: fires credential attacks at a host instead of fuzzing a contract, so the
#: binary must identify itself before it is used.
MEDUSA = register_spec(
    ToolSpec(
        name="medusa", binary="medusa", license="AGPL-3.0",
        homepage="https://github.com/crytic/medusa",
        version_args=["--version"],
        identity_marker="medusa version",
        arg_policy=ArgPolicy(
            tool="medusa",
            allowed_flags={"fuzz", "--config", "--target", "--timeout", "--test-limit", "--workers"},
            value_patterns={"--config": REPO_PATTERN, "--target": REPO_PATTERN},
            numeric_caps={"--timeout": 3600, "--test-limit": 500_000, "--workers": 8},
            allow_positional=True,
            positional_pattern=re.compile(r"fuzz|init"),
        ),
    )
)

#: Slither impact -> EasyHunt severity. Slither's own "High" means high *impact*
#: if real, not high confidence, so nothing above HIGH is assigned from a
#: detector alone: CRITICAL requires a PoC.
_IMPACT = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

#: Detectors worth a human's time first, drawn from what actually pays: access
#: control, reentrancy incl. read-only, arbitrary calls, and delegatecall.
_PRIORITY = {
    "reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign", "reentrancy-events",
    "arbitrary-send-eth", "arbitrary-send-erc20", "controlled-delegatecall",
    "unprotected-upgrade", "suicidal", "unchecked-transfer", "weak-prng",
    "incorrect-equality", "divide-before-multiply", "tx-origin", "uninitialized-state",
}


@easyhunt_tool(
    phase="contracts", mode="passive", targets_arg=None, timeout=900,
    name="contract_static_scan", tags={"contracts", "static"},
    estimated_requests=0, budget_exempt=True,
)
async def contract_static_scan(repo: str, exclude_informational: bool = True) -> dict[str, Any]:
    """Run Slither over a Solidity project and normalize the detector output.

    ``repo`` is a path inside the engagement workspace. Analysis is local: no
    network request is made and no contract is executed, which is why this is
    passive and costs no budget.

    Every result is a CANDIDATE. Slither's high-impact detectors fire on safe
    code often enough that a finding without a runnable PoC is not submittable
    on any platform that pays for smart-contract bugs.
    """
    engagement = get_engagement()
    from easyhunt.control_plane.sanitize import sanitize_path

    path = sanitize_path(repo, workspace=engagement.workspace, name="repo")
    if not path.exists():
        return {
            "ok": False,
            "error": "repo_not_found",
            "message": (
                f"{path} does not exist. Clone the project inside the engagement "
                "workspace; paths outside it are refused."
            ),
        }

    argv = [str(path), "--json", "-", "--fail-none"]
    if exclude_informational:
        argv += ["--exclude-informational", "--exclude-optimization"]

    run = await run_one("slither", argv, timeout=880, allow_codes=(0, 1, 255))
    if not run.ran:
        return {
            "ok": False,
            "error": "tool_unavailable",
            "message": (
                f"slither could not run ({run.error}). Install it with "
                "'pipx install slither-analyzer'. Without it this project is "
                "UNANALYSED, not clean."
            ),
        }

    payload: dict[str, Any] = {}
    for line in run.values:
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                payload = json.loads(stripped)
                break
            except json.JSONDecodeError:
                continue
    if not payload:
        return {
            "ok": False,
            "error": "no_output",
            "message": (
                "slither produced no JSON. Usually a compilation failure — check "
                "the solc version with solc-select. Zero findings here means "
                "UNANALYSED, not clean."
            ),
            "stderr_tail": (run.error or "")[:500],
        }

    detectors = (payload.get("results") or {}).get("detectors") or []
    stored: list[Finding] = []
    for det in detectors:
        check = str(det.get("check") or "unknown")
        impact = str(det.get("impact") or "Informational")
        description = str(det.get("description") or "").strip()
        elements = det.get("elements") or []
        where = ""
        if elements:
            src = (elements[0].get("source_mapping") or {})
            where = f"{src.get('filename_relative', '?')}:{src.get('lines', ['?'])[0]}"

        stored.append(
            Finding(
                asset=where or str(path),
                title=f"{check}: {description.splitlines()[0][:160]}" if description else check,
                phase="contracts",
                severity=_IMPACT.get(impact, Severity.INFO),
                status=Status.CANDIDATE,
                description=description,
                how_found=f"Slither detector '{check}' (impact={impact}, "
                          f"confidence={det.get('confidence')})",
                source_tool="slither",
                rule_id=check,
                # Detector confidence, deliberately below anything that could be
                # mistaken for proof. Only a passing Foundry PoC moves this up.
                confidence=0.6 if check in _PRIORITY else 0.4,
                evidence=[Evidence(kind="log", description="Slither detector output",
                                   excerpt=description[:4000])],
                tags=["slither", check] + (["priority"] if check in _PRIORITY else []),
            )
        )

    for finding in stored:
        engagement.findings.add(finding)
    engagement.findings.save()

    by_sev: dict[str, int] = {}
    for f in stored:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    priority = [f.to_dict() for f in stored if "priority" in f.tags]

    return {
        "ok": True,
        "repo": str(path),
        "count": len(stored),
        "by_severity": by_sev,
        "priority_findings": priority,
        "findings": [f.to_dict() for f in sorted(stored, key=lambda f: -f.severity.rank)],
        "note": (
            "All results are CANDIDATES. Slither reports high *impact if real*, "
            "not high confidence. Nothing here is submittable until a Foundry PoC "
            "on a local fork demonstrates attacker profit or protocol loss."
        ),
    }


@easyhunt_tool(
    phase="contracts", mode="passive", targets_arg=None, timeout=180,
    name="contract_toolchain", tags={"contracts", "inspection"},
    estimated_requests=0, budget_exempt=True,
)
async def contract_toolchain() -> dict[str, Any]:
    """Report which smart-contract tools are present and correctly identified.

    Absence is reported per tool rather than as an overall failure, so a missing
    fuzzer never reads as "the contract is fine".
    """
    from easyhunt.tools.common import installed, verify_identity

    state: dict[str, Any] = {}
    for name in ("slither", "aderyn", "forge", "medusa"):
        present = installed(name)
        entry: dict[str, Any] = {"installed": present}
        if present:
            ok, detail = verify_identity(name)
            entry["identity_ok"] = ok
            entry["detail"] = detail
        state[name] = entry

    missing = [n for n, v in state.items() if not v["installed"]]
    impostor = [n for n, v in state.items() if v.get("identity_ok") is False]
    return {
        "ok": True,
        "tools": state,
        "missing": missing,
        "wrong_binary": impostor,
        "note": (
            "A missing tool means that analysis was NOT performed. "
            + (f"Wrong binary on PATH for: {impostor}. " if impostor else "")
            + "medusa in particular collides with a password brute-forcer of the "
            "same name, which is why identity is verified rather than assumed."
        ),
    }

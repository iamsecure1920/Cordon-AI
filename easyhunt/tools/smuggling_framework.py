"""Canary-proven HTTP request smuggling.

Wraps the operator's own smuggler framework. It differs from the `smuggler`
binary behind `smuggling_probe` in the one way that matters for a bug bounty:
it proves a desync by **poisoning a canary token into another request** rather
than inferring one from timing and status codes.

That distinction is the difference between a finding and a lead. "This request
took 5 seconds longer" is an observation about a network; "my token appeared in
a response I did not send it to" is the vulnerability itself, and it survives a
triager asking how you know.

It also reports **coverage**, which nothing else in this toolchain's smuggling
path does: how many payloads were sent, which detectors ran, and which did not.
Every payload file in that framework was invalid JSON when it was first
audited, so all six detectors ran with zero payloads and it reported targets
clean. Zero findings is only meaningful next to the number behind it, and this
wrapper refuses to report one without the other.

Aggressive, not exploit: it sends malformed requests to a front-end, which is
state-touching and noisy, but it never acts on a successful desync. Proving the
queue can be poisoned is the finding; poisoning a real user's response is not
something this will do.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool, register_container_mount
from easyhunt.tools.common import URL_PATTERN, register_spec, run_one, split_targets

__all__ = ["SMUGGLER_FRAMEWORK", "smuggling_canary_probe"]

#: Where the framework lives. Operator-supplied rather than packaged, so the
#: path is configurable and its absence is reported as UNTESTED, never as clean.
_DEFAULT_PATHS = (
    "/opt/smuggler_framework",
    "/root/Desktop/smuggler_framework",
)


#: Where the framework appears *inside* the sandbox. The host path varies per
#: machine; the container path must not, because it is what ends up in argv.
_CONTAINER_ROOT = "/opt/smuggler-framework"


def _framework_root() -> Path | None:
    configured = os.environ.get("EASYHUNT_SMUGGLER_FRAMEWORK")
    candidates = [configured] if configured else []
    candidates += list(_DEFAULT_PATHS)
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if (path / "smuggler.py").is_file():
            return path
    return None


def _mount_framework(root: Path) -> None:
    """Carry the framework into the container, read-only.

    It is not in the image — it is the operator's own code, living at a path
    only this machine knows. Without the mount the sandboxed `python3` opens a
    file that is not there, which is a "tool failed" indistinguishable at a
    glance from a target that had no desync.

    Read-only because a scan has no business rewriting its own payloads.
    """
    register_container_mount("smuggler-framework", root, _CONTAINER_ROOT)


SMUGGLER_FRAMEWORK = register_spec(
    ToolSpec(
        name="smuggler-framework",
        binary="python3",
        license="operator-supplied",
        homepage="local",
        version_args=["--version"],
        # No user-agent flag: the framework sets its own and a desync test's
        # headers are the payload. Attribution rides on the scope's rate and
        # the audit log instead.
        user_agent_flag=None,
        arg_policy=ArgPolicy(
            tool="smuggler-framework",
            allowed_flags={
                "--target", "--repeat", "--timeout", "--pause", "--concurrency",
                "--pool-size", "--payloads-dir", "--output", "--no-h2",
                "--time-threshold",
            },
            boolean_flags={"--no-h2"},
            denied_flags={
                # Reads a target list the scope engine never saw — every host in
                # it would be attacked without a verdict being recorded.
                "--target-file",
                # Writes an HTML report; the JSON is what this parses, and an
                # extra output path is another place credentials can land.
                "--html",
                "--verbose",
            },
            value_patterns={
                "--target": URL_PATTERN,
                "--output": __import__("re").compile(r"[A-Za-z0-9._/@+=:,\[\]-]{1,512}"),
                "--payloads-dir": __import__("re").compile(r"[A-Za-z0-9._/-]{1,512}"),
            },
            # Ceilings, not suggestions. `--repeat` multiplies every payload by
            # itself: 802 payloads at repeat 20 is 16,040 malformed requests to
            # a front-end, which is the kind of volume a program reads as an
            # attack rather than a test.
            numeric_caps={
                "--repeat": 10, "--timeout": 30, "--pause": 5,
                "--concurrency": 4, "--pool-size": 10, "--time-threshold": 15,
            },
            allow_positional=True,
            positional_pattern=__import__("re").compile(r"[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)


@easyhunt_tool(
    phase="exploit",
    mode="aggressive",
    targets_arg="target",
    timeout=1800,
    name="smuggling_canary_probe",
    spec=SMUGGLER_FRAMEWORK,
    tags={"smuggling", "desync"},
    estimated_requests=8020,
    risk_notes=[
        "Sends deliberately malformed requests to a front-end proxy: conflicting "
        "Content-Length and Transfer-Encoding, chunk extensions, hop-by-hop cloaking.",
        "A successful desync poisons the connection's request queue. The framework "
        "targets its own canary and never acts on another user's response.",
        "--repeat multiplies every payload, and each attempt is two requests. "
        "Capped at 10: 802 payloads x 10 x 2 is 16,040 requests to a front-end.",
        "Request smuggling can disrupt a shared front-end. Do not run it against a "
        "program that forbids testing which could degrade service.",
    ],
    rationale="Prove a desync by canary reflection rather than inferring one from timing.",
)
async def smuggling_canary_probe(
    target: str, repeat: int = 5, timeout: int = 8, http2: bool = False
) -> dict[str, Any]:
    """Test for HTTP request smuggling, proving hits by canary reflection.

    ``repeat`` is how many times each payload is retried; the framework scores
    confidence statistically ("17/20 poisoned"), which is the right model for a
    bug class that is inherently probabilistic. Capped at 10 by the argument
    policy — every increment multiplies the whole payload set.

    Returns coverage alongside findings: payloads sent, detectors run, and
    detectors skipped. A smuggling scan that could not find an echo gadget, or
    could not confirm queue poisoning, has not tested those things — and this
    result says so rather than letting zero findings imply a clean front-end.
    """
    engagement = get_engagement()
    root = _framework_root()
    if root is None:
        return {
            "ok": False,
            "status": "UNTESTED",
            "complete": False,
            "error": "framework_not_found",
            "findings": [],
            "message": (
                "The smuggler framework was not found. Set "
                "EASYHUNT_SMUGGLER_FRAMEWORK to its directory, or place it at "
                f"one of {list(_DEFAULT_PATHS)}. Request smuggling on this target "
                "is UNTESTED, not clean."
            ),
        }

    _mount_framework(root)

    url = split_targets(target)[0]
    if "://" not in url:
        url = f"https://{url}"

    report = engagement.raw_path("smuggler-framework", "json")
    rules = engagement.scope.rules
    argv = [
        f"{_CONTAINER_ROOT}/smuggler.py",
        "--target", url,
        "--repeat", str(max(1, min(int(repeat), 10))),
        "--timeout", str(max(1, min(int(timeout), 30))),
        # Concurrency and pause come from the engagement, never from a caller
        # argument. The framework opens a persistent pool per target and reuses
        # it across hundreds of iterations, so the limiter — which charges once
        # per tool call — cannot throttle any of it.
        "--concurrency", str(max(1, min(int(rules.max_concurrency), 4))),
        "--pause", str(min(max(0.1, round(1 / max(0.01, rules.max_rps), 2)), 5)),
        "--payloads-dir", f"{_CONTAINER_ROOT}/payloads",
        "--output", str(report),
    ]
    if not http2:
        argv.append("--no-h2")

    run = await run_one("smuggler-framework", argv, timeout=1750, allow_codes=(0, 1))
    if not run.ran:
        return {
            "ok": False,
            "status": "UNTESTED",
            "complete": False,
            "error": "tool_unavailable",
            "findings": [],
            "message": (
                f"The framework did not run ({run.error or 'unavailable'}). Request "
                "smuggling on this target is UNTESTED, not clean."
            ),
            "tools": [run.to_dict()],
        }

    data: Any = None
    if report.exists():
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None

    if not isinstance(data, dict) or not data.get("results"):
        return {
            "ok": False,
            "status": "INCOMPLETE",
            "complete": False,
            "error": "no_report",
            "findings": [],
            "message": (
                "The framework ran but produced no parsable report, so nothing can "
                "be concluded. UNTESTED, not clean."
            ),
            "tools": [run.to_dict()],
            "output": "\n".join(run.values)[-1500:],
        }

    result = data["results"][0]
    coverage = result.get("coverage") or {}
    raw_findings = result.get("findings") or []

    findings: list[Finding] = []
    for item in raw_findings:
        kind = str(item.get("type") or item.get("technique") or "desync")
        confidence = item.get("confidence")
        findings.append(
            Finding(
                asset=url,
                title=f"HTTP request smuggling ({kind})",
                phase="exploit",
                severity=Severity.HIGH,
                status=Status.CANDIDATE,
                description=(
                    f"A desync was observed on {url} using the {kind} technique. "
                    f"Confidence: {confidence}. Proof is canary reflection — a token "
                    "sent in a smuggled request appeared in a response it was never "
                    "sent to, which means the front-end and back-end disagreed about "
                    "where one request ended and the next began."
                ),
                how_found=f"smuggler framework, {kind}, canary reflection",
                source_tool="smuggler-framework",
                confidence=0.7,
                tags=["smuggling", "desync", "candidate"],
                evidence=[Evidence(
                    kind="log",
                    description="framework finding record",
                    excerpt=json.dumps(item, default=str)[:1500],
                )],
                remediation=(
                    "Make the front-end and back-end agree on message framing: "
                    "reject requests carrying both Content-Length and "
                    "Transfer-Encoding, normalise before forwarding, and prefer "
                    "HTTP/2 end to end rather than downgrading at the edge."
                ),
            )
        )
    for f in findings:
        engagement.findings.add(f)
    if findings:
        engagement.findings.save()

    skipped = coverage.get("phases_skipped") or []
    ran = coverage.get("phases_run") or []
    payloads = coverage.get("payloads_total")
    # Loaded and sent are different numbers, and the gap between them is the
    # whole story. A connection pool bug once made this framework send about ten
    # requests while reporting 802 payloads tested; the target was declared
    # clean. `requests_sent` is counted at the socket, so it cannot be wrong in
    # that direction, and the framework itself flags a shortfall as a skipped
    # phase — which lands here as PARTIAL rather than a clean bill of health.
    sent = coverage.get("requests_sent")
    send_errors = coverage.get("send_errors")

    return {
        "ok": True,
        # Skipped detectors mean partial coverage, and partial coverage is not a
        # clean result. This is the whole reason the wrapper reads `coverage`.
        "status": "COMPLETE" if not skipped else "PARTIAL",
        "complete": not skipped,
        "target": url,
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "coverage": {
            "payloads_loaded": payloads,
            "requests_sent": sent,
            "send_errors": send_errors,
            "detectors_run": ran,
            "detectors_skipped": skipped,
            "echo_gadget": result.get("echo_path"),
            "delay_gadget": result.get("delay_path"),
        },
        "verdict": coverage.get("verdict"),
        "tools": [run.to_dict()],
        "note": (
            "Proof here is canary reflection, not timing — a token appeared in a "
            "response it was never sent to. That is the vulnerability itself and "
            "survives triage in a way a latency measurement does not."
            if findings
            else (
                f"No desync observed across {payloads} payloads "
                f"({sent} requests actually sent) from {len(ran)} detector(s)."
                + (
                    f" {len(skipped)} detector(s) did NOT run: {skipped}. Those "
                    "techniques are UNTESTED on this target."
                    if skipped else ""
                )
            )
        ),
    }

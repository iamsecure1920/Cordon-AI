"""Jaeles — plugin class C: YAML request/response signatures.

Jaeles covers the middle ground between a Nuclei template and a custom script:
signatures that send a crafted request and assert on the response, with variables
and simple chaining. Where Nuclei's ecosystem is broad and community-maintained,
Jaeles signatures tend to be the target-specific checks a researcher writes for
one application and reuses across its subdomains.

Signatures live in ``rules/jaeles/``. Only that reviewed directory is scanned —
a Jaeles signature can specify arbitrary request bodies and methods, so accepting
a caller-supplied path would let the agent author its own requests outside the
argument policy.

Aggressive by default and gated: every signature sends a real request to the
target, and some send several.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool, guarded_run
from easyhunt.tools.common import register_spec

log = logging.getLogger("easyhunt.engines.jaeles")

__all__ = ["jaeles_scan", "parse_jaeles_output"]

SPEC = register_spec(
    ToolSpec(
        name="jaeles",
        binary="jaeles",
        license="MIT",
        homepage="https://github.com/jaeles-project/jaeles",
        version_args=["version"],
        identity_marker="jaeles",
        arg_policy=ArgPolicy(
            tool="jaeles",
            allowed_flags={
                "-s", "-u", "-U", "-c", "-L", "-o", "-J", "--json", "-Q",
                "--verbose", "--no-background", "--sc", "--retry", "--timeout",
                "--proxy-off", "-p", "--chunk",
            },
            boolean_flags={"-J", "--json", "-Q", "--verbose", "--no-background", "--proxy-off"},
            value_patterns={
                # Signature *selectors*, not paths: no traversal into the filesystem.
                "-s": re.compile(r"[A-Za-z0-9,._*/-]{1,120}"),
                "-u": re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]{1,2000}"),
            },
            numeric_caps={"-c": 20, "--retry": 2, "--timeout": 30, "--chunk": 50},
            allow_positional=True,
            positional_pattern=re.compile(r"scan|server|config|report"),
            relaxed_chars=frozenset("()"),
        ),
    )
)

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "potential": Severity.LOW,
}


def parse_jaeles_output(text: str) -> list[dict[str, Any]]:
    """Parse Jaeles JSON-lines output into plain records.

    Jaeles emits both structured JSON and human lines like
    ``[High] - signature-id - https://host/path``; both forms are handled because
    which one you get depends on the build.
    """
    records: list[dict[str, Any]] = []
    human = re.compile(r"\[(\w+)\]\s*-\s*([A-Za-z0-9._-]+)\s*-\s*(\S+)")

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0] == "{":
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            records.append(
                {
                    "sign_id": str(parsed.get("sign_id") or parsed.get("signature") or "unknown"),
                    "severity": str(parsed.get("risk") or parsed.get("level") or "info").lower(),
                    "url": str(parsed.get("url") or parsed.get("req_url") or ""),
                    "detail": str(parsed.get("detail_result") or parsed.get("detail") or ""),
                    "request": str(parsed.get("req") or "")[:4000],
                    "response": str(parsed.get("res") or "")[:4000],
                }
            )
            continue

        match = human.search(line)
        if match:
            records.append(
                {
                    "sign_id": match.group(2),
                    "severity": match.group(1).lower(),
                    "url": match.group(3),
                    "detail": line[:500],
                    "request": "",
                    "response": "",
                }
            )
    return records


def _signature_dir(engagement: Any) -> Path | None:
    directory = engagement.config.path("rules.jaeles_dir", "./rules/jaeles")
    return directory if directory and Path(directory).is_dir() else None


async def _run(job: Job, *, targets: list[str], selector: str) -> dict[str, Any]:
    engagement = get_engagement()
    signatures = _signature_dir(engagement)

    targets_file = engagement.raw_path("jaeles-targets", "txt")
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    output = engagement.raw_path("jaeles", "jsonl")

    argv = [
        "scan",
        "-U", str(targets_file),
        "-s", selector,
        "-J",
        "-o", str(output.parent),
        "-c", str(max(1, engagement.scope.rules.max_concurrency)),
        "--timeout", "20",
        "--retry", "1",
        # Never route through a proxy we did not configure.
        "--proxy-off",
        "--no-background",
    ]

    job.progress = f"running signatures '{selector}' against {len(targets)} target(s)"
    result = await guarded_run(
        SPEC,
        argv,
        timeout=3600,
        output_name="jaeles",
        engagement=engagement,
        allow_codes=(0, 1),
        check=False,
    )

    records = parse_jaeles_output(result.stdout)
    if output.exists():
        records += parse_jaeles_output(output.read_text(encoding="utf-8", errors="replace"))

    stored: list[Finding] = []
    dropped = 0
    seen: set[str] = set()
    for record in records:
        key = f"{record['sign_id']}|{record['url']}"
        if key in seen:
            continue
        seen.add(key)

        # Same third scope check as Nuclei: a signature can follow a redirect.
        if not record["url"] or not engagement.scope.check(record["url"]).in_scope:
            dropped += 1
            engagement.audit.record(
                "finding_dropped", reason="out_of_scope", asset=record["url"],
                rule=record["sign_id"], tool="jaeles",
            )
            continue

        evidence = []
        if record["request"]:
            evidence.append(Evidence(kind="request", description="Jaeles request", excerpt=record["request"]))
        if record["response"]:
            evidence.append(Evidence(kind="response", description="Jaeles response", excerpt=record["response"]))

        finding = Finding(
            asset=record["url"],
            title=f"Jaeles signature matched: {record['sign_id']}",
            phase="vuln_scan",
            severity=_SEVERITY.get(record["severity"], Severity.INFO),
            status=Status.CANDIDATE,
            description=record["detail"][:1000],
            how_found=f"Jaeles signature '{record['sign_id']}' matched at {record['url']}",
            source_tool="jaeles",
            rule_id=f"jaeles.{record['sign_id']}",
            confidence=0.5,
            evidence=evidence,
            tags=["jaeles"],
        )
        engagement.findings.add(finding)
        stored.append(finding)

    engagement.findings.save()
    job.events_seen = len(stored)

    by_severity: dict[str, int] = {}
    for finding in stored:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

    return {
        "ok": True,
        "targets": len(targets),
        "selector": selector,
        "signature_dir": str(signatures) if signatures else None,
        "count": len(stored),
        "dropped_out_of_scope": dropped,
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in stored],
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "note": (
            "Jaeles matches are candidates. Signatures assert on a response body, "
            "which is exactly the kind of match that needs a PoC before reporting."
        ),
    }


@easyhunt_tool(
    phase="vuln_scan",
    mode="aggressive",
    targets_arg="target",
    timeout=3600,
    name="jaeles_scan",
    spec=SPEC,
    tags={"engine", "vuln", "rules"},
    estimated_requests=300,
    risk_notes=[
        "Sends signature-defined requests to the target, including non-GET methods.",
        "Only signatures from the reviewed rules/jaeles directory are run.",
        "Review a signature before approving — it defines the exact request sent.",
    ],
)
async def jaeles_scan(
    target: str, selector: str = "easyhunt/*", wait_seconds: float = 120.0
) -> dict[str, Any]:
    """Run Jaeles YAML signatures (plugin class C) against in-scope targets.

    selector picks signatures by name or glob, e.g. 'easyhunt/*' or 'cve/*'.
    Signatures are loaded from rules/jaeles/ only.

    Returns inline if it finishes within wait_seconds, otherwise a job_id.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.jaeles.enabled", True):
        raise ToolUnavailable("jaeles engine is disabled in config", tool="jaeles")

    if _signature_dir(engagement) is None:
        raise ToolUnavailable(
            "no signature directory found. Put Jaeles signatures in rules/jaeles/ "
            "(or set rules.jaeles_dir); EasyHunt will not run signatures from an "
            "arbitrary path.",
            tool="jaeles",
        )

    targets = [t.strip() for t in target.replace("\n", ",").split(",") if t.strip()]
    job = engagement.jobs.launch(
        lambda j: _run(j, targets=targets, selector=selector),
        tool="jaeles_scan",
        phase="vuln_scan",
        targets=targets,
    )

    payload = await engagement.jobs.wait(job.id, timeout=max(0.0, min(wait_seconds, 300)))
    if payload.get("ready") and payload.get("ok"):
        return {"job_id": job.id, "completed": True, **payload["result"]}
    return {
        "job_id": job.id,
        "completed": False,
        "status": payload.get("status"),
        "progress": payload.get("progress"),
        "error": payload.get("error"),
        "next_step": f"Poll job_status('{job.id}'), then fetch_slice('{job.id}', path='findings').",
    }

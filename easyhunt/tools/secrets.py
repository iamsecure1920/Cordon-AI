"""Secret detection, with validation status as a first-class field.

Kingfisher is the primary scanner because it does the thing that separates a
useful secrets report from a noisy one: it *validates* the credential against the
issuing service and maps the blast radius. An unvalidated regex match is a
candidate; a credential that authenticates is a critical finding, and the
difference is the whole report.

Nosey Parker covers full git history with ML denoising; TruffleHog and gitleaks
are complements. TruffleHog is **AGPL-3.0** — recorded in its spec, and it matters
the moment anyone redistributes a bundle containing it.

Two boundaries are enforced here:

* **Scanning happens on files in the engagement workspace.** Cloning is a
  separate, audited step, so "what did EasyHunt read" always has an answer.
* **Validation is gated.** Validating a credential means *using* it. That is a
  request to a third party with someone else's key, and it needs a human to say
  yes — even though the request never touches the target.

**Rate governance.** Scanning is local file I/O and sends nothing, so
``secret_scan`` is governed by construction. ``secret_validate`` is the one tool
here that makes network requests, and it makes one or more per candidate to
AWS/GitHub/Stripe/etc. Kingfisher's ``--validation-rps`` is a global
requests-per-second ceiling over exactly that traffic; it is set from
``scope.rules.max_rps``. Before this audit it was not passed at all, so validating
a repository with a few hundred candidates issued a few hundred authenticated
requests as fast as the machine could manage — against third parties who rate
limit, log, and occasionally suspend for it.

``--jobs`` is CPU parallelism over local files and is deliberately not treated as
a rate control. ``noseyparker`` and ``gitleaks`` send nothing at all.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy, sanitize_path
from easyhunt.knowledge.findings import Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import register_spec, run_one

__all__ = ["secret_scan", "secret_validate", "source_fetch"]

REPO_URL = re.compile(r"https://(?:github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:\.git)?")

KINGFISHER = register_spec(
    ToolSpec(
        name="kingfisher", binary="kingfisher", license="Apache-2.0",
        homepage="https://github.com/mongodb/kingfisher", version_args=["--version"],
        # PyPI's "kingfisher" downloads biological FASTA/Q read data. Both print
        # "kingfisher <version>", so the tool name is not a usable marker; -h
        # carries the tagline and that is what this matches.
        identity_marker="detect and validate secrets",
        arg_policy=ArgPolicy(
            tool="kingfisher",
            allowed_flags={
                "--format", "--output", "--no-validate", "--confidence", "--jobs",
                "--git-history", "--exclude", "--redact", "--min-entropy",
                "--validation-rps",
            },
            boolean_flags={"--no-validate", "--redact"},
            value_patterns={
                "--format": re.compile(r"json|jsonl|pretty|sarif|bson"),
                "--confidence": re.compile(r"low|medium|high"),
                "--git-history": re.compile(r"full|none|latest"),
            },
            # --validation-rps is the global requests-per-second ceiling over
            # credential-validation traffic. Capped as well as set, so it stays
            # bounded if a future caller reaches this argv.
            numeric_caps={"--jobs": 16, "--min-entropy": 8, "--validation-rps": 100},
            allow_positional=True,
            positional_pattern=re.compile(r"scan|[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)

NOSEYPARKER = register_spec(
    ToolSpec(
        name="noseyparker", binary="noseyparker", license="Apache-2.0",
        homepage="https://github.com/praetorian-inc/noseyparker", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="noseyparker",
            allowed_flags={"--datastore", "-d", "--format", "--output", "-o", "--jobs", "-j", "--git-history"},
            value_patterns={"--format": re.compile(r"json|jsonl|human|sarif")},
            numeric_caps={"--jobs": 16, "-j": 16},
            allow_positional=True,
            positional_pattern=re.compile(r"scan|report|summarize|[A-Za-z0-9._/-]{1,512}"),
        ),
    )
)

#: Registered but not invoked by any wrapper here. Note for whoever wires it up:
#: trufflehog's `--only-verified` mode makes a validation request per candidate
#: and it has **no requests-per-second flag** — `--concurrency` is the only
#: throttle it offers, which bounds parallelism but not rate.
TRUFFLEHOG = register_spec(
    ToolSpec(
        name="trufflehog", binary="trufflehog", image="trufflesecurity/trufflehog:latest",
        # AGPL-3.0: relevant if EasyHunt is ever redistributed as a bundle.
        license="AGPL-3.0",
        homepage="https://github.com/trufflesecurity/trufflehog", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="trufflehog",
            allowed_flags={"--json", "--no-update", "--only-verified", "--concurrency", "--results"},
            boolean_flags={"--json", "--no-update", "--only-verified"},
            numeric_caps={"--concurrency": 16},
            allow_positional=True,
            positional_pattern=re.compile(r"filesystem|git|github|gitlab|[A-Za-z0-9._/:-]{1,512}"),
        ),
    )
)

GITLEAKS = register_spec(
    ToolSpec(
        name="gitleaks", binary="gitleaks", license="MIT",
        homepage="https://github.com/gitleaks/gitleaks", version_args=["version"],
        arg_policy=ArgPolicy(
            tool="gitleaks",
            allowed_flags={"-s", "--source", "-f", "--report-format", "-r", "--report-path", "--no-banner", "--redact", "--exit-code"},
            boolean_flags={"--no-banner", "--redact"},
            value_patterns={"--report-format": re.compile(r"json|csv|sarif")},
            numeric_caps={"--exit-code": 1},
            allow_positional=True,
            positional_pattern=re.compile(r"detect|dir|git"),
        ),
    )
)

GIT = register_spec(
    ToolSpec(
        name="git", binary="git", license="GPL-2.0", homepage="https://git-scm.com",
        version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="git",
            allowed_flags={"--depth", "--branch", "--single-branch", "--quiet", "--bare", "--mirror"},
            boolean_flags={"--single-branch", "--quiet", "--bare", "--mirror"},
            numeric_caps={"--depth": 5000},
            allow_positional=True,
            positional_pattern=re.compile(r"clone|https://[A-Za-z0-9._/:-]{1,300}|[A-Za-z0-9._/-]{1,300}"),
            max_argv=12,
        ),
    )
)


def _severity_for(rule: str, validated: bool) -> Severity:
    """A validated credential outranks any pattern-based guess."""
    if validated:
        return Severity.CRITICAL
    lowered = rule.lower()
    if any(k in lowered for k in ("private_key", "private key", "aws", "stripe_live", "gcp")):
        return Severity.HIGH
    return Severity.MEDIUM


def _record_finding(
    engagement: Any,
    *,
    rule: str,
    path: str,
    line: int | None,
    validated: bool,
    validation_note: str,
    snippet: str,
    tool: str,
    blast_radius: dict[str, Any] | None = None,
) -> Finding:
    finding = Finding(
        asset=path,
        title=f"{'Validated' if validated else 'Unvalidated'} secret: {rule}",
        phase="secrets",
        severity=_severity_for(rule, validated),
        # A validated credential still enters as needs-review, not confirmed:
        # confirmation means *we* reproduced it, and validation was the scanner's
        # observation. The PoC step is what promotes it.
        status=Status.NEEDS_MANUAL_REVIEW if validated else Status.CANDIDATE,
        description=(
            f"A value matching '{rule}' was found in {path}"
            + (f" at line {line}" if line else "")
            + (". The credential was confirmed live by the scanner." if validated else
               ". The credential was NOT validated — it may be a test fixture, an "
               "example, or already revoked.")
        ),
        how_found=f"{tool} rule '{rule}' matched in {path}",
        source_tool=tool,
        rule_id=f"secret.{rule}",
        confidence=0.9 if validated else 0.4,
        validated=validated,
        evidence=[Evidence(kind="file", description=f"{path}:{line or '?'}", excerpt=snippet[:500])],
        remediation=(
            "Rotate the credential immediately — disclosure is compromise, and "
            "removing the commit does not un-disclose it. Then move the secret to a "
            "secret manager and add a pre-commit scanner so the next one is caught "
            "before it lands."
        ),
        tags=["secret", "validated" if validated else "unvalidated"],
        extra={"validation": validation_note, "blast_radius": blast_radius},
    )
    if not validated:
        finding.note(
            "Unvalidated. Check whether this is a live credential before reporting — "
            "test fixtures and public sample keys are the most common false positive."
        )
    engagement.findings.add(finding)
    return finding


def _parse_kingfisher(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        for item in record if isinstance(record, list) else [record]:
            if not isinstance(item, dict):
                continue
            finding = item.get("finding") or item
            validation = finding.get("validation") or {}
            out.append(
                {
                    "rule": str(finding.get("rule_name") or finding.get("rule") or "unknown"),
                    "path": str(
                        (finding.get("origin") or {}).get("path")
                        or finding.get("path")
                        or finding.get("file")
                        or "unknown"
                    ),
                    "line": finding.get("line") or (finding.get("location") or {}).get("line"),
                    "validated": bool(validation.get("valid") or finding.get("validated")),
                    "validation_note": str(validation.get("status") or ""),
                    "snippet": str(finding.get("snippet") or finding.get("match") or ""),
                    "blast_radius": finding.get("access_map") or finding.get("blast_radius"),
                }
            )
    return out


def _parse_gitleaks(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [
        {
            "rule": str(item.get("RuleID") or "unknown"),
            "path": str(item.get("File") or "unknown"),
            "line": item.get("StartLine"),
            "validated": False,
            "validation_note": "gitleaks does not validate credentials",
            "snippet": str(item.get("Match") or "")[:300],
            "blast_radius": None,
        }
        for item in (payload if isinstance(payload, list) else [])
    ]


@easyhunt_tool(
    phase="secrets", mode="passive", targets_arg=None, timeout=1800,
    name="secret_scan", tags={"secrets"}, estimated_requests=0,
)
async def secret_scan(path: str = ".", git_history: bool = True) -> dict[str, Any]:
    """Scan files in the engagement workspace for credentials. No validation.

    Runs Kingfisher (primary), Nosey Parker (git history + ML denoising), and
    gitleaks where installed. Sends no traffic anywhere — every hit is a
    *candidate* until secret_validate says otherwise.

    path is workspace-relative; paths outside the workspace are refused.
    """
    engagement = get_engagement()
    scan_path = sanitize_path(path, workspace=engagement.workspace, name="path", must_exist=True)

    kingfisher_out = engagement.raw_path("kingfisher", "jsonl")
    gitleaks_out = engagement.raw_path("gitleaks", "json")

    kingfisher = await run_one(
        "kingfisher",
        [
            "scan", str(scan_path),
            "--format", "jsonl", "--output", str(kingfisher_out),
            # Explicitly off: validation is a separate, gated tool.
            "--no-validate",
            "--confidence", "medium",
            "--git-history", "full" if git_history else "none",
            "--redact",
        ],
        timeout=1500,
        allow_codes=(0, 200, 205),
    )
    noseyparker = await run_one(
        "noseyparker",
        ["scan", "--datastore", str(engagement.workspace / "np-datastore"), str(scan_path)],
        timeout=1500,
        allow_codes=(0, 1),
    )
    gitleaks = await run_one(
        "gitleaks",
        [
            "detect", "--source", str(scan_path), "--report-format", "json",
            "--report-path", str(gitleaks_out), "--no-banner", "--redact", "--exit-code", "0",
        ],
        timeout=900,
        allow_codes=(0, 1),
    )

    hits: list[dict[str, Any]] = []
    if kingfisher_out.exists():
        hits.extend(_parse_kingfisher(kingfisher_out.read_text(encoding="utf-8", errors="replace")))
    if gitleaks_out.exists():
        hits.extend(_parse_gitleaks(gitleaks_out.read_text(encoding="utf-8", errors="replace")))

    findings = [
        _record_finding(
            engagement,
            rule=hit["rule"],
            path=hit["path"],
            line=hit["line"],
            validated=hit["validated"],
            validation_note=hit["validation_note"],
            snippet=hit["snippet"],
            tool="kingfisher" if hit.get("blast_radius") is not None or hit["validation_note"] else "gitleaks",
            blast_radius=hit.get("blast_radius"),
        )
        for hit in hits
    ]
    engagement.findings.save()

    return {
        "ok": True,
        "path": str(scan_path),
        "candidates": len(findings),
        "validated": 0,
        "by_rule": _count(hits, "rule"),
        "findings": [f.to_dict() for f in findings[:200]],
        "tools": [kingfisher.to_dict(), noseyparker.to_dict(), gitleaks.to_dict()],
        "next_step": (
            "Nothing here is validated. Triage the candidates, then use "
            "secret_validate on the plausible ones — that step is gated because "
            "validating a credential means using it."
        ),
    }


@easyhunt_tool(
    phase="secrets", mode="aggressive", targets_arg=None, timeout=1800,
    name="secret_validate", tags={"secrets"},
    # One or more requests per candidate, and a repository with any history
    # routinely yields hundreds. 50 was a placeholder.
    estimated_requests=500,
    risk_notes=[
        "Sends each candidate credential to its issuing service to test whether it works.",
        "Those requests are authenticated as the credential's owner and may be logged by them.",
        "Request count scales with the number of candidates found, not with the "
        "estimate above — a repository with deep history can produce hundreds.",
        "Paced by kingfisher --validation-rps at the engagement's max_rps.",
        "Only validate credentials belonging to the program you are testing.",
    ],
)
async def secret_validate(path: str = ".") -> dict[str, Any]:
    """Validate candidate credentials with Kingfisher and map their blast radius.

    This is what makes a secrets report actionable: a live credential is critical,
    an unvalidated match is noise. It is gated because validation is *use* — the
    request goes to AWS/GitHub/Stripe authenticated as whoever owns the key.

    Validation traffic is paced at the engagement's ``max_rps``. That ceiling was
    written for the target, and these requests go to third parties instead — but
    it is the only rate this engagement has consented to, and issuing hundreds of
    authenticated requests per second at anyone is not something a scan should
    decide on its own.
    """
    engagement = get_engagement()
    rules = engagement.scope.rules
    scan_path = sanitize_path(path, workspace=engagement.workspace, name="path", must_exist=True)
    output = engagement.raw_path("kingfisher-validated", "jsonl")

    run = await run_one(
        "kingfisher",
        [
            "scan", str(scan_path),
            "--format", "jsonl", "--output", str(output),
            "--confidence", "medium", "--git-history", "full", "--redact",
            # The global ceiling over credential-validation requests. Without it
            # kingfisher validates as fast as the network allows.
            "--validation-rps", str(max(1, int(rules.max_rps))),
        ],
        timeout=1500,
        allow_codes=(0, 200, 205),
    )

    hits = (
        _parse_kingfisher(output.read_text(encoding="utf-8", errors="replace"))
        if output.exists()
        else []
    )
    validated = [h for h in hits if h["validated"]]
    findings = [
        _record_finding(
            engagement,
            rule=hit["rule"], path=hit["path"], line=hit["line"],
            validated=hit["validated"], validation_note=hit["validation_note"],
            snippet=hit["snippet"], tool="kingfisher", blast_radius=hit.get("blast_radius"),
        )
        for hit in hits
    ]
    engagement.findings.save()

    return {
        "ok": True,
        "path": str(scan_path),
        "total_candidates": len(hits),
        "validated": len(validated),
        "unvalidated": len(hits) - len(validated),
        "validated_findings": [f.to_dict() for f in findings if f.validated],
        "blast_radius": [
            {"rule": h["rule"], "path": h["path"], "access": h.get("blast_radius")}
            for h in validated
            if h.get("blast_radius")
        ],
        "tools": [run.to_dict()],
        "next_step": (
            f"{len(validated)} credential(s) authenticate. Report those immediately and "
            "tell the program to rotate before anything else — a live key in a public "
            "artifact is already compromised. Do not use the credential beyond the "
            "single call that proved it works."
        ),
    }


@easyhunt_tool(
    phase="secrets", mode="passive", targets_arg=None, timeout=900,
    name="source_fetch", tags={"secrets", "recon"}, estimated_requests=5,
    risk_notes=[
        "git clone has no rate flag. Ungoverned, but it is one connection to a "
        "code host and never touches the target.",
    ],
)
async def source_fetch(repo_url: str, depth: int = 100) -> dict[str, Any]:
    """Clone a public repository into the workspace so it can be scanned.

    Cloning is separated from scanning so the audit log always answers "what code
    did EasyHunt read". Only github/gitlab/bitbucket HTTPS URLs are accepted.

    Confirm the repository actually belongs to the program before scanning it —
    an organization name matching the target is not proof of ownership.
    """
    engagement = get_engagement()
    if not REPO_URL.fullmatch(repo_url.rstrip("/")):
        return {
            "ok": False,
            "error": "unsupported_repo_url",
            "message": (
                "Only https://github.com|gitlab.com|bitbucket.org/<owner>/<repo> URLs "
                "are accepted."
            ),
        }

    name = repo_url.rstrip("/").rstrip(".git").rsplit("/", 2)
    destination = engagement.workspace / "source" / f"{name[-2]}_{name[-1]}"
    if destination.exists():
        return {
            "ok": True,
            "path": str(destination),
            "cloned": False,
            "message": "already present in the workspace",
        }
    destination.parent.mkdir(parents=True, exist_ok=True)

    run = await run_one(
        "git",
        ["clone", "--quiet", "--depth", str(max(1, min(depth, 5000))), repo_url, str(destination)],
        timeout=600,
    )
    engagement.audit.record("source_fetch", repo_url=repo_url, destination=str(destination))

    return {
        "ok": destination.exists(),
        "repo_url": repo_url,
        "path": str(destination),
        "cloned": destination.exists(),
        "tools": [run.to_dict()],
        "next_step": (
            f"Confirm this repository belongs to the program, then scan it with "
            f"secret_scan(path='source/{destination.name}')."
        ),
    }


def _count(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        out[str(item.get(key))] = out.get(str(item.get(key)), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))

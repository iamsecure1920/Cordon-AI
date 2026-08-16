"""Nuclei — the vulnerability core, and EasyHunt's primary rule DSL.

Wraps both template selection (``-t``, ``-tags``, ``-severity``) and workflows
(``-w``, conditional template chaining). Community templates and everything under
``rules/nuclei/`` are scanned together, so a user-authored template is a
first-class detection with no code change.

Three things are enforced here rather than left to the caller:

* The rate limit comes from ``scope.yaml`` and is not a caller-supplied argument.
  A tool argument the agent can set is a rate limit the agent can raise.
* ``dos``, ``fuzz``, and ``intrusive`` tags are excluded, and ``-itags`` (which
  re-enables them) is not on the argument allowlist.
* Every result lands as a *candidate*. Nuclei is a very good scanner and it is
  still not a PoC.
"""

from __future__ import annotations

import logging
import math
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
from easyhunt.util.parse import parse_jsonl

log = logging.getLogger("easyhunt.engines.nuclei")

__all__ = ["nuclei_scan", "parse_nuclei_results"]

# Tags whose templates exist to break things, not to find things.
DENIED_TAGS = {"dos", "fuzz", "intrusive", "bruteforce", "brute-force"}

SPEC = register_spec(
    ToolSpec(
        name="nuclei",
        binary="nuclei",
        image="projectdiscovery/nuclei:latest",
        license="MIT",
        homepage="https://github.com/projectdiscovery/nuclei",
        version_args=["-version"],
        # PyPI's "nuclei" is a 2018 Kaggle Data Science Bowl package. This is the
        # most-used tool in the project and the one whose silent substitution
        # would be least visible: the wrong binary exits, prints nothing this
        # parser understands, and the run reports zero findings.
        # Verified: -version prints "Nuclei Engine Version: v3.7.1".
        identity_marker="nuclei engine",
        user_agent_flag="-H",
        arg_policy=ArgPolicy(
            tool="nuclei",
            allowed_flags={
                "-u", "-l", "-t", "-w", "-tags", "-etags", "-severity", "-es",
                "-rate-limit", "-c", "-timeout", "-retries", "-jsonl", "-silent",
                "-no-color", "-duc", "-nc", "-H", "-nh", "-ni", "-stats", "-me",
                "-disable-update-check", "-header", "-follow-redirects", "-mhe",
                # -tl lists the selected templates locally and sends nothing to
                # any target. It is how a scan is sized before it is launched.
                "-tl",
            },
            boolean_flags={
                "-jsonl", "-silent", "-no-color", "-duc", "-nc", "-stats", "-nh", "-ni",
                "-disable-update-check", "-follow-redirects", "-tl",
            },
            # -itags is deliberately absent: it re-enables dos/fuzz/intrusive.
            denied_flags={"-itags", "-headless", "-proxy", "-si", "-interactsh-server"},
            value_patterns={
                "-severity": re.compile(r"[a-z,]+"),
                "-es": re.compile(r"[a-z,]+"),
                "-tags": re.compile(r"[a-z0-9,._-]+"),
                "-etags": re.compile(r"[a-z0-9,._-]+"),
            },
            numeric_caps={"-rate-limit": 150, "-c": 50, "-timeout": 60, "-retries": 3, "-mhe": 30},
            denied_values={"-tags": DENIED_TAGS},
            allow_positional=False,
            max_argv=64,
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
    "unknown": Severity.INFO,
}


def parse_nuclei_results(text: str, *, phase: str = "vuln_scan") -> list[Finding]:
    """Turn Nuclei JSONL into normalized candidate findings."""
    findings: list[Finding] = []
    for record in parse_jsonl(text):
        info = record.get("info") or {}
        template_id = str(record.get("template-id") or record.get("templateID") or "unknown")
        matched = str(record.get("matched-at") or record.get("host") or "")
        severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)

        evidence: list[Evidence] = []
        if record.get("request"):
            evidence.append(
                Evidence(kind="request", description="Nuclei request", excerpt=str(record["request"])[:4000])
            )
        if record.get("response"):
            evidence.append(
                Evidence(kind="response", description="Nuclei response", excerpt=str(record["response"])[:4000])
            )
        if record.get("extracted-results"):
            evidence.append(
                Evidence(
                    kind="log",
                    description="Extracted values",
                    excerpt=", ".join(str(v) for v in record["extracted-results"])[:2000],
                )
            )

        classification = info.get("classification") or {}
        cvss_score = classification.get("cvss-score")

        findings.append(
            Finding(
                asset=matched,
                title=str(info.get("name") or template_id),
                phase=phase,
                severity=severity,
                status=Status.CANDIDATE,
                description=str(info.get("description") or "").strip(),
                how_found=f"Nuclei template '{template_id}' matched at {matched}",
                source_tool="nuclei",
                rule_id=template_id,
                cvss=float(cvss_score) if isinstance(cvss_score, (int, float)) else None,
                cvss_vector=classification.get("cvss-metrics"),
                # Scanner-grade confidence: enough to investigate, never enough
                # to report. Only a PoC moves this past 0.95.
                confidence=0.55 if severity.rank >= 3 else 0.45,
                evidence=evidence,
                remediation=str(info.get("remediation") or "").strip(),
                tags=[str(t) for t in (info.get("tags") or [])],
                references=[str(r) for r in (info.get("reference") or []) if r],
                extra={
                    "matcher_name": record.get("matcher-name"),
                    "type": record.get("type"),
                    "curl_command": record.get("curl-command"),
                    "template_path": record.get("template"),
                },
            )
        )
    return findings


def _template_args(engagement: Any, templates: list[str] | None, workflow: str | None) -> list[str]:
    """Resolve template/workflow selection, always including custom rules."""
    args: list[str] = []
    if workflow:
        args += ["-w", workflow]
        return args

    explicit = list(templates or [])
    for template in explicit:
        args += ["-t", template]

    # Custom templates from the rule layer always participate.
    from easyhunt.plugins.loader import get_registry

    custom_dirs = sorted({str(Path(p).parent) for p in get_registry().nuclei_paths()})
    for directory in custom_dirs:
        args += ["-t", directory]

    # The main library is included whenever the caller did not name specific
    # templates. This used to be an `if not args` fallback, which meant a single
    # custom rule silently *replaced* all 13,391 upstream templates: nuclei then
    # exited with "no templates provided for scan" for any tag the custom rule
    # did not carry. Custom rules add to the library, they do not stand in for it.
    if not explicit:
        configured = engagement.config.get("engines.nuclei.templates_dir")
        if configured:
            expanded = Path(str(configured)).expanduser()
            if expanded.is_dir():
                args += ["-t", str(expanded)]
    return args



#: Requests per template, measured on a live estate: 5,148 templates produced
#: 10,922 requests after nuclei's own clustering. Templates are not 1:1 with
#: requests — some probe several paths, and clustering merges others.
_REQUESTS_PER_TEMPLATE = 2.1

#: Sustained throughput nuclei actually achieved at rate-limit 10, concurrency 5,
#: against a Cloudflare-fronted estate. Used to turn a request count into wall
#: clock, because the ceiling that kills a scan is time, not requests.
_OBSERVED_RPS = 15.0

#: Technology names as http_probe reports them (lowercased) mapped to the nuclei
#: tags worth firing against that stack. The unattended pipeline calls
#: ``nuclei_scan`` with no template selection; without this mapping the default
#: load is every community template (~7,445), which the sizing gate correctly
#: refuses on anything but a handful of hosts. Mapping the observed stack to its
#: tags turns "everything, refused" into "what this estate actually runs", and
#: a stack fingerprint says nothing about — the always-on core below.
#: Keyed on substrings so "Apache HTTP Server:2.4.56" matches "apache".
_STACK_TAGS: dict[str, str] = {
    "wordpress": "wordpress",
    "php": "php",
    "java": "java,spring",
    "spring": "spring",
    "tomcat": "tomcat",
    "weblogic": "weblogic",
    "glassfish": "glassfish",
    "jboss": "jboss",
    "iis": "microsoft-iis",
    "asp.net": "aspnet",
    "sharepoint": "sharepoint",
    "django": "django",
    "rails": "ruby",
    "node.js": "nodejs",
    "express": "nodejs",
    "next.js": "nextjs",
    "nginx": "nginx",
    "apache": "apache",
    "graphql": "graphql",
    "swagger": "swagger",
    "salesforce": "salesforce",
    "magento": "magento",
    "drupal": "drupal",
    "joomla": "joomla",
    "laravel": "laravel",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "react": "react",
    "angular": "angular",
}

#: Tags worth firing regardless of what the stack fingerprint says: exposed
#: files/config and default credentials are the classes a scanner earns its
#: keep on, and none of them depend on knowing the framework.
_CORE_TAGS = "exposure,misconfig,default-login,tech"

#: Severity tiers tried, broadest first, when the unattended pipeline must
#: size its own scan. The full tier usually cannot fit a large estate; each
#: narrowing cuts roughly half the templates until the set fits the ceiling.
_SEVERITY_TIERS = ("low,medium,high,critical", "high,critical", "critical")


def _derive_stack_tags(engagement: Any) -> str:
    """Nuclei tags for the technologies http_probe observed, plus the core set."""
    matched: set[str] = set()
    for tech in engagement.assets.values("technology"):
        name = str(tech).lower()
        for needle, tags in _STACK_TAGS.items():
            if needle in name:
                matched.update(t for t in tags.split(","))
    matched.update(_CORE_TAGS.split(","))
    return ",".join(sorted(matched))


def _prioritize_targets(engagement: Any, targets: list[str]) -> list[str]:
    """Order targets so a budget-limited scan covers the reward surface first.

    Scope focus URLs (``in_scope.urls``, the assets a program names explicitly)
    come first, then hosts that share a focus host, then everything else. A
    scan that can only afford a fraction of a large estate should spend it on
    what the program said matters, not on the alphabetically-first live URL.
    """
    focus = getattr(engagement.scope, "_allow", None)
    focus_hosts: set[str] = set()
    for host, _path in (getattr(focus, "urls", []) or []):
        if host:
            focus_hosts.add(host.lower())

    def host_of(url: str) -> str:
        try:
            from urllib.parse import urlsplit

            return (urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    def rank(url: str) -> tuple[int, int, str]:
        host = host_of(url)
        if host in focus_hosts:
            return (0, 0, url)
        if any(host == f or host.endswith("." + f) for f in focus_hosts):
            return (1, 0, url)
        return (2, 0, url)

    return sorted(targets, key=rank)


async def _size_unattended_scan(
    engagement: Any, targets: list[str], tags: str,
) -> tuple[list[str], str, dict[str, Any]] | None:
    """Pick the severity tier and target subset a scan can actually finish.

    The sizing gate refuses a selection it cannot complete inside the ceiling
    rather than start a scan that will be killed mid-run and read as a clean
    estate. That refusal is right for an agent that can narrow the selection.
    The unattended pipeline cannot, so it must narrow itself: try progressively
    tighter severity tiers until the full target set fits the ceiling and the
    remaining request budget; if even ``critical`` cannot fit everything,
    prioritize the targets (focus URLs first) and scan the largest subset that
    fits, reporting exactly what was covered.

    Returns ``(targets, severity, sizing)`` or ``None`` when even a single
    target with the tightest tier cannot fit — the only case left where the
    right answer is a refusal, not a narrower scan.
    """
    rules = engagement.scope.rules
    rps = min(float(rules.max_rps or _OBSERVED_RPS), _OBSERVED_RPS)
    ceiling = 3600.0
    reachable = int(rps * ceiling)
    budget_remaining = engagement.budget.remaining().get("requests") or 0
    # With budget enforcement off the scope reports unlimited; the request
    # ceiling is then the rate limit x wall clock, not a budget number.
    budget_capped = not math.isinf(budget_remaining)

    for tier in _SEVERITY_TIERS:
        count = None
        try:
            count = await _count_templates(
                engagement, templates=None, workflow=None, tags=tags, severity=tier
            )
        except Exception as exc:  # noqa: BLE001 — sizing must never block the scan
            log.warning("template count unavailable for severity %s: %s", tier, exc)
            pass
        if not count:
            continue
        per_target = count * _REQUESTS_PER_TEMPLATE
        if per_target <= 0:
            continue
        max_targets = int(reachable / per_target)
        if budget_capped:
            max_targets = min(max_targets, int(budget_remaining / per_target))
        if max_targets <= 0:
            # This tier cannot fit even one target; try the next (tighter) one.
            continue
        if max_targets >= len(targets):
            return targets, tier, {
                "templates": count, "severity": tier, "truncated": False,
            }
        # The tier fits some targets but not all. The tightest tier is the last
        # word on what can fit; anything before it, keep trying to fit everyone.
        if tier == _SEVERITY_TIERS[-1]:
            ordered = _prioritize_targets(engagement, targets)
            kept = ordered[:max_targets]
            return kept, tier, {
                "templates": count, "severity": tier, "truncated": True,
                "scanned": len(kept), "total": len(targets),
            }
    return None


async def _count_templates(
    engagement: Any, *, templates: list[str] | None, workflow: str | None,
    tags: str | None, severity: str,
) -> int | None:
    """How many templates would this selection load? Sends nothing to the target.

    ``-tl`` lists templates locally. It costs 30-60s, which is cheap against the
    multi-hour scan it prevents from starting blind.
    """
    argv = ["-tl", "-silent", "-duc", "-disable-update-check", "-severity", severity,
            "-etags", ",".join(sorted(DENIED_TAGS))]
    argv += _template_args(engagement, templates, workflow)
    if tags:
        argv += ["-tags", tags]
    try:
        result = await guarded_run(
            SPEC, argv, timeout=180, engagement=engagement, check=False, allow_codes=(0, 1),
        )
    except Exception:  # noqa: BLE001 — an estimate must never block the scan
        return None
    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    return len(lines) or None


async def _estimate_scan(
    engagement: Any, *, targets: list[str], templates: list[str] | None,
    workflow: str | None, tags: str | None, severity: str,
) -> dict[str, Any]:
    """Predict request count and wall clock, and refuse what cannot finish."""
    count = await _count_templates(
        engagement, templates=templates, workflow=workflow, tags=tags, severity=severity
    )
    if not count:
        # Unknown is not the same as fine; proceed, but say the estimate is absent.
        return {"templates": None, "note": "template count unavailable; scan not sized"}

    rules = engagement.scope.rules
    rps = min(float(rules.max_rps or _OBSERVED_RPS), _OBSERVED_RPS)
    requests = int(count * _REQUESTS_PER_TEMPLATE * len(targets))
    seconds = requests / max(rps, 0.1)
    # The engine's own execution ceiling, matching the decorator's timeout.
    ceiling = 3600.0
    reachable = int(rps * ceiling)

    estimate = {
        "templates": count,
        "targets": len(targets),
        "estimated_requests": requests,
        "estimated_seconds": int(seconds),
        "estimated_hours": round(seconds / 3600, 1),
        "reachable_within_timeout": reachable,
        "coverage_if_run": round(min(1.0, reachable / max(requests, 1)) * 100),
    }

    if seconds > ceiling:
        estimate["infeasible"] = True
        estimate["message"] = (
            f"{count} templates x {len(targets)} targets is ~{requests:,} requests "
            f"(~{seconds / 3600:.1f}h at {rps:.0f} rps), but the execution ceiling is "
            f"{ceiling / 3600:.0f}h. Running this would cover about "
            f"{estimate['coverage_if_run']}% of the templates and then be killed — "
            "and zero findings from a truncated scan reads exactly like a clean estate."
        )
    return estimate


async def _run(
    job: Job,
    *,
    targets: list[str],
    templates: list[str] | None,
    workflow: str | None,
    tags: str | None,
    severity: str,
    concurrency: int,
    sizing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = get_engagement()
    rules = engagement.scope.rules

    targets_file = engagement.workspace / "raw" / f"nuclei-targets-{job.id}.txt"
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    argv: list[str] = [
        "-l", str(targets_file),
        "-jsonl", "-silent", "-nc", "-duc", "-disable-update-check",
        # Rate limit and concurrency come from the engagement, not the caller.
        "-rate-limit", str(max(1, int(rules.max_rps))),
        "-c", str(max(1, min(concurrency, rules.max_concurrency))),
        "-severity", severity,
        # Excluded regardless of what the caller asked for.
        "-etags", ",".join(sorted(DENIED_TAGS)),
        "-timeout", "15",
        "-retries", "1",
    ]
    argv += _template_args(engagement, templates, workflow)
    if tags:
        argv += ["-tags", tags]

    job.progress = f"scanning {len(targets)} target(s)"
    result = await guarded_run(
        SPEC,
        argv,
        timeout=3600,
        output_name="nuclei",
        engagement=engagement,
        # Nuclei exits 1 when it finds nothing on some builds; that is not an error.
        allow_codes=(0, 1),
        check=False,
    )
    if result.timed_out:
        job.progress = "timed out"

    parsed = parse_nuclei_results(result.stdout)
    stored: list[Finding] = []
    dropped = 0
    for finding in parsed:
        # Third scope check: a template can follow a redirect off-scope.
        if engagement.scope.check(finding.asset).in_scope:
            engagement.findings.add(finding)
            stored.append(finding)
        else:
            dropped += 1
            engagement.audit.record(
                "finding_dropped", reason="out_of_scope", asset=finding.asset, rule=finding.rule_id
            )
    engagement.findings.save()
    job.events_seen = len(stored)

    by_severity: dict[str, int] = {}
    for finding in stored:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

    # Nuclei exits 1 both for "found nothing" and for fatal startup errors, so the
    # exit code alone cannot distinguish them. A [FTL] line means the scan never
    # ran — and reporting ok=True there turns "nuclei was misconfigured" into
    # "this estate is clean", which is the most expensive lie this tool can tell.
    fatal = ""
    for line in (result.stderr or "").splitlines():
        if "[FTL]" in line or "Could not run nuclei" in line:
            fatal = line.strip()
            break

    return {
        "ok": not fatal,
        "error": "nuclei_failed" if fatal else None,
        "message": (
            f"nuclei did not run: {fatal}. Zero findings here means UNTESTED, "
            "not clean."
        ) if fatal else None,
        "targets": len(targets),
        "raw_output": str(result.output_path) if result.output_path else None,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "stderr_tail": result.stderr[-1000:] if result.stderr else "",
        # When the unattended pipeline sized its own scan (derived stack tags,
        # severity tier, possibly truncated target set), the phase result must
        # say so — a scan that covered 52 of 944 URLs is not a full-estate scan,
        # and the report must not let it read like one.
        "sizing": sizing,
        "selection": {"tags": tags, "severity": severity} if sizing else None,
        # Counts reflect what was kept, not what the scanner printed.
        "count": len(stored),
        "dropped_out_of_scope": dropped,
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in sorted(stored, key=lambda f: -f.severity.rank)],
        # A timed-out scan covered an unknown fraction of the template set. It is
        # not a clean result and must never be summarized as one: nuclei works
        # through templates in order, so a kill at the wall clock means the tail
        # of the selection was never sent at all.
        "complete": not (result.timed_out or bool(fatal)),
        "coverage": "partial" if result.timed_out else ("none" if fatal else "full"),
        "note": (
            (
                "INCOMPLETE: killed at the execution timeout after covering an "
                "unknown fraction of the selected templates. "
                + (
                    "Zero findings here means UNTESTED, not clean — narrow the "
                    "template selection or raise the timeout and re-run."
                    if not stored
                    else "The findings below are real, but absence of others proves nothing."
                )
                + " "
            )
            if result.timed_out
            else ""
        ) + (
            "All results are CANDIDATES. Run triage, then validate the survivors "
            "with a PoC before any of them is reported as confirmed."
        ),
    }


@easyhunt_tool(
    phase="vuln_scan",
    mode="aggressive",
    targets_arg="target",
    timeout=3600,
    name="nuclei_scan",
    spec=SPEC,
    tags={"engine", "vuln"},
    estimated_requests=500,
    risk_notes=[
        "Sends template payloads directly to the target.",
        "Rate limited to the program's published ceiling, but still visible in logs.",
        "dos/fuzz/intrusive templates are excluded and cannot be re-enabled.",
    ],
)
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    workflow: str | None = None,
    tags: str | None = None,
    severity: str = "low,medium,high,critical",
    concurrency: int = 10,
    wait_seconds: float = 120.0,
) -> dict[str, Any]:
    """Scan in-scope targets with Nuclei templates or a workflow.

    templates: template files/dirs/ids to run. Custom rules under rules/nuclei/
    are always included. workflow: a workflow file for conditional chaining.
    tags: comma-separated template tags (dos/fuzz/intrusive are refused).

    Returns inline if it finishes within wait_seconds, otherwise a job_id.
    """
    engagement = get_engagement()
    if not engagement.config.get("engines.nuclei.enabled", True):
        raise ToolUnavailable("nuclei engine is disabled in config", tool="nuclei")

    if tags:
        requested = {t.strip().lower() for t in tags.split(",")}
        overlap = requested & DENIED_TAGS
        if overlap:
            raise ToolUnavailable(
                f"tags {sorted(overlap)} are disruptive and are never run by EasyHunt",
                tool="nuclei",
                tags=sorted(overlap),
            )

    # No target means "every live URL http_probe recorded". Scanning hosts that
    # were never confirmed alive is the most common way a scan reports complete
    # coverage of nothing.
    from easyhunt.tools.common import targets_or_assets

    targets, target_origin = targets_or_assets(target, kind="url", tool="nuclei_scan")

    # The unattended pipeline (hunt.sh) passes no template selection, which
    # used to mean "every community template" — 7,445 of them, refused by the
    # sizing gate before it starts. Derive a stack-matched selection instead:
    # the technologies http_probe already observed, plus the always-on core.
    # An explicit templates/workflow/tags argument still wins untouched; this
    # is only the no-selection default.
    explicit_selection = bool(templates or workflow or tags)
    sizing: dict[str, Any] | None = None
    if not explicit_selection:
        tags = _derive_stack_tags(engagement)

    # Size the scan before running it. `estimated_requests` on the decorator is a
    # fixed 500, which on a real engagement was 437x too low: 5,148 templates
    # across 20 hosts needed 218,440 requests against a 100,000 budget, and the
    # budget gate waved it through because it was comparing against 500. A gate
    # fed a constant cannot protect anything.
    feasibility = await _estimate_scan(
        engagement, targets=targets, templates=templates, workflow=workflow,
        tags=tags, severity=severity,
    )
    if feasibility.get("infeasible"):
        if explicit_selection:
            # The caller named the selection, so they can narrow it. Keep the
            # refusal and say how.
            return {
                "ok": False,
                "error": "scan_too_large",
                "message": feasibility["message"],
                "estimate": feasibility,
                "hint": (
                    "Narrow the template selection (dropping 'cve' usually removes ~75% "
                    "of them), scan fewer hosts, or raise the timeout deliberately."
                ),
            }
        # No explicit selection: the scan must size itself to what it can
        # actually finish instead of refusing — a refusal here is the pipeline
        # skipping the estate's only vuln scan. Try tighter severity tiers, and
        # if even critical cannot fit everything, prioritize the targets
        # (focus URLs first) and scan the largest subset that fits.
        sized = await _size_unattended_scan(engagement, targets, tags)
        if sized is None:
            return {
                "ok": False,
                "error": "scan_too_large",
                "message": feasibility["message"],
                "estimate": feasibility,
                "hint": (
                    "Even critical-severity stack-matched templates cannot fit one "
                    "target in the execution ceiling; raise the timeout deliberately."
                ),
            }
        targets, severity, sizing = sized
        feasibility = await _estimate_scan(
            engagement, targets=targets, templates=templates, workflow=workflow,
            tags=tags, severity=severity,
        )

    job = engagement.jobs.launch(
        lambda j: _run(
            j,
            targets=targets,
            templates=templates,
            workflow=workflow,
            tags=tags,
            severity=severity,
            concurrency=concurrency,
            sizing=sizing if not explicit_selection else None,
        ),
        tool="nuclei_scan",
        phase="vuln_scan",
        targets=targets,
    )

    payload = await engagement.jobs.wait(job.id, timeout=max(0.0, min(wait_seconds, 300)))
    if payload.get("ready") and payload.get("ok"):
        result = {"job_id": job.id, "completed": True, **payload["result"]}
        # The unattended scan may have sized itself down (tighter severity, or
        # focus URLs first when even critical cannot fit the whole estate). Say
        # so in the result, or a truncated scan reads exactly like a clean one.
        if not explicit_selection and "sizing" in locals():
            result["selection"] = {"tags": tags, "severity": severity}
            result["sizing"] = sizing
        return result
    return {
        "job_id": job.id,
        "completed": False,
        "status": payload.get("status"),
        "progress": payload.get("progress"),
        "error": payload.get("error"),
        "next_step": (
            f"Still scanning. Poll job_status('{job.id}'), then pull results with "
            f"fetch_slice('{job.id}', path='findings', where='high|critical')."
        ),
    }

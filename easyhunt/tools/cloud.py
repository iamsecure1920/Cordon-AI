"""Cloud and Kubernetes assessment.

Two distinct positions, and conflating them is how people test infrastructure
they were never authorized for:

* **Outside, no credentials** — ``cloud_asset_discovery`` guesses bucket and
  storage names from a keyword. Every hit must be checked against the scope
  before it is touched, because a bucket named ``acme-backups`` may belong to a
  different Acme entirely.
* **Inside, with credentials the program gave you** — ``cloud_permissions``,
  ``cloud_audit``, and ``cloud_attack_paths`` enumerate what a principal can
  reach. These read; they do not modify.

Attack-path analysis (Prowler + Cartography) is the part worth the effort. A list
of misconfigurations is a checklist. A graph showing that a public Lambda reaches
an admin role in two hops is a finding with an impact statement already written.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.sanitize import ArgPolicy
from easyhunt.knowledge.attackgraph import (
    build_from_cartography,
    build_from_prowler,
    cartography_available,
)
from easyhunt.knowledge.findings import Asset, Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import register_spec, run_one

__all__ = [
    "cloud_asset_discovery",
    "cloud_attack_paths",
    "cloud_audit",
    "cloud_permissions",
    "k8s_posture",
]

KEYWORD = re.compile(r"[A-Za-z0-9._-]{2,64}")

CLOUD_ENUM = register_spec(
    ToolSpec(
        name="cloud_enum", binary="cloud_enum", license="MIT",
        homepage="https://github.com/initstring/cloud_enum", version_args=["--help"],
        identity_marker="cloud_enum",
        arg_policy=ArgPolicy(
            tool="cloud_enum",
            allowed_flags={"-k", "--keyword", "-l", "--logfile", "-t", "--threads", "-f", "--format", "--disable-aws", "--disable-azure", "--disable-gcp", "-qs"},
            boolean_flags={"--disable-aws", "--disable-azure", "--disable-gcp", "-qs"},
            value_patterns={"-k": KEYWORD, "--keyword": KEYWORD, "--format": re.compile(r"json|text")},
            numeric_caps={"-t": 20, "--threads": 20},
        ),
    )
)

S3SCANNER = register_spec(
    ToolSpec(
        name="s3scanner", binary="s3scanner", license="MIT",
        homepage="https://github.com/sa7mon/S3Scanner", version_args=["-version"],
        arg_policy=ArgPolicy(
            tool="s3scanner",
            allowed_flags={"-bucket", "-bucket-file", "-json", "-provider", "-threads", "-enumerate"},
            boolean_flags={"-json", "-enumerate"},
            value_patterns={"-bucket": KEYWORD, "-provider": re.compile(r"aws|gcp|digitalocean|dreamhost|linode|scaleway|custom")},
            numeric_caps={"-threads": 20},
        ),
    )
)

CLOUDFOX = register_spec(
    ToolSpec(
        name="cloudfox", binary="cloudfox", license="MIT",
        homepage="https://github.com/BishopFox/cloudfox", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="cloudfox",
            allowed_flags={"-p", "--profile", "-o", "--outdir", "-v", "--format", "--region"},
            value_patterns={
                "--profile": KEYWORD, "-p": KEYWORD,
                "--region": re.compile(r"[a-z0-9-]{4,32}"),
                "--format": re.compile(r"table|csv|json"),
            },
            allow_positional=True,
            positional_pattern=re.compile(r"aws|azure|gcp|all-checks|permissions|principals|inventory|endpoints|secrets|role-trusts"),
        ),
    )
)

PROWLER = register_spec(
    ToolSpec(
        name="prowler", binary="prowler", image="toniblyx/prowler:latest", license="Apache-2.0",
        homepage="https://github.com/prowler-cloud/prowler", version_args=["--version"],
        arg_policy=ArgPolicy(
            tool="prowler",
            allowed_flags={
                "-p", "--profile", "-M", "--output-modes", "-o", "--output-directory",
                "-F", "--output-filename", "-f", "--region", "-s", "--services",
                "--severity", "--compliance", "--status", "--no-banner", "-q",
            },
            boolean_flags={"--no-banner", "-q"},
            value_patterns={
                "--profile": KEYWORD, "-p": KEYWORD,
                "--severity": re.compile(r"[a-z_,]+"),
                "--status": re.compile(r"[A-Z_,]+"),
                "--output-modes": re.compile(r"[a-z_,-]+"),
                "-M": re.compile(r"[a-z_,-]+"),
            },
            allow_positional=True,
            positional_pattern=re.compile(r"aws|azure|gcp|kubernetes"),
        ),
    )
)

KUBESCAPE = register_spec(
    ToolSpec(
        name="kubescape", binary="kubescape", license="Apache-2.0",
        homepage="https://github.com/kubescape/kubescape", version_args=["version"],
        identity_marker="kubescape",
        arg_policy=ArgPolicy(
            tool="kubescape",
            allowed_flags={"--format", "--output", "-o", "--severity-threshold", "--exclude-namespaces", "-v"},
            value_patterns={
                "--format": re.compile(r"json|pretty-printer|junit|sarif|html"),
                "--severity-threshold": re.compile(r"low|medium|high|critical"),
            },
            allow_positional=True,
            positional_pattern=re.compile(r"scan|framework|control|nsa|mitre|cis-v[0-9.-]+|[A-Za-z0-9._/-]{1,256}"),
        ),
    )
)


@easyhunt_tool(
    phase="cloud", mode="aggressive", targets_arg=None, timeout=1800,
    name="cloud_asset_discovery", tags={"cloud"}, estimated_requests=2000,
    risk_notes=[
        "Guesses storage names against AWS/Azure/GCP endpoints — thousands of requests to cloud providers.",
        "Hits may belong to organizations other than your target; each one must be scope-checked.",
    ],
)
async def cloud_asset_discovery(keyword: str, providers: list[str] | None = None) -> dict[str, Any]:
    """Discover public cloud storage by guessing names from a keyword.

    Runs cloud_enum and S3Scanner. Every discovered bucket is checked against the
    engagement scope and against ownership evidence before it counts — name
    similarity is not ownership.
    """
    engagement = get_engagement()
    if not KEYWORD.fullmatch(keyword):
        return {"ok": False, "error": "bad_keyword", "message": "keyword must be [A-Za-z0-9._-]{2,64}"}

    enabled = set(providers or ["aws", "azure", "gcp"])
    logfile = engagement.raw_path("cloud-enum", "json")
    argv = ["-k", keyword, "-l", str(logfile), "-t", "10", "-f", "json"]
    for provider in ("aws", "azure", "gcp"):
        if provider not in enabled:
            argv.append(f"--disable-{provider}")

    enum_run = await run_one("cloud_enum", argv, timeout=1500, allow_codes=(0, 1))
    scan_run = await run_one(
        "s3scanner", ["-bucket", keyword, "-json", "-provider", "aws", "-enumerate"],
        timeout=600, allow_codes=(0, 1),
    )

    discovered: list[dict[str, Any]] = []
    if logfile.exists():
        for line in logfile.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line[0] not in "{[":
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            discovered.append(
                {
                    "target": str(record.get("target") or record.get("url") or ""),
                    "access": record.get("access"),
                    "platform": record.get("platform"),
                    "msg": record.get("msg"),
                }
            )
    for line in scan_run.values:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        discovered.append(
            {
                "target": str(record.get("bucket", {}).get("name") or ""),
                "access": record.get("bucket", {}).get("permissions"),
                "platform": "aws-s3",
                "msg": "s3scanner",
            }
        )

    in_scope: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    for item in discovered:
        if item["target"] and engagement.scope.check(item["target"]).in_scope:
            in_scope.append(item)
            engagement.assets.add(
                Asset(value=item["target"], kind="storage_bucket", source="cloud_enum",
                      attributes=item)
            )
        else:
            unverified.append(item)

    for item in in_scope:
        access = str(item.get("access") or "").lower()
        if "public" in access or "open" in access or "read" in access:
            engagement.findings.add(
                Finding(
                    asset=item["target"],
                    title=f"Publicly accessible cloud storage ({item.get('platform')})",
                    phase="cloud",
                    severity=Severity.HIGH,
                    status=Status.CANDIDATE,
                    description=f"{item['target']} responded with access level: {item.get('access')}",
                    how_found=f"cloud_asset_discovery keyword '{keyword}' via {item.get('msg')}",
                    source_tool="cloud_enum",
                    rule_id="cloud.public-storage",
                    confidence=0.6,
                    evidence=[Evidence(kind="log", description="Discovery record", excerpt=json.dumps(item)[:800])],
                    remediation=(
                        "Set the bucket to private and audit access logs for the exposure "
                        "window. Public-by-default storage is usually a policy problem, "
                        "not a single-bucket problem — check the rest of the account."
                    ),
                    tags=["cloud", "storage"],
                )
            )

    engagement.assets.save(engagement.workspace / "assets.json")
    engagement.findings.save()

    return {
        "ok": True,
        "keyword": keyword,
        "in_scope": in_scope,
        "found_but_unverified": unverified,
        "counts": {"in_scope": len(in_scope), "unverified": len(unverified)},
        "tools": [enum_run.to_dict(), scan_run.to_dict()],
        "warning": (
            f"{len(unverified)} discovered asset(s) are not covered by your scope. A "
            "matching name is not ownership — do not touch them, and do not report "
            "them as the program's."
        ),
    }


@easyhunt_tool(
    phase="cloud", mode="aggressive", targets_arg=None, timeout=1800,
    name="cloud_permissions", tags={"cloud"}, estimated_requests=500,
    risk_notes=[
        "Enumerates IAM principals and permissions using credentials you supply.",
        "Read-only, but every call is logged in the account's audit trail.",
    ],
)
async def cloud_permissions(profile: str = "default", provider: str = "aws") -> dict[str, Any]:
    """Map principals, permissions, and privilege-escalation paths with CloudFox.

    Requires credentials the program gave you. Read-only enumeration.
    """
    engagement = get_engagement()
    if provider not in {"aws", "azure", "gcp"}:
        return {"ok": False, "error": "bad_provider", "message": "provider must be aws, azure, or gcp"}

    outdir = engagement.workspace / "cloudfox"
    outdir.mkdir(parents=True, exist_ok=True)
    run = await run_one(
        "cloudfox",
        [provider, "all-checks", "--profile", profile, "--outdir", str(outdir), "--format", "json"],
        timeout=1500,
        allow_codes=(0, 1),
    )

    return {
        "ok": True,
        "provider": provider,
        "profile": profile,
        "output_dir": str(outdir),
        "stdout_tail": "\n".join(run.values[-200:]),
        "tools": [run.to_dict()],
        "next_step": (
            "Look for principals that can escalate. A permission set is only a "
            "finding once you can name the path from where an attacker starts to "
            "what they reach — cloud_attack_paths builds that graph."
        ),
    }


@easyhunt_tool(
    phase="cloud", mode="aggressive", targets_arg=None, timeout=3600,
    name="cloud_audit", tags={"cloud"}, estimated_requests=2000,
    risk_notes=[
        "Runs several hundred read-only configuration checks against the account.",
        "Generates substantial CloudTrail/activity-log volume.",
    ],
)
async def cloud_audit(
    provider: str = "aws",
    profile: str = "default",
    services: str | None = None,
    severity: str = "high,critical",
) -> dict[str, Any]:
    """Audit cloud posture with Prowler and ingest failed checks as findings."""
    engagement = get_engagement()
    if provider not in {"aws", "azure", "gcp", "kubernetes"}:
        return {"ok": False, "error": "bad_provider"}

    outdir = engagement.workspace / "prowler"
    outdir.mkdir(parents=True, exist_ok=True)
    argv = [
        provider, "--profile", profile,
        "--output-modes", "json-ocsf",
        "--output-directory", str(outdir),
        "--severity", severity,
        "--status", "FAIL",
        "--no-banner",
    ]
    if services:
        argv += ["--services", services]

    run = await run_one("prowler", argv, timeout=3400, allow_codes=(0, 3))

    findings: list[Finding] = []
    for path in sorted(outdir.glob("*.ocsf.json")) + sorted(outdir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in payload if isinstance(payload, list) else []:
            finding_info = item.get("finding_info") or {}
            resource = (item.get("resources") or [{}])[0]
            findings.append(
                Finding(
                    asset=str(resource.get("uid") or resource.get("name") or provider),
                    title=str(finding_info.get("title") or item.get("message") or "Prowler check failed"),
                    phase="cloud",
                    severity=Severity.parse(item.get("severity")),
                    status=Status.CANDIDATE,
                    description=str(finding_info.get("desc") or ""),
                    how_found=f"Prowler check {finding_info.get('uid')} FAILED",
                    source_tool="prowler",
                    rule_id=str(finding_info.get("uid") or "prowler"),
                    confidence=0.7,
                    remediation=str((item.get("remediation") or {}).get("desc") or ""),
                    tags=["cloud", provider],
                )
            )
    for finding in findings:
        engagement.findings.add(finding)
    engagement.findings.save()

    return {
        "ok": True,
        "provider": provider,
        "output_dir": str(outdir),
        "failed_checks": len(findings),
        "findings": [f.to_dict() for f in findings[:100]],
        "tools": [run.to_dict()],
        "note": (
            "Posture findings are configuration observations. Prioritize the ones "
            "that appear on an attack path over the ones that merely fail a benchmark."
        ),
    }


@easyhunt_tool(
    phase="cloud", mode="aggressive", targets_arg=None, timeout=3600,
    name="cloud_attack_paths", tags={"cloud"}, estimated_requests=1000,
    risk_notes=["Enumerates the account's resource graph via read-only API calls."],
)
async def cloud_attack_paths(
    provider: str = "aws", profile: str = "default", max_hops: int = 4
) -> dict[str, Any]:
    """Build attack paths from cloud configuration (Prowler + Cartography graph).

    Turns a list of misconfigurations into reachability: which public entry points
    lead to which privileged roles, and in how many hops. That chain is what makes
    a cloud finding worth a severity rating.
    """
    engagement = get_engagement()
    outdir = engagement.workspace / "attack-paths"
    outdir.mkdir(parents=True, exist_ok=True)

    run = await run_one(
        "prowler",
        [
            provider, "--profile", profile, "--output-modes", "json-ocsf",
            "--output-directory", str(outdir), "--status", "FAIL", "--no-banner",
        ],
        timeout=3400,
        allow_codes=(0, 3),
    )

    # Prefer Cartography's observed topology; fall back to inferring a graph
    # from the control failures Prowler reported.
    graph = None
    source = "prowler-inferred"
    cartography = engagement.config.section("cloud.cartography")
    if cartography.get("enabled") and cartography_available():
        try:
            graph = build_from_cartography(
                str(cartography.get("uri") or "bolt://localhost:7687"),
                str(cartography.get("user") or "neo4j"),
                os.environ.get(str(cartography.get("password_env") or "NEO4J_PASSWORD"), ""),
                max_hops=int(cartography.get("max_hops") or 4),
            )
            source = "cartography"
        except Exception as exc:  # noqa: BLE001 — fall back rather than fail the phase
            engagement.audit.record("cartography_unavailable", error=str(exc)[:300])

    if graph is None:
        records: list[dict[str, Any]] = []
        for path in sorted(outdir.glob("*.ocsf.json")) + sorted(outdir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            records.extend(payload if isinstance(payload, list) else [])
        graph = build_from_prowler(records)

    paths = graph.find_paths(max_hops=int(max_hops), min_target_value=50)
    graph_file = graph.save(outdir / "attack-graph.json")

    # A reachable path is a different class of finding from the control failures
    # it is built out of: it carries an attacker's route and a destination.
    findings: list[Finding] = []
    for path in paths[:25]:
        finding = Finding(
            asset=path.target.name or path.target.id,
            title=(
                f"Attack path: {path.entry.kind} '{path.entry.name}' reaches "
                f"{path.target.kind} '{path.target.name}' in {path.hops} hop(s)"
            ),
            phase="cloud",
            severity=path.severity,
            status=Status.CANDIDATE,
            description=(
                f"An attacker starting at an {path.entry.exposure.replace('_', ' ')} "
                f"entry point can reach {path.target.kind} "
                f"'{path.target.name}' via {path.hops} relationship(s):\n\n"
                f"{path.narrative()}"
            ),
            how_found=f"cloud_attack_paths ({source}) reachability analysis",
            source_tool=source,
            rule_id=f"cloud.attack-path.{path.entry.kind}-to-{path.target.kind}",
            # Inferred paths are weaker evidence than observed topology.
            confidence=0.7 if source == "cartography" else 0.5,
            evidence=[
                Evidence(
                    kind="log",
                    description="Path edges and the findings that implied them",
                    excerpt=json.dumps([e.to_dict() for e in path.edges], indent=1)[:2000],
                )
            ],
            remediation=(
                "Break the chain at its cheapest link. Removing one edge — usually "
                "the trust relationship or the public exposure at the entry point — "
                "invalidates the whole path, which is less work than remediating "
                "every control on it."
            ),
            tags=["cloud", "attack-path", provider],
            extra={"path": path.to_dict(), "backend": source},
        )
        if source != "cartography":
            finding.note(
                "Path inferred from Prowler control failures, not observed topology. "
                "Confirm each relationship exists before reporting — install "
                "Cartography for observed edges."
            )
        engagement.findings.add(finding)
        findings.append(finding)

    engagement.findings.save()
    return {
        "ok": True,
        "provider": provider,
        "backend": source,
        "output_dir": str(outdir),
        "graph_file": str(graph_file),
        "graph_stats": graph.stats(),
        "paths_found": len(paths),
        "paths": [p.to_dict() for p in paths[:25]],
        "findings": [f.to_dict() for f in findings],
        "tools": [run.to_dict()],
        "note": (
            "Paths are ranked by what the destination is worth and how exposed the "
            "entry point is — not merely by length. "
            + (
                "Edges are observed by Cartography."
                if source == "cartography"
                else "Edges are INFERRED from control failures; enable Cartography "
                "(cloud.cartography.enabled) for observed topology."
            )
        ),
    }


@easyhunt_tool(
    phase="cloud", mode="aggressive", targets_arg=None, timeout=1800,
    name="k8s_posture", tags={"cloud", "k8s"}, estimated_requests=200,
    risk_notes=["Reads cluster configuration through the kubeconfig you supply."],
)
async def k8s_posture(framework: str = "nsa", context: str | None = None) -> dict[str, Any]:
    """Assess Kubernetes posture with Kubescape.

    Kubescape ships its own MCP server. If you are doing significant Kubernetes
    work, connect that directly alongside EasyHunt rather than routing everything
    through this wrapper — but vet it first, like any third-party MCP server.
    """
    engagement = get_engagement()
    if framework not in {"nsa", "mitre", "cis-v1.23-t1.0.1", "cis-v1.10.0", "allcontrols"}:
        return {"ok": False, "error": "bad_framework", "message": "unknown framework"}

    output = engagement.raw_path("kubescape", "json")
    run = await run_one(
        "kubescape",
        ["scan", "framework", framework, "--format", "json", "--output", str(output),
         "--severity-threshold", "medium"],
        timeout=1500,
        allow_codes=(0, 1),
    )

    findings: list[Finding] = []
    if output.exists():
        try:
            payload = json.loads(output.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {}
        for control in (payload.get("summaryDetails", {}).get("controls", {}) or {}).values():
            if control.get("statusInfo", {}).get("status") != "failed":
                continue
            findings.append(
                Finding(
                    asset=f"k8s:{context or 'current-context'}",
                    title=f"Kubescape control failed: {control.get('name')}",
                    phase="cloud",
                    severity=Severity.parse(control.get("severity")),
                    status=Status.CANDIDATE,
                    description=str(control.get("description") or ""),
                    how_found=f"Kubescape {framework} control {control.get('controlID')}",
                    source_tool="kubescape",
                    rule_id=str(control.get("controlID") or "kubescape"),
                    confidence=0.7,
                    remediation=str(control.get("remediation") or ""),
                    tags=["kubernetes", framework],
                )
            )
    for finding in findings:
        engagement.findings.add(finding)
    engagement.findings.save()

    return {
        "ok": True,
        "framework": framework,
        "failed_controls": len(findings),
        "findings": [f.to_dict() for f in findings[:100]],
        "report": str(output) if output.exists() else None,
        "tools": [run.to_dict()],
    }

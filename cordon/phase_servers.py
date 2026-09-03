"""Phase-sliced MCP servers.

One MCP server per engagement phase is the difference between an agent that
can ask "give me the fingerprint of every live subdomain" and an agent that
has to page through 125 tools. Each phase server exposes exactly the tools
that phase needs — no scanner noise, no approval-gate surprises — while
every tool still passes the same scope → sanitize → budget → rate → approval
→ audit chain, because the slicing happens at *registration time*, not at
execution time.

The full server stays available: ``cordon serve`` registers everything, so
nothing an existing workflow depends on disappears.

Phase servers:

    cordon serve-recon      subdomain enum, DNS, CDN, TLS certs, whois, ASN
    cordon serve-probe      http_probe (live+tech fingerprint), waf, cors
    cordon serve-endpoints  endpoint_discovery, js_analyze, param/content
    cordon serve-scan       nuclei/jaeles/ports/services/nikto/wapiti
    cordon serve-exploit    exploit_chain + every validator
    cordon serve-workflow   engagement_new/attach, run_phase, run_pipeline,
                            pipeline_status, report, findings

Each also carries the shared control tools (scope_check, job_status,
taskgraph, cordon_status) so a phase server is independently drivable.
"""

from __future__ import annotations

from typing import Any

#: tool name -> phase server it belongs to. A tool can appear in several
#: servers (validators also appear under exploit). Tools NOT listed here are
#: full-server-only.
PHASE_SERVERS: dict[str, dict[str, list[str]]] = {
    "recon": {
        "description": "Passive & active subdomain enumeration, DNS, CDN, TLS and ownership.",
        "tools": [
            "subdomain_enum", "dns_permute", "dns_resolve", "cdn_check",
            "tls_info", "asn_lookup", "whois_lookup", "bbot_scan",
            "bbot_scan_active", "osmedeus_flow",
        ],
    },
    "probe": {
        "description": "Liveness + technology fingerprinting, WAF and CORS posture.",
        "tools": [
            "http_probe", "waf_detect", "tls_audit", "cors_audit",
            "fingerprint_waf", "waf_bypass", "waf_vendors",
            "recon_review",
        ],
    },
    "endpoints": {
        "description": "Archive + crawl endpoint discovery, JS analysis, parameter and content discovery.",
        "tools": [
            "endpoint_discovery", "param_discovery", "content_discovery",
            "payload_catalog", "js_analyze", "graphql_audit", "websocket_probe",
            "fuzz_compare", "upload_surface",
        ],
    },
    "scan": {
        "description": "Vulnerability scanning: nuclei, jaeles, ports, services, general scanners.",
        "tools": [
            "nuclei_scan", "jaeles_scan", "port_scan", "service_scan",
            "nikto_scan", "wapiti_scan", "pattern_scan", "secret_scan",
            "secret_validate", "source_fetch", "semgrep_scan", "code_audit",
            "forbidden_chain", "forbidden_candidates", "forbidden_bypass",
        ],
    },
    "exploit": {
        "description": "Proof-of-concept validation: every injection validator and the auto-chain.",
        "tools": [
            "exploit_chain", "web_injection_probe", "sqli_validate", "xss_validate",
            "ssrf_probe", "ssti_probe", "cmdi_probe", "nosqli_probe",
            "smuggling_probe", "smuggling_canary_probe", "validate_findings",
            "guided_validate", "browser_verify", "authz_compare",
            "takeover_detect", "takeover_verify", "takeover_poc_plan",
            "takeover_confirm", "poc_record", "oob_listener",
            "jwt_inspect", "auth_crawl", "auth_surface", "llm_redteam",
            "llm_scan_config", "llm_probe_catalog", "strix_deep",
            "burp_send", "session_register", "session_list", "account_register",
        ],
    },
    "workflow": {
        "description": "Engagement lifecycle, the resumable pipeline, and reporting.",
        "tools": [
            "engagement_new", "engagement_attach", "pipeline_status",
            "run_phase", "run_pipeline", "report_generate", "findings_list",
            "finding_detail", "finding_note", "hunt_plan", "program_scope_fetch",
            "triage_findings", "triage_taskflows", "triage_canary_preview",
            "coverage_report", "wstg_lookup", "technique_lookup",
            "research_guidance", "exploit_prompt", "prompt_classes",
            "cloud_audit", "cloud_asset_discovery", "cloud_attack_paths",
            "cloud_permissions", "k8s_posture", "contract_static_scan",
            "contract_toolchain",
        ],
    },
}

#: Control tools every phase server carries, so each server is independently
#: drivable: you can check scope, poll jobs, and read the task graph without
#: leaving the phase.
SHARED_CONTROL_TOOLS = [
    "scope_check",
    "job_status",
    "job_list",
    "job_fetch",
    "job_cancel",
    "fetch_slice",
    "taskgraph_next",
    "taskgraph_update",
    "taskgraph_view",
    "memory_recall",
    "graph_recall",
    "brain_recall",
    "brain_state",
    "brain_history",
    "dashboard_state",
    "audit_tail",
    "rules_list",
    "cordon_status",
    "cordon_capabilities",
]


def phase_server_names() -> list[str]:
    return sorted(PHASE_SERVERS)


def tools_for_phase(phase: str) -> list[str] | None:
    """The tool set for one phase server, or None for an unknown phase."""
    spec = PHASE_SERVERS.get(phase)
    if spec is None:
        return None
    seen: list[str] = []
    for name in [*spec["tools"], *SHARED_CONTROL_TOOLS]:
        if name not in seen:
            seen.append(name)
    return seen


def describe_servers() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "tools": len(spec["tools"]),
            "plus_shared_control": len(SHARED_CONTROL_TOOLS),
        }
        for name, spec in sorted(PHASE_SERVERS.items())
    ]

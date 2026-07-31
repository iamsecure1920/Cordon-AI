"""BBOT — the recon core.

BBOT already orchestrates 80+ recon modules behind a preset system, so EasyHunt
drives it through the Python API rather than wrapping each of those modules by
hand. One ``bbot_scan`` call replaces most of a traditional recon pipeline, and
returns a normalized event stream instead of a directory of text files.

Scope is enforced twice on purpose: BBOT's own ``whitelist``/``blacklist`` are
populated from ``scope.yaml`` so the engine never *generates* an out-of-scope
request, and every emitted event is re-checked against the scope engine before it
is stored, so a module that resolves outward cannot smuggle a host into the
findings store.

Events stream into the store as they arrive rather than being buffered, because a
scan that dies at minute nine should still leave behind the eight minutes of
attack surface it already mapped.
"""

from __future__ import annotations

import logging
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.control_plane.jobs import Job
from easyhunt.errors import ToolUnavailable
from easyhunt.knowledge.findings import Asset, Evidence, Finding, Severity, Status
from easyhunt.tools.base import ToolSpec, easyhunt_tool
from easyhunt.tools.common import register_spec

log = logging.getLogger("easyhunt.engines.bbot")

__all__ = ["bbot_scan", "normalize_event"]

SPEC = register_spec(
    ToolSpec(
        name="bbot",
        binary="bbot",
        package="bbot",
        license="GPL-3.0",
        homepage="https://github.com/blacklanternsecurity/bbot",
        version_args=["--version"],
    )
)

# Presets EasyHunt will run, and how each is classified. Anything not listed is
# refused: BBOT ships presets that actively probe, and the mode has to be known
# before the call reaches the approval gate, not after.
PRESET_MODES: dict[str, str] = {
    "subdomain-enum": "passive",
    "cloud-enum": "passive",
    "code-enum": "passive",
    "email-enum": "passive",
    "dotnet-audit": "aggressive",
    "web-basic": "passive",
    "web-thorough": "aggressive",
    "spider": "aggressive",
    "paramminer": "aggressive",
    "web-screenshots": "aggressive",
    "baddns": "passive",
    "baddns-thorough": "aggressive",
    "fast": "passive",
    "kitchen-sink": "aggressive",
}

# BBOT event type → (asset kind | "finding")
EVENT_MAP: dict[str, str] = {
    "DNS_NAME": "subdomain",
    "DNS_NAME_UNRESOLVED": "subdomain_unresolved",
    "IP_ADDRESS": "ip",
    "OPEN_TCP_PORT": "open_port",
    "URL": "url",
    "URL_UNVERIFIED": "url_unverified",
    "HTTP_RESPONSE": "http_response",
    "TECHNOLOGY": "technology",
    "STORAGE_BUCKET": "storage_bucket",
    "EMAIL_ADDRESS": "email",
    "CODE_REPOSITORY": "code_repository",
    "SOCIAL": "social",
    "ASN": "asn",
    "WAF": "waf",
    "PROTOCOL": "protocol",
    "AZURE_TENANT": "cloud_tenant",
    "FINDING": "finding",
    "VULNERABILITY": "finding",
}

# BBOT severity strings → ours.
_BBOT_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.INFO,
}


def _event_field(event: Any, name: str, default: Any = None) -> Any:
    value = getattr(event, name, None)
    return default if value is None else value


def normalize_event(event: Any) -> dict[str, Any]:
    """Flatten a BBOT event into a plain dict.

    Kept separate from storage so it can be unit-tested against recorded events
    without a live scan.
    """
    data = _event_field(event, "data", "")
    if not isinstance(data, (str, dict)):
        data = str(data)
    return {
        "type": str(_event_field(event, "type", "UNKNOWN")),
        "data": data,
        "host": str(_event_field(event, "host", "") or ""),
        "module": str(_event_field(event, "module", "") or ""),
        "tags": sorted(str(t) for t in _event_field(event, "tags", []) or []),
        "scope_distance": _event_field(event, "scope_distance", None),
        "id": str(_event_field(event, "id", "") or ""),
    }


def _event_value(record: dict[str, Any]) -> str:
    data = record["data"]
    if isinstance(data, dict):
        for key in ("url", "host", "name", "description", "bucket_name"):
            if key in data:
                return str(data[key])
        return str(data)
    return str(data)


def _store_event(engagement: Any, record: dict[str, Any]) -> dict[str, Any] | None:
    """Scope-check an event, then file it as an asset or a candidate finding."""
    kind = EVENT_MAP.get(record["type"])
    if kind is None:
        return None

    value = _event_value(record)
    host = record["host"] or value

    # Second scope enforcement. A module that pivoted outward gets dropped here
    # even though BBOT's own blacklist should already have stopped it.
    verdict = engagement.scope.check(host or value)
    if not verdict.in_scope:
        engagement.audit.record(
            "event_dropped",
            reason=verdict.reason,
            event_type=record["type"],
            host=host,
            module=record["module"],
        )
        return None

    if kind == "finding":
        data = record["data"] if isinstance(record["data"], dict) else {}
        severity = _BBOT_SEVERITY.get(
            str(data.get("severity", "")).upper(),
            Severity.MEDIUM if record["type"] == "VULNERABILITY" else Severity.INFO,
        )
        finding = Finding(
            asset=host or value,
            title=str(data.get("description") or value)[:200],
            phase="recon",
            severity=severity,
            status=Status.CANDIDATE,
            description=str(data.get("description") or ""),
            how_found=f"BBOT module '{record['module']}' emitted {record['type']}",
            source_tool=f"bbot:{record['module']}",
            rule_id=f"bbot.{record['module']}",
            confidence=0.4,
            tags=record["tags"],
            evidence=[
                Evidence(
                    kind="log",
                    description=f"BBOT {record['type']} event",
                    excerpt=str(record["data"])[:2000],
                )
            ],
            remediation="",
        )
        # baddns emits takeover candidates; they are worth more than a generic
        # finding but still need the verified-takeover flow before confirmation.
        if "baddns" in record["module"].lower() or "takeover" in " ".join(record["tags"]).lower():
            finding.phase = "takeover"
            finding.tags = sorted({*finding.tags, "takeover-candidate"})
            finding.note("Takeover candidate — run takeover_verify before reporting.")
        engagement.findings.add(finding)
        return {"stored": "finding", "value": value, "severity": severity.value}

    asset = Asset(
        value=value,
        kind=kind,
        source=f"bbot:{record['module']}",
        host=host,
        tags=record["tags"],
        attributes={"scope_distance": record["scope_distance"]},
    )
    engagement.assets.add(asset)

    # Let the discovery create downstream work. A subdomain implies a probe; a
    # JS bundle implies a secret scan; a repository implies a history scan.
    discovery_kind = kind
    if kind in {"url", "url_unverified"} and value.lower().split("?")[0].endswith(".js"):
        discovery_kind = "js_bundle"
    if discovery_kind in {"subdomain", "js_bundle", "open_port", "storage_bucket", "code_repository"}:
        engagement.discovered(discovery_kind, value, source=f"bbot:{record['module']}")

    return {"stored": "asset", "kind": kind, "value": value}


def _bbot_config(engagement: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """BBOT config derived from the engagement, not from BBOT's own defaults."""
    rules = engagement.scope.rules
    config: dict[str, Any] = {
        "web": {
            "user_agent": rules.user_agent,
            "http_max_redirects": 5,
            # BBOT's own throttle, on top of the control plane's token bucket.
            # Renamed from web.requests_per_second in BBOT 3.0; the old key is
            # rejected by config validation rather than ignored, so a stale name
            # fails the scan outright.
            "http_rate_limit": max(1, int(rules.max_rps)),
        },
        "dns": {"threads": max(1, min(rules.max_concurrency * 2, 20))},
        "scope": {"report_distance": 0},
        # Keep BBOT's state inside the engagement workspace rather than the
        # user's dotfiles, so an engagement is self-contained and disposable.
        # (`output_dir` was removed in BBOT 3.0; `home` covers both.)
        "home": str(engagement.workspace / "bbot"),
    }
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(config.get(key), dict):
            config[key].update(value)
        else:
            config[key] = value
    return config


async def _run_scan(
    job: Job,
    *,
    targets: list[str],
    preset: str,
    modules: list[str] | None,
    max_events: int,
) -> dict[str, Any]:
    try:
        from bbot.scanner import Scanner  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on the host
        raise ToolUnavailable(
            "bbot is not installed. Install it with 'pipx install bbot' (or "
            "'pip install easyhunt-ai[engines]') and re-run.",
            tool="bbot",
        ) from exc

    engagement = get_engagement()

    # BBOT 3.0 reshaped the scope model: the positional argument is now the
    # in-scope definition (what 2.x called `whitelist`) and `seeds` are the
    # starting points. `blacklist` kept its name. Passing 2.x's `whitelist=`
    # raises TypeError, so this is version-sensitive rather than cosmetic.
    whitelist = engagement.scope.bbot_whitelist() or targets
    kwargs: dict[str, Any] = {
        "seeds": targets,
        "blacklist": engagement.scope.bbot_blacklist(),
        "presets": [preset],
        "config": _bbot_config(engagement),
        "output_modules": ["json"],
        "force_start": True,
    }
    if modules:
        kwargs["modules"] = modules

    try:
        scanner = Scanner(*whitelist, **kwargs)
    except TypeError as exc:
        # BBOT 2.x fallback: seeds were positional and scope was `whitelist=`.
        if "seeds" not in str(exc) and "unexpected keyword" not in str(exc):
            raise
        legacy = {k: v for k, v in kwargs.items() if k != "seeds"}
        legacy["whitelist"] = whitelist
        scanner = Scanner(*targets, **legacy)
    counts: dict[str, int] = {}
    stored_findings = 0
    stored_assets = 0
    dropped = 0
    events_seen = 0

    async for event in scanner.async_start():
        record = normalize_event(event)
        counts[record["type"]] = counts.get(record["type"], 0) + 1
        events_seen += 1
        job.events_seen = events_seen
        job.progress = f"{events_seen} events, {stored_assets} assets, {stored_findings} findings"

        outcome = _store_event(engagement, record)
        if outcome is None:
            dropped += 1
        elif outcome["stored"] == "finding":
            stored_findings += 1
        else:
            stored_assets += 1

        if events_seen >= max_events:
            job.progress += f" (stopped at max_events={max_events})"
            break

    engagement.findings.save()
    engagement.assets.save(engagement.workspace / "assets.json")

    return {
        "ok": True,
        "preset": preset,
        "targets": targets,
        "events_seen": events_seen,
        "event_types": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
        "assets_stored": stored_assets,
        "findings_stored": stored_findings,
        "events_dropped_out_of_scope": dropped,
        "assets": engagement.assets.counts(),
        "subdomains": engagement.assets.values("subdomain")[:500],
        "urls": engagement.assets.values("url")[:500],
        "takeover_candidates": [
            f.to_dict()
            for f in engagement.findings.all()
            if "takeover-candidate" in f.tags
        ],
    }


@easyhunt_tool(
    phase="recon",
    mode="passive",
    targets_arg="target",
    timeout=7200,
    name="bbot_scan",
    spec=SPEC,
    tags={"engine", "recon"},
    estimated_requests=200,
)
async def bbot_scan(
    target: str,
    preset: str = "subdomain-enum",
    modules: list[str] | None = None,
    wait_seconds: float = 90.0,
    max_events: int = 20000,
) -> dict[str, Any]:
    """Map attack surface with BBOT. The primary recon entrypoint.

    Presets: subdomain-enum (default), cloud-enum, code-enum, email-enum,
    web-basic, baddns, fast. Aggressive presets (web-thorough, spider,
    paramminer, web-screenshots, baddns-thorough, kitchen-sink) are routed
    through bbot_scan_active instead, which requires approval.

    Returns inline if the scan finishes within wait_seconds; otherwise returns a
    job_id — poll it with job_status and read results with fetch_slice.
    """
    return await _launch(target, preset, modules, wait_seconds, max_events, expect="passive")


@easyhunt_tool(
    phase="recon",
    mode="aggressive",
    targets_arg="target",
    timeout=7200,
    name="bbot_scan_active",
    spec=SPEC,
    tags={"engine", "recon"},
    estimated_requests=2000,
    risk_notes=[
        "Sends a large volume of requests directly to target infrastructure.",
        "Spidering and parameter mining generate traffic that looks like an attack in logs.",
        "Screenshots fetch and render every discovered page.",
    ],
)
async def bbot_scan_active(
    target: str,
    preset: str = "web-thorough",
    modules: list[str] | None = None,
    wait_seconds: float = 60.0,
    max_events: int = 20000,
) -> dict[str, Any]:
    """Actively probe with BBOT (web-thorough, spider, paramminer, screenshots).

    Requires human approval. Prefer bbot_scan first: active probing on an
    unmapped surface wastes the program's rate limit on hosts you have not yet
    established are interesting.
    """
    return await _launch(target, preset, modules, wait_seconds, max_events, expect="aggressive")


async def _launch(
    target: str,
    preset: str,
    modules: list[str] | None,
    wait_seconds: float,
    max_events: int,
    *,
    expect: str,
) -> dict[str, Any]:
    engagement = get_engagement()
    allowed = engagement.config.get("engines.bbot.allowed_presets") or list(PRESET_MODES)
    if preset not in PRESET_MODES:
        raise ToolUnavailable(
            f"unknown BBOT preset {preset!r}; EasyHunt exposes {sorted(PRESET_MODES)}",
            tool="bbot",
        )
    if preset not in allowed:
        raise ToolUnavailable(
            f"preset {preset!r} is not in engines.bbot.allowed_presets", tool="bbot"
        )

    actual_mode = PRESET_MODES[preset]
    if actual_mode == "aggressive" and expect == "passive":
        raise ToolUnavailable(
            f"preset {preset!r} probes the target actively — call bbot_scan_active, "
            "which routes through the approval gate",
            tool="bbot",
            preset=preset,
        )

    targets = [t.strip() for t in target.replace("\n", ",").split(",") if t.strip()]
    job = engagement.jobs.launch(
        lambda j: _run_scan(
            j, targets=targets, preset=preset, modules=modules, max_events=max_events
        ),
        tool="bbot_scan",
        phase="recon",
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
        "next_step": (
            f"Scan still running. Poll job_status('{job.id}'), then read results with "
            f"fetch_slice('{job.id}', path='subdomains') rather than job_fetch."
        ),
    }

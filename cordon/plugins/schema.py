"""Plugin manifest schema and validation.

Five plugin classes, one manifest shape, so the control plane can gate all of them
identically:

===============  ========  ==========================================
kind             format    executed by
===============  ========  ==========================================
python-tool      .py       the Cordon runner (via @cordon_tool)
nuclei           YAML      the Nuclei engine
jaeles           YAML      the Jaeles engine
semgrep          YAML      the Semgrep engine
rule-pack        YAML      the native matcher engine
bbot-preset      YAML      the BBOT engine
osmedeus-flow    YAML      the Osmedeus engine
===============  ========  ==========================================

Three rules are enforced at load time, and each one exists because of a specific
way a rule layer goes wrong:

1. **Every rule declares a ``verify`` block.** A detection with no stated way to
   confirm it becomes a report full of "possible" findings.
2. **A plugin cannot declare ``mode: passive`` while using aggressive
   primitives.** Otherwise the approval gate is bypassed by mislabeling.
3. **Unknown keys are rejected.** A typo in ``severity`` silently downgrading a
   critical finding is worse than a load error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cordon.errors import PluginError

__all__ = ["PluginManifest", "Verify", "VALID_KINDS", "validate_manifest"]

VALID_KINDS = {
    "python-tool",
    "nuclei",
    "jaeles",
    "semgrep",
    "rule-pack",
    "bbot-preset",
    "osmedeus-flow",
}
VALID_MODES = {"passive", "aggressive", "exploit"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_PHASES = {
    "recon", "expand", "dns", "http_probe", "endpoints", "js_analysis", "ports",
    "vuln_scan", "takeover", "secrets", "cloud", "exploit", "triage", "report", "llmsec",
}

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")

# Manifest keys understood per kind, on top of COMMON_KEYS.
COMMON_KEYS = {
    "id", "kind", "phase", "mode", "severity", "description", "enabled",
    "verify", "remediation", "references", "tags", "author", "license", "version",
}
KIND_KEYS: dict[str, set[str]] = {
    "python-tool": {"entrypoint", "module", "uses", "requires", "binary", "timeout"},
    "rule-pack": {"inputs", "matchers", "extractors", "condition"},
    "nuclei": {"template", "workflow", "tags"},
    "jaeles": {"signature"},
    "semgrep": {"rule", "languages"},
    "bbot-preset": {"preset", "modules", "flags"},
    "osmedeus-flow": {"flow"},
}

# Tokens whose presence in a Python plugin's source means it can reach out
# aggressively. A plugin using any of these may not call itself passive.
AGGRESSIVE_PRIMITIVES = {
    "sqlmap", "dalfox", "xsstrike", "ffuf", "feroxbuster", "gobuster", "dirsearch",
    "nmap", "masscan", "naabu", "hydra", "medusa", "metasploit", "msfconsole",
    "nuclei", "subzy", "dnsreaper", "commix", "wpscan", "nikto",
    "requests.post", "requests.put", "requests.delete", "httpx.post", "httpx.put",
    "session.post", "client.post", "aiohttp.post",
    "subprocess", "os.system", "popen",
}


@dataclass
class Verify:
    """How a human confirms a hit from this rule. Mandatory on every rule."""

    manual: bool = True
    note: str = ""
    command: str | None = None
    nuclei_template: str | None = None

    @classmethod
    def from_dict(cls, data: Any, *, plugin_id: str) -> Verify:
        if not isinstance(data, dict):
            raise PluginError(
                f"{plugin_id}: 'verify' must be a mapping — a rule with no stated "
                "verification path cannot produce a confirmable finding",
                plugin=plugin_id,
            )
        note = str(data.get("note") or "").strip()
        manual = bool(data.get("manual", True))
        command = data.get("command")
        template = data.get("nuclei_template")
        if manual and not note:
            raise PluginError(
                f"{plugin_id}: verify.manual requires verify.note describing what to check",
                plugin=plugin_id,
            )
        if not manual and not (command or template):
            raise PluginError(
                f"{plugin_id}: verify.manual is false, so verify.command or "
                "verify.nuclei_template must say how it is verified automatically",
                plugin=plugin_id,
            )
        return cls(manual=manual, note=note, command=command, nuclei_template=template)


@dataclass
class PluginManifest:
    id: str
    kind: str
    phase: str
    mode: str
    description: str
    verify: Verify
    severity: str = "info"
    enabled: bool = True
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    author: str = ""
    license: str = "unknown"
    version: str = "1"
    inputs: list[str] = field(default_factory=list)
    matchers: list[dict[str, Any]] = field(default_factory=list)
    extractors: list[dict[str, Any]] = field(default_factory=list)
    condition: str = "and"
    entrypoint: str | None = None
    uses: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "phase": self.phase,
            "mode": self.mode,
            "severity": self.severity,
            "enabled": self.enabled,
            "description": self.description,
            "path": str(self.path) if self.path else None,
            "verify": "manual" if self.verify.manual else "automated",
        }


def validate_manifest(
    data: Any, *, path: Path | None = None, source_text: str | None = None
) -> PluginManifest:
    """Validate one manifest. Raises :class:`PluginError` with a usable message."""
    where = str(path) if path else "<inline>"
    if not isinstance(data, dict):
        raise PluginError(f"{where}: manifest must be a YAML mapping", path=where)

    plugin_id = str(data.get("id") or "").strip()
    if not _ID.match(plugin_id):
        raise PluginError(
            f"{where}: 'id' must be lowercase kebab/dot/underscore, 3-64 chars (got {plugin_id!r})",
            path=where,
        )

    kind = str(data.get("kind") or "").strip()
    if kind not in VALID_KINDS:
        raise PluginError(
            f"{plugin_id}: unknown kind {kind!r}; expected one of {sorted(VALID_KINDS)}",
            path=where,
            plugin=plugin_id,
        )

    allowed = COMMON_KEYS | KIND_KEYS.get(kind, set())
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PluginError(
            f"{plugin_id}: unknown manifest key(s) {unknown} for kind {kind!r}. "
            f"Allowed: {sorted(allowed)}",
            path=where,
            plugin=plugin_id,
        )

    phase = str(data.get("phase") or "").strip()
    if phase not in VALID_PHASES:
        raise PluginError(
            f"{plugin_id}: unknown phase {phase!r}; expected one of {sorted(VALID_PHASES)}",
            path=where,
            plugin=plugin_id,
        )

    mode = str(data.get("mode") or "passive").strip()
    if mode not in VALID_MODES:
        raise PluginError(
            f"{plugin_id}: mode must be one of {sorted(VALID_MODES)} (got {mode!r})",
            path=where,
            plugin=plugin_id,
        )

    severity = str(data.get("severity") or "info").strip().lower()
    if severity not in VALID_SEVERITIES:
        raise PluginError(
            f"{plugin_id}: severity must be one of {sorted(VALID_SEVERITIES)} (got {severity!r})",
            path=where,
            plugin=plugin_id,
        )

    description = str(data.get("description") or "").strip()
    if len(description) < 10:
        raise PluginError(
            f"{plugin_id}: 'description' must explain what this detects (10+ chars)",
            path=where,
            plugin=plugin_id,
        )

    if "verify" not in data:
        raise PluginError(
            f"{plugin_id}: missing required 'verify' block. Every rule must state how a "
            "hit is confirmed — no PoC, no finding.",
            path=where,
            plugin=plugin_id,
        )
    verify = Verify.from_dict(data["verify"], plugin_id=plugin_id)

    manifest = PluginManifest(
        id=plugin_id,
        kind=kind,
        phase=phase,
        mode=mode,
        description=description,
        verify=verify,
        severity=severity,
        enabled=bool(data.get("enabled", True)),
        remediation=str(data.get("remediation") or "").strip(),
        references=[str(r) for r in data.get("references") or []],
        tags=[str(t) for t in data.get("tags") or []],
        author=str(data.get("author") or ""),
        license=str(data.get("license") or "unknown"),
        version=str(data.get("version") or "1"),
        inputs=[str(i) for i in data.get("inputs") or []],
        matchers=list(data.get("matchers") or []),
        extractors=list(data.get("extractors") or []),
        condition=str(data.get("condition") or "and").lower(),
        entrypoint=data.get("entrypoint"),
        uses=[str(u) for u in data.get("uses") or []],
        requires=[str(r) for r in data.get("requires") or []],
        path=path,
        raw=dict(data),
    )

    if kind == "rule-pack":
        _validate_rule_pack(manifest, where)
    if kind == "python-tool":
        _validate_python_tool(manifest, where, source_text)

    return manifest


def _validate_rule_pack(manifest: PluginManifest, where: str) -> None:
    if not manifest.matchers:
        raise PluginError(
            f"{manifest.id}: a rule-pack needs at least one matcher", path=where, plugin=manifest.id
        )
    if manifest.condition not in {"and", "or"}:
        raise PluginError(
            f"{manifest.id}: condition must be 'and' or 'or'", path=where, plugin=manifest.id
        )
    from cordon.plugins.matchers import validate_extractor, validate_matcher

    for index, matcher in enumerate(manifest.matchers):
        validate_matcher(matcher, plugin_id=manifest.id, index=index)
    for index, extractor in enumerate(manifest.extractors):
        validate_extractor(extractor, plugin_id=manifest.id, index=index)


def _validate_python_tool(manifest: PluginManifest, where: str, source_text: str | None) -> None:
    if not manifest.entrypoint:
        raise PluginError(
            f"{manifest.id}: a python-tool must name its 'entrypoint' (a .py file next to "
            "this manifest)",
            path=where,
            plugin=manifest.id,
        )

    # The mislabeling check. Source is scanned rather than trusted, because the
    # manifest is written by the same person as the code it describes.
    if manifest.mode == "passive" and source_text:
        lowered = source_text.lower()
        found = sorted({p for p in AGGRESSIVE_PRIMITIVES if p in lowered})
        if found:
            raise PluginError(
                f"{manifest.id}: declares mode 'passive' but its source references "
                f"aggressive primitives {found}. Declare mode 'aggressive' so calls are "
                "routed through the approval gate.",
                path=where,
                plugin=manifest.id,
                primitives=found,
            )

    if manifest.mode == "passive" and manifest.uses:
        from cordon.tools.base import REGISTRY

        escalating = [
            name for name in manifest.uses
            if name in REGISTRY and REGISTRY[name].mode != "passive"
        ]
        if escalating:
            raise PluginError(
                f"{manifest.id}: declares mode 'passive' but uses non-passive tools "
                f"{escalating}",
                path=where,
                plugin=manifest.id,
            )

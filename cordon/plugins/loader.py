"""Plugin discovery.

Walks ``rules/`` and ``plugins/`` at startup, validates every manifest, and makes
valid ones available to the engines. Dropping a YAML file into ``rules/`` adds a
detection with no code change; dropping in a *broken* one produces a clear load
error and changes nothing else — a bad rule must never silently disable a good one.

Nuclei templates are additionally checked with ``nuclei -validate`` when the
binary is present, because a template that fails to parse at scan time is a
detection you think you have and don't.
"""

from __future__ import annotations

import importlib.util
import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cordon.errors import PluginError
from cordon.plugins.matchers import MatchInput, MatchResult, evaluate_rule
from cordon.plugins.schema import PluginManifest, validate_manifest

log = logging.getLogger("cordon.plugins")

__all__ = ["LoadReport", "PluginRegistry", "get_registry", "load_all"]

# Directory name → the kind its files are assumed to be, when a YAML file has no
# Cordon manifest of its own (raw Nuclei/Jaeles/Semgrep rules, BBOT presets).
_DIR_KINDS = {
    "nuclei": "nuclei",
    "jaeles": "jaeles",
    "semgrep": "semgrep",
    "bbot": "bbot-preset",
    "osmedeus": "osmedeus-flow",
    "cordon": "rule-pack",
}


@dataclass
class LoadReport:
    loaded: list[PluginManifest] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    native_files: dict[str, list[str]] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for manifest in self.loaded:
            by_kind[manifest.kind] = by_kind.get(manifest.kind, 0) + 1
        return {
            "loaded": len(self.loaded),
            "by_kind": by_kind,
            "rejected": len(self.rejected),
            "rejections": self.rejected,
            "native_files": {k: len(v) for k, v in self.native_files.items()},
        }


class PluginRegistry:
    """Everything discovered under ``rules/`` and ``plugins/``."""

    def __init__(self) -> None:
        self.manifests: dict[str, PluginManifest] = {}
        self.report = LoadReport()
        self.roots: list[Path] = []

    # -- discovery ---------------------------------------------------------- #

    def load_dir(self, root: Path) -> LoadReport:
        root = Path(root).expanduser()
        if not root.is_dir():
            return self.report
        self.roots.append(root)

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() in {".yaml", ".yml"}:
                self._load_yaml(path, root)
            elif path.suffix.lower() == ".py" and path.name != "__init__.py":
                # Python plugins are loaded via their sibling manifest, not
                # directly — a .py with no manifest is inert by design.
                continue
        return self.report

    def _load_yaml(self, path: Path, root: Path) -> None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            self.report.rejected.append({"path": str(path), "error": f"unreadable YAML: {exc}"})
            return
        if not isinstance(data, dict):
            return

        # A file with no Cordon manifest is a native rule for its directory's
        # engine (a stock Nuclei template, a BBOT preset). Track the path; the
        # owning engine parses it in its own format.
        if "kind" not in data or "verify" not in data:
            kind = _DIR_KINDS.get(self._bucket(path, root))
            if kind:
                self.report.native_files.setdefault(kind, []).append(str(path))
            return

        source_text = None
        if data.get("kind") == "python-tool" and data.get("entrypoint"):
            entry = path.parent / str(data["entrypoint"])
            if entry.is_file():
                source_text = entry.read_text(encoding="utf-8", errors="replace")

        try:
            manifest = validate_manifest(data, path=path, source_text=source_text)
        except PluginError as exc:
            self.report.rejected.append({"path": str(path), "error": exc.message})
            log.warning("rejected plugin %s: %s", path, exc.message)
            return

        if manifest.id in self.manifests:
            existing = self.manifests[manifest.id].path
            self.report.rejected.append(
                {"path": str(path), "error": f"duplicate id {manifest.id!r} (already from {existing})"}
            )
            return

        self.manifests[manifest.id] = manifest
        self.report.loaded.append(manifest)

    @staticmethod
    def _bucket(path: Path, root: Path) -> str:
        try:
            return path.relative_to(root).parts[0]
        except (ValueError, IndexError):
            return ""

    # -- queries ------------------------------------------------------------ #

    def by_kind(self, kind: str, *, enabled_only: bool = True) -> list[PluginManifest]:
        return [
            m for m in self.manifests.values()
            if m.kind == kind and (m.enabled or not enabled_only)
        ]

    def by_phase(self, phase: str) -> list[PluginManifest]:
        return [m for m in self.manifests.values() if m.phase == phase and m.enabled]

    def get(self, plugin_id: str) -> PluginManifest | None:
        return self.manifests.get(plugin_id)

    def rule_packs(self, *, phase: str | None = None) -> list[PluginManifest]:
        packs = self.by_kind("rule-pack")
        return [p for p in packs if phase is None or p.phase == phase]

    def nuclei_paths(self) -> list[str]:
        """Custom Nuclei templates: both manifest-declared and raw files."""
        paths = list(self.report.native_files.get("nuclei", []))
        for manifest in self.by_kind("nuclei"):
            template = manifest.raw.get("template")
            if template and manifest.path:
                candidate = (manifest.path.parent / str(template)).resolve()
                if candidate.is_file():
                    paths.append(str(candidate))
        return sorted(set(paths))

    def bbot_presets(self) -> list[str]:
        return sorted(set(self.report.native_files.get("bbot-preset", [])))

    # -- rule-pack evaluation ---------------------------------------------- #

    def evaluate(
        self, observation: dict[str, Any], *, phase: str | None = None
    ) -> list[MatchResult]:
        """Run every enabled rule-pack against one observation."""
        target = MatchInput.from_dict(observation)
        results: list[MatchResult] = []
        for manifest in self.rule_packs(phase=phase):
            try:
                result = evaluate_rule(manifest, target)
            except Exception as exc:  # noqa: BLE001 — one bad rule must not stop the rest
                log.warning("rule %s raised during evaluation: %s", manifest.id, exc)
                continue
            if result.matched:
                results.append(result)
        return results

    # -- python plugins ----------------------------------------------------- #

    def load_python_tools(self) -> list[str]:
        """Import python-tool entrypoints so their decorators register them.

        The module is imported, not exec'd into our namespace, and it can only
        expose capability through ``@cordon_tool`` — which means the control
        plane wraps it exactly like a builtin.
        """
        loaded: list[str] = []
        for manifest in self.by_kind("python-tool"):
            if manifest.path is None or manifest.entrypoint is None:
                continue
            entry = (manifest.path.parent / manifest.entrypoint).resolve()
            if not entry.is_file():
                self.report.rejected.append(
                    {"path": str(manifest.path), "error": f"entrypoint not found: {entry}"}
                )
                continue
            module_name = f"cordon_plugin_{manifest.id.replace('-', '_').replace('.', '_')}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, entry)
                if spec is None or spec.loader is None:
                    raise PluginError(f"cannot load {entry}")
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                loaded.append(manifest.id)
            except Exception as exc:  # noqa: BLE001
                self.report.rejected.append(
                    {"path": str(entry), "error": f"import failed: {exc}"}
                )
                log.warning("python plugin %s failed to import: %s", manifest.id, exc)
        return loaded

    # -- external validation ------------------------------------------------ #

    def validate_nuclei_templates(self, *, binary: str = "nuclei", timeout: int = 120) -> dict[str, Any]:
        """Run ``nuclei -validate`` over the custom template directories."""
        resolved = shutil.which(binary)
        paths = self.nuclei_paths()
        if not paths:
            return {"checked": 0, "skipped": "no custom nuclei templates found"}
        if not resolved:
            return {"checked": 0, "skipped": "nuclei binary not installed"}

        directories = sorted({str(Path(p).parent) for p in paths})
        problems: list[dict[str, str]] = []
        for directory in directories:
            try:
                proc = subprocess.run(  # noqa: S603
                    [resolved, "-validate", "-t", directory, "-duc", "-silent"],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                problems.append({"path": directory, "error": str(exc)})
                continue
            if proc.returncode != 0:
                problems.append(
                    {"path": directory, "error": (proc.stderr or proc.stdout).strip()[:1000]}
                )
        return {"checked": len(paths), "directories": directories, "problems": problems}

    def summary(self) -> dict[str, Any]:
        return {
            "roots": [str(r) for r in self.roots],
            **self.report.summary(),
            "rule_packs": [m.summary() for m in self.rule_packs()],
            "custom_nuclei_templates": len(self.nuclei_paths()),
            "bbot_presets": len(self.bbot_presets()),
        }


_REGISTRY: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PluginRegistry()
    return _REGISTRY


def load_all(roots: list[str | Path], *, import_python: bool = True) -> PluginRegistry:
    """Discover plugins under each root. Replaces any previous registry."""
    global _REGISTRY
    _REGISTRY = PluginRegistry()
    for root in roots:
        _REGISTRY.load_dir(Path(root))
    if import_python:
        _REGISTRY.load_python_tools()
    log.info("plugin registry: %s", _REGISTRY.report.summary())
    return _REGISTRY

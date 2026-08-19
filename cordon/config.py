"""Runtime configuration loading.

``config.yaml`` controls *how* Cordon runs. ``scope.yaml`` controls *what it may
touch*. They are deliberately separate files: config is a preference, scope is an
authorization, and only one of them belongs in a bug bounty submission.

Resolution order for each file: explicit argument, then ``$CORDON_CONFIG`` /
``$CORDON_SCOPE``, then the current directory, then ``~/.config/cordon/``.
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from cordon.errors import ConfigError

__all__ = ["Config", "find_config", "find_scope"]

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "workspace": {"root": "./engagements", "max_payload_bytes": 262_144},
    "approval": {"backend": "deny", "timeout": 300, "remember_ttl": 0, "policy": {}},
    # OAuth 2.1 for the remote transport. 'none' is safe because binding a
    # non-loopback address without auth is then refused outright.
    "auth": {
        "mode": "none",
        "base_url": "http://127.0.0.1:8765",
        "enforce_tool_scopes": True,
    },
    "sandbox": {"mode": "none", "fallback_to_host": True},
    "engines": {
        "bbot": {"enabled": True, "default_preset": "subdomain-enum"},
        "nuclei": {"enabled": True, "binary": "nuclei"},
        "jaeles": {"enabled": True, "binary": "jaeles"},
        "semgrep": {"enabled": True, "binary": "semgrep"},
        "osmedeus": {"enabled": False},
        "strix": {"enabled": False},
    },
    "llm": {
        "provider": "openrouter",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "tiers": {},
        "max_retries": 4,
        "demote_on_ratelimit": True,
        "phase_token_budget": {},
    },
    "rules": {
        "dirs": ["./rules"],
        "import_python_plugins": True,
        "validate_nuclei": True,
        "jaeles_dir": "./rules/jaeles",
        "semgrep_dir": "./rules/semgrep",
    },
    # Cross-engagement PoC memory lives outside the workspace on purpose.
    "memory": {
        "poc_store": "~/.cordon/poc-memory.jsonl",
        "brain_store": "~/.cordon/neuron-brain.jsonl",
        "brain_activity": "~/.cordon/brain-activity.jsonl",
        "graph_enabled": False,
        "graph_uri": "bolt://localhost:7687",
        "graph_user": "neo4j",
        "graph_password_env": "NEO4J_PASSWORD",
    },
    # Cartography-populated Neo4j gives observed cloud topology instead of the
    # relationships inferred from Prowler control failures.
    "cloud": {
        "cartography": {
            "enabled": False,
            "uri": "bolt://localhost:7687",
            "user": "neo4j",
            "password_env": "NEO4J_PASSWORD",
            "max_hops": 4,
        }
    },
    "triage": {"taskflows_dir": "./taskflows", "canaries_enabled": True, "canary_count": 3},
    "report": {"formats": ["md", "csv", "json"], "include_audit": True},
    "audit": {"file": "audit.jsonl", "hash_chain": True},
    "hardening": {
        "pin_tool_definitions": True,
        "pin_file": ".cordon-pins.json",
        "sanitize_tool_output": True,
        "max_output_lines_to_model": 400,
    },
}

_SEARCH_DIRS = [Path.cwd(), Path.home() / ".config" / "cordon"]


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for key, value in (overlay or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _search(names: list[str], env_var: str) -> Path | None:
    from_env = os.environ.get(env_var)
    if from_env:
        candidate = Path(from_env).expanduser()
        if candidate.is_file():
            return candidate
    for directory in _SEARCH_DIRS:
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def find_config(explicit: str | Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return path
    found = _search(["config.yaml", "cordon.yaml"], "CORDON_CONFIG")
    if found is not None:
        return found
    # A fresh clone has no config.yaml — it is gitignored, because it holds the
    # operator's own choices. Falling through to the code defaults silently sets
    # `sandbox.mode: none`, which runs every tool on the host with no read-only
    # root, no dropped capabilities and no memory ceiling. That is the opposite
    # of the shipped posture, and nothing in the output would say so.
    #
    # The example file *is* the shipped posture: sandbox on, the image map, the
    # per-tool scratch mounts that stop sstimap and semgrep crashing. Use it
    # until the operator writes their own. `bootstrap.sh` copies it into place;
    # this is for everyone who clones and runs something directly.
    return _search(["config.example.yaml"], "CORDON_CONFIG")


def find_scope(explicit: str | Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"scope file not found: {path}")
        return path
    return _search(["scope.yaml"], "CORDON_SCOPE")


class Config:
    """Dotted-path accessor over the merged configuration mapping."""

    def __init__(self, data: dict[str, Any] | None = None, *, source: str = "<defaults>") -> None:
        self.data = _deep_merge(DEFAULTS, data or {})
        self.source = source

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        resolved = find_config(path)
        if resolved is None:
            return cls(source="<defaults>")
        try:
            raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"config is not valid YAML: {exc}", path=str(resolved)) from exc
        if not isinstance(raw, dict):
            raise ConfigError("config must be a mapping", path=str(resolved))
        return cls(raw, source=str(resolved))

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, dotted: str) -> dict[str, Any]:
        value = self.get(dotted, {})
        return value if isinstance(value, dict) else {}

    def path(self, dotted: str, default: str | None = None) -> Path | None:
        """Resolve a configured path relative to the config file's directory."""
        value = self.get(dotted, default)
        if value in (None, ""):
            return None
        candidate = Path(str(value)).expanduser()
        if candidate.is_absolute():
            return candidate
        base = Path(self.source).parent if self.source != "<defaults>" else Path.cwd()
        return (base / candidate).resolve()

    def __repr__(self) -> str:
        return f"Config(source={self.source!r})"

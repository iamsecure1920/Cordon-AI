"""Named payload lists, resolved server-side from the vetted store.

The model asks for a list by *name* ("admin", "api-routes"), never by path.
That keeps two properties that matter:

* ``sanitize_path`` refuses anything outside the engagement workspace, and the
  payload store deliberately lives outside it. Resolving names here means the
  store stays read-only and out of reach of anything the model can write to.
* A name is checkable against a tier. A path is not. Tier C is unreachable by
  construction — there is no name bound to it.

Tiers come from ``payloads/manifest.json``, written by ``scripts/vet_payloads.py``:

    A   discovery wordlists — safe under the normal scope and rate limits
    B   injection payloads — aggressive mode plus the approval gate
    C   quarantined — destructive or exfiltrating, never resolvable

See ``docs/PAYLOADS.md`` for how the tiers are assigned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = ["PayloadList", "PayloadStore", "PayloadError"]


class PayloadError(RuntimeError):
    """A payload list was requested that cannot be served."""


@dataclass(frozen=True)
class PayloadList:
    """One named list, already tier-checked."""

    name: str
    path: Path
    tier: str
    lines: int
    kind: str
    get_only: bool
    tools: tuple[str, ...]
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "lines": self.lines,
            "kind": self.kind,
            "get_only": self.get_only,
            "tools": list(self.tools),
            "purpose": self.purpose,
        }


class PayloadStore:
    """Resolves list names to files inside the vetted store."""

    def __init__(self, root: Path, aliases: dict[str, dict[str, Any]]) -> None:
        self.root = Path(root).expanduser().resolve()
        self._aliases = aliases
        self._manifest: dict[str, dict[str, Any]] = {}
        manifest_path = self.root / "manifest.json"
        if manifest_path.is_file():
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self._manifest = {entry["name"]: entry for entry in data.get("files", [])}

    @property
    def available(self) -> bool:
        """False when the store has not been fetched — not an error, a state.

        Callers report absence rather than substituting a different wordlist:
        silently swapping in a list the operator did not choose changes the size
        of the impact on the target, which is theirs to decide.
        """
        return bool(self._manifest)

    def _entry(self, filename: str) -> dict[str, Any]:
        entry = self._manifest.get(filename)
        if entry is None:
            raise PayloadError(
                f"{filename!r} is not in the payload manifest. Rebuild the store "
                "with: python3 scripts/vet_payloads.py --fetch"
            )
        return entry

    def resolve(self, name: str, *, allow_tier_b: bool = False) -> PayloadList:
        """Look up one list by name, enforcing its tier."""
        alias = self._aliases.get(name)
        if alias is None:
            raise PayloadError(
                f"unknown payload list {name!r}. Known lists: "
                f"{', '.join(sorted(self._aliases))}"
            )
        if not self.available:
            raise PayloadError(
                "the payload store has not been built. Run: "
                "python3 scripts/vet_payloads.py --fetch"
            )

        filename = alias["file"]
        entry = self._entry(filename)
        tier = entry["tier"]

        if tier == "C":
            # Unreachable via the shipped aliases; guarded anyway because a
            # hand-edited config must not be able to reach quarantine.
            raise PayloadError(
                f"{name!r} maps to {filename!r}, which is QUARANTINED (tier C): "
                f"{'; '.join(entry.get('reasons', []))}. It is not runnable."
            )
        if tier == "B" and not allow_tier_b:
            raise PayloadError(
                f"{name!r} is a tier B injection payload list, not a discovery "
                "wordlist. It belongs to an approval-gated exploitation tool."
            )

        path = self.root / tier / filename
        if not path.is_file():
            raise PayloadError(
                f"{name!r} is in the manifest but missing from disk at {path}. "
                "Re-run: python3 scripts/vet_payloads.py --fetch"
            )

        return PayloadList(
            name=name,
            path=path,
            tier=tier,
            lines=int(entry.get("lines", 0)),
            kind=entry.get("kind", "wordlist"),
            get_only=bool(entry.get("get_only", False)),
            tools=tuple(alias.get("tools", ())),
            purpose=alias.get("purpose", ""),
        )

    def catalog(self, *, tool: str | None = None) -> list[dict[str, Any]]:
        """Every resolvable list, optionally filtered to one tool."""
        listed: list[dict[str, Any]] = []
        for name, alias in sorted(self._aliases.items()):
            if tool and tool not in alias.get("tools", ()):
                continue
            entry = self._manifest.get(alias["file"])
            if entry is None or entry["tier"] == "C":
                continue
            listed.append({
                "name": name,
                "file": alias["file"],
                "tier": entry["tier"],
                "lines": entry.get("lines", 0),
                "get_only": bool(entry.get("get_only", False)),
                "tools": list(alias.get("tools", ())),
                "purpose": alias.get("purpose", ""),
            })
        return listed


@lru_cache(maxsize=4)
def _store(root: str, aliases_json: str) -> PayloadStore:
    return PayloadStore(Path(root), json.loads(aliases_json))


def store_from_config(config: Any) -> PayloadStore:
    """Build the store from the ``payloads:`` section of config.yaml."""
    section = config.section("payloads") or {}
    root = section.get("store", "./payloads")
    if not Path(root).is_absolute():
        # Relative to the project root, not the cwd — the server is started from
        # anywhere and the store must still be found.
        root = Path(__file__).resolve().parent.parent.parent / root
    aliases = section.get("lists", {}) or {}
    return _store(str(root), json.dumps(aliases, sort_keys=True))

#!/usr/bin/env python3
"""Regenerate the tool matrix in tools.md from the install recipes.

The matrix used to be maintained by hand, and it rotted the way hand-copied
data always does: it listed 53 of the 85 tools the installer actually knows
about, so `gf`, `commix`, `medusa`, `forge` and 28 others were installable,
catalogued, and absent from the reference a reader consults to find them.

`cordon/install/recipes.py` is the single source of truth — it is what
`cordon install` executes, so it cannot drift from reality without the
installer breaking first. This script renders that data between the
BEGIN/END markers in tools.md; `tests/test_tool_matrix.py` fails when the
file no longer matches, so the next person to add a recipe is told to re-run
it rather than discovering the gap months later.

    python3 scripts/gen_tool_matrix.py           # rewrite tools.md in place
    python3 scripts/gen_tool_matrix.py --check   # exit 1 if stale (CI/tests)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cordon.install.recipes import RECIPES  # noqa: E402

BEGIN = "<!-- BEGIN GENERATED TOOL MATRIX -->"
END = "<!-- END GENERATED TOOL MATRIX -->"

#: How each recipe method reads in the table.
_METHOD = {
    "go": "go install",
    "pipx": "pipx",
    "pip": "pip",
    "cargo": "cargo",
    "apt": "apt",
    "gem": "gem",
    "npm": "npm",
    "github_release": "release binary",
    "git": "git clone",
    "script": "script",
}


def render() -> str:
    recipes = list(RECIPES.values()) if isinstance(RECIPES, dict) else list(RECIPES)
    recipes = [r for r in recipes if not r.library]
    recipes.sort(key=lambda r: (r.category or "", r.tool))

    lines = [
        BEGIN,
        "",
        f"**{len(recipes)} installable tools**, generated from "
        "`cordon/install/recipes.py` by `scripts/gen_tool_matrix.py`.",
        "Do not edit this table by hand — run the script.",
        "`cordon doctor` reports which of these are actually working on *this* machine.",
        "",
        "| Tool | Category | Install | License | Core |",
        "|------|----------|---------|---------|------|",
    ]
    for r in recipes:
        method = _METHOD.get(r.method, r.method or "—")
        lines.append(
            f"| `{r.tool}` | {r.category or '—'} | {method} | "
            f"{r.license or '—'} | {'✅' if r.core else ''} |"
        )
    lines += ["", "**Core** marks the minimum viable pipeline (`cordon install --core`).", "", END]
    return "\n".join(lines)


def main() -> int:
    path = Path(__file__).resolve().parent.parent / "tools.md"
    text = path.read_text(encoding="utf-8")

    if BEGIN not in text or END not in text:
        print(f"markers not found in {path.name}; add {BEGIN} / {END}", file=sys.stderr)
        return 2

    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    updated = head + render() + tail

    if "--check" in sys.argv:
        if updated != text:
            print("tools.md matrix is stale — run: python3 scripts/gen_tool_matrix.py", file=sys.stderr)
            return 1
        print("tools.md matrix is current")
        return 0

    if updated != text:
        path.write_text(updated, encoding="utf-8")
        print(f"rewrote the matrix in {path.name}")
    else:
        print("already current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

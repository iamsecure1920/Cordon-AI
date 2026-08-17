"""The tool matrix in tools.md must match the install recipes.

The matrix was maintained by hand and rotted: it listed 53 of the 85 tools the
installer knows about, so a third of the catalog was installable, catalogued,
and missing from the reference someone reads to find it. Nothing failed —
a stale document produces no error, which is the same shape as a current one.

`scripts/gen_tool_matrix.py --check` compares the rendered table against
`recipes.py` and exits non-zero when they diverge, so adding a recipe without
regenerating fails here rather than silently.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_tool_matrix_matches_recipes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_tool_matrix.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, (
        "tools.md tool matrix is out of date with easyhunt/install/recipes.py.\n"
        "Run: python3 scripts/gen_tool_matrix.py\n"
        f"{result.stdout}{result.stderr}"
    )


def test_every_installable_recipe_appears_in_the_matrix() -> None:
    """The generator is only useful if it renders the whole catalog.

    Guards the generator itself: a filter bug that dropped a category would
    still round-trip cleanly through --check, because both sides would be
    wrong in the same way.
    """
    from easyhunt.install.recipes import RECIPES

    recipes = list(RECIPES.values()) if isinstance(RECIPES, dict) else list(RECIPES)
    expected = {r.tool for r in recipes if not r.library}
    matrix = (ROOT / "tools.md").read_text(encoding="utf-8")
    body = matrix.split("<!-- BEGIN GENERATED TOOL MATRIX -->", 1)[1].split(
        "<!-- END GENERATED TOOL MATRIX -->", 1
    )[0]

    missing = sorted(t for t in expected if f"| `{t}` |" not in body)
    assert not missing, f"installable tools absent from the generated matrix: {missing}"

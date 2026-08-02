#!/usr/bin/env python3
"""Build a queryable index of the OWASP Web Security Testing Guide.

EasyHunt is strong at running tools and weak at knowing what to test next. The
WSTG is the profession's answer to that question — 100+ named tests organised by
phase — and it is far more useful as *data the agent can query* than as a PDF
nobody opens.

Source: github.com/OWASP/wstg, pinned. The guide text is **CC BY-SA 4.0**, so:

* the full text is NOT vendored into this repository — it is fetched locally,
  and the index records where each test came from;
* attribution to OWASP travels with every record;
* anything redistributed that incorporates this text must itself be CC BY-SA.

That is the same treatment the payload store gets, for the same reason: content
someone else owns, pinned so it cannot change under us.

    python3 scripts/fetch_wstg.py --fetch     # clone at the pin, build the index
    python3 scripts/fetch_wstg.py --verify    # check the index against the pin
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "knowledge" / "wstg"
INDEX = STORE / "index.json"

SOURCE = {
    "repo": "https://github.com/OWASP/wstg.git",
    # Bump deliberately, and re-read the diff: the guide's test IDs are stable
    # but its content is not.
    "commit": "58ba846417b5e69464315a3f2521aeabe9fb4b45",
    "license": "CC BY-SA 4.0",
    "attribution": "OWASP Web Security Testing Guide — https://owasp.org/wstg",
    "redistribute": "only under CC BY-SA 4.0, with attribution",
}

TESTS_ROOT = "document/4-Web_Application_Security_Testing"

#: WSTG category prefix -> the engagement phase it belongs to. Lets the agent ask
#: "what should I test now" rather than needing to know the taxonomy.
PHASE = {
    "INFO": "recon",
    "CONF": "configuration",
    "IDNT": "identity",
    "ATHN": "authentication",
    "ATHZ": "authorization",
    "SESS": "session",
    "INPV": "input_validation",
    "ERRH": "error_handling",
    "CRYP": "cryptography",
    "BUSL": "business_logic",
    "CLNT": "client_side",
    "APIT": "api",
}

ID_RE = re.compile(r"\bWSTG-([A-Z]{4})-(\d{2})\b")


def _section(text: str, heading: str) -> str:
    """Pull one '## Heading' section out of a WSTG markdown document."""
    match = re.search(
        rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s+|\Z)",
        text, re.MULTILINE | re.DOTALL,
    )
    return match.group(1).strip() if match else ""


def _bullets(block: str, limit: int = 12) -> list[str]:
    out = [
        re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line.strip().lstrip("-*").strip())
        for line in block.splitlines()
        if line.strip().startswith(("-", "*"))
    ]
    return [b for b in out if b][:limit]


def parse(path: Path, repo: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    found = ID_RE.search(text)
    if not found:
        return None
    wstg_id = found.group(0)
    prefix = found.group(1)

    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else path.stem

    summary = _section(text, "Summary")
    # First paragraph only: enough for an agent to decide relevance.
    summary = re.split(r"\n\s*\n", summary)[0] if summary else ""
    summary = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", summary).strip()

    return {
        "id": wstg_id,
        "title": title,
        "category": prefix,
        "phase": PHASE.get(prefix, "other"),
        "summary": summary[:1200],
        "objectives": _bullets(_section(text, "Test Objectives")),
        "how_to_test": _section(text, "How to Test")[:2500],
        "remediation": _section(text, "Remediation")[:900],
        "source_path": str(path.relative_to(repo)),
        "owasp_url": (
            "https://owasp.org/www-project-web-security-testing-guide/stable/"
            + str(path.relative_to(repo / "document")).replace(".md", "")
        ),
    }


def fetch() -> int:
    scratch = STORE / "_src"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.parent.mkdir(parents=True, exist_ok=True)

    print(f"cloning {SOURCE['repo']}")
    subprocess.run(["git", "clone", "-q", SOURCE["repo"], str(scratch)], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603, S607
        ["git", "-C", str(scratch), "checkout", "-q", SOURCE["commit"]], check=True
    )
    actual = subprocess.run(  # noqa: S603, S607
        ["git", "-C", str(scratch), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if actual != SOURCE["commit"]:
        raise SystemExit(f"pin mismatch: expected {SOURCE['commit']}, got {actual}")
    print(f"pin verified {actual[:12]}\n")

    tests: list[dict[str, Any]] = []
    for path in sorted((scratch / TESTS_ROOT).rglob("*.md")):
        if path.name == "README.md":
            continue
        record = parse(path, scratch)
        if record:
            tests.append(record)

    tests.sort(key=lambda t: t["id"])
    INDEX.write_text(json.dumps({"source": SOURCE, "tests": tests}, indent=2) + "\n")
    shutil.rmtree(scratch, ignore_errors=True)

    by_phase: dict[str, int] = {}
    for t in tests:
        by_phase[t["phase"]] = by_phase.get(t["phase"], 0) + 1
    print(f"indexed {len(tests)} WSTG tests -> {INDEX}")
    for phase, n in sorted(by_phase.items(), key=lambda kv: -kv[1]):
        print(f"   {n:>3}  {phase}")
    print(f"\nlicense: {SOURCE['license']} — {SOURCE['attribution']}")
    return 0


def verify() -> int:
    if not INDEX.exists():
        print(f"no index at {INDEX} — run --fetch first", file=sys.stderr)
        return 1
    data = json.loads(INDEX.read_text())
    tests = data.get("tests", [])
    missing = [t["id"] for t in tests if not t.get("summary")]
    print(f"tests indexed : {len(tests)}")
    print(f"pinned commit : {data['source']['commit'][:12]}")
    print(f"license       : {data['source']['license']}")
    if missing:
        print(f"records with no summary: {len(missing)} — {missing[:5]}")
    return 0 if tests and not missing else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true")
    group.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    return fetch() if args.fetch else verify()


if __name__ == "__main__":
    raise SystemExit(main())

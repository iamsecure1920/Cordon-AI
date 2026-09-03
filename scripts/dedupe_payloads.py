#!/usr/bin/env python3
"""Build category-level unique payload files from the vetted store.

The vetted store is pinned and must not drift, but the raw upstream files
carry heavy duplication — measured on this store:

* tier A: 3,607,843 lines -> 2,946,367 unique (572,290 cross-file dupes)
* tier B:    88,236 lines ->    40,515 unique (46,991 intra-file dupes,
  most of it inside lfi.txt, which holds 70,462 lines for 27,127 unique)

This script derives two consolidated files, one per category:

    payloads/unique/discovery-unique.txt   tier A union, normalized, deduped
    payloads/unique/injection-unique.txt   tier B union, normalized, deduped

Ordering favours the small curated lists first (they are the high-signal
material), so the big grab-bag files only contribute what they add. The files
are derived artifacts with their own manifest
(``payloads/unique/manifest.json``) that ``PayloadStore`` merges in at runtime,
so they are resolvable by name exactly like vetted lists.

The pinned store itself is never rewritten — deduplication lives in these
derived files, not in the vetted originals, so ``vet_payloads.py --verify``
stays meaningful.

    python3 scripts/dedupe_payloads.py --build      # rebuild the unique files
    python3 scripts/dedupe_payloads.py --verify     # check them for drift
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "payloads"
UNIQUE = STORE / "unique"
UNIQUE_MANIFEST = UNIQUE / "manifest.json"

CATEGORIES = {
    "discovery": {
        "tier": "A",
        "filename": "discovery-unique.txt",
        "kind": "wordlist",
        "purpose": "Every tier A (discovery) payload exactly once — normalized, "
        "deduplicated across all vetted discovery wordlists. Large (millions of "
        "lines): use it deliberately, not as a default.",
    },
    "injection": {
        "tier": "B",
        "filename": "injection-unique.txt",
        "kind": "injection",
        "purpose": "Every tier B (injection) payload exactly once — normalized, "
        "deduplicated across all vetted injection lists. Approval-gated: it "
        "belongs to exploitation tools only, never to content discovery.",
    },
}


def normalize(line: str) -> str:
    """The same normalization content_discovery applies to wordlist entries."""
    return line.strip().lower().rstrip(".").lstrip("/")


def read_lines(path: Path) -> list[str]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        return [normalize(line) for line in handle if line.strip()]


def build() -> dict[str, dict[str, int]]:
    UNIQUE.mkdir(parents=True, exist_ok=True)
    report: dict[str, dict[str, int]] = {}
    manifest_files: list[dict[str, object]] = []

    for category, spec in CATEGORIES.items():
        tier_dir = STORE / spec["tier"]
        files = sorted(tier_dir.iterdir(), key=lambda p: (len(read_lines(p)), p.name))
        seen: set[str] = set()
        kept: list[str] = []
        total = 0
        intra_dropped = 0
        cross_dropped = 0

        for source in files:
            if not source.is_file() or source.name == spec["filename"]:
                continue
            lines = read_lines(source)
            total += len(lines)
            for line in lines:
                if line in seen:
                    cross_dropped += 1
                    continue
                seen.add(line)
                kept.append(line)
            # Intra-file duplicates were collapsed by the set above; measure
            # them for the report.
            intra_dropped += len(lines) - len(set(lines))

        target = UNIQUE / spec["filename"]
        target.write_text("\n".join(kept) + "\n", encoding="utf-8")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()

        manifest_files.append(
            {
                "name": spec["filename"],
                "tier": spec["tier"],
                "kind": spec["kind"],
                "lines": len(kept),
                "sha256": digest,
                "get_only": False,
                "reasons": [
                    "derived: union of all vetted "
                    + ("discovery" if spec["tier"] == "A" else "injection")
                    + " lists, deduplicated and normalized"
                ],
                "derived": True,
                "path": f"unique/{spec['filename']}",
                "purpose": spec["purpose"],
            }
        )
        report[category] = {
            "total": total,
            "unique": len(kept),
            "intra_dropped": intra_dropped,
            "cross_dropped": cross_dropped,
            "file": str(target),
        }

    UNIQUE_MANIFEST.write_text(
        json.dumps(
            {
                "source": "derived from the vetted payload store by "
                "scripts/dedupe_payloads.py; never edit by hand",
                "files": manifest_files,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def verify() -> int:
    if not UNIQUE_MANIFEST.is_file():
        print(f"no derived manifest at {UNIQUE_MANIFEST} — run --build first")
        return 1
    drift = 0
    for entry in json.loads(UNIQUE_MANIFEST.read_text())["files"]:
        path = STORE / entry["path"]
        if not path.is_file():
            print(f"MISSING  {entry['name']}")
            drift += 1
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"CHANGED  {entry['name']}")
            drift += 1
    if drift:
        return 1
    print("derived payload files verified, no drift")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--build", action="store_true")
    group.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    if args.verify:
        return verify()

    report = build()
    for category, numbers in report.items():
        print(
            f"{category:10} {numbers['total']:,} lines -> {numbers['unique']:,} unique "
            f"({numbers['intra_dropped']:,} intra-file + {numbers['cross_dropped']:,} "
            f"cross-file dupes dropped)"
        )
        print(f"           wrote {numbers['file']}")
    print("\nnext: vet_payloads.py --verify still passes (the pinned store is untouched)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

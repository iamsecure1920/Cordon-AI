"""Digest an engagement workspace into something worth reading.

`hunt.sh` leaves a status stream and a phase-*.json per phase per target. This
turns that into a short report: what ran, what did not, what it found, and —
the part that matters — which results are worth a human's next hour.

Deliberately does NOT rank by severity alone. A scanner's HIGH means "this
pattern matched"; it does not mean the finding is real, in scope, or rewardable.
Tonight a HIGH severity "credential in URL" turned out to be JSON-LD, and two
MEDIUM Google Maps keys were explicitly out of scope for the program. Both would
have topped a severity-sorted list.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_status(ws: Path) -> list[dict]:
    path = ws / "status.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def main() -> int:
    marker = ROOT / ".cordon-run"
    ws = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(marker.read_text().strip()) if marker.exists() else None
    )
    if ws is None or not ws.exists():
        print("no workspace — run scripts/hunt.sh first")
        return 1

    status = [s for s in load_status(ws) if s.get("state") != "start"]
    print(f"\nENGAGEMENT  {ws.name}")
    print(f"workspace   {ws}\n")

    # ---- what ran ----------------------------------------------------------
    states = Counter(s.get("state") for s in status)
    print("PHASES")
    for state in ("ok", "empty", "incomplete", "failed", "error", "unavailable"):
        if states.get(state):
            print(f"  {state:12} {states[state]}")
    bad = [s for s in status if s.get("state") not in ("ok", None)]
    if bad:
        print("\n  did not do their job:")
        for s in bad:
            msg = (s.get("message") or s.get("error") or "")[:88]
            print(f"    {s.get('phase',''):11} {s.get('state',''):11} {msg}")
    else:
        print("\n  every phase produced output")

    # ---- what it found -----------------------------------------------------
    findings: list[dict] = []
    for path in sorted(ws.glob("phase-*.json")):
        # phase-<name>--<target>.json
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for f in data.get("findings", []) if isinstance(data, dict) else []:
            stem = path.stem.replace("phase-", "")
            f["_phase"], _, f["_target"] = stem.partition("--")
            findings.append(f)

    print(f"\nFINDINGS  {len(findings)} candidate(s)")
    if findings:
        by_sev = defaultdict(list)
        for f in findings:
            by_sev[str(f.get("severity", "info")).lower()].append(f)
        for sev in ("critical", "high", "medium", "low", "info"):
            for f in by_sev.get(sev, []):
                print(f"  [{sev:8}] {f.get('_phase','?'):9} {str(f.get('_target',''))[:28]:28} "
                      f"{str(f.get('title',''))[:44]}")

    # ---- what to do next ---------------------------------------------------
    print("\nNEXT")
    if not findings:
        print("  Nothing raised a candidate. Before reading that as a clean target,")
        print("  check the phase table above: a phase that produced nothing tested")
        print("  nothing, and that is not the same answer.")
    else:
        print("  Every item above is a CANDIDATE. Before any of it is reported:")
        print("   1. Re-read the program's out-of-scope list. Tonight two MEDIUM")
        print("      Google Maps keys and one HIGH 'credential in URL' were all")
        print("      unreportable — two excluded by policy, one a regex artefact.")
        print("   2. Reproduce by hand with curl. A scanner match is a lead.")
        print("   3. Only then does it need a PoC and a write-up.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

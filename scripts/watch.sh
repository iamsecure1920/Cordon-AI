#!/usr/bin/env bash
#
# Live view of a running engagement: which tools are executing, what the audit
# log has recorded, and how the workspace is filling up.
#
# EasyHunt is quiet by design — tool output goes to the workspace, not the
# terminal — so without this it is hard to tell "working" from "hung".
#
# Usage: ./scripts/watch.sh [refresh-seconds]

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFRESH="${1:-3}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

while true; do
    clear
    WS=$(ls -dt "$ROOT"/engagements/*/ 2>/dev/null | head -1)
    printf "${BOLD}EasyHunt — live${NC}   %s\n" "$(date '+%H:%M:%S')"
    printf "${DIM}%s${NC}\n\n" "${WS:-no engagement workspace yet}"

    # ── What is actually executing right now ──────────────────────────────
    printf "${BOLD}Running tools${NC}\n"
    found=0
    for t in subfinder assetfinder findomain amass httpx nuclei katana ffuf \
             feroxbuster dalfox sqlmap naabu dnsx trufflehog semgrep bbot; do
        # -x matches the process name exactly, so this does not match itself.
        if pgrep -x "$t" >/dev/null 2>&1; then
            el=$(ps -o etime= -C "$t" 2>/dev/null | head -1 | tr -d ' ')
            printf "  ${GREEN}●${NC} %-14s %s\n" "$t" "$el"
            found=1
        fi
    done
    if command -v docker >/dev/null 2>&1; then
        # Only EasyHunt's own sandbox containers — the host may run unrelated ones.
        dps=$(docker ps --format '  {{.Names}} {{.Image}} ({{.Status}})' 2>/dev/null \
            | grep -E 'projectdiscovery|dalfox|trufflehog|prowler|semgrep' | head -5)
        [ -n "$dps" ] && { printf '%s\n' "$dps"; found=1; }
    fi
    [ "$found" -eq 0 ] && printf "  ${DIM}idle${NC}\n"

    # ── Audit trail: every call, including the refusals ───────────────────
    printf "\n${BOLD}Audit (last 8)${NC}\n"
    if [ -n "$WS" ] && [ -f "$WS/audit.jsonl" ]; then
        tail -8 "$WS/audit.jsonl" | python3 -c '
import json, sys
for line in sys.stdin:
    try: r = json.loads(line)
    except Exception: continue
    ev, tool = r.get("event", "?"), r.get("tool", "-")
    out = r.get("outcome", "-")
    mark = {"ok": "\033[0;32m✓\033[0m", "refused": "\033[0;33m✗\033[0m"}.get(out, " ")
    ms = r.get("duration_ms")
    print(f"  {mark} {ev:<16} {tool:<20} {out}" + (f"  {ms}ms" if ms else ""))
'
    else
        printf "  ${DIM}no audit log yet${NC}\n"
    fi

    # ── Artifacts landing on disk ─────────────────────────────────────────
    printf "\n${BOLD}Raw output${NC}\n"
    if [ -n "$WS" ] && [ -d "$WS/raw" ]; then
        ls -t "$WS/raw" 2>/dev/null | head -6 | while read -r f; do
            printf "  %-42s %s lines\n" "$f" "$(wc -l < "$WS/raw/$f" 2>/dev/null || echo 0)"
        done
    else
        printf "  ${DIM}nothing yet${NC}\n"
    fi

    printf "\n${DIM}refresh %ss — Ctrl-C to exit${NC}\n" "$REFRESH"
    sleep "$REFRESH"
done

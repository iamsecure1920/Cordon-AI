#!/usr/bin/env bash
# EasyHunt — run a full engagement flow unattended.
#
#   ./scripts/hunt.sh <target> [--from PHASE] [--only PHASE,PHASE] [--exploit]
#
# WHY THIS EXISTS, and what it deliberately does not do.
#
# It does not remove the approval gate. Approval moved from a prompt-per-call to
# a decision-per-engagement: `approval.backend: policy` plus the `auto_approve`
# list in config.yaml, reviewed once against the program's published rules. That
# is a better gate than a prompt, because a human clicking "yes" forty times in a
# row is not consenting to anything — they are pattern-matching to get on with
# their evening. Read auto_approve before an engagement, not during it.
#
# --exploit adds an `exploit` phase after `scan`: it chains the exploit
# validators (web_injection_probe, and sqli_validate/xss_validate when asked)
# over the injection points earlier phases discovered, so a client run proves
# what it finds instead of leaving it to an agent. It only runs with --exploit,
# and each validator it drives is itself in the auto_approve list — approving
# exploit_chain does not approve sqlmap.
#
# What it adds instead is a gate the prompts never provided: **each phase has to
# prove it did something before the next one runs.** Chaining phases multiplies
# the cost of a stage that reports success while testing nothing, and that defect
# has been found seventeen times in this codebase alone — nuclei exiting 0 while
# unable to write its config, commix discarding its own -u flag, Akamai 403s
# counted as coverage. A pipeline without gates turns one silent failure into a
# report where every number is wrong.
#
# Exit codes from scripts/phase.py: 0 did its job, 2 ran but produced nothing,
# 3 failed outright. A 2 or 3 on a phase later phases depend on stops the run.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
# The console script, not `python -m easyhunt` — the package has no __main__,
# so that form fails silently and every target then reads as out of scope.
EH="${ROOT}/.venv/bin/easyhunt"
[ -x "$EH" ] || EH="$(command -v easyhunt)"
[ -x "$EH" ] || die "easyhunt CLI not found — run ./install.sh"

G='\033[0;32m'; Y='\033[0;33m'; R='\033[0;31m'; D='\033[2m'; N='\033[0m'
ok()   { printf "${G}✓${N} %s\n" "$1"; }
warn() { printf "${Y}!${N} %s\n" "$1"; }
die()  { printf "${R}✗${N} %s\n" "$1"; exit 1; }

TARGETS=""; FROM=""; ONLY=""; EXPLOIT=no
while [ $# -gt 0 ]; do
    case "$1" in
        --from)    FROM="$2"; shift 2 ;;
        --only)    ONLY="$2"; shift 2 ;;
        --exploit) EXPLOIT=yes; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *)         TARGETS="$TARGETS $1"; shift ;;
    esac
done
[ -n "$TARGETS" ] || die "usage: $0 <target> [<target>...] [--from PHASE] [--only PHASE,...] [--exploit]"

# Phases that must succeed for the rest to mean anything. A scan of hosts that
# were never confirmed alive is not a scan, it is a WAF survey.
# Per-target phases run once for each host. Global phases run ONCE at the end,
# over everything every host contributed — scanning is sized against the real
# total instead of a set that grows under it, and the report covers the run
# rather than the last host in it.
PER_TARGET_PHASES="recon permute resolve probe cdn waf tls cors endpoints js auth"
# exploit is listed so --from/--only can name it, but it only *runs* when
# --exploit is passed: its validators are individually approval-gated and must
# never fire on a run the operator did not explicitly authorise for exploitation.
# ports/services/params/content/pattern/graphql/websocket/nikto/wapiti are global:
# they consume the whole estate once, not once per host.
GLOBAL_PHASES_LIST="secrets code_audit pattern graphql websocket takeover scan ports services params content nikto wapiti exploit plan report"
ALL_PHASES="$PER_TARGET_PHASES $GLOBAL_PHASES_LIST"
# Only probe is genuinely required: if nothing is alive, later phases scan hosts
# nobody confirmed exist. `resolve` was in here too, so any target already
# written as an address — where there is nothing to resolve — aborted the whole
# run at the second phase.
REQUIRED="probe"

# ── Preflight ────────────────────────────────────────────────────────────────
printf "\n${D}── Preflight ──${N}\n"
[ -f "${ROOT}/scope.yaml" ] || die "no scope.yaml — it is the authorization record and must be
    transcribed from the program's published policy. See CLAUDE.md."

for T in $TARGETS; do
    "$EH" scope "$T" 2>/dev/null | grep -q "IN SCOPE" \
        || die "$T is not in scope.yaml. That is the control plane working; do not work around it."
done
ok "$(echo $TARGETS | wc -w) target(s) in scope"

SCOPE_NAME=$("$PY" -c "
import sys;sys.path.insert(0,'${ROOT}')
from easyhunt.control_plane.scope import Scope
s=Scope.load('${ROOT}/scope.yaml');print(s.name)" 2>/dev/null)
RPS=$("$PY" -c "
import sys;sys.path.insert(0,'${ROOT}')
from easyhunt.control_plane.scope import Scope
s=Scope.load('${ROOT}/scope.yaml');print(s.rules.max_rps)" 2>/dev/null)
ok "engagement ${SCOPE_NAME}, ceiling ${RPS} rps"

if [ "$EXPLOIT" = "yes" ]; then
    ALLOWED=$("$PY" -c "
import sys;sys.path.insert(0,'${ROOT}')
from easyhunt.control_plane.scope import Scope
s=Scope.load('${ROOT}/scope.yaml');print('yes' if s.rules.allow_exploitation else 'no')" 2>/dev/null)
    [ "$ALLOWED" = "yes" ] || die "--exploit given but scope.yaml sets allow_exploitation: false.
    Change the scope only if the program's policy actually permits it."
    warn "exploitation ENABLED — proof-of-concept only, never data extraction"
fi

# ── Phases ───────────────────────────────────────────────────────────────────
RUN_PHASES="$ALL_PHASES"
[ -n "$ONLY" ] && RUN_PHASES="${ONLY//,/ }"
STARTED=no; [ -z "$FROM" ] && STARTED=yes

FAILED=""; EMPTY=""

run_phase() {
    phase="$1"; tgt="$2"
    printf "\n${D}── %s ──${N}\n" "$phase"
    "$PY" "${ROOT}/scripts/phase.py" "$phase" "$tgt"
    return $?
}

# ── Per-target phases ────────────────────────────────────────────────────────
for TARGET in $TARGETS; do
printf "\n${D}══ %s ══${N}\n" "$TARGET"
STARTED=no; [ -z "$FROM" ] && STARTED=yes
for phase in $RUN_PHASES; do
    case " $GLOBAL_PHASES_LIST " in *" $phase "*) continue ;; esac
    [ "$STARTED" = "no" ] && { [ "$phase" = "$FROM" ] && STARTED=yes || continue; }

    printf "\n${D}── %s ──${N}\n" "$phase"
    "$PY" "${ROOT}/scripts/phase.py" "$phase" "$TARGET"
    rc=$?
    case $rc in
        0) ok "$phase" ;;
        2) warn "$phase ran but produced nothing"
           EMPTY="$EMPTY $phase"
           case " $REQUIRED " in
             *" $phase "*) warn "$phase is required and produced nothing — later phases would
    be scanning hosts nobody confirmed exist — skipping the rest of $TARGET."; break ;;
           esac ;;
        *) warn "$phase FAILED (exit $rc)"
           FAILED="$FAILED $phase"
           case " $REQUIRED " in
             *" $phase "*) warn "$phase is required and failed — skipping the rest of $TARGET."; break ;;
           esac ;;
    esac
done
done

# ── Global phases: once, over everything every target found ──────────────────
FIRST=$(echo $TARGETS | awk '{print $1}')
for phase in $GLOBAL_PHASES_LIST; do
    case " $RUN_PHASES " in *" $phase "*) ;; *) continue ;; esac
    if [ "$phase" = "exploit" ] && [ "$EXPLOIT" != "yes" ]; then
        warn "exploit phase skipped — re-run with --exploit to fire the validators"
        continue
    fi
    printf "\n${D}══ all targets ══${N}\n${D}── %s ──${N}\n" "$phase"
    EXTRA=""
    if [ "$phase" = "exploit" ] && [ "$EXPLOIT" = "yes" ]; then
        # --exploit means "fire the heavy validators too": sqlmap and dalfox on
        # the first few injection points, not just the read-only native probes.
        EXTRA='{"include_heavy": true}'
    fi
    "$PY" "${ROOT}/scripts/phase.py" "$phase" "$FIRST" "$EXTRA"
    rc=$?
    case $rc in
        0) ok "$phase" ;;
        2) warn "$phase produced nothing"; EMPTY="$EMPTY $phase" ;;
        *) warn "$phase FAILED (exit $rc)"; FAILED="$FAILED $phase" ;;
    esac
done

# ── Summary ──────────────────────────────────────────────────────────────────
WS=$(cat "${ROOT}/.easyhunt-run" 2>/dev/null || echo "?")
printf "\n${D}── Done ──${N}\n"
ok "workspace: ${WS}"
[ -n "$EMPTY" ]  && warn "produced nothing:${EMPTY}"
[ -n "$FAILED" ] && warn "failed:${FAILED}"
printf "${D}  status stream: %s/status.jsonl${N}\n" "$WS"
printf "${D}  findings are CANDIDATES until a PoC validates them.${N}\n"
"$PY" "${ROOT}/scripts/summary.py" "$WS" 2>/dev/null || true
[ -z "$FAILED" ] && [ -z "$EMPTY" ] && ok "every phase produced output"
exit 0

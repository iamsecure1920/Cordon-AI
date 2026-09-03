#!/usr/bin/env bash
#
# Cordon AI installer.
#
# Installs the Python package, the security tool suite, Nuclei templates, the
# Claude Skills, and registers the MCP server. Everything except the Python
# package is optional — Cordon degrades to "that tool is absent" rather than
# failing, so a partial install still works.
#
# AUTHORIZED TESTING ONLY. Installing this does not authorize anything; the
# scope.yaml you write does.

set -uo pipefail

CORDON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="${HOME}/.claude/skills"
VENV_DIR="${CORDON_DIR}/.venv"
INSTALL_TOOLS="${INSTALL_TOOLS:-yes}"
INSTALL_SKILLS="${INSTALL_SKILLS:-yes}"
REGISTER_MCP="${REGISTER_MCP:-yes}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
ok()   { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}!${NC} %s\n" "$1"; }
fail() { printf "${RED}✗${NC} %s\n" "$1"; }
step() { printf "\n${DIM}── %s ──${NC}\n" "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'USAGE'
Usage: ./install.sh [options]

  --no-tools     skip the Go/Python security tool suite
  --no-skills    skip deploying Claude Skills to ~/.claude/skills
  --no-mcp       skip MCP server registration
  --minimal      Python package only
  -h, --help     this message

Environment: INSTALL_TOOLS, INSTALL_SKILLS, REGISTER_MCP (yes|no)
USAGE
}

for arg in "$@"; do
    case "$arg" in
        --no-tools)  INSTALL_TOOLS=no ;;
        --no-skills) INSTALL_SKILLS=no ;;
        --no-mcp)    REGISTER_MCP=no ;;
        --minimal)   INSTALL_TOOLS=no; INSTALL_SKILLS=no; REGISTER_MCP=no ;;
        -h|--help)   usage; exit 0 ;;
        *) fail "unknown option: $arg"; usage; exit 2 ;;
    esac
done

printf "${GREEN}Cordon AI installer${NC}\n"
printf "${DIM}Authorized testing only: owned assets, in-scope bug bounty targets,\n"
printf "or org assets with documented written approval.${NC}\n"

# --------------------------------------------------------------------------- #
step "Python package"

if ! have python3; then
    fail "python3 is required"; exit 1
fi
PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    fail "Python 3.11+ required (found ${PY_VERSION})"; exit 1
fi
ok "python ${PY_VERSION}"

if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}" || { fail "could not create venv"; exit 1; }
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --quiet --upgrade pip >/dev/null 2>&1

if python -m pip install --quiet -e "${CORDON_DIR}[llm]"; then
    ok "cordon-ai installed (editable) with LLM support"
else
    fail "pip install failed"; exit 1
fi

if python -m pip install --quiet "bbot>=2.4" 2>/dev/null; then
    ok "bbot installed (primary recon engine)"
else
    warn "bbot install failed — recon falls back to subfinder/assetfinder/findomain"
fi

# --------------------------------------------------------------------------- #
if [ "${INSTALL_TOOLS}" = "yes" ]; then
step "Security tools"

# Delegated to `cordon install`, which is dependency-ordered, idempotent, and
# verifies each tool after installing it. A flat list of go-install lines cannot
# tell you that a tool installed successfully and still does not work.
if "${VENV_DIR}/bin/cordon" install --no-color; then
    ok "core tool pipeline installed and verified"
else
    warn "some tools failed — see the report above; re-run to retry (installs are idempotent)"
fi
printf "\n  ${DIM}For everything (cloud, LLM red-team, extra scanners):${NC}\n"
printf "    ${DIM}cordon install --all${NC}\n"
fi

# --------------------------------------------------------------------------- #
step "Nuclei templates"

if have nuclei; then
    if nuclei -update-templates -silent >/dev/null 2>&1; then
        ok "nuclei-templates updated"
    else
        warn "template update failed — check network access"
    fi
    if nuclei -validate -t "${CORDON_DIR}/rules/nuclei" -duc -silent >/dev/null 2>&1; then
        ok "custom templates in rules/nuclei validate"
    else
        warn "custom templates failed validation — run: nuclei -validate -t rules/nuclei"
    fi
else
    warn "nuclei not installed — the vulnerability engine is unavailable"
fi

# --------------------------------------------------------------------------- #
step "Configuration"

# config.yaml only. It is a preference file and copying it is harmless.
src="${CORDON_DIR}/config.example.yaml"; dst="${CORDON_DIR}/config.yaml"
if [ -f "${dst}" ]; then
    ok "config.yaml already exists (not overwritten)"
else
    cp "${src}" "${dst}" && ok "created config.yaml from the example"
fi

# scope.yaml is DELIBERATELY NOT CREATED.
#
# This used to copy scope.example.yaml into place with a warning. The warning was
# not enough. What the operator got was a file declaring
#
#     authorization: bug-bounty
#     program_url: https://hackerone.com/example/policy
#     fetched_at:  <whenever the template was written>
#
# and every check downstream then reported a green tick: `cordon doctor` says
# "✓ scope: scope.yaml (example-bbp, bug-bounty)", and bootstrap.sh's closing
# section says "✓ scope.yaml present" instead of the refusal it prints when the
# file is absent.
#
# scope.yaml is not configuration. It is the record of an authorization, and it
# has to be transcribed from a program's published policy — that text is the
# legal basis for the engagement. A pre-made one inherits an authorization claim
# and a fetched_at date the operator never made, and the staleness check
# (max_age_days) then measures against a date that means nothing.
#
# CLAUDE.md forbids the agent from doing exactly this: "Do not invent, infer, or
# reconstruct a scope file. Do not copy scope.example.yaml and fill in a target."
# The installer was doing it on the agent's behalf, silently, before anyone
# looked. An absent scope.yaml is a correct state; a fabricated one is not.
if [ -f "${CORDON_DIR}/scope.yaml" ]; then
    ok "scope.yaml present"
else
    warn "scope.yaml NOT created — that is deliberate.
    It is an authorization record, not a config file, and must be transcribed
    from the target program's published policy page. Start from the template:
      cp scope.example.yaml scope.yaml && \$EDITOR scope.yaml
    Then: cordon scope validate"
fi

# --------------------------------------------------------------------------- #
if [ "${INSTALL_SKILLS}" = "yes" ]; then
step "Claude Skills"

mkdir -p "${SKILLS_DIR}"
count=0
for skill in "${CORDON_DIR}"/skills/*/; do
    [ -d "${skill}" ] || continue
    name="$(basename "${skill}")"
    rm -rf "${SKILLS_DIR:?}/${name}"
    cp -r "${skill}" "${SKILLS_DIR}/${name}" && count=$((count + 1))
done
ok "${count} skill(s) deployed to ${SKILLS_DIR}"
fi

# --------------------------------------------------------------------------- #
if [ "${REGISTER_MCP}" = "yes" ]; then
step "MCP registration"

# `cordon connect` prints ready-to-paste registration for every stdio
# MCP client (Claude Code, Cursor, Windsurf, Gemini CLI, Copilot, generic).
if have claude; then
    if claude mcp list 2>/dev/null | grep -q cordon; then
        ok "cordon already registered"
    elif claude mcp add cordon --transport stdio -- \
            "${VENV_DIR}/bin/python" -m cordon.mcp_server \
            --scope "${CORDON_DIR}/scope.yaml" \
            --config "${CORDON_DIR}/config.yaml" >/dev/null 2>&1; then
        ok "registered with the Claude CLI"
    else
        warn "registration failed. Run manually:"
        printf "    ${DIM}claude mcp add cordon --transport stdio -- \\\\\n"
        printf "      %s/bin/python -m cordon.mcp_server \\\\\n" "${VENV_DIR}"
        printf "      --scope %s/scope.yaml${NC}\n" "${CORDON_DIR}"
    fi
else
    warn "no agent CLI found on PATH — run 'cordon connect' for"
    warn "copy-paste registration (Claude Code, Cursor, Windsurf, Gemini CLI,"
    warn "Copilot, or any stdio MCP client)."
    printf "    ${DIM}%s/bin/cordon connect${NC}\n" "${VENV_DIR}"
fi
fi

# --------------------------------------------------------------------------- #
step "Verification"

"${VENV_DIR}/bin/cordon" doctor || true

cat <<EOF

$(printf "${GREEN}Installation complete.${NC}")

Next:
  1. Edit scope.yaml with the program's actual scope, and set fetched_at to
     when you read the policy. Cordon refuses to run without it.
  2. Set OPENROUTER_API_KEY for AI triage and report synthesis (optional —
     recon, scanning, and rule-based detection work without it).
  3. Verify:  cordon scope --scope scope.yaml <a-target-you-own>
  4. In Claude Code, run: /cordon

$(printf "${YELLOW}Only test what you are authorized to test.${NC}")
EOF

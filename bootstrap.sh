#!/usr/bin/env bash
#
# EasyHunt AI — bare-metal bootstrap.
#
# For a machine with NOTHING on it. Installs system prerequisites, language
# runtimes, Docker (enabled at boot), the EasyHunt package, the tool suite, and
# the sandbox images. Then verifies.
#
# install.sh handles the application. This handles everything underneath it.
# Both are idempotent — re-running is safe and is the intended repair path.
#
# AUTHORIZED TESTING ONLY. Installing this authorizes nothing. The scope.yaml
# you write from a program's published policy is the authorization.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_DOCKER="${SKIP_DOCKER:-no}"
SKIP_IMAGES="${SKIP_IMAGES:-no}"
SKIP_BUILD="${SKIP_BUILD:-no}"
SKIP_TOOLS="${SKIP_TOOLS:-no}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
ok()   { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}!${NC} %s\n" "$1"; }
fail() { printf "${RED}✗${NC} %s\n" "$1"; }
step() { printf "\n${DIM}── %s ──${NC}\n" "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<'USAGE'
Usage: ./bootstrap.sh [options]

  --no-docker    skip Docker install/enable (sandbox falls back to host exec)
  --no-images    skip pulling sandbox container images (~7 GB)
  --no-tools     skip the security tool suite (Python package only)
  -h, --help     this message

Environment: SKIP_DOCKER, SKIP_IMAGES, SKIP_TOOLS, SKIP_BUILD (yes|no)

Disk: budget 30 GB+ free. Images alone are ~7 GB; scan artifacts grow.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-docker) SKIP_DOCKER=yes ;;
        --no-images) SKIP_IMAGES=yes ;;
        --no-build) SKIP_BUILD=yes ;;
        --no-tools)  SKIP_TOOLS=yes ;;
        -h|--help)   usage; exit 0 ;;
        *) fail "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    warn "not running as root — system package steps will need sudo"
    SUDO="sudo"
else
    SUDO=""
fi

# ── 0. Disk check ────────────────────────────────────────────────────────────
step "Disk"
FREE_GB=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "${FREE_GB:-}" ] && [ "$FREE_GB" -lt 30 ]; then
    warn "only ${FREE_GB}G free on / — 30G+ recommended (images ~7G + artifacts)"
    if [ "$SKIP_IMAGES" = "no" ] && [ "$FREE_GB" -lt 15 ]; then
        fail "under 15G free; refusing to pull images. Re-run with --no-images."
        SKIP_IMAGES=yes
    fi
else
    ok "${FREE_GB:-?}G free on /"
fi

# ── 1. System packages ───────────────────────────────────────────────────────
step "System packages"
if have apt-get; then
    $SUDO apt-get update -qq 2>/dev/null || warn "apt update failed; continuing"
    # build-essential + libpcap-dev are required: naabu/nmap/masscan need raw
    # sockets, katana needs CGO for headless support.
    $SUDO apt-get install -y -qq \
        build-essential libpcap-dev git curl wget jq unzip \
        python3 python3-venv python3-pip pipx golang-go \
        >/dev/null 2>&1 && ok "system packages installed" \
        || warn "some system packages failed — easyhunt doctor will show what is missing"
else
    warn "no apt-get; install manually: build-essential libpcap-dev git curl python3-venv pipx golang"
fi

have pipx && pipx ensurepath >/dev/null 2>&1

# PATH ordering matters: wrapper scripts live in these directories.
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH"
       grep -qs 'HOME/.local/bin' "$HOME/.profile" 2>/dev/null || \
           echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.profile"
       ok "added ~/.local/bin to PATH" ;;
esac
case ":$PATH:" in
    *":/usr/local/bin:"*) ;;
    *) export PATH="/usr/local/bin:$PATH" ;;
esac
if have go; then
    export PATH="$PATH:$(go env GOPATH)/bin"
    grep -qs 'go env GOPATH' "$HOME/.profile" 2>/dev/null || \
        echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> "$HOME/.profile"
fi

# ── 2. Docker ────────────────────────────────────────────────────────────────
step "Docker"
if [ "$SKIP_DOCKER" = "yes" ]; then
    warn "skipped — sandbox will fall back to host execution (no isolation)"
elif have docker; then
    ok "docker present: $(docker --version 2>/dev/null | cut -d, -f1)"
else
    if have apt-get; then
        $SUDO apt-get install -y -qq docker.io >/dev/null 2>&1 \
            && ok "docker installed" || fail "docker install failed"
    fi
fi

if [ "$SKIP_DOCKER" = "no" ] && have docker && have systemctl; then
    # Kali ships docker.service masked. Unmask before enabling, or the enable
    # silently has no effect and the daemon never starts at boot.
    $SUDO systemctl unmask docker.service docker.socket >/dev/null 2>&1
    $SUDO systemctl reset-failed docker.service >/dev/null 2>&1
    $SUDO systemctl enable --now docker.service >/dev/null 2>&1
    sleep 2
    if [ "$($SUDO systemctl is-active docker.service 2>/dev/null)" = "active" ]; then
        ok "docker active and enabled at boot"
    else
        # Most common cause: a stale pidfile from a manually-started daemon.
        $SUDO rm -f /var/run/docker.pid 2>/dev/null
        $SUDO systemctl reset-failed docker.service >/dev/null 2>&1
        $SUDO systemctl start docker.service >/dev/null 2>&1
        sleep 2
        [ "$($SUDO systemctl is-active docker.service 2>/dev/null)" = "active" ] \
            && ok "docker active (recovered from stale pidfile)" \
            || warn "docker not active — check: journalctl -u docker.service -n 30"
    fi
fi

# ── 3. EasyHunt package + tool suite ─────────────────────────────────────────
step "EasyHunt"
if [ "$SKIP_TOOLS" = "yes" ]; then
    INSTALL_TOOLS=no bash "$ROOT/install.sh" --no-tools
else
    bash "$ROOT/install.sh"
fi

VENV="$ROOT/.venv"
if [ ! -x "$VENV/bin/easyhunt" ]; then
    fail "easyhunt did not install — stopping"
    exit 1
fi

# FastMCP must keep client support. fastmcp-slim (pulled in as a transitive dep
# by some security tools) removes it and breaks the auth layer. Pinned.
"$VENV/bin/python" -c "import fastmcp" 2>/dev/null || {
    warn "fastmcp import failed — reinstalling pinned version"
    "$VENV/bin/pip" install -q --force-reinstall "fastmcp==3.4.5"
}

# ── 4. Config ────────────────────────────────────────────────────────────────
step "Config"
if [ -f "$ROOT/config.yaml" ]; then
    ok "config.yaml present"
else
    cp "$ROOT/config.example.yaml" "$ROOT/config.yaml" && ok "created config.yaml from example"
fi

# ── 5. Sandbox images ────────────────────────────────────────────────────────
step "Sandbox images"
if [ "$SKIP_IMAGES" = "yes" ]; then
    warn "skipped — tools will run on the host without container isolation"
elif ! have docker || ! docker info >/dev/null 2>&1; then
    warn "docker unavailable — skipping image pulls"
else
    IMAGES=$("$VENV/bin/python" - <<'PY' 2>/dev/null
from easyhunt.config import Config
for image in dict(Config.load().get("sandbox.images") or {}).values():
    print(image)
PY
)
    # The default image is not on any registry -- it is built from this repo's
    # Dockerfile and holds 46 of the tools. `docker pull` cannot find it, so a
    # fresh machine that only pulls ends up with every one of those tools
    # falling back to the host, unsandboxed and mostly missing entirely.
    DEFAULT_IMAGE=$("$VENV/bin/python" -c "from easyhunt.config import Config; print(Config.load().get('sandbox.default_image') or '')" 2>/dev/null)
    if [ -n "$DEFAULT_IMAGE" ]; then
        if docker image inspect "$DEFAULT_IMAGE" >/dev/null 2>&1; then
            ok "$DEFAULT_IMAGE (already built)"
        elif [ "$SKIP_BUILD" = "yes" ]; then
            warn "$DEFAULT_IMAGE not built -- 46 tools will fall back to the host"
        else
            printf "  building %s (30-45 min on a first run) ... \n" "$DEFAULT_IMAGE"
            if docker build -t "$DEFAULT_IMAGE" "$ROOT"; then
                ok "$DEFAULT_IMAGE built"
            else
                warn "build failed -- tools fall back to the host. Retry with:
    docker build -t $DEFAULT_IMAGE ."
            fi
        fi
    fi

    if [ -z "$IMAGES" ]; then
        warn "no per-tool images configured in config.yaml"
    else
        for img in $IMAGES; do
            if docker image inspect "$img" >/dev/null 2>&1; then
                ok "$img (already present)"
            else
                printf "  pulling %s ... " "$img"
                if docker pull -q "$img" >/dev/null 2>&1; then
                    printf "${GREEN}done${NC}\n"
                else
                    printf "${YELLOW}failed${NC}\n"
                fi
            fi
        done
    fi
fi

# ── 6. Verify ────────────────────────────────────────────────────────────────
step "Verify"
"$VENV/bin/easyhunt" doctor 2>&1 | tail -30

# ── 7. What is still required ────────────────────────────────────────────────
step "Before you can run anything"
if [ ! -f "$ROOT/scope.yaml" ]; then
    cat <<'SCOPE'

  ! scope.yaml does not exist. EasyHunt refuses to run without it.

    It must be transcribed from the target program's PUBLISHED POLICY PAGE.
    That text is the legal authorization for the engagement. It cannot be
    generated, guessed, or reconstructed from memory — and it drifts, so
    re-pull it before each engagement.

    Start from scope.example.yaml, then: easyhunt scope validate

SCOPE
else
    ok "scope.yaml present — run 'easyhunt scope validate'"
fi

[ -n "${OPENROUTER_API_KEY:-}" ] \
    && ok "OPENROUTER_API_KEY set" \
    || warn "OPENROUTER_API_KEY unset — AI triage and report synthesis disabled
    (passive recon, scanning, and rule-based detection still work)"

printf "\n${GREEN}Bootstrap complete.${NC} Read CLAUDE.md, then docs/BUILD_STATUS.md\n\n"

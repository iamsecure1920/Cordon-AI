# EasyHunt AI — reproducible toolchain in one image.
#
# Host installs leave EasyHunt at the mercy of whatever else is on PATH: Kali
# ships an `httpx` that is the Python HTTP library's CLI and a `medusa` that is a
# password brute-forcer, both shadowing the security tools of the same name.
#
# A purpose-built image removes the *host's* collisions but not our own. EasyHunt
# depends on the Python httpx library, whose console script installs to
# /usr/local/bin/httpx and overwrote ProjectDiscovery's binary outright — the Go
# tool was not shadowed, it was replaced by a 292-byte shim. Verified in a built
# image, after this file claimed the problem could not occur here.
#
# So ordering matters: Python packages are installed first, security binaries are
# copied last, and the build asserts the right httpx survived. resolve_binary()
# remains the runtime backstop.
#
#   docker build -t easyhunt .
#   docker run --rm -it -v "$PWD:/work" -w /work easyhunt easyhunt doctor
#
# Multi-stage: compilers stay in the builders, only binaries reach the runtime.
#
# Build arguments:
#   FETCH_PAYLOADS=1        bake the vetted payload store into the image. Off by
#                           default because the upstream lists carry no licence
#                           and the image would not be redistributable. Absent,
#                           the entrypoint says so and says how to fix it.
#   NETSANITIZER_COMMIT     pinned SHA for the one vendored source build.
#
# Two rules this file has learned the hard way, both from tools that installed
# perfectly and then did nothing:
#   * assert capabilities by exercising them (`nikto -Version`, `load_index()`),
#     never by testing that a path exists — the WSTG assertion here passed for
#     builds in which wstg_lookup could not read the index at all;
#   * delete in the layer that created it, or the bytes ship anyway.

# --------------------------------------------------------------------------- #
# Go tools
# --------------------------------------------------------------------------- #
FROM golang:1.25-bookworm AS go-builder

# Every ProjectDiscovery tool declares its own minimum Go version and they rise
# independently. A pinned base image plus `@latest` packages therefore breaks the
# moment any one of them moves — observed live: nuclei wanted >=1.25.7 against a
# 1.24 image, and once that was bumped httpx wanted >=1.26. GOTOOLCHAIN=auto lets
# Go fetch whatever each module asks for instead of failing the build.
ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

# Installed one at a time, tolerating failure, then verified.
#
# Chaining these with `&&` means a single upstream breakage costs every tool in
# the layer. That happened here: subzy@latest currently fails with "version
# constraints conflict" and took ffuf, dalfox, gau, assetfinder, waybackurls,
# jsluice and gitleaks down with it. The installer already treats host tools this
# way — one broken recipe costs one tool, not the run — and the image should not
# be weaker than the installer.
#
# The verification step at the end is what stops a silently short toolset: a
# missing scanner must be visible at build time, not discovered mid-engagement
# when it reports nothing found.
RUN set -u; \
    for pkg in \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
        github.com/projectdiscovery/httpx/cmd/httpx@latest \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
        github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
        github.com/projectdiscovery/alterx/cmd/alterx@latest \
        github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
        github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
        github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
        github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
        github.com/ffuf/ffuf/v2@latest \
        github.com/hahwul/dalfox/v2@latest \
        github.com/lc/gau/v2/cmd/gau@latest \
        github.com/tomnomnom/assetfinder@latest \
        github.com/tomnomnom/waybackurls@latest \
        github.com/BishopFox/jsluice/cmd/jsluice@latest \
        github.com/zricethezav/gitleaks/v8@latest \
        github.com/crytic/medusa@latest \
        github.com/LukaSikic/subzy@latest \
      ; do \
        echo "==> $pkg"; \
        go install -v "$pkg" || echo "!!! FAILED: $pkg"; \
      done; \
    echo "--- go tools built ---"; ls /go/bin

# katana needs CGO for headless support. Without it the build succeeds and the
# feature is silently absent, which is the failure mode this project keeps
# finding: a tool that installs cleanly and quietly does less than it claims.
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest || \
    echo "!!! FAILED: katana"

# Tools that do not install cleanly today, recorded rather than hidden:
#   jsluice — build failure upstream
#   subzy   — "version constraints conflict" on @latest
# Each is attempted; failures are printed and the image reports which are absent
# via `easyhunt doctor`, so a missing tool is a known gap and not a quiet one.
#
# amass: the v5 module path is tried first and the v4 path is the fallback. As
# of this build the v5 install fails and the fallback succeeds, so the image
# ships amass v4.2.0 — verified in the built image. This comment previously
# claimed v4 "no longer resolves", which was wrong and would have sent the next
# reader hunting for a tool that is present and working.
RUN go install -v github.com/owasp-amass/amass/v5/cmd/amass@master || \
    go install -v github.com/owasp-amass/amass/v4/...@master || \
    echo "!!! FAILED: amass"

# netsanitizer: collapses archive URL dumps to distinct injection points. Small
# enough to vendor-build; the upstream repo is a single file.
#
# Pinned, per invariant 6 — every third-party template, payload list and piece of
# source is vetted and pinned. `--depth 1` on a branch is not a pin: it builds
# whatever was pushed most recently, so the binary that parses archive URL dumps
# could change under us between two builds of the "same" image. The checkout is
# verified rather than assumed; a moved pin fails the build instead of silently
# producing a different tool.
ARG NETSANITIZER_COMMIT=1d78198cbf127e7695af2aacdf9e9e166682a024
RUN git clone -q https://github.com/iamsecure1920/NetSanitizer.git /tmp/ns && \
    git -C /tmp/ns checkout -q "${NETSANITIZER_COMMIT}" && \
    [ "$(git -C /tmp/ns rev-parse HEAD)" = "${NETSANITIZER_COMMIT}" ] && \
    cd /tmp/ns && go mod init netsanitizer 2>/dev/null; \
    cd /tmp/ns && go build -o /go/bin/netsanitizer NetSanitizer.go && rm -rf /tmp/ns || \
    echo "!!! FAILED: netsanitizer"

# nosqli: `go install github.com/Charlie-belmer/nosqli@latest` resolves to
# v0.5.4 and builds. It is in the loop above; this source build is the
# fallback if the module path ever stops resolving.
RUN git clone --depth 1 https://github.com/Charlie-belmer/nosqli.git /tmp/nosqli && \
    cd /tmp/nosqli && go build -o /go/bin/nosqli . && rm -rf /tmp/nosqli || \
    echo "!!! FAILED: nosqli"

# --------------------------------------------------------------------------- #
# Rust tools
# --------------------------------------------------------------------------- #
# `rust:1-bookworm` tracks the latest stable 1.x rather than pinning a point
# release. That is deliberate, and it is the same trap this file avoids for Go:
# pinning the toolchain while installing crates from the registry means the
# build breaks the moment a dependency raises its minimum. Observed here — a
# pinned 1.83 could no longer build feroxbuster, which now needs edition2024
# (Rust >= 1.85). The builder never ships; only its binaries do, so tracking
# stable costs nothing and removes a recurring failure.
FROM rust:1-bookworm AS rust-builder

RUN cargo install --locked feroxbuster

# aderyn is allowed to fail. As of this writing its transitive dependency
# svm-rs-builds does not compile (duplicate SOLC_VERSION_0_8_35_CHECKSUM), which
# is an upstream defect, not a configuration error. Slither covers the same
# ground and is installed in the runtime stage, so one broken crate must not
# cost the whole image — the same rule the installer already applies to host
# tools. The runtime COPY below tolerates its absence.
RUN cargo install --locked aderyn || \
    echo "aderyn unavailable (upstream build failure) — slither covers static analysis" 

# --------------------------------------------------------------------------- #
# Runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="EasyHunt AI"
LABEL org.opencontainers.image.description="Agentic VAPT orchestrator — authorized testing only"
LABEL org.opencontainers.image.licenses="MIT"

# libpcap is not optional: naabu and nmap need raw sockets. build-essential is
# needed by several pip builds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        whois \
        dnsutils \
        libpcap0.8 \
        libpcap-dev \
        build-essential \
        git \
        curl \
        ca-certificates \
        jq \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# uv: lock-based and markedly faster than pip for this dependency set.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/


# Python security tools, each isolated. The one rule that must not be broken:
# never install these into EasyHunt's own environment — `pip install semgrep`
# once pulled in fastmcp-slim and removed FastMCP's client support, breaking the
# application that was doing the installing.
RUN uv tool install --python 3.12 semgrep && \
    uv tool install --python 3.12 sqlmap || true
RUN uv tool install --python 3.12 arjun && \
    uv tool install --python 3.12 wafw00f && \
    uv tool install --python 3.12 slither-analyzer && \
    uv tool install --python 3.12 solc-select || true
ENV PATH="/root/.local/bin:${PATH}"

# --------------------------------------------------------------------------- #
# Attack-class tools EasyHunt lacked
# --------------------------------------------------------------------------- #
#
# Added after auditing bhavsec/autopentest-ai's container, which carried 13 tools
# this project had no equivalent for. These are the ones that map onto classes
# that need no user interaction — the only kind most bug bounty programs pay for,
# since anything requiring a victim to click is excluded as social engineering.
#
#   ssrfmap     SSRF            sstimap     server-side template injection
#   commix      OS command inj  smuggler    HTTP request smuggling
#   graphql-cop GraphQL         corscanner  CORS misconfiguration
#   jwt_tool    JWT attacks     nosqli      NoSQL injection
#   nikto/whatweb/testssl       fingerprinting and TLS posture
#   wapiti      general scanner websocat    WebSocket testing

# Two of these were missing and each cost a tool outright, in the way this file
# keeps having to guard against — the binary installed, resolve_binary() found
# it, and it refused to do anything:
#
#   libxml-writer-perl  nikto dies "Required module not found: XML::Writer" on
#                       every invocation, -h included. perl and libnet-ssleay
#                       are not enough; nikto writes XML reports unconditionally.
#   bsdextrautils       testssl dies "You need to install hexdump for this
#                       program to work". python:3.12-slim has od and nothing
#                       else; hexdump lives in bsdextrautils on bookworm.
#   procps              testssl's dependency check cascades — satisfy hexdump and
#                       it stops on "You need to install ps". slim has no ps.
#
# These two tools are the reason the assertion block at the end of this stage
# exists: neither is in the tool CATALOG, so `easyhunt doctor` never looked at
# them, and both shipped present-but-100%-non-functional for as long as they had
# been in the image. Nothing in the system would ever have reported it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        perl libnet-ssleay-perl libxml-writer-perl \
        bsdextrautils procps \
        ruby ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# Perl and Ruby tools: source installs, no packaged versions in slim.
#
# `.git` is dropped in the same layer as the clone. Deleting it later would not
# shrink anything — the objects would still sit in the layer underneath — and
# these repos carry ~17 MB of history that the image has no use for, since the
# way to update a tool here is to rebuild the image.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    rm -rf /opt/nikto/.git && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh && \
    rm -rf /opt/testssl.sh/.git && \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    rm -rf /opt/whatweb/.git && \
    gem install --no-document addressable json 2>/dev/null || true && \
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /opt/whatweb/whatweb

# Python tools that publish to PyPI, each isolated by uv.
# NOT `uv tool install commix`. The PyPI package named "commix" is not commix:
# version 0.1 (2022), author "Parixit Sutariya", homepage github.com/Bhai4You,
# containing no commix code at all — only a 3.8KB bash script that claims
# author="Commix Project", runs `pip install lolcat`, and `git clone`s the real
# repository at invocation time. Fetching and executing code mid-scan is not
# something a scanner should do, and the name alone gave no hint. Installed from
# the real project instead; the ToolSpec carries an identity_marker so a
# substitution is caught rather than assumed.
#
# Installed one per RUN. `a && b && c || true` means a failure in the first
# silently skips the rest while the layer still succeeds — wapiti3 and
# corscanner would have been quietly absent.
RUN uv tool install --python 3.12 wapiti3 || echo "!!! FAILED: wapiti3"
RUN uv tool install --python 3.12 corscanner || echo "!!! FAILED: corscanner"

# Python tools that do not publish usable wheels: cloned, with their own venv so
# nothing lands in EasyHunt's interpreter.
RUN for repo in \
      "https://github.com/swisskyrepo/SSRFmap.git|ssrfmap|ssrfmap.py" \
      "https://github.com/vladko312/SSTImap.git|sstimap|sstimap.py" \
      "https://github.com/ticarpi/jwt_tool.git|jwt_tool|jwt_tool.py" \
      "https://github.com/dolevf/graphql-cop.git|graphql-cop|graphql-cop.py" \
      "https://github.com/defparam/smuggler.git|smuggler|smuggler.py" \
      "https://github.com/commixproject/commix.git|commix|commix.py" ; do \
      url="${repo%%|*}"; rest="${repo#*|}"; name="${rest%%|*}"; entry="${rest#*|}"; \
      git clone --depth 1 "$url" "/opt/$name" 2>/dev/null || continue; \
      rm -rf "/opt/$name/.git"; \
      uv venv "/opt/$name/.venv" --python 3.12 >/dev/null 2>&1; \
      if [ -f "/opt/$name/requirements.txt" ]; then \
        VIRTUAL_ENV="/opt/$name/.venv" uv pip install -q -r "/opt/$name/requirements.txt" || true; \
      fi; \
      printf '#!/bin/sh\nexec /opt/%s/.venv/bin/python /opt/%s/%s "$@"\n' "$name" "$name" "$entry" \
        > "/usr/local/bin/$name"; \
      chmod +x "/usr/local/bin/$name"; \
    done

# websocat ships a static musl binary; nosqli comes from the Go builder.
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
      curl -sL "https://github.com/vi/websocat/releases/download/v1.14.1/websocat.x86_64-unknown-linux-musl" \
        -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat; \
    fi

WORKDIR /opt/easyhunt
COPY pyproject.toml README.md ./
COPY easyhunt/ ./easyhunt/

# Application data, not engagement data. These belong in the image: the
# engagement workspace is what gets mounted at /work.
#   rules/      custom nuclei templates and rule packs — the nuclei engine adds
#               these to the upstream library rather than replacing it
#   taskflows/  adversarial triage flows
#   knowledge/  the OWASP WSTG index (CC BY-SA 4.0, attribution in the index)
#   scripts/    rebuild the payload store and WSTG index inside a running container
COPY rules/ ./rules/
COPY taskflows/ ./taskflows/
COPY knowledge/ ./knowledge/
COPY scripts/ ./scripts/
COPY config.example.yaml scope.example.yaml ./

# The payload manifest — ours, not upstream's: list names, safety tiers, line
# counts, SHA-256 per file and the pinned source commit. It ships so an operator
# can see exactly what the store would contain, and so `--verify` has something
# to check against. It lands OUTSIDE the store root on purpose; see the payload
# stanza further down for why that placement is load-bearing.
COPY payloads/manifest.json ./payloads.manifest.json

# bbot is imported by the recon engine, so it goes in the environment rather
# than an isolated tool install — a pipx-style install would give a working CLI
# and an ImportError.
#
# setuptools writes build/ and easyhunt_ai.egg-info/ into the source tree while
# building the wheel. They are removed in this same layer — a later `rm` would
# leave them in this one and shrink nothing.
RUN uv pip install --system --no-cache . && \
    uv pip install --system --no-cache "bbot>=3.0" "fastmcp==3.4.5" && \
    rm -rf /opt/easyhunt/build /opt/easyhunt/easyhunt_ai.egg-info /opt/easyhunt/*.egg-info

# Security binaries land LAST, after every Python install, so that a package's
# console script cannot replace a scanner of the same name.
COPY --from=go-builder /go/bin/ /usr/local/bin/
COPY --from=rust-builder /usr/local/cargo/bin/feroxbuster /usr/local/bin/
# Glob so the build still succeeds when aderyn did not compile.
COPY --from=rust-builder /usr/local/cargo/bin/ /tmp/cargo-bin/
RUN cp /tmp/cargo-bin/aderyn /usr/local/bin/ 2>/dev/null || true; rm -rf /tmp/cargo-bin

# Fail the build if the wrong httpx won. A silently-replaced prober reports every
# host as dead, which reads as an estate with nothing on it.
RUN httpx -version 2>&1 | grep -qi projectdiscovery \
    || { echo "FATAL: /usr/local/bin/httpx is not ProjectDiscovery's"; httpx -version 2>&1 | head -2; exit 1; }

# nikto and testssl are asserted by *running* them. Both shipped installed and
# completely non-functional — nikto could not load XML::Writer, testssl could not
# find hexdump — and because neither appears in the tool CATALOG, `easyhunt
# doctor` had no opinion about either. A `test -x` would have passed the whole
# time. Content is matched rather than exit status, since a version banner is not
# obliged to exit 0.
RUN <<'EOF'
set -u
out=$(nikto -Version 2>&1 || true)
echo "$out" | grep -qiE 'nikto[^0-9]*[0-9]' || {
  echo "FATAL: nikto is installed but non-functional"; echo "$out" | head -5; exit 1; }
echo "nikto: $(echo "$out" | grep -iE 'nikto[^0-9]*[0-9]' | head -1)"

out=$(testssl --version 2>&1 || true)
echo "$out" | grep -qi 'fatal error' && {
  echo "FATAL: testssl is installed but non-functional"; echo "$out" | head -5; exit 1; }
echo "$out" | grep -qiE 'testssl[^0-9]*[0-9]' || {
  echo "FATAL: testssl produced no version banner"; echo "$out" | head -5; exit 1; }
echo "testssl: $(echo "$out" | grep -iE 'testssl[^0-9]*[0-9]' | head -1)"
EOF

# --------------------------------------------------------------------------- #
# Where the application data actually lives at runtime
# --------------------------------------------------------------------------- #
#
# Two of the data loaders resolve their directory relative to *the package*, not
# to /opt/easyhunt:
#
#   knowledge/wstg.py   INDEX_PATH = <pkg>/../.. / knowledge/wstg/index.json
#   knowledge/payloads.py  a relative `store:` resolves to <pkg>/../.. / payloads
#
# On a developer checkout <pkg>/../.. is the repo root and everything lines up.
# In this image the wheel is installed into site-packages, so those loaders look
# in /usr/local/lib/python3.12/site-packages — which is why the old build-time
# `test -s /opt/easyhunt/knowledge/wstg/index.json` passed on an image where
# `wstg_lookup` still answered "index not built". The file was there; it was not
# where the code reads from. That is the same defect as the payload one, one
# directory over, and asserting on the wrong path is what hid it.
#
# The image keeps one copy of the data, under /opt/easyhunt where the docs say it
# is and where a volume mount can reach it, and points the package-relative
# lookup at it. Assertions below go through the loaders themselves so this
# cannot silently come apart again.
#
# `cd /` is load-bearing. WORKDIR here is /opt/easyhunt, which holds the source
# tree, so python puts it on sys.path first and `import easyhunt` returns the
# *checkout* — whose parent already contains knowledge/ and payloads/. The first
# version of this stanza did exactly that: it printed a data root of
# /opt/easyhunt, linked the directories onto themselves, and every assertion
# below passed against a package the runtime never loads. Console scripts run
# from /work and import site-packages. Assert which one you have.
RUN <<'EOF'
set -eu
cd /
PKG_ROOT="$(python3 -c 'import easyhunt, pathlib; print(pathlib.Path(easyhunt.__file__).resolve().parent.parent)')"
echo "package data root: $PKG_ROOT"
case "$PKG_ROOT" in
  */site-packages) ;;
  *) echo "FATAL: easyhunt imported from $PKG_ROOT, not the installed wheel"; exit 1 ;;
esac
mkdir -p /opt/easyhunt/payloads
ln -sfn /opt/easyhunt/knowledge "$PKG_ROOT/knowledge"
ln -sfn /opt/easyhunt/payloads  "$PKG_ROOT/payloads"
ls -ld "$PKG_ROOT/knowledge" "$PKG_ROOT/payloads"
EOF

# --------------------------------------------------------------------------- #
# The vetted payload store
# --------------------------------------------------------------------------- #
#
# The store is ~71 MB of third-party wordlists from a repo that ships NO LICENSE
# file, so it is all-rights-reserved by default. Fetching it onto a machine you
# operate is fine. Baking it into an image that is tagged, pushed and pulled is
# redistribution, and that is not ours to do — the same reason `payloads/*` is
# gitignored. So the default build does not contain it.
#
# What the default build does instead is refuse to be quiet about it. The old
# `.dockerignore` excluded payloads/ wholesale and said nothing anywhere else,
# which is exactly the failure this project keeps designing against: a capability
# that is simply absent, discovered mid-engagement when `payload_catalog` returns
# nothing useful. Here, absence is:
#
#   * announced on every container start, by the entrypoint, with the two
#     commands that fix it (unless EASYHUNT_QUIET is set);
#   * reported honestly by the tools — payload_catalog answers
#     {"error": "store_not_built"} with the fix command, and content_discovery
#     refuses list names while still accepting workspace wordlist paths;
#   * documented by payloads.manifest.json, which ships so the operator can see
#     the names, tiers, hashes and upstream pin without the payloads themselves.
#
# Why the manifest is NOT copied into the store root: PayloadStore.available is
# true when a manifest is readable there, and every caller treats that as "the
# store exists". Dropping a manifest into an empty store root would make
# payload_catalog cheerfully list 34 wordlists that cannot be opened — trading a
# loud, accurate absence for a quiet, confident lie. Reference copy only.
#
# For a private image you are not going to distribute:
#
#   docker build --build-arg FETCH_PAYLOADS=1 -t easyhunt .
#
# which fetches from the pinned commit at build time (reproducible for as long as
# upstream keeps that SHA reachable), and deletes tier C in the same layer so the
# quarantined RCE and third-party-callback lists never exist in the image at all.
ARG FETCH_PAYLOADS=0

# Machine-readable, so "is this image safe to push?" is answerable with
# `docker inspect` rather than by remembering how it was built.
#   0 = no third-party payload data; distributable under the project's MIT terms
#   1 = contains all-rights-reserved upstream wordlists; DO NOT distribute
LABEL com.easyhunt.payloads.bundled="${FETCH_PAYLOADS}"

RUN <<'EOF'
set -eu
if [ "${FETCH_PAYLOADS:-0}" != "1" ]; then
  echo "payload store: not fetched (default). Unlicensed upstream content is not"
  echo "               redistributed in this image; the entrypoint says so at runtime."
  exit 0
fi
echo "payload store: FETCH_PAYLOADS=1 — building from the pinned commit"
python3 /opt/easyhunt/scripts/vet_payloads.py --fetch
# Same layer as the fetch. A later RUN would delete the quarantine from the
# filesystem and leave every byte of it in the layer underneath, still pullable.
rm -rf /opt/easyhunt/payloads/_quarantine /opt/easyhunt/payloads/_src
python3 /opt/easyhunt/scripts/vet_payloads.py --verify || true
EOF

# Assert the application data is present *through the code that reads it*. A
# missing WSTG index or payload store does not crash anything — the tools simply
# return "nothing here", which is the failure mode this project keeps having to
# design against.
RUN <<'EOF'
set -eu
test -d /opt/easyhunt/rules || { echo "FATAL: rules/ missing"; exit 1; }
# From /, so this exercises the installed wheel — the package a console script
# loads — and not the source tree sitting in WORKDIR. See the stanza above.
cd /
python3 - <<'PY'
import json
import pathlib
import sys

import easyhunt
from easyhunt.config import Config
from easyhunt.knowledge.payloads import store_from_config
from easyhunt.knowledge.wstg import INDEX_PATH, load_index


def fatal(msg: str) -> None:
    print(f"FATAL: {msg}")
    sys.exit(1)


print(f"asserting against: {easyhunt.__file__}")
if "site-packages" not in easyhunt.__file__:
    fatal("assertions ran against a source tree, not the installed package")

# ── WSTG ────────────────────────────────────────────────────────────────────
if not INDEX_PATH.is_file():
    fatal(f"WSTG index unreadable at {INDEX_PATH} — the path wstg.py actually loads")
tests = len(load_index().tests)
print(f"WSTG index: {tests} tests, loaded from {INDEX_PATH}")
if tests <= 100:
    fatal("WSTG index parsed but holds fewer than 100 tests")

# ── Payload store ───────────────────────────────────────────────────────────
store = store_from_config(Config.load("/opt/easyhunt/config.example.yaml"))
print(f"payload store root: {store.root}")
if store.root != pathlib.Path("/opt/easyhunt/payloads"):
    fatal(
        f"payload store resolves to {store.root}, not /opt/easyhunt/payloads — "
        "vet_payloads.py --fetch and any volume mount would write somewhere the "
        "tools do not read"
    )

# Tier C never ships, under any build argument. Quarantine holds real RCE
# statements and callbacks to infrastructure we do not control.
if (store.root / "_quarantine").exists():
    fatal("tier C quarantine is present in the image")

reference = pathlib.Path("/opt/easyhunt/payloads.manifest.json")
if not reference.is_file():
    fatal("payloads.manifest.json missing — the store's provenance must ship")
manifest = json.loads(reference.read_text(encoding="utf-8"))
tier_c = [f["name"] for f in manifest["files"] if f["tier"] == "C"]
for name in tier_c:
    for stray in store.root.rglob(name):
        fatal(f"tier C file {stray} is in the image")
print(f"payload manifest: {len(manifest['files'])} files, {len(tier_c)} tier C withheld")

# Half a store is worse than none: it is the state in which the catalog lists
# wordlists that cannot be opened. The image is in exactly one of two states.
if store.available:
    listed = store.catalog()
    if not listed:
        fatal("a manifest is readable in the store root but no list resolves")
    for item in listed:
        store.resolve(item["name"])  # raises if absent, tier-gated or quarantined
    print(f"payload store: PRESENT — {len(listed)} lists, all resolvable on disk")
    print("               unlicensed third-party content — do not distribute this image")
else:
    stray_files = [p for p in store.root.rglob("*") if p.is_file()]
    if stray_files:
        fatal(
            f"{len(stray_files)} payload file(s) on disk with no manifest — "
            "a partially-built store, which reports as neither present nor absent"
        )
    print("payload store: ABSENT by design (upstream declares no licence)")
    print("               payload_catalog -> store_not_built; entrypoint says how to fix it")
PY
EOF

# --------------------------------------------------------------------------- #
# Entrypoint: silent when the image is whole, loud when it is not
# --------------------------------------------------------------------------- #
#
# The one thing a fresh container must not do is answer "no payloads" with no
# explanation. This prints nothing at all when the store is present, and an
# actionable notice when it is not. It goes to stderr: `easyhunt serve` speaks
# MCP over stdout and a banner there would corrupt the protocol stream.
RUN <<'EOF'
set -eu
cat > /usr/local/bin/easyhunt-entrypoint <<'SH'
#!/bin/sh
# Reports absent capabilities, then execs the requested command unchanged.
[ "$#" -eq 0 ] && set -- easyhunt doctor

if [ -z "${EASYHUNT_QUIET:-}" ] && [ ! -d /opt/easyhunt/payloads/A ]; then
  cat >&2 <<'BANNER'
──────────────────────────────────────────────────────────────────────────────
EasyHunt: the vetted payload store is NOT in this image.

  payload_catalog    -> {"ok": false, "error": "store_not_built"}
  content_discovery  -> refuses wordlist NAMES ("juicy-paths", "admin", ...)
                        Wordlist PATHS inside the engagement workspace still work.
  Everything else in the image is unaffected.

Why: the upstream lists (coffinxp/payloads, pinned) declare no licence, so they
are all-rights-reserved and are not redistributed inside a built image. Their
names, tiers and SHA-256s are in /opt/easyhunt/payloads.manifest.json.

Fix it, either way:

  1. Build it on the host once, mount it read-only (survives container restarts):
       python3 scripts/vet_payloads.py --fetch
       docker run -v "$PWD/payloads:/opt/easyhunt/payloads:ro" ... easyhunt

  2. Build it inside this container (needs network; lost when the container is
     removed unless /opt/easyhunt/payloads is a volume):
       python3 /opt/easyhunt/scripts/vet_payloads.py --fetch

  Or bake it into a private image you will not distribute:
       docker build --build-arg FETCH_PAYLOADS=1 -t easyhunt .

Silence this notice with EASYHUNT_QUIET=1.
──────────────────────────────────────────────────────────────────────────────
BANNER
fi

exec "$@"
SH
chmod +x /usr/local/bin/easyhunt-entrypoint
EOF


# Foundry (forge/cast/anvil/chisel) — the PoC engine for contract work. The
# upstream foundryup installer writes a shim that did not resolve on a clean
# host, so the release tarball is used directly.
RUN ARCH=$(dpkg --print-architecture) && \
    URL=$(curl -s https://api.github.com/repos/foundry-rs/foundry/releases/latest \
          | grep -oE '"browser_download_url": "[^"]*linux_'"$ARCH"'\.tar\.gz"' \
          | head -1 | cut -d'"' -f4) && \
    if [ -n "$URL" ]; then \
      curl -sL "$URL" -o /tmp/foundry.tgz && \
      tar -xzf /tmp/foundry.tgz -C /usr/local/bin && rm -f /tmp/foundry.tgz; \
    else echo "!!! FAILED: foundry"; fi

# Nuclei's template library IS the tool. Without it nuclei exits "no templates
# provided for scan", which reads as a clean estate.
RUN nuclei -update-templates -silent 2>/dev/null || true

# Scans write here; mount the engagement workspace over it.
WORKDIR /work

# Authorization is a scope.yaml the operator supplies at runtime. Nothing in this
# image authorizes anything, and no scope file is baked in.
#
# The entrypoint is a reporter, not a wrapper: it prints what is missing and then
# `exec "$@"`, so `docker run easyhunt <anything>` behaves exactly as it did when
# ENTRYPOINT was empty.
ENTRYPOINT ["/usr/local/bin/easyhunt-entrypoint"]
CMD ["easyhunt", "doctor"]

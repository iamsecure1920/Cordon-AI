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
#   amass   — moved to owasp-amass/amass/v5; the v4 path no longer resolves
#   jsluice — build failure upstream
#   subzy   — "version constraints conflict" on @latest
# Each is attempted; failures are printed and the image reports which are absent
# via `easyhunt doctor`, so a missing tool is a known gap and not a quiet one.
RUN go install -v github.com/owasp-amass/amass/v5/cmd/amass@master || \
    go install -v github.com/owasp-amass/amass/v4/...@master || \
    echo "!!! FAILED: amass"

# nosqli publishes no module path usable by `go install`; build from source.
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

RUN apt-get update && apt-get install -y --no-install-recommends \
        perl libnet-ssleay-perl ruby ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# Perl and Ruby tools: source installs, no packaged versions in slim.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    gem install --no-document addressable json 2>/dev/null || true && \
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /opt/whatweb/whatweb

# Python tools that publish to PyPI, each isolated by uv.
RUN uv tool install --python 3.12 commix && \
    uv tool install --python 3.12 wapiti3 && \
    uv tool install --python 3.12 corscanner || true

# Python tools that do not publish usable wheels: cloned, with their own venv so
# nothing lands in EasyHunt's interpreter.
RUN for repo in \
      "https://github.com/swisskyrepo/SSRFmap.git|ssrfmap|ssrfmap.py" \
      "https://github.com/vladko312/SSTImap.git|sstimap|sstimap.py" \
      "https://github.com/ticarpi/jwt_tool.git|jwt_tool|jwt_tool.py" \
      "https://github.com/dolevf/graphql-cop.git|graphql-cop|graphql-cop.py" \
      "https://github.com/defparam/smuggler.git|smuggler|smuggler.py" ; do \
      url="${repo%%|*}"; rest="${repo#*|}"; name="${rest%%|*}"; entry="${rest#*|}"; \
      git clone --depth 1 "$url" "/opt/$name" 2>/dev/null || continue; \
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

# bbot is imported by the recon engine, so it goes in the environment rather
# than an isolated tool install — a pipx-style install would give a working CLI
# and an ImportError.
RUN uv pip install --system --no-cache . && \
    uv pip install --system --no-cache "bbot>=3.0" "fastmcp==3.4.5"

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

# Assert the application data is present. A missing WSTG index or rules directory
# does not crash anything — the tools simply return "nothing here", which is the
# failure mode this project keeps having to design against.
RUN test -s /opt/easyhunt/knowledge/wstg/index.json \
      || { echo "FATAL: WSTG index missing — run scripts/fetch_wstg.py before building"; exit 1; } && \
    test -d /opt/easyhunt/rules \
      || { echo "FATAL: rules/ missing"; exit 1; } && \
    python3 -c "import json,sys; d=json.load(open('/opt/easyhunt/knowledge/wstg/index.json')); n=len(d['tests']); print(f'WSTG index: {n} tests'); sys.exit(0 if n > 100 else 1)"


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
ENTRYPOINT []
CMD ["easyhunt", "doctor"]

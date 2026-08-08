"""Install recipes — how each catalogued tool is actually obtained.

Derived from ``tools.md``, but expressed as data the installer can execute,
verify, and repair rather than as commands a human copies. The difference
matters: a shell script that runs 55 installs tells you nothing useful when
number 31 fails, whereas this can report *which* tool failed, why, what depends
on it, and what to try instead.

Four things here are not obvious from a list of install commands, and each one
breaks an installation that otherwise looks fine:

* **Ordering.** ``shuffledns`` is useless without the ``massdns`` *binary*, and
  ``naabu`` will not build without ``libpcap`` headers. System dependencies are
  declared, not assumed, so they install first.
* **Build environment.** ``katana`` needs ``CGO_ENABLED=1``. Without it the
  install succeeds and the binary lacks headless support.
* **Privileges.** ``apt`` needs root; ``go install`` must not have it, or the
  binary lands in root's GOPATH and vanishes for the real user.
* **Caveats that outlive the install.** Archived repositories, AGPL licensing,
  raw-socket requirements, and Python version ceilings are recorded so they can
  be surfaced at the point they matter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = ["RECIPES", "Recipe", "SYSTEM_PACKAGES", "recipes_for", "install_order"]

Method = Literal[
    "go", "pip", "pipx", "npm", "cargo", "apt", "script", "git", "release", "manual"
]


@dataclass(frozen=True)
class Recipe:
    """How to install one tool, and what to know about it afterwards."""

    tool: str
    method: Method
    #: Go module path, pip name, apt package, or script URL.
    package: str
    category: str = "misc"
    #: apt packages that must exist before this will build or run.
    system_deps: tuple[str, ...] = ()
    #: Other catalogued tools that must be installed first.
    tool_deps: tuple[str, ...] = ()
    #: Build-time environment, e.g. CGO_ENABLED for katana.
    env: dict[str, str] = field(default_factory=dict)
    #: Clone destination for git-based tools.
    clone_to: str = ""
    #: For method="release": ``owner/repo`` plus a substring matching the Linux
    #: asset. Architecture is substituted for ``{arch}`` at install time.
    asset_match: str = ""
    #: Shell run after a successful install (wrapper scripts, requirements).
    post_install: str = ""
    #: Needs elevated privileges to *run*, not to install.
    needs_root_to_run: bool = False
    #: Upper bound on Python version, where the project has one.
    python_max: str = ""
    license: str = "unknown"
    #: Surfaced by `easyhunt install` and recorded in the report.
    caveat: str = ""
    #: Core tools make up the default pipeline; the rest are opt-in.
    core: bool = False
    #: EasyHunt *imports* this one rather than shelling out to it, so it has to
    #: live in EasyHunt's own environment. Only bbot qualifies: the recon engine
    #: drives its Python API. Isolating it with pipx would give a working CLI and
    #: an ImportError. Everything else is a subprocess and stays isolated.
    library: bool = False


# apt packages needed before anything else compiles.
SYSTEM_PACKAGES: tuple[str, ...] = (
    "git", "curl", "wget", "build-essential", "libpcap-dev",
    "dnsutils", "whois", "unzip", "ca-certificates",
)


def _pd(name: str, module: str, **kwargs) -> Recipe:
    """A ProjectDiscovery Go tool."""
    return Recipe(
        tool=name, method="go", package=f"github.com/projectdiscovery/{module}@latest",
        license="MIT", **kwargs
    )


def _python_repo_setup(tool: str, entry: str, *, requirements: str = "requirements.txt") -> str:
    """Post-install for a git-cloned Python tool: private venv plus a wrapper.

    Each cloned tool gets its own virtualenv under its checkout. Three reasons,
    and the first is not optional on a modern distro:

    * ``pip3 install`` into the system interpreter fails outright with
      ``externally-managed-environment`` on Debian/Ubuntu, so the naive form
      silently leaves a cloned repo and no working command.
    * These tools pin conflicting versions of the same handful of libraries.
    * It keeps the no-pollution rule consistent — nothing lands in a shared
      interpreter, ours or the system's.

    The wrapper on PATH points at that venv's Python, so the tool runs the
    dependencies it asked for.
    """
    root = f"/opt/{tool}"
    # Dependencies are declared differently across these projects: some ship a
    # requirements.txt, some only a pyproject.toml. Try the packaging metadata
    # first, then requirements. Failure is NOT swallowed — a tool whose
    # dependencies did not install runs and immediately exits with an import
    # error, which is worse than a clear install failure.
    return (
        f"set -e; python3 -m venv {root}/.venv; "
        f"{root}/.venv/bin/pip install -q --upgrade pip; "
        f"if [ -f {root}/pyproject.toml ] || [ -f {root}/setup.py ]; then "
        f"  {root}/.venv/bin/pip install -q {root}; "
        f"elif [ -f {root}/{requirements} ]; then "
        f"  {root}/.venv/bin/pip install -q -r {root}/{requirements}; "
        f"fi; "
        f"printf '#!/bin/sh\\nexec {root}/.venv/bin/python {root}/{entry} \"$@\"\\n' "
        f"> /usr/local/bin/{tool}; chmod +x /usr/local/bin/{tool}"
    )


RECIPES: dict[str, Recipe] = {}


def _add(recipe: Recipe) -> Recipe:
    RECIPES[recipe.tool] = recipe
    return recipe


# --------------------------------------------------------------------------- #
# Engines — the tools EasyHunt is built around
# --------------------------------------------------------------------------- #

_add(_pd("nuclei", "nuclei/v3/cmd/nuclei", category="engine", core=True,
         post_install="nuclei -update-templates -silent"))
_add(Recipe(tool="bbot", method="pip", package="bbot>=2.4", category="engine", core=True,
            license="AGPL-3.0", library=True,
            caveat=(
                "AGPL-3.0. Installed into EasyHunt's environment rather than isolated, "
                "because the recon engine drives its Python API directly."
            )))
_add(Recipe(tool="semgrep", method="pipx", package="semgrep", category="engine",
            license="LGPL-2.1"))
_add(Recipe(tool="jaeles", method="go", package="github.com/jaeles-project/jaeles@latest",
            category="engine", license="MIT",
            caveat="Repository archived — still functional, but receives no security updates."))
_add(Recipe(tool="osmedeus", method="script", category="engine", license="MIT",
            package="https://raw.githubusercontent.com/j3ssie/osmedeus/master/install.sh",
            caveat="Installs its own tool suite; expect a long install and a large footprint."))
_add(Recipe(tool="strix", method="manual", package="", category="engine", license="Apache-2.0",
            caveat=(
                "Autonomous exploitation agent — EasyHunt runs it only inside the "
                "container sandbox, so install the image rather than a host binary: "
                "docker pull usestrix/strix:latest"
            )))

# --------------------------------------------------------------------------- #
# Recon
# --------------------------------------------------------------------------- #

_add(_pd("subfinder", "subfinder/v2/cmd/subfinder", category="recon", core=True))
_add(_pd("asnmap", "asnmap/cmd/asnmap", category="recon"))
_add(_pd("tlsx", "tlsx/cmd/tlsx", category="recon"))
_add(_pd("uncover", "uncover/cmd/uncover", category="recon",
         caveat="Needs Shodan/Censys/Fofa API keys to return anything."))
_add(Recipe(tool="assetfinder", method="go", package="github.com/tomnomnom/assetfinder@latest",
            category="recon", license="MIT", core=True))
_add(Recipe(tool="amass", method="go", package="github.com/owasp-amass/amass/v4/...@latest",
            category="recon", license="Apache-2.0"))
_add(Recipe(tool="findomain", method="cargo", package="findomain", category="recon",
            license="GPL-3.0"))
_add(Recipe(tool="theHarvester", method="git", category="recon", license="GPL-2.0",
            package="https://github.com/laramies/theHarvester",
            clone_to="/opt/theHarvester",
            post_install=_python_repo_setup("theHarvester", "theHarvester.py", requirements="requirements/base.txt")))
_add(Recipe(tool="whois", method="apt", package="whois", category="recon",
            license="GPL-2.0+", core=True))

# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

_add(_pd("dnsx", "dnsx/cmd/dnsx", category="dns", core=True))
_add(_pd("alterx", "alterx/cmd/alterx", category="dns"))
_add(_pd("cdncheck", "cdncheck/cmd/cdncheck", category="dns"))
# shuffledns is inert without the massdns *binary*, not a library.
_add(_pd("shuffledns", "shuffledns/cmd/shuffledns", category="dns", tool_deps=("massdns",),
         caveat="Requires the massdns binary on PATH; it exits immediately without it."))
_add(Recipe(tool="massdns", method="git", package="https://github.com/blechschmidt/massdns",
            category="dns", clone_to="/opt/massdns", license="BSD-2-Clause",
            post_install="cd /opt/massdns && make -j$(nproc) && cp bin/massdns /usr/local/bin/"))
_add(Recipe(tool="dig", method="apt", package="dnsutils", category="dns",
            license="MPL-2.0", core=True))

# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

_add(_pd("httpx", "httpx/cmd/httpx", category="http", core=True,
         caveat=(
             "Name collision with the Python httpx CLI. EasyHunt resolves this by "
             "identity rather than PATH order, so no uninstall is needed."
         )))
_add(Recipe(tool="whatweb", method="apt", package="whatweb", category="http",
            license="GPL-2.0"))
_add(Recipe(tool="wafw00f", method="pipx", package="wafw00f", category="http",
            license="BSD-3-Clause"))

# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

# katana silently loses headless support if built without CGO.
_add(_pd("katana", "katana/cmd/katana", category="endpoints", core=True,
         env={"CGO_ENABLED": "1"},
         caveat="Headless crawling additionally needs google-chrome-stable."))
_add(Recipe(tool="gau", method="go", package="github.com/lc/gau/v2/cmd/gau@latest",
            category="endpoints", license="MIT", core=True))
_add(Recipe(tool="waybackurls", method="go", package="github.com/tomnomnom/waybackurls@latest",
            category="endpoints", license="MIT", core=True))
_add(Recipe(tool="waymore", method="pipx", package="waymore", category="endpoints",
            license="MIT"))
_add(Recipe(tool="arjun", method="pipx", package="arjun", category="endpoints",
            license="AGPL-3.0", caveat="AGPL-3.0."))
_add(Recipe(tool="paramspider", method="git", category="endpoints", license="MIT",
            package="https://github.com/devanshbatham/ParamSpider",
            clone_to="/opt/paramspider", post_install=_python_repo_setup("paramspider", "paramspider/main.py")))
_add(Recipe(tool="ffuf", method="go", package="github.com/ffuf/ffuf/v2@latest",
            category="endpoints", license="MIT", core=True))
_add(Recipe(tool="feroxbuster", method="script", category="endpoints", license="MIT",
            package="https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh"))
_add(Recipe(tool="gobuster", method="go", package="github.com/OJ/gobuster/v3@latest",
            category="endpoints", license="Apache-2.0"))
_add(Recipe(tool="dirsearch", method="pipx", package="dirsearch", category="endpoints",
            license="GPL-2.0"))

# --------------------------------------------------------------------------- #
# JavaScript
# --------------------------------------------------------------------------- #

_add(Recipe(tool="jsluice", method="go", package="github.com/BishopFox/jsluice/cmd/jsluice@latest",
            category="js", license="MIT"))
_add(Recipe(tool="retire", method="npm", package="retire", category="js",
            license="Apache-2.0"))
_add(Recipe(tool="linkfinder", method="git", category="js", license="MIT",
            package="https://github.com/GerbenJavado/LinkFinder",
            clone_to="/opt/linkfinder",
            post_install=_python_repo_setup("linkfinder", "linkfinder.py")))
_add(Recipe(tool="secretfinder", method="git", category="js", license="GPL-3.0",
            package="https://github.com/m4ll0k/SecretFinder",
            clone_to="/opt/secretfinder",
            post_install=_python_repo_setup("secretfinder", "SecretFinder.py")))

# --------------------------------------------------------------------------- #
# Ports — all three want raw sockets at run time
# --------------------------------------------------------------------------- #

_add(_pd("naabu", "naabu/v2/cmd/naabu", category="ports", core=True,
         system_deps=("libpcap-dev",), needs_root_to_run=True,
         caveat="SYN scanning needs root or CAP_NET_RAW; connect scan (-s c) works unprivileged."))
_add(Recipe(tool="nmap", method="apt", package="nmap", category="ports", license="NPSL",
            system_deps=("libpcap-dev",), needs_root_to_run=True, core=True,
            caveat="-sS SYN scan needs root; EasyHunt defaults to safe NSE categories only."))
_add(Recipe(tool="masscan", method="apt", package="masscan", category="ports",
            license="AGPL-3.0", system_deps=("libpcap-dev",), needs_root_to_run=True,
            caveat="AGPL-3.0. Always needs raw sockets. Rate is hard-capped by EasyHunt."))

# --------------------------------------------------------------------------- #
# Takeover
# --------------------------------------------------------------------------- #

_add(Recipe(tool="subzy", method="go", package="github.com/PentestPad/subzy@latest",
            category="takeover", license="GPL-2.0", core=True))
_add(Recipe(tool="dnsreaper", method="git", category="takeover", license="AGPL-3.0",
            package="https://github.com/punk-security/dnsReaper",
            clone_to="/opt/dnsreaper",
            post_install=_python_repo_setup("dnsreaper", "main.py"),
            caveat="AGPL-3.0."))
_add(Recipe(tool="subjack", method="go", package="github.com/haccer/subjack@latest",
            category="takeover", license="MIT"))
_add(Recipe(tool="subdominator", method="pipx", package="subdominator",
            category="takeover", license="MIT"))
_add(Recipe(tool="subdomainsleuth", method="manual", category="takeover",
            license="Apache-2.0", package="",
            caveat=(
                "Reads authoritative zone files — catches lame NS delegations that "
                "HTTP-only takeover scanners never see, but only if you hold the zones. "
                "No installable Go package path: build from source with "
                "'git clone https://github.com/yahoo/SubdomainSleuth && cd SubdomainSleuth && go build ./...'"
            )))

# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #

_add(Recipe(tool="kingfisher", method="release", category="secrets", license="Apache-2.0",
            package="mongodb/kingfisher", asset_match="linux-{arch}.tgz", core=True,
            caveat="Primary secrets scanner: validates credentials live and maps blast radius."))
_add(Recipe(tool="noseyparker", method="release", category="secrets",
            license="Apache-2.0", package="praetorian-inc/noseyparker",
            # Rust release naming: the GNU/musl triple, not the short arch form.
            asset_match="{arch}-unknown-linux-musl",
            caveat=(
                "Officially retired by Praetorian. Successor is Titus; trufflehog and "
                "kingfisher cover the same ground and are maintained."
            )))
_add(Recipe(tool="trufflehog", method="go", category="secrets", license="AGPL-3.0",
            package="github.com/trufflesecurity/trufflehog/v3@latest",
            caveat="AGPL-3.0 — matters if you redistribute a bundle."))
# The repo moved to gitleaks/gitleaks but go.mod still declares the old path,
# so the new URL fails with a version-constraints conflict.
_add(Recipe(tool="gitleaks", method="go",
            package="github.com/zricethezav/gitleaks/v8@latest",
            category="secrets", license="MIT", core=True))
_add(Recipe(tool="git", method="apt", package="git", category="secrets",
            license="GPL-2.0", core=True))
_add(Recipe(tool="gitdorker", method="git", category="secrets", license="MIT",
            package="https://github.com/obheda12/GitDorker", clone_to="/opt/gitdorker",
            post_install=_python_repo_setup("gitdorker", "GitDorker.py"),
            caveat="Needs a GitHub token to be useful."))

# --------------------------------------------------------------------------- #
# Smart contracts
# --------------------------------------------------------------------------- #

_add(Recipe(tool="netsanitizer", method="git", category="endpoints", license="MIT",
            package="https://github.com/iamsecure1920/NetSanitizer.git",
            clone_to="/opt/netsanitizer",
            post_install="cd /opt/netsanitizer && go mod init netsanitizer 2>/dev/null; "
                         "go build -o /usr/local/bin/netsanitizer NetSanitizer.go",
            caveat="Collapses archive URL dumps to distinct injection points. "
                   "Absence is non-fatal: endpoint_discovery returns the raw list."))
_add(Recipe(tool="slither", method="pipx", package="slither-analyzer",
            category="contracts", license="AGPL-3.0",
            caveat="AGPL-3.0 — matters if an EasyHunt bundle is redistributed. "
                   "Needs a matching solc; install solc-select alongside it."))
_add(Recipe(tool="aderyn", method="cargo", package="aderyn",
            category="contracts", license="MIT",
            caveat="Rust build; the first install compiles for several minutes."))
_add(Recipe(tool="forge", method="release", package="foundry-rs/foundry",
            asset_match="linux_{arch}.tar.gz", category="contracts",
            license="Apache-2.0 OR MIT",
            caveat="Ships forge/cast/anvil/chisel. The upstream foundryup "
                   "installer writes a shim that did not resolve on this host, "
                   "so the release tarball is used directly."))
_add(Recipe(tool="medusa", method="go",
            package="github.com/crytic/medusa@latest",
            category="contracts", license="AGPL-3.0",
            caveat="AGPL-3.0. NAME COLLISION: Kali ships /usr/bin/medusa, a password "
                   "brute-forcer by Foofus Networks. The catalog carries an "
                   "identity_marker so the wrong binary is reported rather than "
                   "run — running it would fire credential attacks at a host."))


# --------------------------------------------------------------------------- #
# Cloud
# --------------------------------------------------------------------------- #

_add(Recipe(tool="cloud_enum", method="git", category="cloud", license="MIT",
            package="https://github.com/initstring/cloud_enum", clone_to="/opt/cloud_enum",
            post_install=_python_repo_setup("cloud_enum", "cloud_enum.py")))
_add(Recipe(tool="s3scanner", method="go", package="github.com/sa7mon/s3scanner@latest",
            category="cloud", license="MIT"))
_add(Recipe(tool="cloudfox", method="go", package="github.com/BishopFox/cloudfox@latest",
            category="cloud", license="MIT"))
_add(Recipe(tool="prowler", method="pipx", package="prowler", category="cloud",
            license="Apache-2.0"))
# Its install.sh downloads a GitHub release binary anyway, but places it
# somewhere that depends on an interactive shell profile. Fetch the asset directly.
_add(Recipe(tool="kubescape", method="release", category="cloud", license="Apache-2.0",
            package="kubescape/kubescape", asset_match="linux_amd64",
            caveat="Ships its own MCP server; consider connecting it directly for K8s work."))
_add(Recipe(tool="cloudpeass", method="git", category="cloud", license="MIT",
            package="https://github.com/carlospolop/CloudPEASS", clone_to="/opt/cloudpeass",
            post_install="pip3 install -r /opt/cloudpeass/requirements.txt 2>/dev/null || true"))

# --------------------------------------------------------------------------- #
# Exploitation
# --------------------------------------------------------------------------- #

_add(Recipe(tool="dalfox", method="go", package="github.com/hahwul/dalfox/v2@latest",
            category="exploit", license="MIT", core=True))
_add(Recipe(tool="sqlmap", method="pipx", package="sqlmap", category="exploit",
            license="GPL-2.0", core=True,
            caveat="EasyHunt hard-blocks --dump, --dbs, --tables, --os-shell, --file-read."))
_add(_pd("interactsh-client", "interactsh/cmd/interactsh-client", category="exploit"))
_add(Recipe(tool="xsstrike", method="git", category="exploit", license="GPL-3.0",
            package="https://github.com/s0md3v/XSStrike", clone_to="/opt/xsstrike",
            post_install=_python_repo_setup("xsstrike", "xsstrike.py")))

# --------------------------------------------------------------------------- #
# Injection classes the wrapped engines do not cover
# --------------------------------------------------------------------------- #
#
# These ship in the container image. They are catalogued here so `easyhunt doctor`
# can see them at all: a tool that is in the image but not in the recipes is
# invisible to the health check, which is exactly how nikto and testssl below
# shipped 100% non-functional for days with nothing reporting it.

_add(Recipe(tool="ssrfmap", method="git", category="exploit", license="MIT",
            package="https://github.com/swisskyrepo/SSRFmap",
            clone_to="/opt/ssrfmap",
            post_install=_python_repo_setup("ssrfmap", "ssrfmap.py"),
            caveat=(
                "Driven by a saved HTTP request file (-r) with the injectable parameter "
                "named by -p; there is no URL-only mode, so it cannot be pointed at a "
                "bare host the way nuclei can. Modules beyond detection (portscan, redis, "
                "smtp, readfiles) are active exploitation and belong behind approval."
            )))
_add(Recipe(tool="sstimap", method="git", category="exploit", license="GPL-3.0",
            package="https://github.com/vladko312/SSTImap",
            clone_to="/opt/sstimap",
            post_install=_python_repo_setup("sstimap", "sstimap.py"),
            caveat=(
                "Maintained successor to the abandoned tplmap. Detection is safe; "
                "--os-cmd, --os-shell, --upload and --download execute on the target and "
                "are exploitation, not scanning. Pins urllib3~=1.26 and requests~=2.27 — "
                "old, which is why it gets its own venv rather than sharing one."
            )))
# NOT from PyPI. See the caveat: the PyPI package of this name is not commix.
_add(Recipe(tool="commix", method="git", category="exploit", license="GPL-3.0",
            package="https://github.com/commixproject/commix",
            clone_to="/opt/commix",
            post_install=_python_repo_setup("commix", "commix.py"),
            caveat=(
                "Installed from upstream git, deliberately NOT from PyPI. The PyPI project "
                "named 'commix' (version 0.1, uploaded 2022 by an unrelated author) contains "
                "no commix code at all — its single payload is a Termux helper shell script "
                "that clones this repository into $HOME when you run it. `pip install commix` "
                "therefore puts a 'commix' on PATH that is not commix, which no identity "
                "check based on the binary's name would catch. "
                "Everything past detection is OS command execution on the target."
            )))
_add(Recipe(tool="smuggler", method="git", category="exploit", license="MIT",
            package="https://github.com/defparam/smuggler",
            clone_to="/opt/smuggler",
            post_install=_python_repo_setup("smuggler", "smuggler.py"),
            caveat=(
                "Unmaintained — last commit April 2021. Vendors its dependencies, so the "
                "venv stays empty and it must be run by path from its checkout: it loads "
                "configs/ from the script directory and writes proof-of-concept payload "
                "files into /opt/smuggler/payloads, which therefore has to stay writable. "
                "Desync probes are deliberately malformed requests that can poison or wedge "
                "a shared front-end proxy — never run outside an authorised window."
            )))
_add(Recipe(tool="smuggler-framework", method="manual", package="",
            category="exploit", license="operator-supplied",
            caveat=(
                "Operator-supplied: not a public package, so there is nothing to "
                "install. Place the framework at /opt/smuggler_framework or point "
                "EASYHUNT_SMUGGLER_FRAMEWORK at its directory, and it is bind-mounted "
                "read-only into the sandbox at run time. Absent, smuggling_canary_probe "
                "reports UNTESTED rather than a clean target. It proves a desync by "
                "canary reflection instead of timing, and reports how many requests "
                "actually reached the wire alongside how many payloads it loaded — "
                "a pool bug once made those numbers differ by two orders of magnitude."
            )))
# `go install …@latest` was verified working here (resolves v0.5.4) even though the
# Dockerfile builds it from a checkout. The simpler path is kept.
_add(Recipe(tool="nosqli", method="go", category="exploit", license="AGPL-3.0",
            package="github.com/Charlie-belmer/nosqli@latest",
            caveat=(
                "AGPL-3.0 — matters the moment an EasyHunt bundle is redistributed. "
                "Dormant upstream (last release v0.5.4, 2021) against a go 1.15 module, so "
                "it builds only because Go stayed backward-compatible; if a future toolchain "
                "drops that, fall back to 'git clone && go build -o /usr/local/bin/nosqli .'"
            )))

# --------------------------------------------------------------------------- #
# Web scanners and TLS posture
# --------------------------------------------------------------------------- #
#
# nikto and testssl are the reason this section exists. Both were in the image and
# in neither the catalog nor the recipes, and both were completely non-functional
# — nikto could not load XML::Writer, testssl could not find hexdump — for as long
# as they had been shipping. Their run-time dependencies are declared, not assumed.

_add(Recipe(tool="nikto", method="git", category="http", license="GPL-3.0",
            package="https://github.com/sullo/nikto",
            clone_to="/opt/nikto",
            system_deps=("perl", "libnet-ssleay-perl", "libxml-writer-perl"),
            post_install=(
                "chmod +x /opt/nikto/program/nikto.pl && "
                "ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto"
            ),
            caveat=(
                "Needs the XML::Writer Perl module (Debian: libxml-writer-perl) or it dies "
                "with 'Required module not found: XML::Writer' on EVERY invocation, -Version "
                "included — it builds its XML report object unconditionally. perl and "
                "libnet-ssleay-perl alone are not enough. Licensing is split: the Perl code "
                "is GPL-3.0, but the scan databases are NOT under the GPL and may only be "
                "redistributed as part of the official Nikto package (see cirt.net/"
                "Nikto-Licensing) — check that before shipping a bundle. Loud by design: "
                "thousands of requests, trivially logged."
            )))
_add(Recipe(tool="testssl", method="git", category="http", license="GPL-2.0",
            package="https://github.com/testssl/testssl.sh",
            clone_to="/opt/testssl.sh",
            system_deps=("bsdextrautils", "procps"),
            post_install=(
                "chmod +x /opt/testssl.sh/testssl.sh && "
                "ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl"
            ),
            caveat=(
                "Two run-time dependencies that a successful install does not imply, both "
                "of which it exits on rather than degrades: hexdump ('You need to install "
                "hexdump for this program to work' — Debian ships it in bsdextrautils, not "
                "coreutils) and ps ('You need to install ps' — procps). Its dependency check "
                "cascades, so fixing one only reveals the next. Also needs bash (it is not "
                "POSIX sh) and runs from its checkout, which carries the etc/ cipher mappings "
                "and the bundled OpenSSL builds — a lone copied testssl.sh loses them. "
                "Upstream moved from drwetter/testssl.sh to testssl/testssl.sh; the old URL "
                "still redirects, but the new one is used here."
            )))
_add(Recipe(tool="wapiti", method="pipx", package="wapiti3", category="http",
            license="GPL-2.0", python_max="3.14",
            caveat=(
                "PyPI name is 'wapiti3'; the command is 'wapiti'. Release 3.3.1 needs "
                "Python >=3.12,<3.15 — the recipe can only express the ceiling, so on a host "
                "whose newest interpreter is older than 3.12 the install fails at resolution "
                "with an unhelpful message. Its browser-driven modules additionally need "
                "'wapiti-install-headless-browser'. A full crawl is slow and noisy; scope it "
                "with -m and a module list rather than running the default set."
            )))
_add(Recipe(tool="graphql-cop", method="git", category="http", license="MIT",
            package="https://github.com/dolevf/graphql-cop",
            clone_to="/opt/graphql-cop",
            post_install=_python_repo_setup("graphql-cop", "graphql-cop.py"),
            caveat=(
                "Pins requests==2.25.1 and simplejson==3.17.6, both of which predate "
                "Python 3.12 — the private venv keeps that off everything else, but "
                "simplejson may have to compile, so build-essential must be present. "
                "Several of its checks (batch queries, alias overloading, field duplication) "
                "are denial-of-service probes by construction: they are testing whether the "
                "endpoint can be made to do too much work. Treat as load-generating."
            )))
_add(Recipe(tool="corscanner", method="pipx", package="corscanner", category="http",
            license="MIT",
            caveat=(
                "Unmaintained — 0.9.7, last touched 2021. The wheel's console script is "
                "'corscanner'; a source install from the git repo names the same entry point "
                "'cors' instead, so the binary that appears depends on how it was installed. "
                "Pulls in gevent, which needs a C toolchain wherever no wheel is published. "
                "Reports misconfiguration, not exploitability — a permissive ACAO is only a "
                "finding once you show it reaches authenticated data."
            )))
_add(Recipe(tool="jwt_tool", method="git", category="http", license="GPL-3.0",
            package="https://github.com/ticarpi/jwt_tool",
            clone_to="/opt/jwt_tool",
            post_install=_python_repo_setup("jwt_tool", "jwt_tool.py"),
            caveat=(
                "The first invocation ALWAYS exits 1. It creates ~/.jwt_tool/jwtconf.ini, "
                "prints 'Configuration file built', and stops — so any check that reads a "
                "non-zero exit as broken will misreport a healthy install, and HOME must be "
                "writable. Run it once after installing. That generated config also defaults "
                "'jwksdynamic' to a httpbin.org URL carrying your JWKS; leave it unset unless "
                "sending key material to a third party is intended. Its -X exploit modes "
                "forge tokens — exploitation, not scanning."
            )))
_add(Recipe(tool="websocat", method="release", category="http", license="MIT",
            package="vi/websocat", asset_match="{arch}-unknown-linux-musl",
            caveat=(
                "The release asset is a bare static musl binary, not an archive, and only "
                "x86_64 and aarch64 Linux are published — anywhere else needs 'cargo install "
                "websocat'. Tracks whatever the latest release is (v1.14.1 at time of "
                "writing) rather than a pinned version. A raw WebSocket client, not a "
                "scanner: it has no scope or rate awareness of its own, so anything driving "
                "it has to supply both."
            )))

# --------------------------------------------------------------------------- #
# LLM red-team
# --------------------------------------------------------------------------- #

_add(Recipe(tool="garak", method="pipx", package="garak", category="llmsec",
            license="Apache-2.0", python_max="3.12",
            caveat="Supports Python 3.10–3.12 only; pipx can pin an interpreter."))
_add(Recipe(tool="promptfoo", method="npm", package="promptfoo", category="llmsec",
            license="MIT"))
_add(Recipe(tool="deepteam", method="pipx", package="deepteam", category="llmsec",
            license="Apache-2.0"))

# --------------------------------------------------------------------------- #
# Optional runtime dependencies
# --------------------------------------------------------------------------- #

_add(Recipe(tool="google-chrome-stable", method="script", category="runtime",
            package="chrome",  # handled specially: Google's repo, not the distro's
            license="proprietary",
            caveat="Needed only for headless crawling and screenshots."))


def recipes_for(
    *, category: str | None = None, core_only: bool = False
) -> list[Recipe]:
    out = list(RECIPES.values())
    if category:
        out = [r for r in out if r.category == category]
    if core_only:
        out = [r for r in out if r.core]
    return out


def install_order(recipes: list[Recipe]) -> list[Recipe]:
    """Topologically sort so a tool's dependencies install before it.

    Only ``massdns`` → ``shuffledns`` matters today, but getting this wrong
    produces a shuffledns that installs cleanly and then does nothing, which is
    exactly the failure this whole module exists to prevent.
    """
    by_name = {r.tool: r for r in recipes}
    ordered: list[Recipe] = []
    placed: set[str] = set()

    def place(recipe: Recipe, seen: frozenset[str] = frozenset()) -> None:
        if recipe.tool in placed or recipe.tool in seen:
            return
        for dependency in recipe.tool_deps:
            upstream = by_name.get(dependency)
            if upstream is not None:
                place(upstream, seen | {recipe.tool})
        if recipe.tool not in placed:
            ordered.append(recipe)
            placed.add(recipe.tool)

    for recipe in recipes:
        place(recipe)
    return ordered


def categories() -> list[str]:
    return sorted({r.category for r in RECIPES.values()})

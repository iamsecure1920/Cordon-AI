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

"""A ToolSpec with no call site is a promise the code does not keep.

This project's recurring defect is "absence is not a clean result", and one of
its faces is capability that was never wired up: a tool with a ToolSpec, an
installed binary, a docstring saying it runs, and nothing anywhere that calls it.
It reports nothing because it runs nothing, and in a report that is
indistinguishable from a target with nothing wrong.

It has happened repeatedly and was never caught by a test:

* ``jsluice`` had a spec, a binary on PATH and no caller. The native regex pass
  alone was returning "/./", "/a/b", "/_next/" — minifier noise instead of routes.
* ``retire`` could not run because ``--js`` was declared value-taking, so the
  sanitizer swallowed the following ``--path``. Two rounds of fixes to the
  argument policy, neither to the thing that executes; retire had never once
  scanned anything.
* 13 tools were added to the Docker image with no ToolSpec at all.
* ``shuffledns`` and ``linkfinder`` sat catalogued and uncalled for months.

Each was found by a person reading code, which does not scale and did not
recur. So the property is asserted here instead: **every catalogued spec is
either reachable from an MCP tool, or is named in _DELIBERATELY_UNWIRED with a
reason.** The next unwired tool fails this file rather than sitting unnoticed.

The exemption list is deliberately not a dumping ground. A name that gains a
call site must be removed from it (``test_no_stale_exemptions``), because a list
claiming a wired tool is unwired hides exactly what it was built to reveal.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Any

import pytest

from cordon.control_plane.sanitize import sanitize_argv
from cordon.mcp_server import load_capabilities
from cordon.tools.base import REGISTRY
from cordon.tools.common import CATALOG, ToolRun

load_capabilities()

_SOURCE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "cordon"


# --------------------------------------------------------------------------- #
# Finding the call sites
# --------------------------------------------------------------------------- #


def _spec_variables(tree: ast.Module) -> dict[str, str]:
    """Module-level ``VAR = register_spec(ToolSpec(name="x", ...))`` → {VAR: "x"}.

    Engines execute through ``guarded_run(SPEC, argv)`` rather than by name, so
    the variable has to be resolved back to the tool it declares.
    """
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "ToolSpec":
                for keyword in sub.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                        found[target.id] = str(keyword.value.value)
    return found


def _imported_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def call_sites() -> dict[str, set[str]]:
    """Map every catalogued tool to the places that can actually execute it.

    Four execution paths exist, and a scanner that knows only the first reports
    working tools as dead:

    1. ``run_one("name", argv)`` — the common case.
    2. ``guarded_run(SPEC, argv)`` — how the engines run.
    3. ``run_one(variable, argv)`` — ``llm_scan_config`` dispatches on an
       ``engine`` argument constrained to {"promptfoo", "deepteam"}. Every
       catalog name appearing as a constant in such a function is credited.
    4. A library, not a binary: ``bbot`` is driven through
       ``from bbot.scanner import Scanner``, so a spec declaring ``package`` is
       credited where that package is imported.

    Static rather than dynamic on purpose. Importing every module and
    monkeypatching ``run_one`` would only find the paths a test happens to
    execute, and the whole point is to find the ones nothing executes.
    """
    names = set(CATALOG)
    wired: dict[str, set[str]] = {}

    def record(tool: str, where: str) -> None:
        if tool in names:
            wired.setdefault(tool, set()).add(where)

    for path in sorted(_SOURCE_ROOT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover - defensive
            continue

        specs = _spec_variables(tree)
        label = path.relative_to(_SOURCE_ROOT.parent)

        scopes: list[Any] = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        scopes.append(tree)

        for scope in scopes:
            dispatches_on_a_variable = False
            for node in ast.walk(scope):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                fname = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)

                if fname == "run_one" and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant):
                        record(str(first.value), f"{label}:{node.lineno}")
                    else:
                        dispatches_on_a_variable = True
                elif fname == "guarded_run" and node.args and isinstance(node.args[0], ast.Name):
                    declared = specs.get(node.args[0].id)
                    if declared:
                        record(declared, f"{label}:{node.lineno}")

            if dispatches_on_a_variable:
                for node in ast.walk(scope):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        record(node.value, f"{label}:{node.lineno}")

        roots = _imported_roots(tree)
        for name, spec in CATALOG.items():
            package = (spec.package or "").replace("-", "_").split(".")[0]
            if package and package in roots:
                record(name, f"{label} (library import)")

    return wired


# --------------------------------------------------------------------------- #
# The exemptions
# --------------------------------------------------------------------------- #

#: Catalogued but deliberately not invoked, with the reason for each.
#:
#: A spec earns a place here only when an already-wired tool covers the same
#: ground, or when running it needs something an automated engagement does not
#: have (an operator's API key, authoritative zone files). "We never got round to
#: it" is not a reason — that is the defect this file exists to surface.
#:
#: Every reason below was checked against the code, not against the comment that
#: claimed it. One did not survive: ``cordon/tools/extra_specs.py`` states that
#: gobuster and dirsearch are unwired because "ffuf and feroxbuster are faster and
#: already have rate ceilings wired in", but feroxbuster has no call site either.
#: ffuf alone carries content discovery.
_DELIBERATELY_UNWIRED: dict[str, str] = {
    # --- an already-wired tool covers the same ground ---
    "gobuster": "content discovery is ffuf (endpoints.py:487); gobuster duplicates it",
    "dirsearch": "content discovery is ffuf (endpoints.py:487); dirsearch duplicates it",
    "feroxbuster": (
        "content discovery is ffuf (endpoints.py:487). extra_specs.py claims "
        "feroxbuster is already wired; it is not, and nothing calls it"
    ),
    "xsstrike": "dalfox (exploitation.py:423) verifies execution context; XSStrike reports reflection",
    "secretfinder": "the native JS pattern scan plus jsluice (js_analysis.py) cover the same regexes",
    "gf": (
        "pattern_scan (pattern_scan.py) runs the same vetted rules/gf/ patterns "
        "natively; the gf binary is catalog-only for interactive use"
    ),
    "trufflehog": (
        "secret scanning is kingfisher/noseyparker/gitleaks (secrets.py:285,299,305). "
        "Also has no requests-per-second flag for its --only-verified mode"
    ),
    "masscan": (
        "port scanning is naabu (ports.py:190) and nmap (ports.py:273), both rate-governed. "
        "masscan's --rate would be the whole of its governance"
    ),
    "whatweb": "technology fingerprinting comes from httpx (http_probe.py:128)",
    # subjack and subdominator are NOT listed here. extra_specs.py groups them with
    # the unwrapped tools, but takeover.py:240 and :246 call both — this test
    # rejected them as stale exemptions, which is the check doing its job on the
    # author of the check.
    # --- needs something an unattended engagement does not have ---
    "uncover": "needs Shodan/Censys/Fofa API keys that belong to the operator",
    "gitdorker": "needs a GitHub token that belongs to the operator",
    "cloudpeass": "needs cloud credentials that belong to the operator",
    "subdomainsleuth": "needs authoritative zone files, which an external engagement does not hold",
    # --- contract tooling: presence is reported, analysis is slither's job ---
    "aderyn": "contract_toolchain (contracts.py:317) reports presence; slither (contracts.py:213) analyses",
    "forge": "contract_toolchain (contracts.py:317) reports presence; slither (contracts.py:213) analyses",
    "medusa": "contract_toolchain (contracts.py:317) reports presence; slither (contracts.py:213) analyses",
    # --- pending, not settled ---
    # (linkfinder was here as "WIRING PROPOSED"; the call site landed in
    # js_analysis.py and this entry must stay gone — see test_no_stale_exemptions)
}


# --------------------------------------------------------------------------- #
# Every spec is reachable, or declared
# --------------------------------------------------------------------------- #


class TestEverySpecIsReachable:
    """The property that would have caught jsluice, shuffledns and linkfinder."""

    def test_no_spec_is_silently_unreachable(self) -> None:
        wired = call_sites()
        orphans = sorted(set(CATALOG) - set(wired) - set(_DELIBERATELY_UNWIRED))
        assert orphans == [], (
            f"{len(orphans)} catalogued tool(s) have a ToolSpec and no call site: "
            f"{orphans}. A spec nobody calls reports nothing because it runs "
            "nothing, which is indistinguishable from a clean target. Either add a "
            "wrapper that invokes it, delete the spec, or add it to "
            "_DELIBERATELY_UNWIRED with the reason."
        )

    def test_no_stale_exemptions(self) -> None:
        """A tool that gained a call site must leave the exemption list.

        Otherwise the list drifts into a graveyard that asserts the opposite of
        the truth, and the next genuinely-unwired tool hides among entries nobody
        rechecks.
        """
        wired = call_sites()
        stale = sorted(set(_DELIBERATELY_UNWIRED) & set(wired))
        assert stale == [], (
            f"{stale} are listed in _DELIBERATELY_UNWIRED but now have call sites "
            f"({ {t: sorted(wired[t])[:2] for t in stale} }). Delete their entries."
        )

    @pytest.mark.parametrize("tool", sorted(_DELIBERATELY_UNWIRED))
    def test_every_exemption_names_a_real_tool(self, tool: str) -> None:
        assert tool in CATALOG, f"{tool} is exempted but is not in the catalog"

    @pytest.mark.parametrize("tool", sorted(_DELIBERATELY_UNWIRED))
    def test_every_exemption_gives_a_substantive_reason(self, tool: str) -> None:
        reason = _DELIBERATELY_UNWIRED[tool]
        assert len(reason) > 30, f"{tool}: give a real reason, not {reason!r}"
        assert "todo" not in reason.lower(), f"{tool}: 'todo' is not a reason"

    def test_the_wiring_scan_finds_the_paths_it_claims_to(self) -> None:
        """Guard the detector itself.

        A scanner that silently stopped finding call sites would make this whole
        file pass by declaring everything unwired-but-exempt. These four cover the
        four execution paths in ``call_sites``.
        """
        wired = call_sites()
        assert wired.get("dnsx"), "run_one with a literal name was not detected"
        assert wired.get("nuclei"), "guarded_run(SPEC, ...) was not detected"
        assert wired.get("promptfoo"), "run_one with a variable name was not detected"
        assert wired.get("bbot"), "a library-backed spec was not detected"


class TestShuffleDnsStaysDeleted:
    """shuffledns was removed rather than wired, and the reason is structural.

    `shuffledns -h` lists exactly one flag under RATE-LIMIT: "-t int  Number of
    concurrent massdns resolves (default 10000)". `massdns --help` underneath it
    offers `-s/--hashmap-size` ("Number of concurrent lookups") and `-i/--interval`
    ("Interval in milliseconds to wait between multiple resolves of the same
    domain") — concurrency and retry spacing, not a rate. No layer of that stack
    can honour `scope.rules.max_rps`.

    dnsx does the same job with `-d`/`-w` and has both `-rl` and `-t`. Re-adding
    the spec without a governed call site would restore an ungovernable
    bruteforcer to the catalog.
    """

    def test_the_spec_is_gone(self) -> None:
        assert "shuffledns" not in CATALOG

    def test_dnsx_can_still_express_the_capability(self) -> None:
        """The replacement is real: dnsx's policy already permits bruteforce."""
        policy = CATALOG["dnsx"].arg_policy
        assert policy is not None
        for flag in ("-d", "-w", "-rl", "-t"):
            assert flag in policy.allowed_flags, f"dnsx cannot express {flag}"


# --------------------------------------------------------------------------- #
# A wrapper's argv must survive its own sanitizer
# --------------------------------------------------------------------------- #


def _spy(monkeypatch: pytest.MonkeyPatch, module: str) -> list[dict[str, Any]]:
    """Capture every argv a module builds, and sanitize it exactly as runtime does."""
    import importlib

    target = importlib.import_module(f"cordon.tools.{module}")
    calls: list[dict[str, Any]] = []

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        calls.append({"tool": name, "argv": list(argv)})
        return ToolRun(tool=name, ran=True, values=[], duration_s=0.1, exit_code=0)

    monkeypatch.setattr(target, "run_one", fake_run_one)
    return calls


class TestArgvSurvivesItsOwnSanitizer:
    """A policy that rejects its own tool's call is inert, and reads as clean.

    ``sanitize_argv`` raises, ``run_one`` catches it and returns ``ran=False``,
    and the wrapper reports an empty result. Nothing crashes and nothing is
    scanned. This is the same failure mode as a missing binary, arriving from the
    opposite direction.
    """

    async def test_dns_resolve_argv_is_accepted_by_the_dnsx_policy(
        self, engagement, monkeypatch
    ) -> None:
        calls = _spy(monkeypatch, "dns")
        await REGISTRY["dns_resolve"].fn(target="api.example.com")

        assert calls, "dns_resolve never invoked dnsx"
        for call in calls:
            spec = CATALOG[call["tool"]]
            assert sanitize_argv(spec.name, call["argv"], policy=spec.arg_policy) == call["argv"]

    @pytest.mark.parametrize(("rps", "concurrency"), [(0.5, 1), (5, 3), (300, 100), (5000, 4000)])
    async def test_a_scope_above_the_policy_ceiling_still_produces_a_runnable_argv(
        self, engagement, monkeypatch, rps: float, concurrency: int
    ) -> None:
        """The regression that clamping fixed.

        ``dns_resolve`` passed ``max_rps`` straight into ``-rl``, whose policy cap
        is 300. A scope declaring 500 rps built an argv its own sanitizer refused,
        so dnsx never ran and ``dns_resolve`` returned ``resolved: 0`` — a tool
        that never executed, shaped exactly like a domain that resolves to nothing.

        Latent rather than observed: no scope.yaml in this repo sets ``max_rps``
        above 300. An owned-asset engagement legitimately can.
        """
        engagement.scope.rules.max_rps = rps
        engagement.scope.rules.max_concurrency = concurrency
        calls = _spy(monkeypatch, "dns")

        await REGISTRY["dns_resolve"].fn(target="api.example.com")

        argv = next(c["argv"] for c in calls if c["tool"] == "dnsx")
        spec = CATALOG["dnsx"]
        assert sanitize_argv("dnsx", argv, policy=spec.arg_policy) == argv
        # And it is still governed: never above the ceiling, never below 1.
        caps = spec.arg_policy.numeric_caps
        assert 1 <= float(argv[argv.index("-rl") + 1]) <= caps["-rl"]
        assert 1 <= float(argv[argv.index("-t") + 1]) <= caps["-t"]

    async def test_the_rate_still_tracks_the_engagement_below_the_ceiling(
        self, engagement, monkeypatch
    ) -> None:
        """Clamping must not become a constant.

        A ``min()`` that always returned the cap would pass the test above while
        ignoring every program's published limit.
        """
        engagement.scope.rules.max_rps = 7
        engagement.scope.rules.max_concurrency = 4
        calls = _spy(monkeypatch, "dns")

        await REGISTRY["dns_resolve"].fn(target="api.example.com")

        argv = next(c["argv"] for c in calls if c["tool"] == "dnsx")
        assert argv[argv.index("-rl") + 1] == "7"
        assert argv[argv.index("-t") + 1] == "4"


# --------------------------------------------------------------------------- #
# An absent binary is UNTESTED, not zero findings
# --------------------------------------------------------------------------- #


def _absent(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    import importlib

    target = importlib.import_module(f"cordon.tools.{module}")

    async def missing(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        return ToolRun(tool=name, ran=False, error="not installed")

    monkeypatch.setattr(target, "run_one", missing)


class TestAbsenceIsNotACleanResult:
    """Measured before it was fixed, not theorised.

    With dnsx absent, ``dns_resolve`` returned::

        {"ok": true, "queried": 1, "resolved": 0, "records": [],
         "next_step": "Probe the resolved hosts with http_probe."}

    The only trace of the failure was ``tools[0].ran = false``, four keys down,
    and the advice actively told the agent to carry on. Every later phase reads
    that as a domain whose hosts do not resolve.
    """

    @pytest.mark.parametrize(
        ("tool", "kwargs"),
        [
            ("dns_resolve", {"target": "api.example.com"}),
            ("dns_permute", {"target": "example.com"}),
            ("cdn_check", {"target": "api.example.com"}),
        ],
    )
    async def test_a_missing_binary_reports_untested(
        self, engagement, monkeypatch, tool: str, kwargs: dict[str, Any]
    ) -> None:
        from cordon.control_plane.approval import PolicyBackend

        engagement.approval.backend = PolicyBackend(auto_approve={tool})
        # dns_permute declares 20,000 requests; at the fixture's 5 rps the limiter
        # refuses the call outright before the wrapper is ever reached. The
        # subject here is the wrapper's response to an absent binary, not the
        # ceiling, so the limiter is widened for the duration. (The limiter is
        # built once in Engagement.__init__, so mutating scope.rules alone does
        # not reach it.)
        engagement.limiter.rps = 1000.0
        _absent(monkeypatch, "dns")

        result = await REGISTRY[tool].fn(**kwargs)

        assert result["ok"] is False
        assert result["complete"] is False
        assert result["untested"] is True
        assert result["error"] == "tool_unavailable"
        assert "UNTESTED, not clean" in result["message"]

    @pytest.mark.parametrize(
        ("tool", "kwargs"),
        [
            ("dns_resolve", {"target": "api.example.com"}),
            ("dns_permute", {"target": "example.com"}),
            ("cdn_check", {"target": "api.example.com"}),
        ],
    )
    async def test_a_missing_binary_reports_nothing_that_reads_as_a_result(
        self, engagement, monkeypatch, tool: str, kwargs: dict[str, Any]
    ) -> None:
        """No count, no empty list, no "next step" telling the agent to proceed."""
        from cordon.control_plane.approval import PolicyBackend

        engagement.approval.backend = PolicyBackend(auto_approve={tool})
        # dns_permute declares 20,000 requests; at the fixture's 5 rps the limiter
        # refuses the call outright before the wrapper is ever reached. The
        # subject here is the wrapper's response to an absent binary, not the
        # ceiling, so the limiter is widened for the duration. (The limiter is
        # built once in Engagement.__init__, so mutating scope.rules alone does
        # not reach it.)
        engagement.limiter.rps = 1000.0
        _absent(monkeypatch, "dns")

        result = await REGISTRY[tool].fn(**kwargs)

        for key in ("resolved", "records", "count", "next_step", "behind_cdn", "new_hosts"):
            assert key not in result, f"{tool} still returns {key!r} when the tool never ran"

    async def test_a_tool_that_ran_and_found_nothing_is_not_reported_as_untested(
        self, engagement, monkeypatch
    ) -> None:
        """The other half. Absence and emptiness must stay distinguishable."""
        _spy(monkeypatch, "dns")

        result = await REGISTRY["dns_resolve"].fn(target="api.example.com")

        assert result["ok"] is True
        assert result.get("untested") is not True
        assert result["resolved"] == 0

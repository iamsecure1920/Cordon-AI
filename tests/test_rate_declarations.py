"""``estimated_requests`` is a control, and an undeclared one controls nothing.

`RateLimiter.slot()` charges what a tool says it will send. `base.py` turns that
declaration into the price of the call::

    cost = float(estimated_requests or 1)

The `or 1` is the honest floor for a tool that declares nothing — a call was
made, so a call is charged — but it is also a silent 8,283x under-charge for
`ssrf_probe`, whose portscan module walks an 8,282-entry port list through a
thread pool the limiter never sees. That exact bug shipped: the limiter reported
a compliant engagement on traffic three orders of magnitude past the published
ceiling, because a parameter that had always existed was never passed.

The numbers were filled in afterwards, one tool at a time. This file exists so
they cannot quietly go missing again, because the next wrapper is the one that
matters:

* **A missing declaration is invisible.** It does not raise, it does not warn,
  and the approval prompt renders without an "est. requests" line rather than
  with a wrong one. A budget that under-counts by 100x looks exactly like a
  budget that works.
* **This is authorization, not accounting.** The programs this runs against
  forbid "any activity that could lead to disruption of our service, including
  stress-testing or load-testing tools". The request ceiling is how the tool
  keeps that promise; a ceiling fed a constant of 1 is not keeping it.
* **An aggressive tool costing 1 is a declaration nobody wrote.** The mode
  system already says these are noisy, state-touching, or high volume. A tool
  that is both aggressive and free is a contradiction, and every instance found
  so far has been an omission rather than a genuinely cheap tool.

Nothing here checks that a number is *right* — that is `test_rate_governance.py`,
which pins specific figures against measured runs. This checks the weaker and
more durable property: that somebody made a decision and wrote it down.
"""

from __future__ import annotations

import pytest

import easyhunt.mcp_server as mcp_server
from easyhunt.tools.base import REGISTRY, RegisteredTool

# The registry is populated by import side effects, so every capability module
# has to be loaded before anything here can claim to have seen "every tool".
# Counting 40 of 73 and passing is the failure this file is about.
mcp_server.load_capabilities()


def _is_product_tool(tool: RegisteredTool) -> bool:
    """Is this a capability EasyHunt ships, or a fixture the test suite built?

    `REGISTRY` is process-global and `easyhunt_tool` registers into it at import
    time, so `tests/test_decorator.py` — which declares throwaway tools named
    `t_passive`, `t_aggressive`, `t_exploit` and friends to exercise the
    decorator's control sequence — puts them in the same dict this file reads.
    Those deliberately declare no `estimated_requests`: what they test is the
    pipeline wrapped *around* the declaration. Judging them by this file's rule
    made the whole module pass alone and fail in the full suite, which is the
    worst shape a test can have.

    The filter is on the DEFINING MODULE and it is an exclusion, not an
    allowlist. Two deliberate consequences:

    * Filtering on the `t_*` name convention instead would mean a real tool ever
      named `t_something` silently stopped being checked. A product tool cannot
      be defined inside the `tests` package, so this cannot mis-fire that way.
    * Everything outside `tests.` stays in scope, including tools registered by
      a plugin or a rule pack rather than by `easyhunt.*`. An unvetted
      third-party tool that declares nothing is exactly what this file must
      catch, so it must not be excluded for living in an unfamiliar module.
    """
    module = getattr(tool.fn, "__module__", "") or ""
    return module != "tests" and not module.startswith("tests.")


def _product_tools() -> dict[str, RegisteredTool]:
    return {name: tool for name, tool in REGISTRY.items() if _is_product_tool(tool)}


#: Snapshot for `@pytest.mark.parametrize`, which is evaluated at import time.
#: Whether `tests/test_decorator.py` has been imported yet depends on collection
#: order, so the filter — not the timing — is what makes this deterministic.
_PRODUCT_TOOL_NAMES = sorted(_product_tools())


#: Tools that genuinely send nothing, with the reason each one is offline.
#:
#: Zero is a real answer and inflating it wastes the budget — a local SAST run
#: reserving 500 requests denies them to a scan that would have used them. But
#: zero is also what a forgotten declaration looks like once someone "fixes" the
#: None, so every entry here has to name the thing that keeps it offline.
_SENDS_NOTHING: dict[str, str] = {
    "coverage_report": "reads the static bug-class coverage matrix",
    "contract_static_scan": "slither analyses Solidity already in the workspace",
    "contract_toolchain": "reports which contract binaries are installed",
    "finding_detail": "reads one record out of the findings store",
    "finding_note": "writes an analyst note into the findings store",
    "findings_list": "lists the findings store",
    "hunt_plan": "reads the asset store; its optional LLM call bills the model budget",
    "job_status": "reads the in-process job registry",
    "jwt_inspect": "jwt_tool decodes offline; its replay and forge modes are denied",
    "llm_probe_catalog": "prints the static probe-family table",
    "payload_catalog": "lists the vetted wordlist store",
    "poc_record": "stores a PoC a human already reproduced",
    "report_generate": "renders the findings store to disk",
    "secret_scan": "kingfisher runs with --no-validate; every scanner reads local files",
    "semgrep_scan": "SAST over source already fetched into the workspace",
    "session_list": "lists registered sessions, masked",
    "session_register": "stores a credential the operator already holds",
    "takeover_poc_plan": "writes the PoC steps; claiming the resource is a human's job",
    "triage_canary_preview": "fabricates decoy findings locally",
    "triage_findings": "LLM triage over stored findings; no target traffic",
    "technique_lookup": "reads the bundled technique index",
    "triage_taskflows": "parses taskflow YAML from disk",
    "wstg_lookup": "reads the bundled WSTG index",
}


#: Aggressive or exploit tools currently declaring 1 — pending correction.
#:
#: This set may SHRINK and must never GROW. It is not an exemption: each entry is
#: a known-wrong number with a derivation next to it, kept green only so the rule
#: can land before the fixes do. Adding a name here to make a new tool pass is
#: the precise move this file exists to make visible in review.
#:
#: (oob_listener was here while it declared 1; it now derives its cost from
#: OOB_POLL_INTERVAL_S and OOB_MAX_DURATION_S in exploitation.py. Empty on
#: purpose — the rule is live and every gated tool now declares its real price.)
_KNOWN_UNDER_DECLARED: dict[str, str] = {}


def _declared(name: str) -> int | None:
    return REGISTRY[name].estimated_requests


class TestEveryToolStatesItsPrice:
    """The decorator default is None, and None is indistinguishable from cheap."""

    def test_the_registry_is_actually_populated(self) -> None:
        # A rule applied to an empty collection passes and proves nothing. If
        # capability loading ever breaks, this fails first and says so, rather
        # than letting every test below report a clean sweep of nothing.
        assert len(_PRODUCT_TOOL_NAMES) > 50, (
            f"only {len(_PRODUCT_TOOL_NAMES)} product tools registered — did loading fail?"
        )

    def test_the_test_fixture_filter_excludes_only_test_fixtures(self) -> None:
        """The exclusion must never be able to hide a real tool.

        If this ever reports a name, the filter has widened past the test suite's
        own dummies and every rule in this file has quietly stopped applying to
        whatever it swallowed.
        """
        excluded = {
            name: getattr(tool.fn, "__module__", None)
            for name, tool in REGISTRY.items()
            if not _is_product_tool(tool)
        }
        non_test = {n: m for n, m in excluded.items() if not str(m).startswith("tests")}
        assert non_test == {}, f"filter excluded tools defined outside the test suite: {non_test}"

    @pytest.mark.parametrize("name", _PRODUCT_TOOL_NAMES)
    def test_the_tool_declares_estimated_requests_explicitly(self, name: str) -> None:
        """A new tool with no `estimated_requests=` fails here, by construction.

        `easyhunt_tool` defaults the parameter to None and the registry stores
        it verbatim, so None means *nobody typed a number* — as distinct from 0,
        which is somebody stating the tool is offline.
        """
        assert _declared(name) is not None, (
            f"{name} declares no estimated_requests, so the limiter charges it the "
            f"floor of 1 whatever it actually sends. Add estimated_requests= to its "
            f"@easyhunt_tool decorator, or list it in _SENDS_NOTHING with a reason."
        )

    @pytest.mark.parametrize("name", _PRODUCT_TOOL_NAMES)
    def test_a_zero_declaration_is_justified_in_this_file(self, name: str) -> None:
        """Zero is legitimate, but only for a tool somebody argued is offline."""
        if _declared(name) != 0:
            return
        assert name in _SENDS_NOTHING, (
            f"{name} declares 0 requests but is not in _SENDS_NOTHING. Either it "
            f"sends nothing — say why, in one line — or the 0 is a placeholder."
        )
        assert _SENDS_NOTHING[name].strip(), f"{name} needs a real reason, not an empty string"

    def test_the_offline_allowlist_has_no_stale_entries(self) -> None:
        """A renamed or deleted tool must not leave a permanent exemption behind.

        An allowlist keyed on a name nobody registers any more is dead text that
        reads as coverage. It also silently stops guarding the tool it was
        written for, which is now registered under a different name.
        """
        stale = sorted(set(_SENDS_NOTHING) - set(_product_tools()))
        assert stale == [], f"_SENDS_NOTHING names tools that are not registered: {stale}"


class TestAggressiveToolsCannotCostOne:
    """Mode already says this tool is loud. One token is not what loud costs.

    `mode` is the gate that asks a human. A tool that trips it is, by the
    decorator's own documentation, "state-touching, noisy, or high request
    volume" — so the two facts contradict each other, and every case examined so
    far resolved as the number being wrong rather than the mode.
    """

    #: The modes that require human approval before the tool body runs.
    GATED = ("aggressive", "exploit")

    @pytest.mark.parametrize(
        "name",
        sorted(n for n, t in _product_tools().items() if t.mode in ("aggressive", "exploit")),
    )
    def test_a_gated_tool_declares_more_than_one_request(self, name: str) -> None:
        declared = _declared(name)
        if name in _KNOWN_UNDER_DECLARED:
            pytest.xfail(f"{name}: {_KNOWN_UNDER_DECLARED[name]} — pending correction")
        assert declared is not None and declared > 1, (
            f"{name} is mode={REGISTRY[name].mode} but declares {declared}. An "
            f"approval-gated tool that costs one token is a number nobody chose. "
            f"Derive it from the wrapper's own argv — payload count, wordlist "
            f"length, hosts x ports, poll interval x duration."
        )

    def test_the_pending_list_does_not_grow(self) -> None:
        """The rule lands now; the corrections land next. Only shrinking is allowed.

        Asserting the *actual* violators are a subset of the recorded ones means a
        newly-added under-declared tool fails here even though its own
        parametrized case was xfailed — the escape hatch cannot be widened by
        accident, only by editing this set on purpose.
        """
        violating = {
            name
            for name, tool in _product_tools().items()
            if tool.mode in self.GATED and (tool.estimated_requests or 0) <= 1
        }
        new = sorted(violating - set(_KNOWN_UNDER_DECLARED))
        assert new == [], (
            f"{new} are aggressive/exploit tools declaring <= 1 and are not on the "
            f"pending list. Fix the declaration rather than extending the list."
        )

    def test_the_pending_list_has_no_entries_that_are_already_fixed(self) -> None:
        """A stale entry silently re-exempts a tool if its number regresses."""
        fixed = sorted(
            name
            for name in _KNOWN_UNDER_DECLARED
            if name in _product_tools() and (REGISTRY[name].estimated_requests or 0) > 1
        )
        assert fixed == [], (
            f"{fixed} now declare more than 1 — delete them from _KNOWN_UNDER_DECLARED "
            f"so the rule protects them again."
        )


class TestDeclarationsAreNonNegative:
    """A negative cost would refund the limiter, which is not a thing budgets do."""

    @pytest.mark.parametrize("name", _PRODUCT_TOOL_NAMES)
    def test_the_declaration_is_a_non_negative_integer(self, name: str) -> None:
        declared = _declared(name)
        assert isinstance(declared, int) and not isinstance(declared, bool), (
            f"{name} declares {declared!r}; estimated_requests must be an int"
        )
        assert declared >= 0, f"{name} declares a negative request count ({declared})"

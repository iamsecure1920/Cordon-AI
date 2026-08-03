"""Rate governance: does the traffic a tool generates actually obey the ceiling?

The control plane's limiter charges one token per **tool call**. Every wrapper in
this file hands a target list to a binary that then makes its own requests — often
from its own thread pool — and the limiter never sees any of them. For those
tools the only thing standing between the engagement and a policy violation is the
rate or concurrency flag on the command line.

So these tests capture the argv at ``run_one`` and assert three things:

1. **The value tracks the engagement.** Not a constant, not a default, not a
   multiple. ``max_rps`` is changed mid-test and the argv must follow it. A test
   that hardcodes the expected number passes just as happily against
   ``str(5)`` as against ``str(rules.max_rps)``, which is why every assertion here
   varies the scope first.
2. **No multipliers.** ``naabu -rate`` was ``max_rps * 20`` and ``dnsx -rl`` was
   ``max_rps * 10``. Both read as governed and neither was. The regression test is
   an equality against ``max_rps``, because that is the only value with a
   justification behind it.
3. **No floors that override the engagement.** ``max(10, ...)`` silently ignores
   any program publishing a ceiling below 10 rps, which is most of the strict
   ones. A sub-1-rps engagement is tested explicitly.

The stand-in for ``run_one`` runs the real sanitizer over the argv it is handed,
so every test here also proves the wrapper's command line is acceptable to that
tool's own argument policy — the two are written in different places and drift.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from easyhunt.control_plane.approval import PolicyBackend
from easyhunt.control_plane.sanitize import sanitize_argv
from easyhunt.mcp_server import load_capabilities
from easyhunt.tools.base import REGISTRY
from easyhunt.tools.common import CATALOG, ToolRun

load_capabilities()

#: Tools whose *request rate* is bounded by a flag we set from the engagement,
#: as ``tool -> (module, flag, kind)``. ``kind`` is "rps" when the flag is a
#: requests/packets-per-second ceiling and "concurrency" when it only bounds how
#: many requests are in flight at once.
#:
#: Verified against each binary's real ``--help`` output, not from memory.
RPS_FLAGS: dict[str, tuple[str, str]] = {
    "subfinder": ("recon", "-rl"),
    "dnsx": ("dns", "-rl"),
    "naabu": ("ports", "-rate"),
    "nmap": ("ports", "--max-rate"),
    "kingfisher": ("secrets", "--validation-rps"),
}

CONCURRENCY_FLAGS: dict[str, tuple[str, str]] = {
    "tlsx": ("recon", "-c"),
    "dnsx": ("dns", "-t"),
    "naabu": ("ports", "-c"),
    "subzy": ("takeover", "--concurrency"),
    "dnsreaper": ("takeover", "--parallelism"),
    "subjack": ("takeover", "-t"),
}

#: Tools invoked by the audited wrappers that expose no rate, concurrency, or
#: delay flag at all. Verified by reading each binary's real ``--help``. These are
#: structurally ungovernable, and the wrappers that run them must say so.
UNGOVERNABLE = {
    "assetfinder": "subdomain_enum",
    "amass": "subdomain_enum",
    "asnmap": "asn_lookup",
    "whois": "whois_lookup",
    "cdncheck": "cdn_check",
    "git": "source_fetch",
}


def _spy(monkeypatch: pytest.MonkeyPatch, module: str) -> list[dict[str, Any]]:
    """Replace ``run_one`` in one tools module and record every argv built.

    The argv goes through the real sanitizer first, so a wrapper that passes a
    flag its own policy does not allow fails here rather than at runtime.
    """
    import importlib

    target = importlib.import_module(f"easyhunt.tools.{module}")
    calls: list[dict[str, Any]] = []

    async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
        spec = CATALOG[name]
        sanitize_argv(name, list(argv), policy=spec.arg_policy)
        calls.append({"tool": name, "argv": list(argv), **kwargs})
        return ToolRun(tool=name, ran=True, values=[], duration_s=0.1, exit_code=0)

    monkeypatch.setattr(target, "run_one", fake_run_one)
    return calls


def _argv_for(calls: list[dict[str, Any]], tool: str) -> list[str]:
    for call in calls:
        if call["tool"] == tool:
            return call["argv"]
    raise AssertionError(f"{tool} was never invoked; saw {[c['tool'] for c in calls]}")


def _value(argv: list[str], flag: str) -> str:
    assert flag in argv, f"{flag} missing from argv: {argv}"
    return argv[argv.index(flag) + 1]


def _approve(engagement: Any, tool: str) -> None:
    engagement.approval.backend = PolicyBackend(auto_approve={tool})


# --------------------------------------------------------------------------- #
# The rate passed is the engagement's rate — exactly
# --------------------------------------------------------------------------- #


class TestRpsFlagsEqualMaxRps:
    """Every requests-per-second flag equals ``max_rps``. No multiplier, no floor."""

    @pytest.mark.parametrize("rps", [0.5, 1, 6, 20])
    async def test_subfinder_rate_limit_tracks_the_engagement(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        engagement.scope.rules.max_rps = rps
        calls = _spy(monkeypatch, "recon")
        monkeypatch.setattr(
            "easyhunt.tools.recon._detect_wildcard",
            _no_wildcard,
        )
        await REGISTRY["subdomain_enum"].fn(target="example.com")

        argv = _argv_for(calls, "subfinder")
        assert _value(argv, "-rl") == str(max(1, int(rps)))

    @pytest.mark.parametrize("rps", [0.5, 1, 6, 20])
    async def test_dnsx_rate_limit_is_not_ten_times_the_ceiling(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        """Regression: ``-rl`` was ``int(max_rps * 10)``.

        Ten times a published ceiling is a violation with a comment next to it.
        """
        engagement.scope.rules.max_rps = rps
        calls = _spy(monkeypatch, "dns")
        await REGISTRY["dns_resolve"].fn(target="a.example.com,b.example.com")

        argv = _argv_for(calls, "dnsx")
        assert _value(argv, "-rl") == str(max(1, int(rps)))
        assert _value(argv, "-rl") != str(int(rps * 10))

    @pytest.mark.parametrize("rps", [0.5, 1, 6, 20])
    async def test_naabu_rate_is_not_twenty_times_the_ceiling(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        """Regression: ``-rate`` was ``min(1000, max(10, int(max_rps) * 20))``.

        Both halves were wrong. The multiplier exceeded the ceiling by 20x, and
        the ``max(10, ...)`` floor meant any program publishing fewer than 10 rps
        was ignored outright.
        """
        engagement.scope.rules.max_rps = rps
        _approve(engagement, "port_scan")
        calls = _spy(monkeypatch, "ports")
        await REGISTRY["port_scan"].fn(target="example.com")

        argv = _argv_for(calls, "naabu")
        assert _value(argv, "-rate") == str(max(1, int(rps)))
        assert _value(argv, "-rate") != str(int(rps) * 20)

    @pytest.mark.parametrize("rps", [0.5, 1, 6, 20])
    async def test_nmap_max_rate_is_not_ten_times_the_ceiling(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        engagement.scope.rules.max_rps = rps
        _approve(engagement, "service_scan")
        calls = _spy(monkeypatch, "ports")
        await REGISTRY["service_scan"].fn(target="example.com")

        argv = _argv_for(calls, "nmap")
        assert _value(argv, "--max-rate") == str(max(1, int(rps)))
        assert _value(argv, "--max-rate") != str(int(rps) * 10)

    @pytest.mark.parametrize("rps", [1, 6, 20])
    async def test_kingfisher_validation_rps_tracks_the_engagement(
        self, engagement, monkeypatch, rps: float, tmp_path: Path
    ) -> None:
        """``secret_validate`` sends one authenticated request per candidate.

        Before this audit ``--validation-rps`` was not passed at all, so a
        repository with 400 candidates issued 400 authenticated requests to third
        parties as fast as the machine managed.
        """
        engagement.scope.rules.max_rps = rps
        _approve(engagement, "secret_validate")
        (engagement.workspace / "src").mkdir(parents=True, exist_ok=True)
        calls = _spy(monkeypatch, "secrets")
        await REGISTRY["secret_validate"].fn(path="src")

        argv = _argv_for(calls, "kingfisher")
        assert _value(argv, "--validation-rps") == str(max(1, int(rps)))

    async def test_a_sub_one_rps_engagement_is_not_floored_away(
        self, engagement, monkeypatch
    ) -> None:
        """A program publishing 0.5 rps must not be rounded up to a floor of 10.

        This is the shape of the bug that matters most: the strictest programs are
        exactly the ones a ``max(10, ...)`` floor silently ignored.
        """
        engagement.scope.rules.max_rps = 0.5
        _approve(engagement, "port_scan")
        calls = _spy(monkeypatch, "ports")
        await REGISTRY["port_scan"].fn(target="example.com")

        rate = int(_value(_argv_for(calls, "naabu"), "-rate"))
        assert rate == 1, "sub-1-rps engagement was floored up"
        assert rate < 10


class TestConcurrencyFlagsEqualMaxConcurrency:
    """Concurrency ceilings come from the engagement, never from a literal."""

    @pytest.mark.parametrize("concurrency", [1, 2, 7])
    async def test_tlsx_concurrency_and_delay_track_the_engagement(
        self, engagement, monkeypatch, concurrency: int
    ) -> None:
        """tlsx defaults to **300** concurrent handshakes and was passed neither flag."""
        engagement.scope.rules.max_concurrency = concurrency
        engagement.scope.rules.max_rps = 4
        calls = _spy(monkeypatch, "recon")
        await REGISTRY["tls_info"].fn(target="example.com")

        argv = _argv_for(calls, "tlsx")
        assert _value(argv, "-c") == str(concurrency)
        # 1000ms / 4 rps
        assert _value(argv, "-delay") == "250ms"

    @pytest.mark.parametrize("concurrency", [1, 2, 7])
    async def test_dnsx_threads_track_the_engagement(
        self, engagement, monkeypatch, concurrency: int
    ) -> None:
        """dnsx defaults to 100 threads; ``-t`` was not passed at all."""
        engagement.scope.rules.max_concurrency = concurrency
        calls = _spy(monkeypatch, "dns")
        await REGISTRY["dns_resolve"].fn(target="a.example.com")

        assert _value(_argv_for(calls, "dnsx"), "-t") == str(concurrency)

    @pytest.mark.parametrize("concurrency", [1, 2, 7])
    async def test_takeover_detectors_share_the_engagement_concurrency(
        self, engagement, monkeypatch, concurrency: int
    ) -> None:
        """subzy was hardcoded at 10, subjack at 20, dnsReaper left at its 200 default."""
        engagement.scope.rules.max_concurrency = concurrency
        _approve(engagement, "takeover_detect")
        calls = _spy(monkeypatch, "takeover")
        await REGISTRY["takeover_detect"].fn(target="a.example.com,b.example.com")

        assert _value(_argv_for(calls, "subzy"), "--concurrency") == str(concurrency)
        assert _value(_argv_for(calls, "subjack"), "-t") == str(concurrency)
        assert _value(_argv_for(calls, "dnsreaper"), "--parallelism") == str(concurrency)

    async def test_no_takeover_detector_uses_a_literal_ceiling(
        self, engagement, monkeypatch
    ) -> None:
        """The old constants must not reappear when the engagement says otherwise."""
        engagement.scope.rules.max_concurrency = 3
        _approve(engagement, "takeover_detect")
        calls = _spy(monkeypatch, "takeover")
        await REGISTRY["takeover_detect"].fn(target="a.example.com")

        for call in calls:
            assert "10" not in call["argv"] or call["tool"] == "subdominator", (
                f"{call['tool']} still carries a hardcoded 10: {call['argv']}"
            )
            assert "20" not in call["argv"], (
                f"{call['tool']} still carries a hardcoded 20: {call['argv']}"
            )


# --------------------------------------------------------------------------- #
# The rate is not something a caller can choose
# --------------------------------------------------------------------------- #


AUDITED_TOOLS = (
    "subdomain_enum", "asn_lookup", "tls_info", "whois_lookup",
    "dns_resolve", "dns_permute", "cdn_check",
    "port_scan", "service_scan",
    "secret_scan", "secret_validate", "source_fetch",
    "takeover_detect", "takeover_verify", "takeover_poc_plan", "takeover_confirm",
)


class TestRateIsNotCallerControlled:
    @pytest.mark.parametrize("name", AUDITED_TOOLS)
    def test_no_wrapper_exposes_a_rate_argument(self, name: str) -> None:
        """A rate an agent can set is a rate an agent can raise."""
        import inspect

        params = set(inspect.signature(REGISTRY[name].fn).parameters)
        forbidden = {
            "rate", "rps", "max_rps", "rate_limit", "threads", "concurrency",
            "delay", "pause", "workers", "tasks", "parallelism", "jobs",
        }
        assert not (params & forbidden), (
            f"{name} lets the caller set {sorted(params & forbidden)}"
        )

    @pytest.mark.parametrize(("tool", "spec_flag"), sorted(RPS_FLAGS.items()))
    def test_every_rps_flag_is_capped_by_its_own_policy(
        self, tool: str, spec_flag: tuple[str, str]
    ) -> None:
        """Setting the flag is not enough — the policy must also refuse a bigger one.

        The wrapper is the only caller today, but ``guarded_run`` re-sanitizes any
        argv built from parsed tool output, and that is the path where a rate could
        be reintroduced without anyone editing a wrapper.
        """
        from easyhunt.errors import SanitizeError

        _, flag = spec_flag
        policy = CATALOG[tool].arg_policy
        assert policy is not None
        assert flag in policy.allowed_flags, f"{tool} {flag} is not on its own allowlist"
        assert flag in policy.numeric_caps, f"{tool} {flag} has no numeric cap"

        with pytest.raises(SanitizeError):
            sanitize_argv(tool, [flag, "999999"], policy=policy)


# --------------------------------------------------------------------------- #
# Where nothing can be governed, the tool says so
# --------------------------------------------------------------------------- #


class TestEveryWrapperArgvSurvivesItsOwnPolicy:
    """A command line refused by its own sanitizer is a tool that never runs.

    ``run_one`` catches the refusal and returns ``ToolRun(ran=False)``, which every
    wrapper renders as "this tool found nothing" — indistinguishable from a clean
    result. Found by this file: every ``dig`` invocation in ``takeover.py`` was
    refused, because the sanitizer's flag detector only recognises ``-``-prefixed
    flags and dig's ``+short`` fell through to a positional pattern that rejected
    it. ``takeover_verify`` therefore returned ``verified: False`` for every host
    it was ever given.
    """

    def test_dig_query_options_are_accepted(self) -> None:
        argv = ["+short", "+time", "3", "+tries", "2", "a.example.com", "CNAME"]
        sanitize_argv("dig", argv, policy=CATALOG["dig"].arg_policy)

    def test_dig_still_refuses_an_unlisted_plus_option(self) -> None:
        """Widening the pattern must not turn it into 'anything starting with +'."""
        from easyhunt.errors import SanitizeError

        with pytest.raises(SanitizeError):
            sanitize_argv("dig", ["+trace"], policy=CATALOG["dig"].arg_policy)

    async def test_takeover_verify_can_actually_verify(
        self, engagement, monkeypatch
    ) -> None:
        """The end-to-end consequence: a CNAME lookup that returns something."""
        import easyhunt.tools.takeover as tk

        async def fake_run_one(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
            sanitize_argv(name, list(argv), policy=CATALOG[name].arg_policy)
            record = argv[-1]
            return ToolRun(
                tool=name,
                ran=True,
                values=["target.s3.amazonaws.com"] if record == "CNAME" else [],
            )

        monkeypatch.setattr(tk, "run_one", fake_run_one)

        class _Response:
            status_code = 404
            text = "NoSuchBucket"

        class _Client:
            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *exc: object) -> None:
                return None

            async def get(self, url: str) -> _Response:
                return _Response()

        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: _Client())
        result = await REGISTRY["takeover_verify"].fn(target="a.example.com")

        assert result["checks"]["cname_present"] is True, (
            "the CNAME lookup returned nothing — dig was refused by its own policy again"
        )


class TestUngovernedToolsAreDeclared:
    """A tool with no rate flag is not a tool that is safely paced.

    The failure mode this guards against is silence: a wrapper that runs an
    ungovernable binary and carries no note reads, to an operator at the approval
    gate, exactly like one that is fully paced.
    """

    @pytest.mark.parametrize(("binary", "wrapper"), sorted(UNGOVERNABLE.items()))
    def test_the_wrapper_admits_the_gap(self, binary: str, wrapper: str) -> None:
        notes = " ".join(REGISTRY[wrapper].risk_notes).lower()
        assert notes, f"{wrapper} runs ungovernable {binary} and carries no risk_notes"
        assert "ungoverned" in notes or "no rate" in notes, (
            f"{wrapper} runs {binary}, which has no rate flag, without saying so: {notes}"
        )

    def test_takeover_detect_declares_it_has_no_rps_ceiling(self) -> None:
        """Concurrency is not a rate limit, and the note must not imply it is."""
        notes = " ".join(REGISTRY["takeover_detect"].risk_notes)
        assert "requests-per-second flag" in notes
        assert "max_concurrency" in notes

    def test_findomain_delay_is_not_described_as_a_rate_limit(self) -> None:
        """``--rate-limit`` is seconds *between targets*, not requests per second."""
        notes = " ".join(REGISTRY["subdomain_enum"].risk_notes)
        assert "delay between targets" in notes
        assert "per-request rate" in notes


class TestEstimatedRequestsAreHonest:
    """``estimated_requests`` is the budget reservation, so a placeholder overspends.

    These are floors, not exact figures — the real count scales with the host or
    port list. The point is that none of them is the old round number that was
    chosen to look tidy.
    """

    @pytest.mark.parametrize(
        ("tool", "floor", "was"),
        [
            ("dns_permute", 20_000, 5_000),      # one query per permutation
            ("port_scan", 10_000, 1_000),        # hosts x ports
            ("takeover_detect", 2_000, 200),     # 4 detectors x every host
            ("secret_validate", 500, 50),        # one request per candidate
            ("dns_resolve", 600, 100),           # hosts x record types
        ],
    )
    def test_estimate_is_no_longer_a_placeholder(
        self, tool: str, floor: int, was: int
    ) -> None:
        estimate = REGISTRY[tool].estimated_requests
        assert estimate is not None
        assert estimate >= floor, f"{tool} still estimates {estimate}"
        assert estimate != was, f"{tool} still carries its placeholder {was}"

    def test_tools_that_send_nothing_still_estimate_zero(self) -> None:
        """Honesty runs both ways — inflating a local scan wastes the budget."""
        assert REGISTRY["secret_scan"].estimated_requests == 0
        assert REGISTRY["takeover_poc_plan"].estimated_requests == 0


# --------------------------------------------------------------------------- #
# The requests we issue ourselves take a token each
# --------------------------------------------------------------------------- #


class TestInProcessRequestsAreCharged:
    """Requests issued from our own process can be governed properly, so they are.

    This is the contrast that makes the rest of the file necessary: ``httpx`` in
    our event loop takes a limiter token per request, and a subprocess with its own
    thread pool cannot be made to.
    """

    async def test_takeover_verify_charges_each_http_request(
        self, engagement, monkeypatch
    ) -> None:
        granted_before = engagement.limiter.stats()["requests_granted"]
        _spy(monkeypatch, "takeover")

        class _Response:
            status_code = 200
            text = "nothing here"

        class _Client:
            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *exc: object) -> None:
                return None

            async def get(self, url: str) -> _Response:
                return _Response()

        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: _Client())
        await REGISTRY["takeover_verify"].fn(target="a.example.com")

        granted = engagement.limiter.stats()["requests_granted"] - granted_before
        # One for the tool call itself, at least one for the fetch.
        assert granted >= 2, "takeover_verify's HTTP fetch was not charged"

    async def test_wildcard_probe_is_charged_per_query(
        self, engagement, monkeypatch
    ) -> None:
        """Three DNS probes that used to bypass the limiter and the sandbox.

        ``_detect_wildcard`` called ``asyncio.create_subprocess_exec`` directly.
        Three queries is not a lot, but "the limiter never saw it" is the whole
        class of bug this file exists for, and it was in the codebase.
        """
        from easyhunt.tools.recon import _detect_wildcard

        calls = _spy(monkeypatch, "recon")
        granted_before = engagement.limiter.stats()["requests_granted"]
        result = await _detect_wildcard("example.com", probes=3)

        granted = engagement.limiter.stats()["requests_granted"] - granted_before
        assert granted >= 3, "wildcard DNS probes were not charged to the limiter"
        assert [c["tool"] for c in calls] == ["dig"] * 3
        assert result["checked"] is True

    async def test_wildcard_probe_reports_when_dig_is_absent(
        self, engagement, monkeypatch
    ) -> None:
        """A missing dig must not read as 'this domain has no wildcard'."""
        import easyhunt.tools.recon as recon

        async def absent(name: str, argv: list[str], **kwargs: Any) -> ToolRun:
            return ToolRun(tool=name, ran=False, error="not installed")

        monkeypatch.setattr(recon, "run_one", absent)
        result = await recon._detect_wildcard("example.com", probes=3)

        assert result["checked"] is False
        assert result["wildcard"] is False


async def _no_wildcard(seed: str, probes: int = 3) -> dict[str, Any]:
    return {"wildcard": False, "addresses": [], "probes": probes, "answered": 0, "checked": True}


class TestArchiveAndInjectionFlagsTrackTheEngagement:
    """The wrappers the first rate pass missed.

    naabu, dnsx, nmap and tlsx were fixed when the multiplier bug was found.
    These six were not, because nobody grepped for the *absence* of a rate flag —
    only for wrong ones. A tool that never had a rate argument looks correct in a
    diff and is exactly as ungoverned as one multiplying by twenty.
    """

    @pytest.mark.parametrize("concurrency", [1, 3, 20])
    async def test_gau_threads_track_max_concurrency(
        self, engagement, monkeypatch, concurrency: int
    ) -> None:
        """Regression: ``--threads`` was the literal "5"."""
        engagement.scope.rules.max_concurrency = concurrency
        calls = _spy(monkeypatch, "endpoints")
        await REGISTRY["endpoint_discovery"].fn(target="example.com")

        assert _value(_argv_for(calls, "gau"), "--threads") == str(min(concurrency, 20))

    @pytest.mark.parametrize("concurrency", [1, 3, 20])
    async def test_waymore_parallelism_tracks_max_concurrency(
        self, engagement, monkeypatch, concurrency: int
    ) -> None:
        """Regression: ``-p`` was the literal "5". Clamped to its cap of 10."""
        engagement.scope.rules.max_concurrency = concurrency
        calls = _spy(monkeypatch, "endpoints")
        await REGISTRY["endpoint_discovery"].fn(target="example.com")

        assert _value(_argv_for(calls, "waymore"), "-p") == str(min(concurrency, 10))

    @pytest.mark.parametrize("rps,concurrency", [(0.5, 1), (2, 4), (20, 20)])
    async def test_arjun_had_no_rate_argument_at_all(
        self, engagement, monkeypatch, rps: float, concurrency: int
    ) -> None:
        """Regression: ``-t`` was the literal "10" and ``-d`` was never passed.

        arjun fans out over its own thread pool, so with no delay it ran at
        whatever ten threads could manage regardless of what the program
        published.
        """
        engagement.scope.rules.max_rps = rps
        engagement.scope.rules.max_concurrency = concurrency
        calls = _spy(monkeypatch, "endpoints")
        _approve(engagement, "param_discovery")
        await REGISTRY["param_discovery"].fn(target="https://www.example.com/")

        argv = _argv_for(calls, "arjun")
        assert _value(argv, "-t") == str(min(concurrency, 15))
        assert "-d" in argv, "arjun ran with no inter-request delay"
        assert float(_value(argv, "-d")) == pytest.approx(min(round(1 / rps, 2), 10))

    @pytest.mark.parametrize("rps", [0.5, 2, 20])
    async def test_sqlmap_delay_and_threads_track_the_engagement(
        self, engagement, monkeypatch, rps: float
    ) -> None:
        """Regression: ``--threads 2 --delay 1``, both literals."""
        engagement.scope.rules.max_rps = rps
        engagement.scope.rules.max_concurrency = 4
        calls = _spy(monkeypatch, "exploitation")
        _approve(engagement, "sqli_validate")
        await REGISTRY["sqli_validate"].fn(target="https://www.example.com/?id=1")

        argv = _argv_for(calls, "sqlmap")
        assert _value(argv, "--threads") == str(min(4, 5))
        assert float(_value(argv, "--delay")) == pytest.approx(min(round(1 / rps, 2), 5))

    @pytest.mark.parametrize("probe,tool", [("ssti_probe", "sstimap"), ("cmdi_probe", "commix")])
    @pytest.mark.parametrize("rps", [0.5, 2, 20])
    async def test_injection_probe_delays_track_the_engagement(
        self, engagement, monkeypatch, probe: str, tool: str, rps: float
    ) -> None:
        """Regression: both passed ``--delay 1``, right only at exactly 1 rps."""
        engagement.scope.rules.max_rps = rps
        calls = _spy(monkeypatch, "injection")
        _approve(engagement, probe)
        await REGISTRY[probe].fn(target="https://www.example.com/?q=1")

        argv = _argv_for(calls, tool)
        assert float(_value(argv, "--delay")) == pytest.approx(min(round(1 / rps, 2), 5))

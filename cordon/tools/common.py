"""Shared plumbing for atomic tool wrappers.

Two ideas keep the wrapper layer small:

**A catalog, not forty MCP tools.** Every wrapped binary gets a :class:`ToolSpec`
entry in :data:`CATALOG` — that is what ``cordon doctor`` reports on and where
each tool's license is recorded. But the *MCP* surface groups them by job:
``subdomain_enum`` runs whichever of subfinder/assetfinder/findomain are present
and merges the results. An agent choosing between four subdomain tools is an
agent spending tokens on a decision that has one right answer: run them all.

**Missing tools degrade, they do not fail.** A wrapper runs the tools it finds and
reports which ones were absent, so a partial install still produces useful recon
instead of an error.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from cordon.control_plane.context import get_engagement
from cordon.knowledge.findings import Asset
from cordon.tools.base import ToolSpec, guarded_run
from cordon.util.parse import host_of
from cordon.util.run import ProcResult

__all__ = [
    "CATALOG",
    "ToolRun",
    "VerifyVerdict",
    "register_spec",
    "run_many",
    "split_targets",
    "resolve_binary",
    "store_assets",
    "verify_identity",
    "verify_output",
]

CATALOG: dict[str, ToolSpec] = {}


def register_spec(spec: ToolSpec) -> ToolSpec:
    """Add a tool to the catalog (and register its argument policy)."""
    CATALOG[spec.name] = spec
    return spec


def installed(name: str) -> bool:
    """Whether a usable copy of this tool is present.

    For tools with a name collision this means *the correct binary*, wherever it
    sits on PATH — a Python CLI called ``httpx`` does not count as httpx being
    installed.
    """
    spec = CATALOG.get(name)
    if spec is None:
        return False
    if spec.binary:
        if spec.identity_marker:
            if resolve_binary(name) is not None:
                return True
        elif shutil.which(spec.binary):
            return True
    if spec.package:
        import importlib.util

        return importlib.util.find_spec(spec.package.replace("-", "_")) is not None
    return False


def _candidates(binary: str) -> list[str]:
    """Every executable of this name on PATH, in order, deduplicated."""
    found: list[str] = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            resolved = os.path.realpath(candidate)
            if resolved not in {os.path.realpath(f) for f in found}:
                found.append(candidate)
    return found


def _identifies_as(binary: str, spec: ToolSpec) -> bool:
    """Whether running this binary produces the tool's identity marker."""
    marker = (spec.identity_marker or "").lower()
    for args in (spec.version_args, ["--version"], ["-version"], ["version"], ["-h"]):
        try:
            proc = subprocess.run(  # noqa: S603
                [binary, *args], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout + proc.stderr).lower()
        if output.strip() and marker in output:
            return True
    return False


@lru_cache(maxsize=128)
def resolve_binary(name: str) -> str | None:
    """The path to the *correct* binary for this tool, ignoring PATH order.

    Several security tools share a name with unrelated software. ``httpx`` is
    both ProjectDiscovery's prober and the Python HTTP library's CLI, and which
    one ``shutil.which`` returns depends on how the operator's PATH happens to be
    ordered. Picking the wrong one is the worst failure mode available to a recon
    tool: it exits zero, prints nothing, and looks exactly like a target with no
    live hosts.

    So for any tool declaring an ``identity_marker``, every candidate on PATH is
    executed once and the first that identifies itself correctly wins. Tools
    without a marker resolve normally. Cached — this spawns processes.
    """
    spec = CATALOG.get(name)
    if spec is None or not spec.binary:
        return None

    if not spec.identity_marker:
        return shutil.which(spec.binary)

    candidates = _candidates(spec.binary)
    for candidate in candidates:
        if _identifies_as(candidate, spec):
            return candidate
    # Nothing identified correctly; report absence rather than run an impostor.
    return None


@lru_cache(maxsize=128)
def verify_identity(name: str) -> tuple[bool, str]:
    """Confirm a correct binary for this tool exists somewhere on PATH.

    Returns ``(ok, detail)``. Tools that declare no ``identity_marker`` are
    assumed correct.
    """
    spec = CATALOG.get(name)
    if spec is None:
        return False, "not in catalog"
    if not spec.identity_marker or not spec.binary:
        return True, "no identity marker declared"

    candidates = _candidates(spec.binary)
    if not candidates:
        return False, "not installed"

    resolved = resolve_binary(name)
    if resolved is None:
        listed = ", ".join(candidates[:3])
        return False, (
            f"none of the {len(candidates)} {spec.binary!r} on PATH look like {name} "
            f"(expected {spec.identity_marker!r} in the version output). Found: {listed}"
        )

    first = candidates[0]
    if os.path.realpath(resolved) != os.path.realpath(first):
        # Correct binary found, just not the one PATH would have picked.
        return True, f"verified at {resolved} (shadowed on PATH by {first})"
    return True, "verified"


@dataclass
class ToolRun:
    """Outcome of one binary's execution inside a grouped wrapper."""

    tool: str
    ran: bool
    values: list[str] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0
    exit_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "ran": self.ran,
            "found": len(self.values),
            "error": self.error,
            "duration_s": round(self.duration_s, 1),
        }


def _available_in_sandbox(name: str) -> bool:
    """True when the tool has a working container home, even if the host lacks it.

    Deliberately conservative: an image mapping alone is not enough, because the
    Dockerfile's per-tool installs are failure-tolerant and produce an image that
    is missing roughly 29 of the tools it tried to install. ``binary_in_image``
    actually probes, so a mapping to an image without the binary reads as absent
    rather than launching a container that exits 127.
    """
    from cordon.control_plane.context import current_engagement

    engagement = current_engagement()
    sandbox = getattr(engagement, "sandbox", None)
    if sandbox is None or not sandbox.runtime_available():
        return False
    try:
        image = sandbox.image_for(name)
        if not image:
            return False
        spec = CATALOG.get(name)
        binary = (spec.binary if spec else None) or name
        # Signature is (image, binary) — passing them the other way round reports
        # every tool as absent, which is indistinguishable from the bug this
        # function exists to fix.
        return sandbox.binary_in_image(image, binary)
    except Exception:  # noqa: BLE001 — a probe failure must not mask the tool
        return False


def subprocess_timeout_for(hosts: list[str], rps: int, *, minimum: float = 300.0) -> float:
    """A subprocess timeout that fits the work, not a constant.

    dnsx and httpx pace themselves with ``-rl`` at the engagement's ceiling, so
    N hosts at R rps need N/R seconds minimum. Hard-coded timeouts (600s for
    dnsx, 800s for httpx) silently killed the run when the input outgrew them:
    the tool was cut down mid-scan, its partial output discarded, and the phase
    reported "0 resolved" for a 60k-subdomain estate. Scale by input size with
    a generous safety factor, floored at the old constants so small runs are
    unchanged.
    """
    if not hosts or rps < 1:
        return minimum
    return max(minimum, (len(hosts) / rps) * 3 + 60)


async def run_one(
    name: str,
    argv: list[str],
    *,
    timeout: float = 300.0,
    stdin: str | None = None,
    extract: Callable[[ProcResult], list[str]] | None = None,
    allow_codes: tuple[int, ...] = (0,),
) -> ToolRun:
    """Run one catalog tool, capturing failure rather than propagating it."""
    spec = CATALOG.get(name)
    if spec is None:
        return ToolRun(tool=name, ran=False, error="not in catalog")
    # Host PATH is not the only home a tool can have. Ten tools live only inside
    # cordon:latest — smuggler, sstimap, nosqli, jwt_tool, testssl, websocat,
    # graphql-cop, corscanner, ssrfmap, medusa — and gating solely on the host
    # left every one of them reporting "not installed" while sitting in a
    # container the sandbox was ready to launch. Capability present, silently
    # unused: the same defect this file keeps producing.
    if not installed(name) and not _available_in_sandbox(name):
        return ToolRun(tool=name, ran=False, error="not installed")

    try:
        result = await guarded_run(
            spec, argv, timeout=timeout, stdin=stdin, output_name=name,
            allow_codes=allow_codes, check=False,
        )
    except Exception as exc:  # noqa: BLE001 — one absent tool must not sink the group
        return ToolRun(tool=name, ran=False, error=str(exc))

    if result.timed_out:
        return ToolRun(tool=name, ran=True, error="timed out", duration_s=result.duration_s)

    values = extract(result) if extract else lines_of(result.stdout)
    return ToolRun(
        tool=name,
        ran=True,
        values=values,
        duration_s=result.duration_s,
        exit_code=result.exit_code,
        error=None if result.exit_code in allow_codes else (result.stderr or "")[-300:],
    )


async def run_many(runs: Iterable[Any]) -> list[ToolRun]:
    """Run several tools concurrently. The rate limiter still governs the total."""
    return list(await asyncio.gather(*runs))


def lines_of(text: str, *, limit: int = 100_000) -> list[str]:
    """Non-empty, non-banner lines from a tool's stdout."""
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        # ProjectDiscovery tools print banners and [INF]/[WRN] lines to stdout.
        if not stripped or stripped.startswith(("[INF]", "[WRN]", "[ERR]", "[FTL]", "__")):
            continue
        out.append(stripped)
        if len(out) >= limit:
            break
    return out


def split_targets(target: str | list[str]) -> list[str]:
    if isinstance(target, list):
        items = target
    else:
        items = target.replace("\n", ",").split(",")
    return [t.strip() for t in items if t and t.strip()]


#: What a phase reads when the caller does not name a target. The engagement's
#: asset store already deduplicates across tools — `values(kind)` is the union
#: of every subdomain subfinder, amass, assetfinder and findomain found, minus
#: anything the scope engine rejected.
AUTO = {"", "auto", "-"}


def targets_or_assets(
    target: str | list[str], *, kind: str, tool: str, limit: int = 5000
) -> tuple[list[str], str]:
    """Resolve a phase's input: the caller's targets, or the previous phase's output.

    Returns ``(targets, origin)`` where origin is "argument" or
    "assets:<kind>", so a wrapper can say in its result where its input came
    from. A pipeline that silently scans the wrong set is worse than one that
    scans nothing, and "which hosts did this actually cover" is the first
    question anyone asks of a report.

    Why this exists: every stage deduplicated its own output correctly, and
    nothing passed that output to the next stage. A full ten-phase run left 52
    assets, all of one kind, because the driver handed every phase the same
    hostname instead of chaining. The components were right; the conveyor
    between them was missing.
    """
    explicit = split_targets(target) if target else []
    if explicit and not (len(explicit) == 1 and explicit[0].lower() in AUTO):
        return explicit, "argument"

    engagement = get_engagement()
    inherited = engagement.assets.values(kind)[:limit]
    engagement.audit.record(
        "targets_inherited", tool=tool, kind=kind, count=len(inherited)
    )
    return inherited, f"assets:{kind}"


def in_scope_only(values: Iterable[str], *, phase: str, tool: str) -> tuple[list[str], int]:
    """Filter tool output through the scope engine.

    Recon tools routinely return hosts the target does not own — a certificate
    covering several organizations, a shared CDN name. Those are dropped here so
    they can never become the input to a later active scan.
    """
    engagement = get_engagement()
    kept: list[str] = []
    dropped = 0
    for value in values:
        if engagement.scope.check(value).in_scope:
            kept.append(value)
        else:
            dropped += 1
    if dropped:
        engagement.audit.record(
            "results_filtered", tool=tool, phase=phase, dropped=dropped, kept=len(kept)
        )
    return kept, dropped


def store_assets(
    values: Iterable[str], *, kind: str, source: str, tags: list[str] | None = None,
    hosts: dict[str, str] | None = None,
    attributes: dict[str, dict[str, Any]] | None = None,
) -> int:
    """Persist discovered assets.

    ``hosts`` optionally binds specific values to their origin host. Relative
    paths (JS routes, endpoints) carry no host of their own, so ``host_of``
    would return the path itself; the caller that knows where the value was
    found (the bundle that served it) passes the binding so the exploit chain
    does not resolve every endpoint against every live host.

    ``attributes`` optionally attaches per-value scalars (title, tech,
    content_length, status…) so later phases — ``recon_review`` ranking hosts
    for manual testing — can consume probe results without re-probing.
    """
    engagement = get_engagement()
    attrs = attributes or {}
    return engagement.assets.add_many(
        Asset(
            value=value, kind=kind, source=source,
            host=(hosts or {}).get(value) or host_of(value),
            tags=list(tags or []),
            attributes=dict(attrs.get(value) or {}),
        )
        for value in values
    )


def merge_runs(runs: list[ToolRun]) -> list[str]:
    """Union of every tool's output, deduplicated and sorted."""
    merged: set[str] = set()
    for run in runs:
        merged.update(v.strip().lower().rstrip(".") for v in run.values if v.strip())
    return sorted(merged)


def grouped_result(
    *,
    kind: str,
    runs: list[ToolRun],
    values: list[str],
    dropped: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Uniform return shape for grouped wrappers."""
    missing = [r.tool for r in runs if not r.ran and r.error == "not installed"]
    payload: dict[str, Any] = {
        "ok": True,
        "kind": kind,
        "count": len(values),
        kind: values,
        "dropped_out_of_scope": dropped,
        "tools": [r.to_dict() for r in runs],
    }
    if missing:
        payload["tools_not_installed"] = missing
        payload["coverage_note"] = (
            f"{len(missing)} tool(s) absent — results are partial. Install them or "
            "run 'cordon doctor' to see what is missing."
        )

    # "Found nothing" and "found things, all of them out of scope" are different
    # answers, and they were reported identically: an empty list and no message.
    # Measured on a live run — subfinder returned a result, the scope filter
    # dropped it, and the phase reported `subdomains: []` with nothing to say.
    #
    # The distinction matters because the fixes are opposite. Nothing found means
    # look somewhere else; everything filtered means your scope is narrower than
    # your seed, which is usually a seed mistake — enumerating subdomains of a
    # HOST rather than of a domain is the common case.
    found = sum(len(r.values) for r in runs)
    if not values and dropped:
        payload["message"] = (
            f"{found} result(s) found and all {dropped} were dropped as out of scope. "
            "This is not an empty result — it is a scope mismatch. Check that the "
            "seed is a registrable domain rather than a single host, and that the "
            "hosts you expect are actually listed in scope.yaml."
        )
        payload["complete"] = False
    elif not values and not found:
        payload["message"] = (
            "No results from any source. Every tool ran and returned nothing — "
            "check `tools` below for one that failed rather than found nothing."
        )
    if extra:
        payload.update(extra)
    return payload


# Shared value patterns for argument policies.
HOST_PATTERN = re.compile(r"[A-Za-z0-9._*:/-]{1,253}")
URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]{1,2000}")
PORT_PATTERN = re.compile(r"[0-9,\-]{1,64}")
PATH_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,512}")


# --------------------------------------------------------------------------- #
# Output verification — "absence ≠ negative" made machine-enforced
# --------------------------------------------------------------------------- #

#: Verdict a wrapper attaches to a tool run that returned nothing or failed.
class VerifyVerdict:
    __slots__ = ("status", "hint")

    def __init__(self, status: str, hint: str = "") -> None:
        #: ok | suspicious | empty | failed
        self.status = status
        #: Corrected-command hint, when the fix is a flag change.
        self.hint = hint

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "hint": self.hint}

    def __bool__(self) -> bool:
        return self.status == "ok"


#: Per-tool post-checks. Each entry is a callable ``(argv, exit_code, stdout) ->
#: VerifyVerdict``. Ported in concept from autopentest-ai's ``tool_verification.py``
#: (MIT, bhavsec): the invariant "a tool that produced no output proves nothing"
#: is enforced per binary, with a corrected-command hint when the cause is a flag
#: rather than an absent vulnerability.
_VERIFIERS: dict[str, Any] = {}


def _verify_nmap(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    if "Host is up" not in stdout and "1 host up" not in stdout:
        return VerifyVerdict(
            "suspicious",
            "nmap reported no live host — if the target drops ICMP, add -Pn "
            "(host discovery off) so the port scan still runs.",
        )
    return VerifyVerdict("ok")


def _verify_nuclei(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    # A result carrying findings is a result. The check below must only look at
    # genuinely empty output — the previous heuristic treated any stdout that
    # merely *contained* the strings "{" and "results" and "}" as empty, so a
    # successful scan printing real findings was reported UNTESTED.
    try:
        parsed = json.loads(stdout.strip()) if stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    has_results = bool(parsed) if isinstance(parsed, (list, dict)) else bool(stdout.strip())
    if not has_results:
        return VerifyVerdict(
            "suspicious",
            "nuclei returned an empty result set — verify the template library "
            "is mounted (~/nuclei-templates) and the run actually scanned, not "
            "that the estate is clean.",
        )
    return VerifyVerdict("ok")


def _verify_sqlmap(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    lowered = stdout.lower()
    if "no parameter" in lowered and "injectable" not in lowered:
        return VerifyVerdict(
            "suspicious",
            "sqlmap found no injectable parameter — if the target sits behind a "
            "WAF, re-run with a bypass boundary (sqli_validate bypass_vendor) or "
            "raise --level. An empty result here means UNTESTED for a WAF-filtered "
            "parameter, not clean.",
        )
    if "all tested parameters" in lowered and "injectable" not in lowered:
        return VerifyVerdict("suspicious", "sqlmap tested parameters but none injectable — genuine negative.")
    return VerifyVerdict("ok")


def _verify_dalfox(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    if not stdout.strip():
        return VerifyVerdict(
            "empty",
            "dalfox produced no output — check the binary ran (it is silent on "
            "absence) and whether a headless browser exists for DOM XSS.",
        )
    return VerifyVerdict("ok")


def _verify_ffuf(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    # The check asks "did this run produce output I can read". ffuf writes its
    # results to the file given by -o when -of json is set, so stdout silence is
    # expected there — the wrapper reads the output file, not stdout. Only a
    # run with NO -o whose stdout is empty is suspicious.
    if not stdout.strip() and "-o" not in " ".join(argv):
        return VerifyVerdict(
            "empty",
            "ffuf found nothing — confirm the wordlist resolves and -ac is not "
            "filtering everything as the catch-all page.",
        )
    return VerifyVerdict("ok")


def _verify_commix(argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    lowered = stdout.lower()
    if "not vulnerable" in lowered or "no injection point" in lowered:
        return VerifyVerdict("suspicious", "commix reports no injection point — genuine negative under its payload set.")
    return VerifyVerdict("ok")


#: Wire the verifiers above to catalog tool names.
_VERIFIER_TABLE: dict[str, Any] = {
    "nmap": _verify_nmap,
    "nuclei": _verify_nuclei,
    "sqlmap": _verify_sqlmap,
    "dalfox": _verify_dalfox,
    "ffuf": _verify_ffuf,
    "commix": _verify_commix,
}


def register_verifier(tool: str, verifier: Any) -> None:
    """Attach a custom verifier to a catalog tool (plugins, operator tools)."""
    _VERIFIER_TABLE[tool] = verifier


def verify_output(tool: str, argv: list[str], exit_code: int, stdout: str) -> VerifyVerdict:
    """Post-check one tool run: empty/failed ⇒ UNTESTED, with a fix hint.

    Wrappers call this after ``run_one``; a non-``ok`` verdict should be recorded
    in the wrapper's result (``untested`` + hint) instead of reading as a clean
    negative. Tools without a registered verifier default to ``ok`` — the
    registry covers the scanners whose silence is ambiguous, not everything.
    """
    verifier = _VERIFIER_TABLE.get(tool)
    if verifier is None:
        return VerifyVerdict("ok")
    try:
        return verifier(list(argv), int(exit_code or 0), stdout or "")
    except Exception:  # noqa: BLE001 — a verifier bug must not crash the scan
        return VerifyVerdict("ok")

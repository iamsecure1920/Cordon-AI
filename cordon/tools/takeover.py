"""Subdomain takeover — detected, then *verified*, then proven.

Three steps, and skipping the middle one is how takeover reports get closed as
informative:

1. **Enumerate** — subdomains from BBOT or passive recon.
2. **Detect** — subzy / dnsReaper / nuclei takeover templates / BBOT's baddns
   produce *candidates*. Every one of these tools reports false positives,
   because they mostly match on a response body.
3. **Verify** — resolve the CNAME chain, fetch the live page, and match the
   unclaimed-service fingerprint from the can-i-take-over-xyz data. All three
   have to agree. A fingerprint on a host whose CNAME still resolves to a live
   resource is a hosting provider's empty-project page, not a vulnerability.

NS and MX takeovers are graded higher than a CNAME on a marketing page: one gives
an attacker the whole zone, the other gives them mail.

Cordon never registers a resource on a third-party provider. ``takeover_poc_plan``
writes out exactly what a human should do, and ``takeover_confirm`` verifies and
records the proof once they have done it. That boundary is deliberate — claiming
a resource is an action with consequences at a provider Cordon has no
relationship with.

**Rate governance.** ``takeover_detect`` is the heaviest tool in this module: four
detectors, each handed the whole host list, each fetching every host. None of them
has a requests-per-second flag — the best any of them offers is a concurrency or
parallelism ceiling, which bounds simultaneity but not rate. Those ceilings are
now taken from ``scope.rules.max_concurrency`` instead of the hardcoded 10 and 20
that were there before; the residual gap is declared in the tool's ``risk_notes``
rather than papered over.

``takeover_verify`` and ``takeover_confirm`` use httpx directly and take a limiter
token per request via ``engagement.limiter.slot``. That is the pattern that
actually works, and it works precisely because the request is issued in our
process rather than inside someone else's thread pool.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets as secrets_mod
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from cordon.control_plane.context import get_engagement
from cordon.control_plane.sanitize import ArgPolicy
from cordon.errors import CordonError
from cordon.knowledge.findings import Evidence, Finding, PoC, Severity, Status
from cordon.tools.base import ToolSpec, cordon_tool
from cordon.tools.common import HOST_PATTERN, register_spec, run_one, split_targets

__all__ = ["takeover_confirm", "takeover_detect", "takeover_poc_plan", "takeover_verify"]

FINGERPRINT_FILE = Path(__file__).resolve().parent.parent / "data" / "takeover_fingerprints.json"

SUBZY = register_spec(
    ToolSpec(
        name="subzy", binary="subzy", license="MIT",
        homepage="https://github.com/PentestPad/subzy", version_args=["version"],
        arg_policy=ArgPolicy(
            tool="subzy",
            allowed_flags={"--targets", "--target", "--concurrency", "--timeout", "--output", "--hide_fails", "--https", "--vuln"},
            boolean_flags={"--hide_fails", "--https", "--vuln"},
            value_patterns={"--target": HOST_PATTERN},
            numeric_caps={"--concurrency": 20, "--timeout": 30},
            allow_positional=True,
            positional_pattern=re.compile(r"run|version"),
        ),
    )
)

DNSREAPER = register_spec(
    ToolSpec(
        name="dnsreaper", binary="dnsreaper", license="GPL-3.0",
        homepage="https://github.com/punk-security/dnsReaper", version_args=["--help"],
        arg_policy=ArgPolicy(
            tool="dnsreaper",
            # --filename, not --domain-csv. dnsReaper's `file` provider names its
            # input --filename; --domain-csv belongs to no provider at all, so
            # every call exited 2 with "unrecognized arguments" and the wrapper
            # read it as a scan that found nothing. Measured against the lab.
            allowed_flags={"--domain", "--filename", "--out", "--out-format", "--parallelism", "--signature"},
            value_patterns={
                "--domain": HOST_PATTERN,
                "--out-format": re.compile(r"json|csv"),
                "--signature": re.compile(r"[a-z0-9_,-]{1,120}"),
            },
            numeric_caps={"--parallelism": 30},
            allow_positional=True,
            positional_pattern=re.compile(r"single|file|aws|cloudflare"),
        ),
    )
)

DIG = register_spec(
    ToolSpec(
        name="dig", binary="dig", license="MPL-2.0", homepage="https://www.isc.org/bind/",
        version_args=["-v"],
        arg_policy=ArgPolicy(
            tool="dig",
            # These entries are inert and kept only as documentation. The
            # sanitizer's flag detector is `^--?[A-Za-z0-9]...`, so dig's
            # `+`-style query options are never recognised as flags at all — they
            # fall through to the positional check below. Listing them here looks
            # like an allowlist and is not one.
            #
            # That gap was not cosmetic: `positional_pattern` did not accept a
            # leading `+`, so *every* dig invocation in this module was refused by
            # its own policy. `run_one` swallows the refusal into
            # `ToolRun(ran=False)`, so `_dig` returned an empty list every time,
            # `checks["cname_present"]` was always False, and `takeover_verify`
            # could never verify anything. A tool that always says "not a
            # candidate" looks exactly like a clean estate.
            allowed_flags={"+short", "+noall", "+answer", "+nocomments", "+time", "+tries"},
            boolean_flags={"+short", "+noall", "+answer", "+nocomments"},
            allow_positional=True,
            positional_pattern=re.compile(
                # The `+` options this module actually uses, named explicitly
                # rather than a blanket `\+\w+`, so the allowlist stays an
                # allowlist. `+time`/`+tries` take their value as a separate
                # argument, which the numeric branch below accepts.
                r"\+(?:short|noall|answer|nocomments|time|tries)"
                r"|[A-Za-z0-9._-]{1,253}"
                r"|CNAME|NS|MX|A|AAAA|TXT|SOA"
            ),
            max_argv=12,
        ),
    )
)


@lru_cache(maxsize=1)
def load_fingerprints() -> list[dict[str, Any]]:
    """Curated can-i-take-over-xyz data. Refresh it periodically — providers fix things."""
    try:
        payload = json.loads(FINGERPRINT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return list(payload.get("services") or [])


def match_service(cnames: list[str], body: str) -> dict[str, Any] | None:
    """Return the service entry whose CNAME *and* body fingerprint both match."""
    haystack = body[:200_000]
    for service in load_fingerprints():
        cname_hit = any(
            marker.lower() in cname.lower()
            for cname in cnames
            for marker in service.get("cname", [])
        )
        body_hit = any(fp.lower() in haystack.lower() for fp in service.get("fingerprints", []))
        if cname_hit and body_hit:
            return service
    return None


async def _dig(host: str, record: str) -> list[str]:
    run = await run_one("dig", ["+short", "+time", "3", "+tries", "2", host, record], timeout=30)
    return [v.strip().rstrip(".") for v in run.values if v.strip() and not v.startswith(";")]


# --------------------------------------------------------------------------- #
# Step 2 — detect
# --------------------------------------------------------------------------- #


#: Terminal colour codes. subjack writes them into whatever file it is given, so
#: any text comparison has to strip them first.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: A hostname token, matched whole. The previous code used `host in line`, which
#: made every parent domain a substring of its own children.
_HOST_TOKEN = re.compile(r"\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

#: Phrasing that means "checked, and fine". Tested before the positive marker
#: because "Not Vulnerable" contains "Vulnerable" — the substring trap that
#: caused this bug now guarded against in the fix for it.
_CLEARED = re.compile(r"(?i)\b(?:not\s+vulnerable|no[t]?\s+found|nothing\s+found|is\s+not)\b")

#: Phrasing that means "this host may be claimable".
_TAKEOVER = re.compile(r"(?i)\b(?:vulnerable|takeover|can\s+be\s+claimed|unclaimed|dangling)\b")


def _is_takeover_hit(line: str) -> bool:
    """Does this output line assert a takeover, or merely mention a host?

    Fails CLOSED: a line whose wording is not recognised is not a hit. These
    detectors print one line per host examined, so treating unknown phrasing as
    a positive turns a clean estate into a full-length candidate list — which is
    exactly what happened.
    """
    if not line.strip():
        return False
    if _CLEARED.search(line):
        return False
    return bool(_TAKEOVER.search(line))


def _hosts_in(line: str) -> set[str]:
    """Hostname tokens in a line, lowercased, matched whole."""
    return {m.group(0).rstrip(".").lower() for m in _HOST_TOKEN.finditer(line)}


@cordon_tool(
    phase="takeover", mode="aggressive", targets_arg="target", timeout=1200,
    name="takeover_detect", tags={"takeover"},
    # Four detectors x every host x roughly two schemes. A 300-host list is on the
    # order of 2,400 requests, not 200.
    estimated_requests=2400,
    risk_notes=[
        "Fetches each candidate host over HTTP to compare response fingerprints.",
        "Four detectors each receive the whole host list, so volume is roughly "
        "8 requests per host — a 300-subdomain list is ~2,400 requests.",
        "NONE of subzy, dnsReaper, subjack or Subdominator has a "
        "requests-per-second flag. Their concurrency is pinned to the "
        "engagement's max_concurrency, which bounds how many requests are in "
        "flight at once but NOT the rate. On a program with a published rps "
        "ceiling this tool can exceed it; run it against short host lists, or "
        "prefer takeover_verify per host, which is rate-limited properly.",
        "Produces candidates only — every tool in this category has false positives.",
    ],
)
async def takeover_detect(target: str) -> dict[str, Any]:
    """Screen hosts for takeover candidates with subzy and dnsReaper.

    Output is a candidate list, never findings. Run takeover_verify on each hit
    before treating any of them as real.
    """
    engagement = get_engagement()
    hosts = split_targets(target) or engagement.assets.values("subdomain")
    if not hosts:
        return {"ok": False, "error": "no_hosts", "message": "no subdomains known — run recon first"}

    targets_file = engagement.raw_path("takeover-targets", "txt")
    targets_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    dnsreaper_out = engagement.raw_path("dnsreaper", "json")

    # Every detector that is installed gets a pass. They disagree often, which
    # is the point: agreement across independent signatures is worth more than
    # any single tool's verdict, and verification still gates all of them.
    #
    # Every concurrency ceiling below comes from the engagement. They were
    # hardcoded at 10 and 20 — higher than two of the tools' own defaults — which
    # meant an engagement could publish max_concurrency: 2 and still get 20
    # simultaneous connections out of subjack. None of these tools has a
    # requests-per-second flag, so this is the only governor available and it is
    # an incomplete one; see this tool's risk_notes.
    concurrency = str(max(1, int(engagement.scope.rules.max_concurrency)))
    runs = await asyncio.gather(
        run_one(
            "subzy",
            [
                "run", "--targets", str(targets_file),
                "--concurrency", concurrency,
                "--hide_fails", "--vuln",
            ],
            timeout=900,
            allow_codes=(0, 1),
        ),
        run_one(
            "dnsreaper",
            [
                "file", "--filename", str(targets_file),
                "--out", str(dnsreaper_out), "--out-format", "json",
                # dnsReaper defaults to 200 domains in parallel (an asyncio
                # semaphore); it was previously left at that default.
                "--parallelism", concurrency,
            ],
            timeout=900,
            allow_codes=(0, 1),
        ),
        run_one(
            "subjack",
            ["-w", str(targets_file), "-t", concurrency, "-timeout", "15", "-ssl", "-v"],
            timeout=900,
            allow_codes=(0, 1),
        ),
        run_one(
            # Subdominator's concurrency flag is -c/--concurrency. It is not on
            # the allowlist in tools/extra_specs.py, so passing it here would be
            # refused by the sanitizer and this detector runs at its own default.
            # Reported rather than worked around: widening another module's arg
            # policy from here is exactly the kind of quiet drift the policies
            # exist to prevent.
            "subdominator",
            ["--domain-list", str(targets_file)],
            timeout=900,
            allow_codes=(0, 1),
        ),
    )

    candidates: dict[str, dict[str, Any]] = {}
    # Line-oriented detectors: attribute each hit to the tool that found it, so
    # the report can say how many independent signatures agreed.
    #
    # Two bugs lived in the four lines this replaces, and both were measured
    # against a real 141-host estate rather than reasoned about:
    #
    # 1. It filed a candidate whenever a hostname appeared in ANY line. subjack
    #    prints "[Not Vulnerable] host" for every host it clears, so a run in
    #    which subjack found NOTHING produced 141 takeover candidates — one per
    #    host, each sourced from the line saying it was fine.
    # 2. `host in line` is a substring test. The line for
    #    `ads.cdn-vendor.example.com` also "matched" `cdn-vendor.example.com`
    #    and the apex, so one host's verdict was attributed to two others.
    #
    # A takeover report is an assertion that somebody else can claim your DNS.
    # 141 of those, every one false, is not noise — it is the whole output being
    # wrong in the direction that gets a researcher's submissions closed.
    host_set = set(hosts)
    for run, name in ((runs[0], "subzy"), (runs[2], "subjack"), (runs[3], "subdominator")):
        for raw_line in run.values:
            line = _ANSI.sub("", raw_line)
            if not _is_takeover_hit(line):
                continue
            # Exact host match on tokens parsed out of the line, never a
            # substring of it.
            for host in _hosts_in(line) & host_set:
                entry = candidates.setdefault(host, {"host": host, "sources": []})
                if name not in entry["sources"]:
                    entry["sources"].append(name)

    if dnsreaper_out.exists():
        try:
            payload = json.loads(dnsreaper_out.read_text(encoding="utf-8"))
            for record in payload if isinstance(payload, list) else payload.get("findings", []):
                host = str(record.get("domain") or record.get("host") or "")
                if host:
                    entry = candidates.setdefault(host, {"host": host, "sources": []})
                    entry["sources"].append("dnsreaper")
                    entry["signature"] = record.get("signature")
        except (json.JSONDecodeError, AttributeError):
            pass

    ranked = sorted(candidates.values(), key=lambda c: -len(c["sources"]))
    corroborated = [c for c in ranked if len(c["sources"]) > 1]

    return {
        "ok": True,
        "hosts_screened": len(hosts),
        "candidates": ranked,
        "count": len(candidates),
        "corroborated": corroborated,
        "detectors_run": [r.tool for r in runs if r.ran],
        "detectors_absent": [r.tool for r in runs if not r.ran],
        "tools": [r.to_dict() for r in runs],
        "next_step": (
            f"Run takeover_verify on each candidate — start with the "
            f"{len(corroborated)} that more than one detector flagged. Detection "
            "tools match on a response body and are wrong often; nothing here is "
            "a finding yet."
        ),
    }


# --------------------------------------------------------------------------- #
# Step 3 — verify
# --------------------------------------------------------------------------- #


@cordon_tool(
    phase="takeover", mode="passive", targets_arg="target", timeout=300,
    name="takeover_verify", tags={"takeover"}, estimated_requests=6,
)
async def takeover_verify(target: str) -> dict[str, Any]:
    """Verify a takeover candidate: CNAME chain + live response + fingerprint.

    All three must agree before the host is recorded as a verified candidate. A
    verified candidate is filed as 'needs manual review' — confirming it requires
    actually claiming the resource, which is takeover_poc_plan followed by
    takeover_confirm.

    NS and MX delegations are graded higher: those hand over the zone or the mail.
    """
    engagement = get_engagement()
    host = split_targets(target)[0]

    cnames, ns_records, mx_records, a_records = await asyncio.gather(
        _dig(host, "CNAME"), _dig(host, "NS"), _dig(host, "MX"), _dig(host, "A")
    )

    body = ""
    status_code: int | None = None
    fetch_error: str | None = None
    async with httpx.AsyncClient(
        timeout=15, follow_redirects=True,
        headers={"User-Agent": engagement.scope.rules.user_agent},
    ) as client:
        for scheme in ("https", "http"):
            async with engagement.limiter.slot(host=host):
                try:
                    response = await client.get(f"{scheme}://{host}/")
                except httpx.HTTPError as exc:
                    fetch_error = str(exc)[:200]
                    continue
            status_code = response.status_code
            body = response.text[:200_000]
            fetch_error = None
            break

    service = match_service(cnames, body)

    # The three checks, stated separately so the report can show which held.
    checks = {
        "cname_present": bool(cnames),
        "no_address_record": not a_records,
        "fingerprint_matched": service is not None,
        "service_known_claimable": bool(service and service.get("claimable")),
    }
    verified = checks["cname_present"] and checks["fingerprint_matched"]

    severity = Severity.MEDIUM
    kind = "cname"
    if ns_records and not a_records:
        severity, kind = Severity.CRITICAL, "ns"
    elif mx_records and service:
        severity, kind = Severity.HIGH, "mx"
    elif service and service.get("claimable"):
        severity = Severity.HIGH

    finding: Finding | None = None
    if verified:
        finding = Finding(
            asset=host,
            title=f"Subdomain takeover candidate ({kind.upper()}) — {service['service'] if service else 'unknown service'}",
            phase="takeover",
            severity=severity,
            status=Status.NEEDS_MANUAL_REVIEW,
            description=(
                f"{host} delegates to {', '.join(cnames) or 'an external provider'} "
                f"and the provider returns an unclaimed-resource page for "
                f"{service['service'] if service else 'the service'}."
            ),
            how_found=(
                "takeover_verify: CNAME chain resolved, live page fetched, and the "
                "response matched the can-i-take-over-xyz fingerprint for "
                f"{service['service'] if service else 'the service'}"
            ),
            source_tool="takeover_verify",
            rule_id=f"takeover.{(service or {}).get('service', 'unknown').lower().replace(' ', '-')}",
            confidence=0.8 if checks["service_known_claimable"] else 0.6,
            evidence=[
                Evidence(kind="dns", description=f"dig CNAME {host}", excerpt=", ".join(cnames)),
                Evidence(kind="dns", description=f"dig A {host}", excerpt=", ".join(a_records) or "(none)"),
                Evidence(
                    kind="response",
                    description=f"HTTP {status_code} from {host}",
                    excerpt=body[:1500],
                ),
            ],
            remediation=(
                f"Remove the dangling DNS record for {host}, or re-claim the resource "
                f"at {service['service'] if service else 'the provider'}. Audit the "
                "zone for other records pointing at decommissioned services."
            ),
            references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
            tags=["takeover", kind, (service or {}).get("status", "unknown")],
            extra={"service": service, "checks": checks},
        )
        if service and not service.get("claimable"):
            finding.downgrade(
                f"{service['service']} is an edge case: {service.get('note', 'provider verifies domain ownership')}. "
                "Confirm the resource is genuinely claimable before reporting."
            )
        engagement.findings.add(finding)
        engagement.findings.save()

    return {
        "ok": True,
        "host": host,
        "verified": verified,
        "checks": checks,
        "kind": kind,
        "severity": severity.value if verified else None,
        "cname": cnames,
        "ns": ns_records,
        "mx": mx_records,
        "a": a_records,
        "http_status": status_code,
        "fetch_error": fetch_error,
        "service": service,
        "finding_id": finding.id if finding else None,
        "status": "needs_manual_review" if verified else "not_a_candidate",
        "next_step": (
            f"Verified. Get the PoC steps with takeover_poc_plan('{host}'), and note "
            "that claiming the resource is a human action, not an Cordon one."
            if verified
            else "Not verified — the fingerprint, CNAME, or both did not hold. Do not report this."
        ),
    }


# --------------------------------------------------------------------------- #
# PoC — planned by Cordon, executed by a human, recorded here
# --------------------------------------------------------------------------- #


@cordon_tool(
    phase="takeover", mode="passive", targets_arg="target", timeout=60,
    name="takeover_poc_plan", tags={"takeover"}, estimated_requests=0,
)
async def takeover_poc_plan(target: str) -> dict[str, Any]:
    """Produce the minimal, responsible PoC steps for a verified takeover.

    Cordon does not register resources at third-party providers on your behalf.
    This returns the exact steps, including a unique proof path tied to your
    researcher handle, so the proof is unambiguous and the impact stops at
    'I could have'.
    """
    engagement = get_engagement()
    host = split_targets(target)[0]
    handle = engagement.scope.researcher_handle or "researcher"
    nonce = secrets_mod.token_hex(4)
    proof_path = f"/.well-known/cordon-poc-{handle}-{nonce}.txt"

    matching = [
        f for f in engagement.findings.all()
        if f.asset == host and "takeover" in f.tags
    ]
    if not matching:
        return {
            "ok": False,
            "error": "not_verified",
            "message": (
                f"No verified takeover finding for {host}. Run takeover_verify first — "
                "a PoC plan for an unverified candidate is how people end up claiming "
                "a resource that was never dangling."
            ),
        }

    vdp_note = engagement.scope.engagement.get("vdp_note")
    return {
        "ok": True,
        "host": host,
        "finding_id": matching[0].id,
        "proof_path": proof_path,
        "proof_content": (
            f"Cordon subdomain takeover proof of concept\n"
            f"host: {host}\n"
            f"researcher: {handle}\n"
            f"nonce: {nonce}\n"
            f"This resource was claimed to demonstrate a dangling DNS record. "
            f"No other content was served and no user data was accessed. "
            f"It will be released as soon as the report is triaged.\n"
        ),
        "steps": [
            "1. Confirm the program permits claiming the resource. If it routes "
            "infrastructure issues elsewhere, stop and report there instead."
            + (f" (This program says: {vdp_note})" if vdp_note else ""),
            f"2. Register the unclaimed resource at the provider so {host} resolves to it.",
            f"3. Serve the proof content above at exactly {proof_path}. Nothing else — "
            "no index page, no redirect, no collection of any request data.",
            f"4. Fetch https://{host}{proof_path} and save the response.",
            f"5. Run takeover_confirm(host='{host}', proof_url='https://{host}{proof_path}') "
            "to verify the proof is live and attach it to the finding.",
            "6. Report immediately, and release the resource as soon as the program confirms the fix.",
        ],
        "do_not": [
            "Do not serve any content beyond the proof file.",
            "Do not collect, log, or inspect traffic that arrives at the claimed resource.",
            "Do not issue TLS certificates for the domain.",
            "Do not leave the resource claimed longer than triage requires.",
        ],
        "note": (
            "This plan is deliberately not automated. Claiming a resource creates a "
            "relationship with a third-party provider and a real change to the "
            "target's live DNS behaviour — that is a person's decision to make."
        ),
    }


@cordon_tool(
    phase="takeover", mode="exploit", targets_arg="target", timeout=120,
    name="takeover_confirm", tags={"takeover"}, estimated_requests=2,
    risk_notes=[
        "Confirms a takeover you have already performed by fetching your proof file.",
        "Only run this after takeover_poc_plan and only where the program permits claiming.",
    ],
)
async def takeover_confirm(target: str, proof_url: str, notes: str = "") -> dict[str, Any]:
    """Verify a human-executed takeover PoC is live and attach it to the finding.

    Fetches the proof URL, checks the proof content is actually served from the
    target host, and only then promotes the finding to confirmed. This is the
    single place a takeover can become 'confirmed'.
    """
    engagement = get_engagement()
    host = split_targets(target)[0]

    matching = [f for f in engagement.findings.all() if f.asset == host and "takeover" in f.tags]
    if not matching:
        raise CordonError(
            f"no verified takeover finding for {host}; run takeover_verify first",
            code="not_verified",
        )
    finding = matching[0]

    async with httpx.AsyncClient(
        timeout=15, follow_redirects=False,
        headers={"User-Agent": engagement.scope.rules.user_agent},
    ) as client:
        async with engagement.limiter.slot(host=host):
            try:
                response = await client.get(proof_url)
            except httpx.HTTPError as exc:
                return {
                    "ok": False,
                    "error": "proof_unreachable",
                    "message": f"could not fetch {proof_url}: {exc}",
                }

    body = response.text[:4000]
    proof_is_live = response.status_code == 200 and "Cordon subdomain takeover proof" in body
    if not proof_is_live:
        return {
            "ok": False,
            "error": "proof_not_served",
            "http_status": response.status_code,
            "message": (
                "The proof file is not being served from that URL. The finding stays "
                "at 'needs manual review' — an unproven takeover is not a takeover."
            ),
            "body_excerpt": body[:500],
        }

    finding.add_evidence(
        Evidence(
            kind="response",
            description=f"Proof file served from {proof_url}",
            excerpt=body[:1000],
        )
    )
    finding.confirm(
        PoC(
            reproduction=(
                f"1. dig CNAME {host} — observe the dangling delegation.\n"
                f"2. Fetch {proof_url} — the proof file is served, demonstrating that "
                f"content on {host} is under the claimant's control."
            ),
            expected_result=f"HTTP 200 with the Cordon proof content at {proof_url}",
            observed_result=f"HTTP {response.status_code}; proof content confirmed present.",
            impact_limit_note=(
                "Only a static proof file was served. No traffic was collected, no "
                "certificate was issued, and the resource is released after triage."
            ),
            tool="takeover_confirm",
            artifacts=[proof_url],
        )
    )
    if notes:
        finding.note(notes)
    engagement.findings.save()

    return {
        "ok": True,
        "host": host,
        "finding_id": finding.id,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "proof_url": proof_url,
        "reminder": (
            "Report now, and release the claimed resource as soon as the program "
            "confirms the DNS record is removed."
        ),
    }

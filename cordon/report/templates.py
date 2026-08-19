"""Report templates, separated from the synthesis logic that fills them.

Kept apart so the *wording* of a report can be changed without touching the code
that assembles it. Bug bounty programs differ in what they want to see, and a
team should be able to adjust tone, add a section, or translate the whole thing
by editing this file alone.

Every template that describes an unproven finding is written to say so plainly.
That phrasing is the report's most load-bearing feature: a triager who finds one
unproven item filed among your confirmed ones will re-check all of them, and you
will have spent credibility that took months to earn.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CONFIRMED_INTRO",
    "EMPTY_CONFIRMED",
    "NEEDS_REVIEW_INTRO",
    "NO_POC_NOTE",
    "PARTIAL_BANNER",
    "SECTION_TITLES",
    "closing_statement",
    "severity_guidance",
]

SECTION_TITLES = {
    "authorization": "Authorization",
    "executive": "Executive summary",
    "confirmed": "Confirmed findings",
    "needs_review": "Needs manual review",
    "untriaged": "Untriaged candidates",
    "scope": "Scope",
    "methodology": "Methodology",
    "tools": "Tool inventory",
    "coverage": "Coverage and cost",
    "audit": "Audit trail",
}

CONFIRMED_INTRO = (
    "Each finding below was reproduced with a proof of concept. The steps are "
    "sufficient to reproduce it from this document alone."
)

EMPTY_CONFIRMED = (
    "_No findings were confirmed with a reproducible proof of concept._\n\n"
    "This is a real result, not an empty one: everything the scanners raised "
    "either failed validation or needs a human to prove. See the next section."
)

NEEDS_REVIEW_INTRO = (
    "**These are not confirmed vulnerabilities.** Each is a plausible lead that "
    "could not be proven automatically — either because proving it requires "
    "causing real impact, or because validation was inconclusive. They are "
    "listed so a human can decide, not so the report looks longer."
)

NO_POC_NOTE = (
    "_None. This finding is not confirmed and is reported as requiring manual "
    "review._"
)

PARTIAL_BANNER = (
    "> **PARTIAL REPORT** — the run stopped early: {reason}. Coverage is "
    "incomplete; treat the absence of a finding as unknown, not as evidence of "
    "absence."
)

UNTRIAGED_INTRO = (
    "Raised by a scanner and not yet examined. Included for completeness — these "
    "have had no analysis applied and should not be read as findings."
)

AUDIT_NOTE = (
    "Every request Cordon made — including the ones it refused to make — is in "
    "that file, hash-chained so edits are detectable."
)


def closing_statement(*, exploitation_ran: bool = True) -> str:
    """The statement of restraint that closes the report."""
    base = (
        "*Testing was limited to the authorized scope above."
    )
    if exploitation_ran:
        base += (
            " Where a proof of concept was executed, it was the minimum needed to "
            "demonstrate the issue; no data was extracted or retained beyond what "
            "appears in this report."
        )
    else:
        base += " No exploitation was performed."
    return base + "*"


def severity_guidance() -> dict[str, str]:
    """What each severity should mean in this report, stated for the reader.

    Included because the most common way to lose a program's trust is severity
    inflation, and an explicit rubric makes a rating checkable rather than
    assertable.
    """
    return {
        "critical": (
            "Direct compromise of data or infrastructure, demonstrated. A live "
            "credential, RCE, or full account takeover with a working PoC."
        ),
        "high": (
            "Serious impact demonstrated against a real asset — another user's "
            "data, authentication bypass, or a takeover of a named host."
        ),
        "medium": (
            "Demonstrated flaw with limited or conditional impact, or one "
            "requiring an unlikely precondition."
        ),
        "low": (
            "Real but minor: information disclosure with no clear path to "
            "escalation."
        ),
        "info": (
            "Observation, not a vulnerability. Included as context; not expected "
            "to be actioned or rewarded."
        ),
    }


def finding_header(finding: Any, index: int) -> list[str]:
    """The fixed metadata block at the top of every finding."""
    cvss = (
        f"{finding.cvss:.1f}" + (f" ({finding.cvss_vector})" if finding.cvss_vector else "")
        if finding.cvss
        else "not scored"
    )
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"- **Severity:** {finding.severity.value.upper()}",
        f"- **CVSS:** {cvss}",
        f"- **Asset:** `{finding.asset}`",
        f"- **Status:** {finding.status.value}",
        f"- **Confidence:** {finding.confidence:.2f}",
    ]
    if finding.validated:
        lines.append("- **Credential validated:** yes — treat as compromised")
    lines += [
        f"- **How it was found:** {finding.how_found or finding.source_tool}",
        f"- **Detection source:** `{finding.source_tool}`"
        + (f" / rule `{finding.rule_id}`" if finding.rule_id else ""),
        "",
    ]
    return lines


def poc_block(poc: Any) -> list[str]:
    """A proof of concept, formatted so a triager can run it as-is."""
    lines = [
        "**Proof of concept**",
        "",
        "```",
        poc.reproduction.strip(),
        "```",
        "",
        f"- *Expected:* {poc.expected_result}",
        f"- *Observed:* {poc.observed_result}",
    ]
    if poc.impact_limit_note:
        lines.append(f"- *Impact limited to:* {poc.impact_limit_note}")
    lines += [f"- *Validated by:* {poc.validated_by} at {poc.validated_at}", ""]
    return lines

---
name: easyhunt-report
description: >
  Synthesize an EasyHunt engagement into a submittable report: confirmed findings
  with reproducible PoCs, unproven leads kept separate, scope, methodology, tool
  inventory, and cost. Use when asked to write up, report, or submit findings.
---

# EasyHunt reporting

```
findings_list(status="confirmed")
findings_list(status="needs_manual_review")
report_generate()
```

Writes `Report.md`, `Report.csv`, `findings.json`, and `taskgraph.mmd` into the
engagement's `reports/` directory, alongside `evidence/` and `audit.jsonl`.

## The structure, and why

**Confirmed findings** — each with a reproduction a triager can run without
asking you a question. If a finding needs a follow-up email to reproduce, it is
not finished.

**Needs manual review** — a separate section, explicitly labelled unproven.
Never blend these into the confirmed section to make the report look fuller. A
triager who finds one unproven item among your confirmed ones will re-check all
of them, and you will have spent credibility that took months to build.

**Scope, methodology, tool inventory, cost** — how a reader checks your work.
The task graph shows why each step happened; the audit log records every request,
including the refusals.

## Before you hand it over

Read `Report.md` yourself and check:

1. Every confirmed finding reproduces from the document alone.
2. Nothing unproven leaked into the confirmed section.
3. Severity matches the *evidence*, not the vulnerability class's potential. An
   exposed `.env` with live AWS keys is critical. An exposed `.env` containing
   only `APP_NAME` is not, however much the filename suggests otherwise.
4. Impact is stated in the target's terms — what an attacker gets — not in terms
   of the vulnerability's name.
5. `impact_limit_note` is present on every PoC, so the program can see exactly
   how far you went.

## Partial reports

If a budget ceiling fired, the report is labelled **PARTIAL** on its first page
and states that coverage is incomplete. Leave that label in place. "We ran out of
budget at 60% coverage" is honest and useful; silently shipping a partial report
as complete tells the program their surface is clean when you never looked.

## Severity honesty

The most common way to lose a program's trust is inflating severity. Some
specifics:

- Version disclosure is informational unless you demonstrated exploitation.
- Missing security headers are low at best, and most programs consider them noise.
- A takeover on an `edge-case` provider is probably not exploitable — the
  verifier flags this, and reporting past the flag is a false positive with your
  name on it.
- "Could lead to" is not impact. Either you demonstrated the chain or you did not.

## Submitting

`findings.json` is platform-ready. Attach `evidence/` for anything visual. The
audit log is your record of what you actually did — useful if a program asks,
and the thing that lets you say "here is every request we sent" with confidence.

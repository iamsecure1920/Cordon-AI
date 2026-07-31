---
name: easyhunt-validate
description: >
  Prove candidate findings with minimal proof-of-concept validation in EasyHunt,
  and record human-reproduced PoCs. Use when asked to validate, confirm, prove,
  or produce a PoC for a finding — and before writing any report.
---

# EasyHunt validation

**No PoC, no finding.** A candidate becomes confirmed only through
`validate_findings`, `poc_record`, or `takeover_confirm`. Nothing else can set
that status.

## The rule that governs every PoC

**The smallest proof that settles the question.**

Proving SQL injection means showing `1 AND 1=1` and `1 AND 1=2` differ, or that a
`SLEEP(5)` delays the response. It does **not** mean dumping the users table. The
extra step adds no evidence, converts a clean report into a data-handling
incident, and is exactly what programs mean by "do not exfiltrate".

This is enforced, not advised: sqlmap's data-extraction flags (`--dump`, `--dbs`,
`--tables`, `--file-read`) are absent from its argument allowlist. No approval
can produce an extraction run.

## Automatic validation

```
validate_findings(min_severity="medium")     # exploit mode, needs approval
xss_validate(url)                            # dalfox, verifies execution
sqli_validate(url)                           # detection only
oob_listener()                               # callback domain for blind classes
```

Validators run in parallel, one per vulnerability class. Each returns proven or
not-proven with a reason. Not-proven downgrades the finding to
`needs_manual_review` with that reason attached — which is a useful result, not a
failure.

## Classes that need a human, by design

| Class | Why automation stops |
| --- | --- |
| IDOR / authz | Proving it means reading another user's data |
| Auth bypass | Proving it means being someone else |
| RCE | Proving it means executing code on their host |
| Blind SSRF | Needs an out-of-band listener and injection context |

For these, reproduce by hand with the least impact that demonstrates the issue,
then:

```
poc_record(
  finding_id=...,
  reproduction="GET /api/users/2 with user A's session cookie",
  expected_result="403 Forbidden",
  observed_result="200 OK returning user B's email address",
  impact_limit_note="Read one adjacent record to prove the flaw; nothing retained.",
)
```

All three of reproduction, expected, and observed are required. A PoC without an
observed result is a hypothesis, and the tool refuses it.

## Minimal-impact rules

- Use a test account you control, not a real user's data. If you must touch real
  data, touch exactly one record and say so in `impact_limit_note`.
- Never persist, never pivot, never escalate beyond what the proof needs.
- Use a payload marker traceable to you, so the target's team can identify your
  traffic in their logs.
- Never test availability. Nothing in EasyHunt does load or DoS testing, and
  neither should you by hand.
- For stored XSS, use a benign marker that identifies you — not `alert(1)` on a
  page other users will load.

## Reusing what worked

`memory_recall(query, vuln_class=...)` returns PoC techniques that succeeded on
previous engagements, with target-specific values generalized. Check it before
designing a PoC from scratch. It stores methods only — never credentials, never
another client's data.

## Etiquette when approval is requested

Present the risk notes as written, say what the tool will actually send, and
wait. If the human declines, that is the answer — record it and move on. Never
call `approval_respond` yourself except to relay a decision a person gave you.

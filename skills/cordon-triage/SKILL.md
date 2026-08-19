---
name: cordon-triage
description: >
  Reduce scanner false positives with Cordon's adversarial taskflow triage and
  canary defense. Use after a scan produces candidates, when asked to triage
  findings, cut noise, or decide what is worth validating.
---

# Cordon triage

Triage ranks, downgrades, and drops. **It cannot confirm anything** — the code
path from triage to a confirmed finding does not exist, and a taskflow that
declares a `confirm` verdict is rejected at load time.

## Running it

```
triage_taskflows()                    # what is available
triage_findings(taskflow="default-triage.yaml", min_severity="info")
```

The default flow runs three steps:

1. **falsifier** — argues each finding is a false positive.
2. **red-team** — argues each is real, and states what a PoC would need to show.
3. **severity-check** (T2, high/critical only) — does the evidence support the
   rating, or just the vulnerability class's reputation?

## Reading the result

**`canary_check` first.** Fabricated findings on `.invalid` hosts are mixed into
every batch. A pass that keeps or escalates one is hallucinating:

- `canaries_caught: 3/3` — verdicts weighted normally.
- `canaries_missed: 2` — `confidence_multiplier` drops toward 0.4, and you should
  discount that pass's judgement too, not just its numbers.

**Then the verdicts.** Disagreement between falsifier and red-team escalates to
validation rather than averaging into a middling score. That is the honest
outcome: a split decision means automated triage cannot settle it.

**Drops require agreement.** A single `drop` alongside any non-drop verdict never
discards the finding — it downgrades or escalates instead. Automated triage does
not get to throw away evidence on one opinion.

## What triage is good at, and what it is not

Good at: soft 404s that return 200 with the site's HTML shell, version banners
without exploitability, WAF interstitials matching a fingerprint, sample and
documentation files that look like config, default pages on shared hosting.

Bad at: anything requiring state, sequence, or authorization context. A model
cannot tell you whether `/api/users/2` returning data is an IDOR without knowing
whose session made the request. Those go to a human.

## Without a model

`triage_findings` needs an OpenRouter key. Without one it says so and does
nothing — it does not silently pass everything through. Triage by hand instead:
the findings store has the rule id, the evidence excerpt, and the detection
source for each candidate, which is most of what the falsifier pass reasons over
anyway.

## After triage

Escalated and kept findings go to `validate_findings`. Dropped ones are marked
`false_positive` with the reason recorded — they stay in `findings.json` for
audit, and they do not appear in the report's findings sections.

# Troubleshooting

## "no active engagement"

No scope loaded. Call `easyhunt_load_scope(scope_path="scope.yaml")`.

## A tool returns `tool_unavailable`

The binary is not installed. `easyhunt_capabilities()` shows what is registered;
`easyhunt doctor` on the command line shows what is actually present. Grouped
wrappers (`subdomain_enum`, `endpoint_discovery`) run whatever they find and
report `tools_not_installed` — coverage is partial, and the report should say so
rather than implying a clean sweep.

## A scan returns nothing

In order of likelihood:

1. **The target is behind a CDN.** Run `cdn_check` — you may be scanning the
   edge. Scan the direct-origin hosts instead.
2. **Rate limit is doing its job.** At 5 rps a large host list takes a long time.
   Check `job_status` rather than assuming failure.
3. **Rules were rejected at load time.** `rules_list()` shows `rejected` entries.
   A rejected rule is a detection you think you have and do not.
4. **Nothing is there.** A clean result is a real result. Report it as such
   instead of escalating aggression until something turns up.

## Approval never arrives

`approval_pending()` lists parked requests. If the client cannot show elicitation
prompts, set `approval.backend: pending` in config and resolve them with
`approval_respond` once a human has actually decided.

Never set `approval.backend: policy` with a broad `auto_approve` list to make
prompts go away. That is removing the human from human-in-the-loop.

## The budget fired mid-run

Expected behaviour, not a crash. `report_generate` still works — it is exempt
from the budget precisely so a stopped run produces a partial report. The report
will be labelled PARTIAL on its first page.

## The audit chain reports as broken

Something edited or truncated `audit.jsonl`. That file is the engagement's
evidence. Do not "fix" it — note when it broke, and treat any finding whose
provenance depends on the missing records as unverified.

## Findings look duplicated

They are merged by `(asset, title, rule)`. Genuinely distinct findings on the
same asset need distinct titles. Re-running a scan updates rather than
duplicates; severity can be raised by a repeat sighting but never silently
lowered.

# Phase detail

Progressive disclosure: the main SKILL.md gives the order, this gives the
judgement calls.

## 1. Authorize

`cordon_load_scope` returns `seeds` (sensible starting targets) and `warnings`.

Warnings worth stopping for:

- *"scope is N days old"* — re-read the program policy. Programs remove assets,
  and testing a removed asset is unauthorized testing.
- *"'\*.example.com' does not cover the apex"* — Cordon fails closed. If the
  program means to include the apex, add it under `in_scope.domains`.
- *"unparseable DENY entry ignored — this WIDENS your effective scope"* — fix
  this before running anything. A broken exclusion is worse than no exclusion,
  because you believe you have one.

## 2. Recon

`bbot_scan` presets, in rough order of value:

- `subdomain-enum` — the default. Certificate transparency, passive DNS, and
  ~30 other sources.
- `cloud-enum` — storage buckets and cloud tenancy.
- `code-enum` — public repositories mentioning the target.
- `baddns` — takeover candidates, directly feeding phase 5.

If BBOT is not installed, `subdomain_enum` merges subfinder/assetfinder/findomain
instead. It covers less; say so in the report rather than implying full coverage.

Active presets (`web-thorough`, `spider`, `paramminer`) live behind
`bbot_scan_active` and need approval. Do not reach for them on an unmapped
surface — you will spend the program's rate limit on hosts you have not yet
established are interesting.

## 3. Expand

- `dns_resolve` — flags hosts whose CNAME resolves with no address record. Those
  auto-spawn takeover tasks; check `taskgraph_next()`.
- `http_probe` — the highest-value single call. Status, title, technology,
  server, IP, CDN. Rule-packs run against every response for free.
- `endpoint_discovery` — reads archives, costs the target nothing. The
  `unique_parameters` field is the cheapest lead in the whole run: parameter
  names point at IDOR, SSRF, and redirect surface without spending a request.
- `js_analyze` — bundles contain API paths that appear nowhere else. Secret
  candidates come back masked and unvalidated; treat them as leads.

## 4. Scan

`nuclei_scan` is aggressive. Before approving, know:

- Rate is fixed at the program's ceiling and is not an argument you can raise.
- `dos`, `fuzz`, and `intrusive` templates are excluded and cannot be re-enabled.
- Everything it returns is a **candidate**. Nuclei is a very good scanner and it
  is still not a proof of concept.

Scan the interesting surface, not everything. A thousand hosts at 5 rps is a
three-hour scan that mostly rediscovers the same CDN.

## 5. Takeover

Never skip `takeover_verify`. Detection tools match on a response body and are
wrong often. Verification requires the CNAME chain, the live response, and the
fingerprint to agree.

Grade honestly: NS delegation is critical (the whole zone), MX is high (mail),
a CNAME on a marketing subdomain is usually medium. Several providers in the
fingerprint database are marked `edge-case` — CloudFront, Netlify, Vercel,
Shopify verify domain ownership, so a fingerprint match there is usually *not*
exploitable. The verifier flags these; do not argue past the flag.

## 6. Triage

`triage_findings` runs an adversarial falsifier/red-team pair and mixes in
fabricated canary findings. Read the `canary_check` in the result: if a pass
"confirmed" decoys, its verdicts were weighted down and you should trust them
less too.

Disagreement between passes escalates to validation rather than averaging. That
is correct — a split decision is genuine uncertainty, not a middling score.

## 7. Validate

`validate_findings` proves what can be proven with the smallest possible PoC.
Classes it deliberately will not attempt automatically:

- **IDOR / authz** — proving it means reading another user's data.
- **Auth bypass** — proving it means being someone else.
- **RCE** — proving it means executing code.
- **Blind SSRF** — needs an out-of-band listener (`oob_listener`).

For those, reproduce by hand and record with `poc_record`, which requires the
reproduction, the expected result, *and* the observed result. A PoC without an
observed result is a hypothesis.

## 8. Report

`report_generate`. Then read `Report.md` yourself before handing it over. Check:

- Every confirmed finding is reproducible from the document alone.
- Nothing unproven leaked into the confirmed section.
- Severity claims match the evidence, not the vulnerability class's potential.

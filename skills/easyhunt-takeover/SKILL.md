---
name: easyhunt-takeover
description: >
  Detect and verify subdomain takeovers with EasyHunt's three-step flow, then
  produce a responsible PoC. Use when checking for dangling DNS, takeover
  candidates, unclaimed cloud resources, or NS/MX delegation issues.
---

# EasyHunt subdomain takeover

Most takeover reports get closed as informative because the reporter skipped
verification. A fingerprint on a page is not a takeover.

## The three steps

```
1. Enumerate   bbot_scan(preset="subdomain-enum") or subdomain_enum
2. Detect      takeover_detect(hosts)   → candidates (noisy, expect false positives)
               dns_resolve(hosts)       → CNAME with no A record, auto-queued
3. Verify      takeover_verify(host)    → all three checks must agree
```

`takeover_verify` requires:

- the CNAME chain resolves to a provider,
- the live page returns that provider's unclaimed-resource fingerprint,
- and the service is in the can-i-take-over-xyz data.

Anything short of that is `not_a_candidate`. Do not report it.

## Severity

| Record | Severity | Why |
| --- | --- | --- |
| NS with no address record | Critical | Whoever claims it controls the entire zone |
| MX matching a fingerprint | High | Mail interception |
| CNAME, provider claimable | High | Content control on a target hostname |
| CNAME, provider `edge-case` | Medium, often not a bug | Provider verifies ownership |

### NS and MX coverage is conditional

The CNAME flow above runs on the tools that ship by default (subzy, dnsReaper).
**Lame NS delegation is not covered by any of them** — HTTP-oriented scanners
only see hosts that answer HTTP, and a broken delegation usually answers
nothing at all.

`subdomainsleuth` is the tool for that, it needs authoritative zone files, and
it is not installed by default. Check before you claim coverage:

```
easyhunt doctor | grep subdomainsleuth
```

If it is absent, NS and MX delegation on this engagement is **UNTESTED, not
clean** — say so in the report rather than letting a silent gap read as a
negative result. That distinction is the same one the validators make when a
binary is missing.

CloudFront, Netlify, Vercel, Shopify, and Fastly are marked `edge-case`: they
verify domain ownership, so the fingerprint appears but the takeover usually is
not possible. The verifier flags this and downgrades with a reason. Do not argue
past that flag — a wrong takeover report is expensive for the program's trust
in you.

## Proving it

EasyHunt does not claim resources for you. `takeover_poc_plan(host)` returns:

- a unique proof path tied to your researcher handle,
- exact steps,
- and a **do not** list.

Follow it exactly. In particular: serve *only* the proof file, collect nothing
that arrives at the claimed resource, do not issue certificates for the domain,
and release it as soon as triage confirms the fix.

Then `takeover_confirm(host, proof_url)` fetches your proof, checks it is really
served, and only then marks the finding confirmed. If the proof is not live, the
finding stays unproven — that check exists so a claimed-but-broken PoC cannot
become a confirmed report.

## Before you claim anything

Check the program's policy. Some route infrastructure issues to a separate VDP;
some forbid claiming resources entirely and want the dangling record reported as
observed. `scope.yaml`'s `vdp_note` carries this if it was recorded. When in
doubt, report the verified dangling record without claiming — that is still a
valid, useful finding.

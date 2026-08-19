---
name: cordon-recon
description: >
  Map an authorized target's attack surface with Cordon: BBOT preset selection,
  DNS resolution, HTTP probing, endpoint and JavaScript analysis. Use when asked
  to do recon, enumerate subdomains, find assets, or map attack surface.
---

# Cordon recon

Goal: turn a scope entry into a ranked list of things worth attacking, spending
as few of the program's requests as possible.

## Order

```
bbot_scan(seed, preset="subdomain-enum")     # passive, broadest coverage
  → dns_resolve(hosts)                       # which names actually exist
    → cdn_check(hosts)                       # which are origin vs edge
      → http_probe(hosts)                    # which serve something
        → endpoint_discovery(domain)         # archives: free URLs and params
          → js_analyze(js_urls)              # bundles: hidden endpoints, keys
```

Then `taskgraph_next()` — discoveries have queued follow-up work with reasons
attached.

## Choosing a BBOT preset

- `subdomain-enum` — always start here.
- `cloud-enum` — add when the target clearly runs on AWS/Azure/GCP.
- `code-enum` — add when the org publishes code; feeds `source_fetch`.
- `baddns` — add when you want takeover candidates early.

Active presets need `bbot_scan_active` and human approval. Justify them: on an
unmapped surface they spend the rate limit on hosts you cannot yet rank.

## Gap-filling

BBOT covers most of this. Reach for the atomic tools when it is absent or you
want one specific source:

| Need | Tool |
| --- | --- |
| Subdomains without BBOT | `subdomain_enum` |
| Netblocks and ASN | `asn_lookup` (ownership ≠ authorization) |
| Certificate SANs | `tls_info` |
| Registrant / confirm ownership | `whois_lookup` |
| Names no source knows | `dns_permute` (aggressive — brute force over DNS) |

## What to look for

Rank the surface, do not just list it:

- **Non-standard hosts** — `admin.`, `staging.`, `internal.`, `legacy.`,
  `old.`, `test.`, `vpn.`, `jira.`. These are where policy is weakest.
- **Technology outliers** — one host on a different stack from the other fifty
  usually means a different team, a different review process, or an acquisition.
- **Parameters from archives** — `endpoint_discovery`'s `unique_parameters` is
  the cheapest lead in the run. `url=`, `redirect=`, `next=`, `file=`, `id=`,
  `template=` each point at a specific bug class.
- **Endpoints only present in JS** — an API path a crawler never sees is a path
  nobody tested.
- **CNAMEs with no address record** — takeover candidates; they auto-spawn a
  verification task.

## Stop conditions

- Out of scope: document where the trail led and halt. Do not resolve it, do not
  probe it, do not "just check".
- A host that looks like someone else's infrastructure (shared hosting, a
  third-party SaaS the target merely uses): confirm ownership before touching it.
  `asn_lookup` and `whois_lookup` help; a matching name does not.
- Recon has diminishing returns. When new sources stop producing new in-scope
  hosts, move to scanning rather than adding another enumerator.

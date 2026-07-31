---
name: easyhunt-cloud
description: >
  Assess cloud and Kubernetes posture with EasyHunt: external storage discovery,
  IAM permission mapping, Prowler posture audit, attack-path analysis, Kubescape.
  Use when the target runs on AWS/Azure/GCP or Kubernetes, or when asked about
  buckets, IAM, cloud misconfiguration, or cluster security.
---

# EasyHunt cloud

Two very different positions. Conflating them is how people end up testing
infrastructure they were never authorized for.

## Outside, without credentials

```
cloud_asset_discovery(keyword="acme")
```

Guesses storage names against provider endpoints. Read the result carefully:

- `in_scope` — covered by your scope artifact. Safe to look at.
- `found_but_unverified` — **a matching name is not ownership.** A bucket called
  `acme-backups` may belong to a completely different Acme. Do not touch these,
  do not report them as the program's, and do not "just check if it's public".

A publicly readable bucket that *is* in scope is a real finding. Prove it by
listing it once and stopping — do not download the contents. The report needs
"this was world-readable", not a copy of the data.

## Inside, with credentials the program gave you

```
cloud_permissions(profile, provider)   # CloudFox: principals, permissions, privesc
cloud_audit(provider, severity="high,critical")  # Prowler: posture checks
cloud_attack_paths(provider)           # graph: what reaches what
k8s_posture(framework="nsa")           # Kubescape
```

All read-only, all logged in the account's audit trail. That is fine and
expected — but tell the client, because a sudden burst of enumeration API calls
looks exactly like an intrusion to their detection team.

## What actually makes a cloud finding

A list of failed benchmark checks is a checklist, not a report. What earns a
severity rating is **reachability**: an internet-facing function that can assume
a role that can read the production database, in two hops.

Prioritize in this order:

1. Findings that sit on an attack path from an unauthenticated entry point.
2. Validated credentials with real blast radius (see `easyhunt-validate`).
3. Public data exposure.
4. Everything else — posture observations, reported as such.

Full attack-path graphs need Cartography with a Neo4j backend; without it,
`cloud_attack_paths` returns Prowler's own path data only and says so.

## Stop conditions

- Never modify anything. Every tool here reads; if you find yourself wanting a
  write to prove impact, that is a conversation with the client, not a tool call.
- Credentials found in code are candidates until validated, and validating them
  is a gated step for good reason (see `easyhunt-validate`).
- If enumeration reveals another tenant's data, stop immediately and tell a
  human. That is an incident, not a finding.

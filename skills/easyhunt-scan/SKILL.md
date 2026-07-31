---
name: easyhunt-scan
description: >
  Run vulnerability and port scans with EasyHunt under the program's rate limit:
  Nuclei templates and workflows, naabu/nmap port and service scanning, custom
  rule packs. Use when asked to scan for vulnerabilities, check for CVEs, or
  enumerate ports and services.
---

# EasyHunt scanning

Everything here is aggressive and stops for approval. Bring a reason.

## Vulnerability scanning

```
nuclei_scan(target, severity="low,medium,high,critical")
nuclei_scan(target, tags="cve,exposure,misconfig")
nuclei_scan(target, workflow="path/to/workflow.yaml")   # conditional chaining
```

Fixed by the control plane, not by argument:

- Rate limit comes from `scope.yaml`. There is no flag to raise it.
- `dos`, `fuzz`, `intrusive` templates are excluded. `-itags` is not available.
- Custom templates under `rules/nuclei/` are always included.

Scan the surface you ranked in recon, not everything you found. A thousand hosts
at the program's rate limit is hours of scanning that mostly rediscovers the same
CDN edge.

## Ports and services

```
cdn_check(hosts)          # first — do not scan CDN edges
port_scan(hosts)          # naabu, top-100 by default
service_scan(host, ports="80,443,8080", scripts="default,safe")
```

NSE categories are restricted to `default`, `safe`, `discovery`, `version`,
`banner`. `exploit`, `dos`, `brute`, `malware`, and `intrusive` are refused —
those are exploitation wearing a scanner's clothes, and they belong behind the
validation flow if anywhere.

A version banner is a lead, not a finding. "Apache 2.4.49 is vulnerable to
CVE-2021-41773" is not a report; a working path-traversal PoC is.

## Custom detections

Drop a YAML file into `rules/` and it becomes a detection with no code change:

- `rules/nuclei/*.yaml` — full Nuclei templates and workflows.
- `rules/easyhunt/*.yaml` — native rule-packs (matchers/extractors) that run
  against `http_probe` responses for free during recon.

`rules_reload()` after editing, `rule_test(body=..., status=...)` to dry-run a
rule against a sample without touching a host, and `rules_list()` to see what was
**rejected** — a rejected rule is a detection you believe you have and do not.

## Reading results

Everything is a candidate. Pull results with
`fetch_slice(job_id, path="findings", where="high|critical")` rather than
fetching the whole set. Then triage, then validate. A scanner hit that goes
straight into a report is how people get their bounty accounts restricted.

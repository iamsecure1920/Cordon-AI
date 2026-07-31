# EasyHunt AI — User Guide

> **EasyHunt AI** is a Python-based MCP (Model Context Protocol) security framework that lets AI assistants (Claude, Gemini, etc.) perform ethical security research using 53 real security tools — all controlled through a mandatory safety pipeline.

---

## Table of Contents

1. [What Is EasyHunt AI?](#1-what-is-easyhunt-ai)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Tool Categories](#5-tool-categories)
   - [Reconnaissance](#51-reconnaissance)
   - [DNS Analysis](#52-dns-analysis)
   - [HTTP Probing](#53-http-probing)
   - [Endpoint Discovery](#54-endpoint-discovery)
   - [JavaScript Analysis](#55-javascript-analysis)
   - [Port Scanning](#56-port-scanning)
   - [Subdomain Takeover](#57-subdomain-takeover)
   - [Secrets Detection](#58-secrets-detection)
   - [Cloud Security](#59-cloud-security)
   - [Exploitation](#510-exploitation)
   - [LLM Security](#511-llm-security)
   - [Scan Engines](#512-scan-engines)
6. [Safety and Ethics](#6-safety-and-ethics)
7. [Troubleshooting](#7-troubleshooting)
8. [Updating Tools](#8-updating-tools)
9. [Quick Reference Cheat Sheet](#9-quick-reference-cheat-sheet)

---

## 1. What Is EasyHunt AI?

EasyHunt AI bridges the gap between AI assistants and real penetration testing tools. Instead of asking an AI to *describe* how to test for SQL injection, you ask it to *actually run sqlmap* — within safe, audited, scope-controlled boundaries.

### How It Works

```
AI Assistant (Claude / Gemini)
        │
        │  MCP Protocol (JSON-RPC over stdio)
        ▼
   mcp_server.py          ← Entry point, registers all capabilities
        │
        ▼
   Control Plane          ← Mandatory, non-bypassable safety pipeline
   ┌─────────────────────────────────────────────────────────┐
   │  scope → sanitize → budget → rate-limit → approval      │
   │                → sandbox → audit                         │
   └─────────────────────────────────────────────────────────┘
        │
        ▼
   Tool Registry          ← easyhunt_tool() decorator wraps every execution
        │
        ▼
   Real Security Tools    ← nmap, nuclei, sqlmap, ffuf, etc.
```

### What You Can Do With It

- **Subdomain enumeration** — run subfinder, amass, assetfinder against a target
- **Web crawling** — use katana to spider a web app and extract endpoints
- **Vulnerability scanning** — run nuclei templates against discovered hosts
- **Secret scanning** — scan code repos for leaked API keys with trufflehog / gitleaks
- **LLM security** — red-team your AI models with garak, promptfoo, deepteam
- **Cloud posture** — check AWS/Azure/GCP misconfigurations with prowler / cloudfox

---

## 2. Prerequisites

### Supported Operating Systems

| OS | Support |
|----|---------|
| Ubuntu 22.04 LTS | ✅ Fully supported |
| Ubuntu 24.04 LTS | ✅ Supported |
| Debian 11 / 12 | ✅ Supported |
| Kali Linux 2024+ | ✅ Supported |
| macOS 13+ | ⚠️ Partial (some tools Linux-only) |
| Windows | ❌ Use WSL2 with Ubuntu 22.04 |

### Required Runtimes

| Runtime | Minimum Version | Used By |
|---------|-----------------|---------|
| Go | ≥ 1.21 (1.25 for httpx) | 28 tools |
| Python | ≥ 3.10 (3.10–3.12 for garak) | 14 tools |
| Rust + cargo | latest stable | 4 tools |
| Node.js | ≥ 20.20.0 | 2 tools |
| Ruby | ≥ 2.7 | whatweb |

### Recommended System Specs

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8+ GB |
| Disk | 5 GB free | 15+ GB |
| CPU | 2 cores | 4+ cores |
| Network | Broadband | 100Mbps+ |

---

## 3. Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/EasyHunt-AI.git
cd EasyHunt-AI
```

### Step 2: Install EasyHunt Python Package

```bash
pip install -e .
# or
pip install -r requirements.txt
```

### Step 3: Install Security Tools

Run the provided installer (or manually follow `tools.md`):

```bash
# If install.sh exists:
chmod +x install.sh
./install.sh

# Check what's installed:
easyhunt doctor
```

### Step 4: Start the MCP Server

```bash
# Stdio mode (for MCP clients like Claude Desktop)
python -m easyhunt

# Or directly:
python easyhunt/mcp_server.py
```

### Verifying Installation

```bash
easyhunt doctor
```

Expected output:
```
✅ subfinder       v2.6.3
✅ httpx           v1.6.5  (ProjectDiscovery)
✅ nuclei          v3.2.1
✅ nmap            7.95
✅ ffuf            v2.1.0
⚠️ massdns         not found  (required by shuffledns)
❌ garak           not installed
...
Summary: 48/53 tools available
```

> [!NOTE]
> The `doctor` command checks if each binary is on your PATH. A tool showing ❌ means EasyHunt will skip it rather than crash — the framework degrades gracefully.

---

## 4. Configuration

### 4.1 Subfinder API Keys

Location: `~/.config/subfinder/provider-config.yaml`

```yaml
# Create the directory first:
# mkdir -p ~/.config/subfinder

binaryedge:
  - YOUR_BINARYEDGE_KEY
censys:
  - YOUR_CENSYS_APP_ID:YOUR_CENSYS_SECRET
certspotter:
  - YOUR_CERTSPOTTER_KEY
chaos:
  - YOUR_CHAOS_KEY
github:
  - YOUR_GITHUB_PAT
hunter:
  - YOUR_HUNTER_KEY
securitytrails:
  - YOUR_SECURITYTRAILS_KEY
shodan:
  - YOUR_SHODAN_KEY
virustotal:
  - YOUR_VT_KEY
```

> [!TIP]
> Without API keys, subfinder still works using public sources (crt.sh, etc.) — but with keys you get 5-10x more subdomains.

### 4.2 theHarvester API Keys

Location: `<install_dir>/api-keys.yaml`

```yaml
apikeys:
  shodan:
    key: YOUR_SHODAN_KEY
  virustotal:
    key: YOUR_VT_KEY
  hunter:
    key: YOUR_HUNTER_KEY
  securitytrails:
    key: YOUR_ST_KEY
  censys:
    id: YOUR_CENSYS_APP_ID
    secret: YOUR_CENSYS_SECRET
```

### 4.3 Amass API Keys

Location: `~/.config/amass/datasources.yaml`

```yaml
# Full list at: https://github.com/owasp-amass/amass/blob/master/examples/datasources.yaml
datasources:
  - name: Shodan
    creds:
      apikey: YOUR_SHODAN_KEY
  - name: VirusTotal
    creds:
      apikey: YOUR_VT_KEY
```

### 4.4 Cloud Credentials

```bash
# AWS
aws configure
# or environment variables:
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# GCP
gcloud auth application-default login

# Azure
az login
```

### 4.5 LLM API Keys

```bash
# Add to ~/.bashrc or ~/.profile:
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=...

# For HuggingFace:
export HUGGINGFACE_API_KEY=hf_...
```

---

## 5. Tool Categories

---

### 5.1 Reconnaissance

**What it does**: Discovers subdomains, email addresses, IP ranges, and organizational assets before active testing.

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Passive subdomain discovery via 40+ sources | `go install ...` |
| `assetfinder` | Lightweight subdomain finder | `go install ...` |
| `findomain` | Rust-based subdomain finder with CT logs | `cargo install findomain` |
| `amass` | Full attack surface mapper (OWASP Flagship) | `go install ...` |
| `asnmap` | ASN → IP range mapper | `go install ...` |
| `tlsx` | TLS cert analysis, JARM/JA3 fingerprinting | `go install ...` |
| `theHarvester` | OSINT — emails, names, IPs, subdomains | `pip + git clone` |
| `whois` | Domain/IP/ASN registration data | `apt install whois` |

**Example Usage**:

```bash
# Passive subdomain enumeration
subfinder -d example.com -silent -o subs.txt

# Aggressive multi-source enumeration
amass enum -d example.com -active -src

# Map org's IP ranges from ASN
asnmap -org "Target Corp" -json

# OSINT email + subdomain harvest
python3 theHarvester.py -d example.com -b google,bing,crtsh -l 500

# TLS cert-based subdomain discovery
tlsx -u example.com -san -cn -json | jq '.san[]'

# WHOIS for domain registration info
whois example.com
```

**Typical EasyHunt output**:
```json
{
  "tool": "subfinder",
  "target": "example.com",
  "subdomains": ["api.example.com", "staging.example.com", "admin.example.com"],
  "count": 47,
  "duration_sec": 12.3
}
```

---

### 5.2 DNS Analysis

**What it does**: Resolves discovered subdomains, generates permutations, identifies CDN/WAF providers, and brute-forces DNS names.

| Tool | Purpose |
|------|---------|
| `dnsx` | Fast multi-type DNS resolver + brute-forcer |
| `alterx` | DSL-powered subdomain permutation generator |
| `cdncheck` | CDN/WAF/Cloud provider identifier |
| `shuffledns` | massdns wrapper for high-speed brute-force |

**Example Usage**:

```bash
# Resolve subdomains and get A records
dnsx -l subs.txt -a -resp -silent

# Resolve multiple record types
dnsx -l subs.txt -a -aaaa -cname -mx -resp

# Generate permutations and resolve in one pipeline
echo "api.example.com" | alterx | dnsx -silent

# Identify which subdomains are behind Cloudflare
cat subs.txt | cdncheck -cdn -match-waf cloudflare

# Brute-force DNS at scale (requires massdns)
shuffledns -d example.com -w /opt/wordlists/subdomains.txt -r /opt/resolvers.txt -o found.txt
```

> [!NOTE]
> `shuffledns` requires `massdns` binary on PATH. If `massdns` is missing, EasyHunt will skip shuffledns and fall back to dnsx brute-force.

---

### 5.3 HTTP Probing

**What it does**: Probes discovered hosts to identify live web servers, technology stacks, WAF presence, and web application fingerprints.

| Tool | Purpose |
|------|---------|
| `httpx` | Multi-probe HTTP toolkit — status, title, tech, TLS, CDN |
| `whatweb` | 1,800+ plugin web tech fingerprinter |
| `wafw00f` | WAF fingerprinting — detects 100+ WAF products |

**Example Usage**:

```bash
# Probe all discovered subdomains
httpx -l subs.txt -sc -title -tech-detect -silent

# Full HTTP probe with JSON output
httpx -l subs.txt -cdn -ip -cname -tls-probe -json -o http_results.json

# Take screenshots of all live targets
httpx -l live_hosts.txt -screenshot -system-chrome -o screenshots/

# Fingerprint web technologies
whatweb -i live_hosts.txt -a 3 --log-json=whatweb.json

# Detect WAF presence
wafw00f https://example.com
cat live_hosts.txt | wafw00f -i -
```

> [!WARNING]
> **httpx binary collision**: Python's `httpx` package installs a conflicting CLI. Always verify with `httpx -version` — output must contain "ProjectDiscovery". If it doesn't, run `pip uninstall httpx-cli`.

---

### 5.4 Endpoint Discovery

**What it does**: Crawls web applications, fetches historical URLs from archives, discovers hidden parameters, and fuzzes for unreferenced paths.

| Tool | Purpose |
|------|---------|
| `katana` | Next-gen web crawler (standard + headless JS) |
| `gau` | Passive URL gathering from Wayback/OTX/CC/URLScan |
| `waybackurls` | Wayback Machine URL fetcher |
| `waymore` | Extended archive URL + response body downloader |
| `arjun` | HTTP parameter discovery (25,000+ word wordlist) |
| `paramspider` | Archive-based parameter URL miner with FUZZ placeholders |
| `ffuf` | High-speed web fuzzer for dirs/params/vhosts |
| `feroxbuster` | Recursive forced browsing in Rust |

**Example Usage**:

```bash
# Standard web crawl
katana -u https://example.com -d 3 -silent -o crawl.txt

# Headless JS crawl (discovers dynamic endpoints)
katana -u https://example.com -hl -system-chrome -d 3 -jc -kf -o crawl_js.txt

# Passive URL discovery from archives
gau example.com --blacklist png,jpg,gif,css --fc 404 -o urls.txt

# Fetch historical URLs from Wayback
echo "example.com" | waybackurls -no-subs | sort -u > wayback.txt

# Discover HTTP parameters
arjun -u https://example.com/api/v1/search -m GET

# Mine parameterized URLs for fuzzing
paramspider -d example.com -s | tee param_urls.txt

# Directory fuzzing
ffuf -w /opt/wordlists/common.txt -u https://example.com/FUZZ -mc 200,301,302,403 -fc 404

# Recursive content discovery
feroxbuster -u https://example.com -w /opt/wordlists/common.txt -x php,html,js -depth 3
```

---

### 5.5 JavaScript Analysis

**What it does**: Analyzes JavaScript files for hidden endpoints, leaked secrets, API keys, vulnerable library versions, and embedded credentials.

| Tool | Purpose |
|------|---------|
| `jsluice` | AST-based JS secrets/URL extractor (resolves variable concatenation) |
| `retire` | Vulnerable/outdated JavaScript library detector + SBOM |
| `linkfinder` | Regex-based JS endpoint extractor |

**Example Usage**:

```bash
# Extract all endpoints from a JS file
jsluice urls app.js

# Extract secrets (API keys, tokens) from JS
jsluice secrets app.js

# From a live URL via pipeline
curl -sL https://example.com/static/app.js | jsluice secrets

# Resolve relative paths against base URL
jsluice urls -R https://example.com app.js

# Scan for vulnerable JS libraries
retire --path ./src --severity medium

# Generate SBOM from Node project
retire --outputformat cyclonedx --outputpath sbom.json

# Extract endpoints from JS on a domain
python3 linkfinder.py -i https://example.com -d -o cli

# Scan a specific JS file
python3 linkfinder.py -i https://example.com/app.js -o results.html
```

---

### 5.6 Port Scanning

**What it does**: Discovers open ports, services, and versions on target hosts to identify attack surface.

| Tool | Purpose |
|------|---------|
| `naabu` | Fast SYN/CONNECT/UDP port scanner with CDN exclusion |
| `nmap` | Gold standard — host discovery, OS fingerprinting, NSE scripts |
| `masscan` | Internet-scale async scanner — up to 10M pps |

**Example Usage**:

```bash
# Quick port scan (top 1000 ports)
naabu -host example.com -top-ports 1000 -silent

# Full port scan with service detection
naabu -host example.com -p 1-65535 -sV

# Pipe naabu output to nmap for service detection
naabu -l hosts.txt -p 80,443,8080,8443 -silent | nmap -sV -iL -

# Standard nmap scan
nmap -sS -sV -O -p 1-1000 example.com

# Nmap with vulnerability NSE scripts
nmap --script=http-vuln-cve2021-41773 example.com

# Fast subnet scan with masscan
sudo masscan -p80,443,8080 10.0.0.0/24 --rate 1000
```

> [!CAUTION]
> `naabu` (SYN mode), `nmap` (-sS), and `masscan` all require **root or CAP_NET_RAW**. EasyHunt automatically switches naabu to CONNECT mode if not running as root.

---

### 5.7 Subdomain Takeover

**What it does**: Checks if discovered subdomains are vulnerable to takeover — dangling DNS records pointing to unclaimed cloud services.

| Tool | Purpose |
|------|---------|
| `subzy` | Response signature matching against fingerprint DB |
| `dnsreaper` | Cloud-aware scanner — queries AWS/Azure/GCP APIs directly |
| `dig` | Manual CNAME chain verification |

**Example Usage**:

```bash
# Check all subdomains for takeover
subzy run --targets subs.txt --concurrency 20 --hide_fails

# Cloud-aware takeover check
python main.py file --filename subs.txt --out results --out-format json

# Check via AWS Route53
python main.py aws --aws-access-key-id KEY --aws-access-key-secret SECRET

# Manual CNAME verification
dig CNAME sub.example.com
# If response is NXDOMAIN for the CNAME target → potentially takeable
```

**What a vulnerable finding looks like**:
```
[VULNERABLE] staging.example.com -> s3-website-us-east-1.amazonaws.com
  The S3 bucket does not exist and can be registered.
  Signature: aws_s3
```

---

### 5.8 Secrets Detection

**What it does**: Scans source code, git history, file systems, and cloud storage for leaked credentials, API keys, tokens, and passwords.

| Tool | Purpose |
|------|---------|
| `kingfisher` | SIMD-accelerated scan + live validation + revocation |
| `noseyparker` | 188-rule Rust scanner with deduplication (retired) |
| `trufflehog` | 800+ secret types with live API validation |
| `gitleaks` | Lightweight git/dir/stdin secret scanner |

**Example Usage**:

```bash
# Scan a directory
kingfisher scan /path/to/project

# Scan with live validation (only show confirmed live credentials)
kingfisher scan /path/to/project --only-valid

# Open interactive HTML report
kingfisher scan /path/to/project --view-report

# Scan git repo for verified secrets
trufflehog git https://github.com/org/repo --results=verified

# Scan local git repository
trufflehog git file:///path/to/local/repo --results=verified,unknown

# Scan S3 bucket for secrets
trufflehog s3 --bucket=my-bucket --results=verified

# Scan GitHub organization
trufflehog github --org=myorg --results=verified

# Git repo scan with JSON report
gitleaks git -v /path/to/repo --report-path findings.json --report-format json

# Scan a directory
gitleaks dir -v /path/to/code

# Scan stdin (e.g. for piping)
cat secrets_dump.txt | gitleaks stdin -v
```

> [!NOTE]
> `noseyparker` is officially retired by Praetorian. It still works but receives no security updates. `trufflehog` and `kingfisher` are the recommended modern alternatives.

---

### 5.9 Cloud Security

**What it does**: Discovers public cloud misconfigurations, exposed storage buckets, insecure IAM policies, and compliance violations.

| Tool | Purpose |
|------|---------|
| `cloud_enum` | Passive multi-cloud asset enumeration (AWS/Azure/GCP) |
| `s3scanner` | S3 bucket misconfiguration scanner |
| `cloudfox` | Attack path discovery across AWS/Azure/GCP |
| `prowler` | CSPM — CIS/NIST/PCI-DSS/SOC2 compliance checking |
| `kubescape` | Kubernetes security — NSA-CISA/MITRE/CIS scanning |

**Example Usage**:

```bash
# Enumerate cloud assets for a company name
python3 cloud_enum.py -k "targetcorp"
python3 cloud_enum.py -k "targetcorp" -k "target-corp" -k "target_corp"

# Scan for open S3 buckets
s3scanner -bucket-file potential_names.txt -enumerate

# GCP bucket scan
s3scanner -provider gcp -bucket-file names.txt -json

# Cloud attack path discovery (requires configured credentials)
cloudfox aws --profile default all-checks
cloudfox gcp --project my-project all-checks

# Full AWS security posture assessment
prowler aws
prowler aws --compliance cis_1.5_aws     # CIS benchmark
prowler aws -M json csv sarif             # multiple output formats

# Kubernetes security scan
kubescape scan
kubescape scan framework nsa              # NSA-CISA guidelines
kubescape scan image nginx:latest         # container image scan
```

> [!IMPORTANT]
> `cloudfox` and `prowler` require cloud credentials configured before running. For AWS: `aws configure` or set `AWS_*` environment variables. For GCP: `gcloud auth application-default login`.

---

### 5.10 Exploitation

**What it does**: Detects and verifies vulnerabilities in web applications — XSS, SQL injection, and out-of-band interaction catching.

| Tool | Purpose | EasyHunt Restriction |
|------|---------|---------------------|
| `dalfox` | XSS scanning and parameter analysis | Detection only, no exfiltration |
| `sqlmap` | SQL injection detection | Detection ONLY — extraction flags hard-blocked |
| `interactsh-client` | OOB interaction catching (SSRF/blind/XXE proof) | None |

**Example Usage**:

```bash
# XSS scanning
dalfox url "https://example.com/search?q=test"
cat urls.txt | dalfox pipe --silence

# SQL injection detection (EasyHunt safe mode)
sqlmap -u "https://example.com/item?id=1" --batch --level 3 --risk 2
sqlmap -r saved_request.txt --batch --technique BEUSTQ

# Out-of-band interaction proof
interactsh-client -n 5 -json
# → generates URLs like: abc123.interact.sh
# → inject these into SSRF/blind params
# → interactsh catches the callback and shows proof
```

> [!CAUTION]
> **sqlmap extraction is HARD-BLOCKED** by EasyHunt's ArgPolicy. The following flags will always be rejected: `--dump`, `--dbs`, `--tables`, `--columns`, `--schema`, `--sql-shell`, `--os-shell`, `--file-read`, `--file-write`, `--tamper`, `--proxy`

---

### 5.11 LLM Security

**What it does**: Red-teams AI language models and AI-powered applications for jailbreaks, prompt injection, data leakage, and safety failures.

| Tool | Purpose |
|------|---------|
| `garak` | NVIDIA's LLM vulnerability scanner |
| `promptfoo` | LLM evaluation and red-team automation |
| `deepteam` | LLM red-teaming framework for AI agents/RAG |

**Example Usage**:

```bash
# Scan GPT-4o for vulnerabilities
python -m garak --target_type openai --target_name gpt-4o --probes encoding
python -m garak --target_type openai --target_name gpt-4o --probes dan.Dan_11_0

# List available probe types
python -m garak --list_probes

# Scan a local HuggingFace model
python -m garak --target_type huggingface --target_name gpt2 --probes all

# Promptfoo evaluation
promptfoo init                     # create config
promptfoo eval                     # run evaluations
promptfoo view                     # open web dashboard

# Promptfoo red-team
promptfoo redteam run
promptfoo redteam generate         # generate attack prompts only

# DeepTeam red-team (Python API)
deepteam test
```

**Required Environment Variables**:
```bash
export OPENAI_API_KEY=sk-...         # for garak openai target
export ANTHROPIC_API_KEY=sk-ant-...  # for Anthropic models
```

---

### 5.12 Scan Engines

**What it does**: Orchestrates multi-tool scanning workflows, template-based vulnerability detection, static analysis, and full reconnaissance pipelines.

| Tool | Purpose |
|------|---------|
| `bbot` | OSINT/recon/ASM event-driven framework (80+ modules) |
| `nuclei` | Template-based vulnerability scanner |
| `semgrep` | Fast SAST — 30+ languages, IaC |
| `jaeles` | YAML request signature scanner (archived) |
| `osmedeus` | Declarative security orchestration engine |

**Example Usage**:

```bash
# BBOT subdomain enumeration
bbot -t example.com -p subdomain-enum

# BBOT thorough web scan
bbot -t example.com -p web-thorough

# BBOT passive only
bbot -t example.com -rf passive -p subdomain-enum

# Nuclei single target scan
nuclei -u https://example.com -s critical,high

# Nuclei with auto tech detection
nuclei -u https://example.com -as

# Nuclei specific tag scan
nuclei -u https://example.com -tags cve,xss,sqli

# Nuclei batch scan
nuclei -l targets.txt -s critical,high,medium -j -o results.json

# Semgrep SAST scan
semgrep scan --config auto /path/to/code
semgrep scan --config p/security-audit /path/to/code
semgrep scan --metrics=off --config auto /path/to/code  # offline mode

# Jaeles with CVE signatures
jaeles scan -s /opt/jaeles-signatures/cves/ -u https://example.com

# Osmedeus recon
osmedeus run -m recon -t example.com
osmedeus run -f general -t example.com
```

> [!IMPORTANT]
> **Nuclei excluded tags in EasyHunt**: `dos`, `fuzz`, `intrusive`, `bruteforce` — these will be automatically filtered out and will not run.

> [!WARNING]
> **jaeles** repository is archived and no longer maintained. Signatures still work but may miss new CVEs. Consider using `nuclei` as the primary template scanner.

---

## 6. Safety and Ethics

### The Control Plane

Every tool execution passes through a 7-stage safety pipeline. This is **non-bypassable** — there is no API or code path that skips it.

```
1. scope     → Is the target within allowed scope? (CIDR/domain whitelist)
2. sanitize  → Are arguments safe? (no shell injection, path traversal)
3. budget    → Within scan budget? (CPU time, requests, data limits)
4. rate-limit → Within rate limits? (requests/sec per tool per target)
5. approval  → Requires human sign-off for high-risk operations?
6. sandbox   → Execute in isolated subprocess with resource limits
7. audit     → Log all executions to immutable audit trail
```

### Hard-Blocked Operations

These are enforced at the `ArgPolicy` level and cannot be overridden:

| Tool | Blocked Flags/Modes |
|------|---------------------|
| sqlmap | `--dump`, `--dbs`, `--tables`, `--columns`, `--schema`, `--sql-shell`, `--os-shell`, `--os-cmd`, `--file-read`, `--file-write`, `--passwords`, `--tamper`, `--proxy`, `--tor` |
| nuclei | Tags: `dos`, `fuzz`, `intrusive`, `bruteforce` |
| nmap | NSE categories: `exploit`, `dos`, `brute`, `malware` |
| masscan | `--rate` capped at 100 pps |
| dalfox | No `--exploit-param` or blind XSS exfiltration flags |
| ffuf | No `-v` verbose mode that dumps full response bodies |

### Scope Control

EasyHunt enforces target scoping. You must define allowed targets before running scans:

```python
# In your EasyHunt config or session:
allowed_targets = [
    "example.com",
    "*.example.com",
    "192.168.1.0/24"
]
```

Any scan attempting to target an out-of-scope host will be rejected with `ScopeViolation`.

### Audit Logging

All tool executions are logged to:
- **Console**: Real-time execution log
- **Audit file**: `~/.easyhunt/audit.jsonl` — append-only, includes timestamp, tool, args, user, duration, exit code

### Responsible Use

> [!CAUTION]
> EasyHunt is designed for **authorized security testing only**. Using these tools against systems without explicit written permission is illegal in most jurisdictions. Always obtain proper authorization before scanning.

---

## 7. Troubleshooting

### `httpx` Shows Wrong Version

**Symptom**: `httpx -version` shows something that doesn't mention "ProjectDiscovery"

**Cause**: Python's `httpx` package installs a conflicting CLI

**Fix**:
```bash
pip uninstall httpx-cli 2>/dev/null
pip uninstall httpx 2>/dev/null
# Reinstall the Go binary
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Verify:
httpx -version  # should show "ProjectDiscovery"
```

---

### `shuffledns` Fails Immediately

**Symptom**: `Error: massdns binary not found in PATH`

**Cause**: massdns is required but not installed

**Fix**:
```bash
git clone https://github.com/blechschmidt/massdns /opt/massdns
cd /opt/massdns && make -j$(nproc)
sudo cp bin/massdns /usr/local/bin/
massdns --version  # verify
```

---

### `naabu` Permission Denied for SYN Scan

**Symptom**: `Error sending SYN packets: operation not permitted`

**Fix (Option 1 — run as root)**:
```bash
sudo naabu -host example.com -p 80,443
```

**Fix (Option 2 — use CONNECT mode)**:
```bash
naabu -host example.com -scan-type c -p 80,443
```

**Fix (Option 3 — grant capability)**:
```bash
sudo setcap cap_net_raw+ep $(which naabu)
```

---

### `garak` Import Error / Python Version

**Symptom**: `ImportError` or `garak requires Python 3.10-3.12`

**Cause**: garak does NOT support Python 3.13+

**Fix**:
```bash
# Install Python 3.11 via pyenv
curl https://pyenv.run | bash
pyenv install 3.11.9
pyenv local 3.11.9

# Create dedicated venv
python3.11 -m venv ~/.venvs/garak
source ~/.venvs/garak/bin/activate
pip install garak
```

---

### `katana` Headless Mode Fails

**Symptom**: `Error: chrome not found` or headless mode doesn't discover JS endpoints

**Fix**:
```bash
# Install Chrome from Google's repo (not Ubuntu's outdated version)
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update && sudo apt install -y google-chrome-stable

# Test:
google-chrome --version
katana -u https://example.com -hl -system-chrome
```

---

### Tool Not Found in PATH

**Symptom**: `easyhunt doctor` shows ❌ for Go tools that were installed

**Cause**: Go binary directory not in PATH

**Fix**:
```bash
# Add to ~/.bashrc:
echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/.cargo/bin"'    >> ~/.bashrc  # Rust
echo 'export PATH="$PATH:$HOME/.local/bin"'    >> ~/.bashrc  # pipx
source ~/.bashrc

# Verify:
which subfinder
which nuclei
```

---

### Rate Limit / Budget Exceeded

**Symptom**: `BudgetExceeded` or `RateLimitError` in EasyHunt output

**Fix**: Adjust rate limits in your EasyHunt config, or wait for the rate limit window to reset:
```python
# In EasyHunt config:
rate_limits = {
    "nuclei": "10/minute",
    "ffuf": "100/minute",
    "sqlmap": "5/minute",
}
```

---

### `jaeles` Returns No Results

**Symptom**: jaeles runs but finds nothing

**Cause**: Signatures directory not configured or empty

**Fix**:
```bash
# Clone signatures
git clone https://github.com/jaeles-project/jaeles-signatures /opt/jaeles-signatures

# Test with a specific signature
jaeles scan -s /opt/jaeles-signatures/ -u https://example.com
```

---

## 8. Updating Tools

### Update All Go Tools

```bash
# Re-run go install for each tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# ... (repeat for each Go tool)
```

### Update All Python Tools

```bash
pip install --upgrade wafw00f waymore sqlmap prowler garak deepteam semgrep kingfisher-bin
pipx upgrade arjun
pipx upgrade bbot
```

### Update Git-Cloned Python Tools

```bash
cd /opt/theHarvester && git pull && pip3 install -r requirements/base.txt
cd /opt/linkfinder && git pull
cd /opt/paramspider && git pull && pip3 install -e .
cd /opt/cloud_enum && git pull
cd /opt/dnsreaper && git pull && pip3 install -r requirements.txt
```

### Update Nuclei Templates

```bash
nuclei -update-templates
# or force update:
nuclei -update-templates -ud ~/.config/nuclei/
```

### Update Jaeles Signatures

```bash
cd /opt/jaeles-signatures && git pull
```

### Update massdns

```bash
cd /opt/massdns && git pull && make -j$(nproc)
sudo cp bin/massdns /usr/local/bin/
```

---

## 9. Quick Reference Cheat Sheet

### By Task

| Goal | Command |
|------|---------|
| Find all subdomains | `subfinder -d example.com -all -o subs.txt` |
| Resolve which subs are live | `dnsx -l subs.txt -a -resp -silent` |
| Probe live hosts | `httpx -l live.txt -sc -title -tech-detect` |
| Crawl a web app | `katana -u https://example.com -d 3 -o crawl.txt` |
| Find hidden parameters | `arjun -u https://example.com/api/endpoint` |
| Directory fuzzing | `ffuf -w wordlist.txt -u https://target/FUZZ` |
| Port scan | `naabu -host example.com -top-ports 1000` |
| Vulnerability scan | `nuclei -u https://example.com -s critical,high -as` |
| Scan for WAF | `wafw00f https://example.com` |
| Find secrets in code | `trufflehog git https://github.com/org/repo --results=verified` |
| XSS scan | `dalfox url "https://example.com/search?q=test"` |
| SQL injection detect | `sqlmap -u "https://example.com/item?id=1" --batch` |
| Check subdomain takeover | `subzy run --targets subs.txt --hide_fails` |
| AWS security check | `prowler aws` |
| SAST code scan | `semgrep scan --config p/security-audit /path/to/code` |
| LLM red-team | `python -m garak --target_type openai --target_name gpt-4o --probes all` |

### By Tool Type

| Runtime | Key Tools |
|---------|-----------|
| Go binaries | subfinder, httpx, nuclei, dnsx, katana, ffuf, naabu, gau, waybackurls, jsluice, amass, asnmap, tlsx, alterx, cdncheck, shuffledns, s3scanner, cloudfox, dalfox, trufflehog, gitleaks, interactsh-client, jaeles, subzy |
| Python | theHarvester, wafw00f, waymore, arjun, paramspider, linkfinder, cloud_enum, sqlmap, prowler, garak, deepteam, bbot, semgrep, kingfisher, dnsreaper |
| Rust binaries | findomain, feroxbuster, noseyparker, dalfox (v3), kingfisher |
| Node.js | retire, promptfoo |
| Ruby | whatweb |
| System | nmap, masscan, whois, dig, git |

### Binary Locations

```
~/go/bin/           → Go tools (subfinder, httpx, nuclei, etc.)
~/.cargo/bin/       → Rust tools (findomain, feroxbuster)
~/.local/bin/       → pipx tools (arjun, bbot)
/usr/local/bin/     → massdns, manually installed binaries
/usr/bin/           → apt-installed tools (nmap, whatweb, whois)
/opt/*/             → git-cloned Python tools
```

---

*EasyHunt AI User Guide — last updated 2026-07-30*
*Research based on 53 official GitHub repositories*

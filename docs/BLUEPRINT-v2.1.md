# Cordon AI — v2.1 Integration Blueprint

**Author:** code review of 7 repositories (2026-08-17)
**Status:** P0 (WAF bypass, response-diff, regex bypass) + P1 (endpoint scoring,
chains, verification, coverage ledger) + **P2 (prompt packs, Burp handoff,
code audit, llms.txt) implemented and shipped** (2026-08-17).
**Scope:** every repo was cloned and read at source level (not README only)

## Implemented map (where each item landed)

| Blueprint item | Landed in | Verified by |
|---|---|---|
| WAF fingerprint DB + bypass tables + encodings | `cordon/knowledge/waf.py` | `tests/test_waf_bypass.py` |
| `waf_bypass` / `fingerprint_waf` / `waf_vendors` MCP tools | `cordon/tools/waf_bypass.py` | `tests/test_waf_bypass.py` |
| Chain injects bypass into sqlmap (`--prefix/--suffix`) + dalfox (`--custom-payload`) on clean base pass | `cordon/tools/exploit_chain.py`, `exploitation.py` | `tests/test_v21_integration.py::TestWafBypassChainPass` |
| Response-diff engine (body-hash clustering, deltas) | `cordon/tools/fuzz_diff.py` | `tests/test_fuzz_diff.py` |
| `fuzz_compare` MCP tool + cache-poison re-request mode | `cordon/tools/webscan.py` | suite green |
| fuzz_diff wired into `content_discovery` soft-404 triage | `cordon/tools/endpoints.py` | suite green |
| Regex-bypass generator (4 modes × 4 encodings) | `cordon/knowledge/bypass.py` | `tests/test_bypass_generator.py` |
| Generator wired into `web_injection_probe(regex_bypass=True)` | `cordon/tools/web_injection.py` | suite green |
| Endpoint risk scoring + scored ordering in the chain | `cordon/tools/exploit_chain.py` (`_score_injection_point`) | `tests/test_v21_integration.py::TestEndpointScoring` |
| Finding chains + `find_finding_chains` + report section | `cordon/knowledge/attackgraph.py`, `cordon/report/synthesize.py` | `tests/test_v21_integration.py::TestFindingChains` |
| `verify_output` per-tool post-checks | `cordon/tools/common.py` | `tests/test_v21_integration.py::TestVerifyOutput` |
| verify_output wired into `nuclei_scan` + `content_discovery` empty-result cases | `cordon/engines/nuclei_engine.py`, `cordon/tools/endpoints.py` | suite green |
| Runtime coverage ledger + report coverage table | `cordon/knowledge/coverage.py` (`CoverageLedger`), `control_plane/context.py`, report | `tests/test_v21_integration.py::TestCoverageLedger` |
| P2-10 JS escape normalization | `cordon/tools/js_analysis.py` (`_normalize_escapes`) | `tests/test_v21_integration.py::TestJsEscapeNormalization` |
| P2-8 Prompt packs (18 classes, role/objective/scope/denies/criteria/evidence) | `cordon/knowledge/prompts.py` + `cordon/tools/prompts.py` (`exploit_prompt`, `prompt_classes`) | `tests/test_v22_p2.py::TestPromptPacks` |
| P2-9 Burp handoff (scope-enforced, approval-gated, bounded batch) | `cordon/tools/burp.py` (`burp_send`) | `tests/test_v22_p2.py::TestBurpSend` |
| P2-11 Code-audit deliverable (semgrep + gitleaks → code-audit.json/.md, redacted) | `cordon/tools/code_audit.py` (`code_audit`), phase in `scripts/phase.py` + `hunt.sh` | `tests/test_v22_p2.py::TestCodeAudit` |
| llms.txt agent index | `llms.txt` | — |

Full suite: **2081 passed** (was 1,973 at sprint start); ruff clean on all new files.

---

## 0. Executive summary

Seven repositories were analyzed end-to-end (full source, configs, migrations,
docs): **HuntProxy**, **autopentest-ai**, **bugbounty-lab101**, **Cordon-AI**
(local, already deeply known), **PayloadsAllTheThings** (already integrated
locally), **shannon**, **ReconX**.

Cordon-AI's real, honest gaps — from its own `knowledge/coverage.py` matrix —
are:

1. **13 bug classes without an auto-validator** (6 `detect-only`: XXE, CRLF,
   LFI, open redirect, HTTP parameter pollution, file upload; 7 `manual`: IDOR,
   business logic, CSRF, deserialization, cache poisoning, race conditions,
   mass assignment).
2. **No WAF-bypass capability** — `waf_detect` names the vendor; nothing
   generates bypass payloads for it. The one thing the user explicitly asked
   for ("advanced bypass techniques").
3. **Fuzzing uses ffuf's crude filters** — no response-diffing engine, so
   soft-404s and cache-poisoning deltas go unseen.
4. **No chain detection across findings** — `attackgraph.py` exists but no
   BFS chain patterns (XSS+no-CSP, SSRF→metadata, IDOR+admin) upgrade severity.

The five external repos were filtered for components that close these gaps.
**Three land in this sprint (P0), four in P1, four in P2.** Everything maps to a
specific file or tool in this codebase. License notes: MIT code (autopentest-ai,
HuntProxy) may be ported with attribution; AGPL (shannon) and Apache-2.0
(ReconX) concepts may be reimplemented, not copied.

---

## 1. Repository analysis

### 1.1 HuntProxy — BehiSecc (Rust, ~73k LOC, Apache-2.0)

**Purpose.** A self-hosted web security workbench built *for AI agents*: a
Burp-style intercepting proxy + browser automation + fuzzer, exposed over MCP,
that runs headless on a VPS so an agent can hunt from anywhere.

**Architecture.** Rust single-binary daemon + browser worker:
`proxy` (HTTP/HTTPS CONNECT interception with a local CA, `ValidatedDial`
upstream resolver) → `reply` (a full bounded HTTP stack, `raw.rs` 1.6k lines) →
`storage` (SQLite, 14 migrations covering exchanges, findings, cookies, IP
rotation, fuzz response groups, request rules) → `crawler` (one-level,
deliberately non-recursive) → `page_analyzer` (static endpoint/URL/email
extraction from JS+HTML) → `fuzzer` (templated fuzzing with response diffing) →
`plugins` (QuickJS extension runtime: entrypoints are SHA-256 hashed, no
filesystem/process/socket/secret APIs, CPU budget per plan/analyze stage) →
`mcp` + `api` + web UI (all thin adapters over one `AppState`).

**Core modules and I/O.**

| Module | Input | Output |
|---|---|---|
| `proxy` | raw HTTP traffic | captured `Exchange`s (decrypted) |
| `fuzzer` + `generators.rs` | `FuzzTemplate`, insertion points | `FuzzResponseGroup` + `FuzzResponseDiff` |
| `page_analyzer` | JS/HTML body bytes | endpoints, absolute URLs, emails |
| `compare.rs` | two saved exchanges | bounded diff, sensitive headers redacted |
| `plugins` | JS package + SHA-256 | validated, budgeted execution plan |

**Concrete techniques worth stealing.**

- **`FuzzResponseDiff`** (`fuzzer/mod.rs`): per-case diff vs a baseline —
  status/mime/length-delta/percent, duration-ratio, header-change list,
  body-hash equality, bounded text diff. **This is soft-404 detection done
  right** — cluster cases by body hash, keep clusters that differ from
  baseline, and you have a clean "what did the payload actually change" signal
  that ffuf's `-fl/-fw/-fs` filters cannot give you.
- **`PayloadGenerator::RegexBypass`** (`generators.rs`): mutate an input at
  four positions — `Start`, `Separator` (between bytes), `End`,
  `RegexMetachar` — under four encodings (`Url`, `Unicode`, `Raw`,
  `DoubleUrl`), bounded to N payloads. A generic WAF-regex bypass engine, not
  a hardcoded list.
- **`page_analyzer` escape normalization**: normalizes `https:\/\/host` and
  `\u002Fapi` before regexing, so minified bundles yield endpoints. (Cordon's
  `js_analysis.py` does not do this — see P2-10.)
- **`compare.rs`** redaction discipline: raw evidence is diffed, sensitive
  header values are never returned. Matches Cordon's evidence-handling ethos.

### 1.2 autopentest-ai — bhavsec (Python MCP server, ~9.6k LOC, MIT)

**Purpose.** An LLM-driven automated web pentest that follows OWASP WSTG
top-to-bottom, with an MCP server enforcing coverage tracking, phase gates,
evidence checklists, WAF evasion, and a knowledge graph.

**Architecture.** One FastMCP-style server (`server/server.py`, 6.1k LOC)
exposing ~70 tools over three layers: engagement state (checkpoints, task
tree, audit log, deliverables), knowledge (WSTG index, 31 PortSwigger
technique guides, WAF DB), and orchestration (phase gates, exploitation
queue, judge review). All modules follow a `configure(data_dir, atomic_write,
append_event)` dependency-injection pattern.

**Core modules and I/O.**

| Module | Input | Output |
|---|---|---|
| `waf_evasion.py` (616 LOC) | response headers/body/status | vendor ID + ordered bypass payloads per vuln class + encoding strategies |
| `endpoint_priority.py` (247) | endpoint dicts | risk scores, sorted queue |
| `knowledge_graph.py` (683) | nodes + typed edges | chains (BFS over `CHAIN_PATTERNS`) with severity upgrades |
| `tool_verification.py` (454) | command + tool raw output | valid/suspicious/empty + corrected command |
| `tool_parsers.py` (643) | nmap/nuclei/sqlmap/ffuf/httpx output | condensed structured summaries (3–5× token cut) |
| `context_compression.py` / `task_tree.py` | phase activity | per-phase summaries, tree w/ auto-propagation |

**Concrete techniques worth stealing.**

- **WAF fingerprint DB + bypass tables** (`waf_evasion.py`): 12 vendors
  (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5…) keyed on headers /
  `Server` / body regexes / status codes / block-page markers; then
  `WAF_BYPASSES[vendor][vuln]` with payloads tiered `basic → intermediate →
  advanced`, plus encoding strategies (double-URL, unicode, HTML-entity,
  chunked). **This is the exact "advanced bypass techniques" capability the
  user asked for, and Cordon has nothing like it.**
- **`find_chains()`** (`knowledge_graph.py`): BFS over typed edges with named
  patterns — `XSS + no CSP`, `SSRF + cloud metadata`, `IDOR + admin`,
  `reflected input + authz` — each with a severity-upgrade suggestion.
- **Per-tool result verification** (`tool_verification.py`): nmap "Host is up"
  checks with `-Pn` corrections, nuclei empty-result checks, etc. The
  "absence ≠ negative" invariant, enforced per binary.
- **WSTG phase gates**: `track_test`/`track_tool`/`get_coverage`/
  `phase_gate_check` — a runtime test-status ledger with PASS/FAIL gates,
  which is exactly what Cordon's static `coverage.py` matrix cannot show.

### 1.3 bugbounty-lab101 — DevCop95 (bash + Python, 52 files)

**Purpose.** A HackerOne workflow workspace: program scope docs in Markdown →
`bugbounty-hunter.sh` → H1-format report template; a 974-line registry of 400+
Kali tools; Burp REST integration; local VM lab.

**High-value components.**

- **`scripts/scope_guard.py`** — target normalization with real edge cases:
  rejects URL credentials, validates ports, rejects control chars/whitespace,
  IP-vs-CIDR-vs-wildcard matching, Markdown scope-section parsing. Cordon's
  `scope.py` is stricter (YAML, policy text) — this is a **test/reference
  oracle** for normalization, not a replacement.
- **`auto-scanner/burp-integration/burp_api.py`** — Burp REST client (target,
  active scan, spider, sitemap, issues, export) with **scope enforcement on
  every call** (`require_authorized()`). Cordon has no Burp integration at
  all — an optional human-handoff surface (P2-9).
- **Tool registry with risk ratings** — informational; Cordon's
  `install/recipes.py` already supersedes it.

### 1.4 Cordon-AI — local (the project being upgraded)

Deeply known from the v2.0 engagement work. Relevant state for this
blueprint:

- 82 catalogued tools; 24 pipeline phases; MCP server (`cordon serve`);
  control plane (`scope/sanitize/ratelimit/budget/approval/audit`); findings
  store with `Severity` enum; `knowledge/` holds `coverage.py` (the honest
  gap matrix), `techniques.py` + `pat/index.json` (PayloadsAllTheThings
  technique index), `payloads.py` (vetted store: tiers A/B/C + quarantine),
  `attackgraph.py`, `graphmemory.py`, `wstg.py`.
- Exploit chain (`tools/exploit_chain.py`) fires web_injection (open redirect,
  CRLF, LFI, XXE, HPP) → cmdi (commix) → ssti (sstimap) → nosqli → ssrf
  (ssrfmap) → heavy (sqlmap/dalfox, capped at 3 points).
- `tools/pattern_scan.py` runs gf; `tools/waf.py` does NOT exist — `waf_detect`
  (wafw00f) names a vendor and stops.

### 1.5 PayloadsAllTheThings — swisskyrepo (already integrated)

Verified local state: `payloads/` vetted store (tiers A/B/C, quarantine,
manifest pinned to `coffinxp/payloads` commit), `knowledge/pat/index.json`
technique index built by `scripts/fetch_pat.py` with per-record attribution,
`knowledge/techniques.py` query layer (stopword-aware scoring), used by
`hunt_plan` (`payloads: tech.get("payloads", [])`).

**Remaining PAT gap:** PAT contains large per-vendor WAF-bypass sections
(SQLi/XSS/SSRF bypass tables) that the index references but that nothing
*consumes at runtime* — no tool asks "the target is behind Akamai, give me the
Akamai XSS bypass set." P0-1 closes exactly this.

### 1.6 shannon — KeygraphHQ (TypeScript monorepo, AGPL-3.0)

**Purpose.** An autonomous **white-box** AI pentester: analyzes the
application's source code first, derives attack paths, then runs real
exploits against the live app+API and reports only proof-backed findings.

**High-value components (concepts, not code — AGPL).**

- **Proof-based exploitation prompt packs**: per-class role prompts
  (`exploit-injection`, `exploit-auth`, `exploit-authz`, `exploit-ssrf`,
  `exploit-xss`) + validation prompts (`validate-authentication`…) + vuln
  write-up prompts, each with role/objective/scope/success-criteria/
  evidence-format sections. This is Cordon's "No PoC, no finding" invariant
  expressed as agent instructions (P2-8).
- **Cross-cutting code-path deny** (permission-system.ts): every `avoid` path
  compiles into deny patterns applied across *all* tools and child sessions,
  not overridable by a per-tool allow. Audit target for Cordon's `scope.py`
  + `sanitize.py` — confirm forbidden paths are enforced in every tool's
  sanitizer (P1-6 check).
- **Structured deliverable handoff** between pipeline stages (`set_*` tools,
  `.shannon/deliverables/`): pre-recon code analysis → recon → vuln → exploit
  → findings, each stage's output typed and consumed by the next. Mirrors
  Cordon's `status.jsonl` handoff but for *LLM-mode* artifacts (P2-11).
- **llms.txt / llms-full.txt** — the repo publishes an agent-readable index
  of itself. Cheap documentation win for this repo (P2, docs).

### 1.7 ReconX — 0xshahriar (Python FastAPI, ~6.2k LOC)

**Purpose.** Mobile-first recon platform for Termux/Android: FastAPI backend,
SQLite, offline Ollama LLM with memory-aware model scaling, cloudflare/ngrok
tunnels, power/internet resilience.

**High-value components.**

- **`core/scanners/gf_analyzer.py`** — pure-Python regex packs per class
  (xss/sqli/ssrf/lfi/rce/idor/debug…). Cordon already has the `gf` binary
  and a `pattern` phase, so this is **reference material**, not a port — but
  its compact per-class regexes are a good second opinion for
  `pattern_scan.py` rules (P2, minor).
- **`core/state_checkpoint.py`** — scan-state serialization/resume; Cordon
  already has `status.jsonl` + `--from` resume. No action.
- **`api/resilience_manager.py`, `tunnel_manager.py`, `notifications.py`** —
  mobile/ops concerns; **not relevant** to a server-side orchestrator.
- **`core/scanners/nuclei_wrapper.py`** — plain severity/tags selection;
  Cordon's `nuclei_engine.py` stack-tag derivation is strictly better.

---

## 2. Filter: high-value components → Cordon-AI mapping

| # | Component | Source | License | Fits where in Cordon-AI | Closes gap |
|---|---|---|---|---|---|
| 1 | WAF fingerprint DB + bypass tables + encoding strategies | autopentest-ai `waf_evasion.py` | MIT — port with attribution | `cordon/knowledge/waf.py` (data) + `cordon/tools/waf_bypass.py` (tool) | "WAF bypass techniques" — none today |
| 2 | Fuzz response-diff engine (body-hash clustering, duration/header deltas) | HuntProxy `fuzzer/mod.rs`, `compare.rs` | Apache-2.0 — port algorithm | `cordon/tools/fuzz_diff.py` + `fuzz_compare` MCP tool; used by `content_discovery` + new cache-poison check | detect-only soft-404s; web cache poisoning (manual class) |
| 3 | Regex-bypass payload generator (4 modes × 4 encodings) | HuntProxy `fuzzer/generators.rs` | Apache-2.0 — port algorithm | `cordon/knowledge/bypass.py`; feeds `web_injection.py` payloads | generic WAF-regex bypass for every injection class |
| 4 | Endpoint risk scoring (tech+method+params) | autopentest-ai `endpoint_priority.py` | MIT | upgrade `exploit_chain.py` `_API_SIGNAL_TIER0/1` + `endpoints.py` | validator budget spent on wrong endpoints |
| 5 | Chain patterns + `find_chains` BFS w/ severity upgrade | autopentest-ai `knowledge_graph.py` | MIT | extend `cordon/knowledge/attackgraph.py` + report | IDOR/business-logic "manual" classes get chain evidence |
| 6 | Per-tool output verification (empty ≠ clean, corrected flags) | autopentest-ai `tool_verification.py` | MIT | `cordon/tools/common.py` / wrapper post-check | "absence ≠ negative" made machine-enforced |
| 7 | WSTG runtime coverage ledger + phase gates | autopentest-ai `server.py` (track_test/get_coverage) | MIT | `cordon/knowledge/coverage.py` runtime tracking + report % | report can't say "we covered 9/12 classes" today |
| 8 | Per-class proof-based exploit prompt packs | shannon `apps/worker/prompts/exploit-*.txt` | AGPL — reimplement concept | `skills/` or `cordon/knowledge/prompts/` | LLM-mode exploitation rigor |
| 9 | Burp REST integration with scope-enforced calls | bugbounty-lab101 `burp_api.py` | MIT | new optional `cordon/tools/burp.py` | human handoff for classes no scanner owns |
| 10 | JS escape normalization (`https:\/\/`, `\u002F`) | HuntProxy `page_analyzer` | Apache-2.0 | `cordon/tools/js_analysis.py` | endpoint extraction from minified bundles |
| 11 | Pre-recon code-analysis deliverable stage | shannon | AGPL — reimplement | optional `cordon/tools/code_audit.py` (semgrep already exists) | white-box engagements |
| 12 | scope normalization edge-case oracle | bugbounty-lab101 `scope_guard.py` | MIT | `tests/test_scope.py` fixtures | scope.py hardening |

---

## 3. Implementation blueprint

### PHASE 0 — WAF bypass engine (P0-1) ⚡ highest value

**What.** Vendor fingerprint → ordered bypass payloads per vulnerability class
→ injected into the exploit chain's validators.

**Why.** The user's #1 explicit ask ("advanced bypass techniques" for
SQL/XSS/SSRF/…). Today `waf_detect` identifies the vendor and nothing uses
that fact. Every validator (sqlmap, dalfox, commix, sstimap, ssrfmap,
web_injection) currently sends textbook payloads straight into the WAF.

**Where.**
- `cordon/knowledge/waf.py` — port `WAF_SIGNATURES` (12 vendors) and
  `WAF_BYPASSES[vendor][class]` from autopentest-ai (MIT, add attribution
  header). Add PAT cross-reference: when a PAT technique record has a
  `waf-bypass` section, merge it in at index-build time
  (`scripts/fetch_pat.py` extension).
- `cordon/tools/waf_bypass.py` — new `@cordon_tool` **`waf_bypass`**:
  input `(vendor_or_fingerprint, vuln_class, level)` → payload list, ordered
  basic→advanced, with encoding strategies. Read-only — approval class
  `discovery`.
- `cordon/tools/web_injection.py` / `exploit_chain.py` — the chain asks
  `waf_bypass` for the observed vendor (from the `waf` phase's stored result)
  before firing each validator, and passes payloads via each tool's
  `--prefix/--suffix` (sqlmap `--prefix/--suffix`, dalfox `--custom-payload`,
  commix `--prefix/--suffix`, sstimap `--tamper`-style injection) — only when
  the base pass came back clean.

**Dependencies.** None new — payload lists live in the existing vetted
`payloads/` store conventions (tier B = aggressive, approval-gated; the
validator gate already applies).

**Risks.** Bypass payloads are aggressive → keep them tier-B; the existing
`mode="exploit"` gate on the chain is the boundary. Payload count bloat →
cap at ~50/call, ordered by complexity.

**Acceptance criteria.**
1. `waf_bypass("akamai", "xss")` returns ≥10 payloads ordered basic→advanced,
   each tagged with technique + level, in ≤200 ms.
2. Fingerprint function identifies the vendor from a stored `waf_detect`
   result and from raw headers/body samples (unit tests with Cloudflare,
   Akamai, AWS WAF, ModSecurity fixtures).
3. Exploit chain, when the WAF phase recorded a vendor and the base validator
   pass is clean, injects bypass payloads into at least sqlmap and dalfox —
   proven by a chain test asserting the payload parameter reaches argv.
4. Full suite green; ruff clean on new files.

### PHASE 1 — Response-diff fuzzing + bypass generator (P0-2, P0-3)

**What.** (a) A `fuzz_compare` engine that diffs fuzz cases against a baseline
by body-hash cluster + status/length/duration/header deltas, replacing ffuf's
crude filters for soft-404 triage; (b) the `RegexBypass` generator
(Start/Separator/End/RegexMetachar × Url/Unicode/Raw/DoubleUrl).

**Where.**
- `cordon/tools/fuzz_diff.py` — port the algorithm from HuntProxy
  `FuzzResponseDiff`/`FuzzResponseGroup` (Apache-2.0, attribution). Pure
  functions: `group_cases(cases) -> clusters`, `diff_case(baseline, case) ->
  FuzzResponseDiff`-shaped dataclass. Body-hash via existing hashing utils.
- `cordon/tools/webscan.py` — `content_discovery` post-processes ffuf JSON
  with `fuzz_diff` instead of relying on ffuf's filters; new MCP tool
  **`fuzz_compare`** (read-only, discovery class) exposed to the agent for
  on-demand baseline-vs-injected comparisons.
- Cache poisoning: a small `cache_probe` mode re-requesting a diffed case and
  comparing the *second* response to the baseline (poisoned cache serves the
  injected body to the next requester) — the only honest way to move
  "web cache poisoning" from `manual` toward detectable.
- `cordon/knowledge/bypass.py` — port `PayloadGenerator::RegexBypass`
  (Apache-2.0, attribution). `generate_regex_bypass(input, modes, encoding,
  max_payloads)`. Wire into `web_injection.py` as a payload source behind the
  tier-B gate.

**Dependencies.** None new (pure stdlib). Cache probe is HTTP-only.

**Risks.** Diffing on huge bodies → cap diff text at 64 KiB like HuntProxy;
skip binary MIME. Bypass generation is combinatorial → honor the
`max_payloads` bound (2,000 default like upstream).

**Acceptance criteria.**
1. `group_cases` clusters identical-body fuzz responses with 100% precision
   on a fixture set (200 synthetic responses, 4 clusters); `diff_case`
   flags length/status/duration/header deltas with values redacted from
   sensitive headers.
2. `content_discovery` produces the same findings as before on the lab target
   but with soft-404 clusters labelled (no regression on `test_webscan`).
3. `generate_regex_bypass("<script>", modes=all, encoding=url, max=500)`
   yields ≤500 unique strings; unit tests cover all 4 modes × 4 encodings.
4. Full suite green.

### PHASE 2 — Smart targeting & chaining (P1-4, P1-5)

**What.** (a) Endpoint risk scoring replaces the tier regexes in
`exploit_chain.py`; (b) `attackgraph.py` gains named chain patterns with
severity-upgrade suggestions, surfaced in the report.

**Where.**
- `cordon/tools/endpoints.py` — port `_score_endpoint` (tech risk, method
  score, param count, auth weight) from autopentest-ai (MIT); `endpoints`
  phase stores a scored queue; `exploit_chain.py` consumes the top-N instead
  of regex tiers.
- `cordon/knowledge/attackgraph.py` — add `CHAIN_PATTERNS` (XSS+no-CSP,
  SSRF+cloud-metadata, IDOR+admin, reflected-input+authz, open-redirect+OAuth)
  and a `find_chains()` BFS; `cordon/report/synthesize.py` renders chain
  upgrades in the findings section (a chained Medium becomes High with the
  chain named).

**Acceptance criteria.**
1. Endpoint scores match the priority queue on 3 fixture estates; chain
   validator order equals score order.
2. Two-fixture integration test: injected findings with a real
   `chains_to` edge produce a severity upgrade in the report, chain named.
3. No change to existing single-finding severities (upgrades only when a
   pattern matches).

### PHASE 3 — Verification & coverage honesty (P1-6, P1-7)

**What.** (a) Per-wrapper output post-checks (empty/refused ⇒ UNTESTED, with a
corrected-command hint); (b) runtime WSTG coverage ledger so the report shows
per-class coverage and phase gates.

**Where.**
- `cordon/tools/common.py` — a `verify_output(tool, cmd, raw)` registry
  (nmap `-Pn`, nuclei empty JSON, sqlmap "no parameter found", dalfox no
  output). Wrappers call it after `run_one`; UNTESTED is recorded in the
  findings store instead of silence. Port the rule tables from
  autopentest-ai `tool_verification.py` (MIT).
- `cordon/knowledge/coverage.py` — add runtime status per class
  (not_attempted / detected / validated / disproven / n_a) written from each
  phase; `report_generate` renders a coverage % table and a phase-gate
  PASS/FAIL per WSTG category.

**Acceptance criteria.**
1. A wrapper fed an empty scanner result records UNTESTED with the
   correction hint; unit test per tool table row.
2. Report shows per-class coverage status from a fixture engagement with ≥2
   phases recorded.
3. Existing 1,973-test suite stays green (additive only).

### PHASE 4 — Agent-mode & integrations (P2-8 … P2-11, low risk, optional)

- **P2-8 exploit prompt packs** — **IMPLEMENTED** (`cordon/knowledge/prompts.py`
  + `cordon/tools/prompts.py`): 18 classes, each with role/objective/scope/
  universal+class denies/success-criteria/evidence-format (the "No PoC, no
  finding" fields), reimplemented AGPL-clean from shannon's structure; exposed
  via `exploit_prompt` / `prompt_classes` (read-only).
- **P2-9 Burp handoff** — **IMPLEMENTED** (`cordon/tools/burp.py`):
  `burp_send` forwards one scope-checked request per target (≤10 per call)
  through the operator's local Burp proxy so the traffic lands in Proxy
  history; approval-gated, cost derived from its own batch cap, distinct
  `burp_not_running` failure.
- **P2-10 JS escape normalization** — **IMPLEMENTED**: `js_analysis.py`
  normalizes `https:\/\/` and `\u002F` before endpoint extraction (HuntProxy
  technique).
- **P2-11 code-audit deliverable** — **IMPLEMENTED** (`cordon/tools/code_audit.py`):
  `code_audit` stage (global phase in `hunt.sh`) wraps semgrep + gitleaks into
  a structured pre-recon deliverable (`code-audit.json`/`.md`, secrets
  redacted, semgrep hits filed as candidates) for white-box engagements.
- **Docs**: `llms.txt` — **IMPLEMENTED**, mirroring shannon's pattern.

---

## 4. Priority and sequencing

| Order | Item | Effort | Effect |
|---|---|---|---|
| 1 | P0-1 WAF bypass engine | 2–3 days | closes the user's explicit #1 gap; every injection validator gets bypass depth |
| 2 | P0-2 response-diff fuzzing | 2–3 days | soft-404 truth; cache-poison detection moves from manual → detected |
| 3 | P0-3 regex bypass generator | 1 day | generic WAF-regex bypass for all injection classes |
| 4 | P1-4 endpoint scoring | 1 day | validator budget spends on the right endpoints |
| 5 | P1-5 chain patterns | 1–2 days | manual classes (IDOR, business logic) gain chain evidence + severity truth |
| 6 | P1-6 tool verification | 1 day | "absence ≠ negative" machine-enforced |
| 7 | P1-7 coverage ledger | 1–2 days | reports finally prove what was covered |
| 8 | P2 items | optional | agent-mode rigor + human handoff |

**Expected result.** The 6 `detect-only` classes stay detection-only (they
need scanners, not plumbing), but: WAF bypass depth is added to every
validator, soft-404 truth and cache-poison detection land, manual classes
gain chain-based severity evidence, and the report proves per-class coverage
instead of asserting it. Full suite must stay green after every phase; each
phase ships its own tests.

---

## 5. Licensing appendix

| Repo | License | Reuse mode |
|---|---|---|
| autopentest-ai | MIT | port with attribution header |
| HuntProxy | Apache-2.0 | port algorithm with attribution |
| bugbounty-lab101 | (see LICENSE) | reference / tests |
| shannon | AGPL-3.0 | reimplement concept only |
| ReconX | (see LICENSE) | reference only |
| PayloadsAllTheThings | NONE (all-rights-reserved) | already handled: pinned, vetted, non-redistributed |

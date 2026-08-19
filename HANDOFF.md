# Handoff

Written for the next agent picking this up cold. Read `CLAUDE.md` first — it has
the invariants and they are not negotiable. This file is the rest: what exists,
how it was verified, what is actually true about its performance, and what to
build next.

**Verified 2026-08-08.** Every number here was measured, not recalled. Re-derive
before trusting: `easyhunt doctor`, `pytest -q`.

**Amended 2026-08-14.** Three things landed after the 2026-08-08 sweep. Only the
test suite was re-run for this amendment (`1853 passed, 1 skipped`) — the
performance numbers and coverage percentages below still carry their 08-08
measurement date and have *not* been re-derived. Treat them accordingly.

- **§6c is closed.** chromium is in the image; DOM XSS is now actually exercised.
- **`pattern_scan` is new** — gf's pattern library as pinned data. See §6f.
- **`technique_lookup` is new** — PayloadsAllTheThings as a queryable index
  (`knowledge/pat/index.json`, built by `scripts/fetch_pat.py`), the "how" to the
  WSTG index's "what". See `docs/TECHNIQUES.md`.
- **§6a advanced**: `sessions.py` +151, `auth_crawl.py` +174,
  `exploitation.py` +131. The gap is narrower than §6a describes but not shut;
  re-read that section against the code before trusting its shape.

**Amended 2026-08-18 — the neuron brain.** Added the first *active* memory
layer: `easyhunt/knowledge/neuron.py` (NeuronBrain), an associative
(Hebbian-style) experience store. Unlike PoCMemory/GraphMemory/TechniqueIndex
— which record what was seen or what the docs say — the brain learns from
validator *outcomes* and feeds the lessons back into planning. `2112 passed,
1 skipped` for this amendment (full suite, incl. 16 new `tests/test_neuron.py`).

- **What it learns**: every `exploit_chain` validator result (sqli/xss/ssti/
  cmdi/nosqli/ssrf/smuggling/web-injection per injection point, with the
  observed tech stack + WAF as context) — `exploit_chain.py` now calls
  `_brain_learn(...)` after each probe; every triage DROP teaches a false
  positive (`llm/triage.py::_brain_learn_fp`).
- **What it does**: `recall()` ranks techniques for a target context by learned
  weight (fuzzy stack matching, trial-count confidence, recency decay —
  half-life 90d); `suppress()` demotes fresh hits from tools that have
  repeatedly false-positived on the same shape of target (the testssl
  `ipv4_in_header`-over-a-cookie class is now learned, not hardcoded).
- **Wiring**: `Engagement.brain` (config `memory.brain_store`, default
  `~/.easyhunt/neuron-brain.jsonl`), persisted on `finish()` and per exploit
  run; `hunt_plan` returns a `learned` list; MCP tools `brain_recall` /
  `brain_learn`. Methods and outcomes only — never credentials or bodies.

**Amended 2026-08-18 (second pass) — the brain senses and animates.** The
first pass made the brain *learn*; this pass made it *sense* — connected to
every script — and gave it a face. `2120 passed, 1 skipped`.

- **Sensing**: `AuditLog.observe(fn)` — a tap on the single chokepoint every
  tool call passes. `Engagement` registers `brain.sense`, so every phase/tool
  in every script reaches the brain with zero per-tool changes. The brain keeps
  a 256-event ring (live state) + a JSONL timeline (`memory.brain_activity`,
  default `~/.easyhunt/brain-activity.jsonl`). `state()` = what's happening
  now; `history()` = episodic memory, filterable by phase/tool/outcome — the
  "what failed, what succeeded, what was FP, what was true" record.
- **The animation**: `easyhunt brain watch` — a live ANSI neural pop-up (brain
  node, electrical pulses traveling along pipelines to the active phase,
  red ★ pulse on findings), pure stdlib, tails the same JSON activity stream
  any front-end can consume. `easyhunt brain export [--open]` writes a
  self-contained `brain.html` (no external deps) that replays the same JSON as
  an animated neural net — shareable, attachable to a report.
- **MCP**: `brain_state` (live pulse), `brain_history` (episodic memory),
  `brain_recall` (query experience), `brain_learn` (teach manually).
- **CLI**: `easyhunt brain watch|state|history|export`.
- **Tests**: 8 new in `tests/test_neuron.py` (TestSensing), incl. the audit
  observer wiring and observer-failure isolation (a crashing observer cannot
  break the audit trail).

### The live dashboard (`easyhunt/tools/dashboard.py` + `dashboard/` React app)

Turns any engagement workspace into a live ops view — the answer to "what
has the run found, and what phase is it on right now":

- **Data layer**: `collect_state()` reads status.jsonl (phase machine),
  findings.json (severity/status ledger, severity-sorted), assets.json
  (discovered estate, grouped by kind), coverage.json (CoverageLedger),
  audit.jsonl (tool usage), brain activity + learned FP lessons, and the
  scope file, into one JSON blob. Audit phase slugs are canonicalized to
  pipeline labels exactly like the animation (http_probe→probe, etc.).
  `collect_state(root, workspace=name)` pins a specific engagement;
  `?ws=<name>` on the API does the same.
- **React SPA**: `dashboard/` is a Vite + React + TypeScript app
  (react, react-dom, lucide-react only; `npm ci && npm run build` →
  `dashboard/dist`). Views: Overview (stat cards + live phase pipeline),
  Findings (search / severity / status / phase / tool / sort filters,
  expandable detail rows), Assets (tabbed subdomains / endpoints / urls /
  technologies / open ports / …), Coverage (per-class runtime status),
  Activity (brain feed), Tools (what fired, from the audit trail), False
  positives (dismissed + learned), Reports. Deep-linkable `/#view`, workspace
  switcher in the top bar, 2s polling via `useLiveState`.
- **Serve**: `easyhunt dashboard --serve` serves `dist/` with an SPA
  fallback + `/api/state` + `/reports/*`; falls back to the legacy
  dependency-free page when `dist` is absent. `--build` runs npm ci + vite
  build; `--workspace NAME` pins the snapshot; `--port`/`--out` as before.
- **MCP**: `dashboard_state` returns the same blob to the agent — "where is
  the scan, what has it found" without reading workspace files.
- **CLI**: `easyhunt dashboard [--build|--serve|--out path|--port N|--workspace NAME]`.
- **Tests**: 11 in `tests/test_dashboard.py` (phase mapping incl. the
  canonical-slug fix, findings sorting/counting, full state blob, embedded
  legacy page render, assets-by-kind, coverage, tool usage from audit,
  false positives, workspace pinning).
- **Playwright e2e**: `cd dashboard && npm run e2e` starts the server and
  verifies every view renders against real data (uses system Chrome via
  `playwright-core` — no browser download). 16 checks incl. filter clicks.

### 403 access-control bypass (`easyhunt/tools/forbidden.py` + unKover)

unKover (BruteLogic) — a 12-technique 403-bypass tester (IP-header spoofing,
method tampering/case, protocol headers, Referer trust, path normalization /
encoding, HTTP/1.0 downgrade, hop-by-hop, path suffix, API version prefix /
swap) with wildcard-baseline FP filtering and a curl PoC on first success.

- **Install**: recipe in `easyhunt/install/recipes.py` (git clone to
  `/opt/unkover`, symlink to PATH). Pure bash + curl — no build.
- **`forbidden_bypass(url, prefix=)`** — runs unKover, files a finding
  (`needs_manual_review`, MEDIUM base → HIGH on admin-flavoured paths with
  authz-relevant techniques), PoC as evidence, teaches the brain
  (`access-control-bypass` class), records the coverage ledger. The
  wildcard calibration is unKover's own — a 2xx on a 403 path is not a
  soft-404. Refuses anything that is not 403.
- **`forbidden_candidates(urls)`** — passive pre-check (one HEAD per URL)
  returning the actual 403s, so you only feed the bypass tester real 403s.
- **`forbidden_chain(urls, max_candidates=200, max_bypass=15)`** — the
  auto-chain: HEAD-pre-checks the estate, then fires `forbidden_bypass` at
  each real 403. Wired into `hunt.sh` as the global `forbidden` phase (after
  `wapiti`, before `exploit`), inheriting live URLs from the asset store.
  A 403 is either bypassed (finding) or proven enforced (coverage).
- **When to use**: any URL that returned 403 from probe / content discovery /
  nuclei. A 403 is an access decision; these techniques find the routes
  around it. Verified live against a purpose-built 403 lab.

### The research advisor (`easyhunt/tools/research_guide.py`)

`research_guidance(vuln_class, asset, evidence, stack)` — the "I found
something / scanned clean, what do I do next" answer. Assembles into one
actionable playbook: the brain's learned experience for the class on this
stack, the technique-index entry (payloads/tools), the exact validators to
run next (from the coverage matrix), WAF-tailored bypass payloads when a
vendor is observed, a per-class evidence checklist, and canonical resources
(PAT, PortSwigger, OWASP). With an LLM enabled it also produces a grounded
step plan; without one the knowledge playbook is the answer. Sends no
traffic. Fuzzy class names work (`sqli`, "request smuggling", `JWT`).

- **`guided_validate(vuln_class, asset, limit=3)`** — closes the loop:
  assembles the same playbook, then EXECUTES the validators the coverage
  matrix wires to the class (`sqli` → `sqli_validate`, `open redirect` →
  `web_injection_probe`, …) against the asset. Each dispatch is
  independently approval-gated; classes with no auto-validator return the
  evidence checklist instead of a fake dispatch.
- Alias tables fixed to the real coverage class names (`jwt` →
  `json-web-token`, `file upload` → `upload-insecure-files`, `csrf` →
  `cross-site-request-forgery`, `cache poisoning` → `web-cache-deception`,
  `idor` → `insecure-direct-object-references`, `path traversal` →
  `file-inclusion`).

### Browser-verified exploitation (`easyhunt/tools/browser_verify.py`)

`browser_verify(url, param, payload, screenshot=True)` — drives headless
Chromium (Playwright + system Chrome, no download) at a URL and captures
render-time evidence: unescaped reflection (`raw`/`escaped`/`plain`), payload
execution (dialog/page-error/console — the authoritative XSS signal, HIGH),
open-redirect (host change, LOW), console trace, and a screenshot + DOM
excerpt saved to the workspace `evidence/` dir. Plain-token echoes are NOT
findings (FP guard, live-tested). Payloads pass unescaped via `text_args`.

- **Install**: `pip install 'playwright>=1.40'` (declared as the `browser`
  optional extra in `pyproject.toml`); uses `CHROME_BIN`/`CHROME_PATH` or
  PATH discovery. Degrades to `dependency_missing`/`browser_unavailable`
  cleanly. Registered in `CAPABILITY_MODULES`.
- **Live-verified**: reflection + `<svg onload=alert(...)>` execution filed a
  HIGH finding with screenshot evidence; `hello-world` echoed back filed
  nothing.

### Live-pipeline audit (the "does it actually work" pass)

A real end-to-end run of the phase chain against the juice-shop lab found and
fixed four wired-but-dead defects. These are the bugs that make the tool look
credible in code and fail in reality:

1. **phase.py handed every tool a `target=` kwarg** — a tool that declares
   `targets_arg="urls"` (forbidden_chain) looked to the scope gate like a call
   with no target, and its phase failed with "no target supplied" on every
   run. Now uses the tool's own `targets_arg` name. Regression tests cover
   every phase's kwarg construction.
2. **A capability module that fails to import was silently skipped** — its
   tools vanished from the MCP surface while the report still claimed the
   scans ran. `build_server` now refuses to start with a module whose failure
   is a bug (SyntaxError etc.), not a missing optional dependency.
3. **pattern_scan never returned the `count` key its phase gate reads** — the
   pattern phase reported "produced nothing" even when it found sink
   candidates. Now returns `count` (plus `candidates_total`).
4. **service_scan defaulted to `ports="80,443"`** — it ignored what port_scan
   discovered, so any estate on 3000/8080/8443 reported "no services". It now
   inherits the open_port assets from the store (falls back to 80,443 only
   when nothing was discovered). Regression tests pin all three branches.

**Amended 2026-08-19 — the estate-wide services pass.** The myfitnesspal run
caught two more defects in the same chain, both invisible until a real estate
was scanned:

5. **The `services` phase was `focus: True`** — it aimed service_scan at the
   program's focus host only, so 59 discovered ports across 29 hosts sat
   unfingerprinted (the run reported 2 services; 192 ports found). The phase
   now inherits `open_port` assets and passes every host that has one, and
   service_scan accepts multiple hosts, merges their discovered ports, and
   fingerprints them in one nmap pass — 102 services on the live run.
6. **The `default,safe` NSE selection crashes and hangs nmap on real estates.**
   The `safe` category pulls broadcast-* scripts, which crash nmap with the
   known `nse_nsock.cc:342` assertion (and probe the LAN, not the target),
   and http-slowloris-check, which holds connections open and stalls the
   whole scan at the engagement's rate limit. `safe` is now refused outright
   and every selection is suffixed `and not broadcast`. Verified live:
   `default and not broadcast` is deterministic, `safe` hangs at exit 124.

Verified working end-to-end on the lab through the real control plane: probe,
waf, cors, tls, endpoints (83 URLs), js, pattern, nuclei scan (Prometheus
finding), forbidden, ports (2 open), content (`/api-docs`, `/metrics`), and
exploit_chain (16 injection points tested). `easyhunt doctor`: 80/83 tools
working, all 38 capability modules load.

---

## 1. What this is

An agentic VAPT orchestrator. Claude plans, an MCP server enforces, 82
catalogued tools execute. The value is not the tool count — it is that every
call passes one fixed sequence and no code path skips it:

```
scope → sanitize → budget → rate-limit → approval → sandbox → parse → audit
```

The model never holds a shell. A jailbroken prompt cannot reach the network.

| | |
|---|---|
| Code | ~32,500 lines |
| MCP tools | 80 |
| Catalogued binaries | 82 |
| Tests | 1,958 across 49 files |
| Image | `easyhunt:latest`, 4.54 GB |
| Commits | 98 |

---

## 2. The one thing to understand before changing anything

**Absence is not a clean result.** A killed scan, a tool that could not write
its config, a tool that rejected its own arguments, and a genuinely secure
target all produce *zero findings* — and zero findings reads as good news.

This defect has been found **~37 times** in this codebase. It is not a bug that
was fixed; it is a bug class that keeps recurring in new forms. Known faces:

1. **Never ran** — killed, crashed, or missing, reported as clean.
2. **Never wired up** — a tool with a spec, a binary, and no call site.
3. **Wrong mode** — a "passive" tool sending exploit payloads.
4. **Present but false** — 1,989 "open" loopback ports from a saturated oracle.
5. **Tuned below detection** — sqlmap at `--level 2` cannot find a textbook SQLi.
6. **Rejected its own flags** — commix exits 0 on a usage error.
7. **Checked in the wrong place** — health checks against the host for a tool
   that runs in a container.
8. **Counted intent, not delivery** — a smuggling scan reporting "802 payloads"
   while a dead connection pool let roughly ten requests reach the wire.
9. **Read the wrong language** — HTML patterns run over a minified bundle: no
   `type="password"` to find, and "register" matches `registerOnChange`.

And its inverse, which is not absence but excess: **discovery that became the
attack.** `auth_crawl` followed ids from an authenticated `/api/Users/` and read
thirteen other users' records while merely mapping the site. Enumerate the
reference; dereference it only under `authz_compare`, with two identities, an
approval, and a human deciding.

If you change anything, assume you have introduced an instance of this. Two of
the bugs found on the last day were introduced by earlier fixes *in the same
session*.

---

## 3. How it is verified — three layers, each catches what the others cannot

**Tests (1,958).** Mock the subprocess. Prove the wrapper's shape. Cannot
tell you whether a real binary accepts the argv.

**`easyhunt doctor`.** Executes every tool *inside the container it will run
in*, under the real read-only root and dropped capabilities. Catches "installed
but broken". Cannot tell you whether the wrapper parses the output.

**Live runs.** The only layer that finds the serious bugs. Every significant
defect came from pointing it at something real and disbelieving the result.

The working loop, and it is the whole method:

1. Run it against something real.
2. Distrust every clean result — verify the tool actually ran.
3. Verify hits by hand before believing them.
4. Fix the class, not the instance.
5. Write a test that encodes the bug.
6. Re-measure and record the number.

---

## 4. Results — the honest version

### It works as a control plane

Scope enforcement, rate limits derived from published policy, honest UNTESTED
reporting, sandboxing, hash-chained audit. All verified against live targets.
It will not get you banned and it will not lie to you about coverage.

### It has found almost nothing

**One real finding across the project's life** — a publicly exposed phpMyAdmin.
Everything else: zero. A 5,976-host engagement produced zero. A 12-host focused
run produced zero exploitable.

### Why

- **Scanners find known CVEs and misconfigurations.** Mature programs fixed
  those years ago. The bugs that pay — IDOR, access control, business logic,
  auth bypass — need application understanding, not templates.
- **Everything has been unauthenticated.** The valuable surface is behind login.
  A session primitive now exists; auth-aware crawling does not. See section 5.
- **Half the exploit chain was silently broken** until the last day. See below.

### The exploit-chain audit (against OWASP Juice Shop, deliberately vulnerable)

| Tool | Result |
|---|---|
| `sqli_validate` | **was broken** — `--level 2` + `--smart` suppressed detection. Now proves a real SQLi (`proven: true`) |
| `xss_validate` | **was misleading** — no browser in the image, so DOM XSS was silently untested. Gap now stated in every negative |
| `cmdi_probe` | **was broken twice** — non-integer `--delay` rejected (exit 0!), and a 500-prompt abort. 0.8s → 120.6s of real testing |
| `ssti_probe` | clean |
| `nosqli_probe` | clean |
| `smuggling_probe` | clean — full desync mutation set |
| `ssrf_probe` | clean — 1,994 ports, saturation guard correct in both directions |
| `smuggling_canary_probe` | **was broken** — the pool recycled sockets its own victim request had closed, so ~10 of ~4,800 requests were sent while the report claimed 802 payloads. Now reports `requests_sent` counted at the socket |

**Four of eight were producing false negatives.** All would have reported "not
vulnerable" against a target that was.

---

## 5. Coverage, measured against OWASP WSTG

The WSTG index this project ships has **115 tests**. 42 of them — 36% — had no
tool behind them, and the gap is not scattered:

| Category | Uncovered | |
|---|---|---|
| Authentication (ATHN) | 11 | every test |
| Session management (SESS) | 11 | every test |
| Business logic (BUSL) | 10 | every test |
| Authorization (ATHZ) | 5 | every test |
| Identity management (IDNT) | 5 | every test |

The pattern is the finding. **Every covered category is testable without an
account; every uncovered one requires being logged in** — and the ATHZ tests
require being logged in *twice, as different people*. That is not 42 features to
build. It is one missing primitive, which is why the session store was the next
thing built rather than another scanner.

It also explains section 4: the tool has found almost nothing because it has
only ever looked at the third of the surface that does not need a login, and
that third is where mature programs have already fixed everything.

---

## 6. What is left, in priority order

### 6a. Authenticated testing — the biggest gap by far

**Partly built.** `session_register` / `session_list` / `authz_compare` exist
(`easyhunt/knowledge/sessions.py`, `easyhunt/tools/sessions.py`). A session is
bound to the host that issued it and fails closed; values are masked in every
result; `authz_compare` is GET/HEAD only and refuses two sessions carrying the
same credentials, because a login-bypass that returns one admin token for any
email otherwise files a HIGH IDOR candidate about nothing.

**Auth-aware crawling is now built too** — `auth_crawl`. It walks an
application as a registered session (GET only, forms reported and never
submitted) and hands `authz_compare` the thing it needs: URLs carrying an
object reference. Reads HTML links and JSON references, because a single-page
app's authenticated surface is its API and an API has no `<a href>`.

Four guards, each for a way this goes silently wrong:

- **The session is proven first.** Entry point fetched with and without it; if
  the responses match, the crawl is refused. A dead cookie otherwise yields a
  tidy list of public pages labelled "the authenticated surface".
- **Liveness is re-checked** every `liveness_every` pages, and immediately after
  three responses that look like the anonymous entry page. An app that logs you
  out at page 40 hands back 80 more that look fine.
- **Destructive-looking links are skipped**, logout above all — following it is
  the previous failure arriving by our own hand.
- **References are enumerated, not dereferenced.** Item URLs synthesised from
  ids in a collection are recorded and never fetched.

Still missing:

- **Nothing creates accounts, deliberately.** Self-registration is a policy
  question: of four programs read during this project two permitted it and two
  were silent, and silence is not permission. It belongs behind an explicit
  scope rule the way exploitation already is.
- **No form submission and no XHR replay.** Anything reachable only by posting a
  form, or by an API call the pages do not link to, is outside the crawl.
`hunt_plan` now reads it. The authenticated surface is kept in its own section
rather than merged into the pile — "this URL was only visible to a logged-in
user" is the most important fact about a URL, and averaging it into 2,700
anonymous ones throws it away. `reference_candidates_unfetched` carries the
objects the application named and `auth_crawl` declined to read. Gaps track what
has actually been done: no session, one identity, or two identities with nothing
to aim them at are three different answers.

### 6b. Auth-surface detection — built

`auth_surface` (phase `auth` in `hunt.sh`). Nine GETs per host against
conventional auth paths, then — if the host is a single-page app — its
same-origin bundles, because that is the only place an SPA's login exists.
Reports signup / login / reset / MFA / OAuth / session cookies, ranks hosts by
whether an account can be obtained legitimately, and extracts the client-side
route table split into `privileged_routes` and `user_scoped_routes`. The second
of those is where `authz_compare` should be pointed.

Verified against Juice Shop: score 12, all four auth signals, 44 routes
including `administration`, `accounting`, `wallet`, `2fa/enter`.

It creates no accounts and submits no forms — every request is a GET. The
output ends in a recommendation to a human, who registers by hand if the
program permits it and brings the sessions back via `session_register`.

**Its own first live run was a false negative** and is worth knowing about: it
read the SPA shell, found no `type="password"` anywhere, and reported "no
authentication surface found" about an application built entirely around a
login. An SPA whose bundles cannot be read is now UNEXAMINED, not clean.

Still open here: no headless render, so a route guarded behind a lazily-loaded
chunk that the shell does not reference is invisible.

### 6c. A headless browser in the image — built

`dalfox` needs one for DOM XSS and fails silently without it: it scans, finds
nothing, and `xss_validate` reports "not vulnerable" for the most common modern
XSS class.

chromium is now installed in the `Dockerfile`. Two details that matter and
should not be undone:

- It is installed into `easyhunt:latest` — the image dalfox *actually* runs in
  after the dalfox image mapping was removed — not into a separate one.
  `_headless_available()` in `exploitation.py` probes that same image.
- The build **asserts by running it** (`chromium --version`), not by checking
  the path. A browser binary that cannot execute under the container's dropped
  capabilities is present-but-dead, which is the exact failure this file keeps
  having to guard against. That assertion is the point; a path check would
  reintroduce the silent-skip bug one layer down.

Cost: ~500 MB with its dependency tree. That is the price of a scanner that
does not report DOM XSS as clean without ever exercising the DOM.

### 6d. `hunt_plan` has never run against a live model

Built to make the model hunt rather than only triage. It reads the observed
surface and groups it by why it matters — object-reference candidates,
server-side sinks, parameter vocabulary. On a real run it reduced 2,748 URLs to
46 actionable items.

Agent mode works (returns the surface for the calling agent). The internal-LLM
path is untested because no OpenRouter key was available. `openai` is also not
installed — `pip install 'easyhunt-ai[llm]'`. `doctor` now reports this.

### 6e. Known smaller items

- `ssrfmap` is ungovernable: ~8,283 requests through its own thread pool, no
  rate flag. Labelled honestly; not fixed.
- `identity_marker` on **19 of 81** specs, not 6 — the old number was wrong.
  Audited against Kali's apt Contents index, host PATH and the image's own
  console_scripts: exactly three names have a real installable impostor
  (`forge`, `httpx`, `medusa`) and all three are already marked. There is
  nothing to add, and adding more risks turning a working tool into a
  permanent "wrong-tool".
- **16 of 81 tools have no call site**, not 2. Eight were undocumented
  anywhere. `tests/test_wiring.py` now enumerates them with a per-entry reason
  and fails when a new one appears or an exemption goes stale.
  `shuffledns` was deleted rather than wired: its only pacing flag is `-t`,
  defaulting to 10,000 concurrent massdns resolves, and neither it nor massdns
  has a requests-per-second control — `dnsx -d -w -rl` already does the job
  under a real rate ceiling.
  `linkfinder` is measured and ready to wire: over 12 real bundles it found 422
  endpoints to the native miner's 210, with **zero** native-only results. Runs
  over already-saved files, so it costs no extra requests.
- `RateLimiter` charges declared `estimated_requests`; many wrappers declare
  nothing and charge the floor of 1. Silent under-charge. Needs an audit pass.
- 24 of 82 tools ran on the host rather than the sandbox — mostly fixed, but
  re-check with `doctor`; a green tick prints `@image` when containerised.
- `bootstrap.sh` has never been run end to end on a genuinely clean machine
  beyond a Debian container with Docker skipped.

### 6f. `pattern_scan` — built

`easyhunt/tools/pattern_scan.py`, registered in `mcp_server.py`, patterns in
`rules/gf/` (11 packs: xss, ssrf, sqli, lfi, rce, redirect, ssti, idor, upload,
s3-buckets, + `manifest.json`).

The value of `gf` is not the binary — that is a hundred lines piping stdin
through `grep -oP`. It is the *named pattern library*: per-bug-class regex packs
for the sink shapes a human pentester holds in their head. This module holds
them as data.

Two decisions to preserve:

- **Patterns are vetted and pinned, and fail loudly.** They live in gf's native
  `{"flags": "HnriP", "patterns": [...]}` format, so the same files run under
  the real `gf` binary dropped into `~/.gf/`. A bad regex, or a manifest naming
  a missing file, fails at **import** — not silently at scan time. Same posture
  as `scope` keeping uncompilable patterns in an `invalid` list rather than
  dropping them.
- **This is candidate generation, not detection.** A regex match is a *shape*,
  not a bug. It stores `sink_candidate` assets and reports a classified list,
  each entry naming the validator that would prove it. It files **no Findings**.
  That is invariant 4 ("no PoC, no finding") held at the tool boundary; do not
  "improve" it into a finder.

**Counts elsewhere in this file are now stale by one.** `pattern_scan` is a new
tool with a call site, so the "16 of 81 tools have no call site" and "82
catalogued tools" (CLAUDE.md §2) figures predate it. Re-derive with
`tests/test_wiring.py` rather than adjusting them by hand.

---

## 7. How to start

```bash
git clone <repo> && cd EasyHunt-AI
./bootstrap.sh                 # 30-45 min, builds easyhunt:latest
easyhunt doctor                # expect 0 broken
```

**You must write `scope.yaml` by hand** from a program's published policy. The
installer deliberately refuses to create one — it used to, and three separate
green ticks then confirmed an authorization nobody had earned.

### For development, use the local vulnerable target

```bash
docker run -d --name juice-shop \
  -p 127.0.0.1:3000:3000 -p 172.17.0.1:3000:3000 bkimminich/juice-shop
cp scope.juiceshop.yaml scope.yaml     # ships with the repo
./scripts/hunt.sh http://172.17.0.1:3000/
```

Bind the Docker bridge gateway as well as loopback: sandboxed tools run with
`--network bridge`, where `127.0.0.1` is the container itself. Without it every
containerised tool scans itself, finds nothing, and reports a clean target.

### The pipeline

```bash
./scripts/hunt.sh <target> [<target>...]   # all phases, gated
./scripts/hunt.sh <target> --only probe,scan
./scripts/hunt.sh <target> --from scan     # resume
./scripts/hunt.sh <target> --exploit       # refused unless scope permits
./.venv/bin/python scripts/summary.py      # digest a workspace
```

Phases are **per-target** (recon → js → auth) or **global** (takeover, scan, plan,
report — once over everything found). Each phase must prove it did something:
exit 0 did its job, 2 produced nothing, 3 failed. Only `probe` is required.

Each phase appends to `status.jsonl` with `input=` showing where its targets
came from (`argument` or `assets:url[live](n)`). That is the audit trail for
"which hosts did this actually cover".

---

## 8. Traps that cost real time here

- **A tool that finishes a network scan in under a second did not do one.**
  Duration is a signal. Compare it against what the work would have to cost.
  802 payloads with a 0.1s pause cannot finish in 2.0 seconds; that arithmetic
  is what exposed the smuggling pool bug, and the framework now counts requests
  at the socket so the next such bug reports itself.
- **A count of what a tool loaded is not a count of what it sent.** Any coverage
  number sourced from configuration rather than from the wire is a statement of
  intent. Prefer numbers a failure cannot inflate.
- **A silent `except` around a network call turns a broken scan into a clean
  one.** The smuggling detectors swallowed every broken pipe unless `--verbose`
  was passed — and `--verbose` was on the wrapper's denied-flag list, so the
  diagnostic was unreachable by construction. Fixed by counting failed sends
  and reporting the count unconditionally: a failure that only shows up under a
  debug flag will not show up.
- **A denied flag is not a denied behaviour.** commix opened a shell despite
  `--os-shell` being on the denied list, because `--batch` answered its prompt.
- **Clamp derived values to what the *binary* accepts**, not to the policy cap.
  waymore rejects `-p > 5`; commix rejects a non-integer `--delay`. Both broke
  from a correct rate fix that ignored the receiving parser.
- **Verify in the environment that will run it.** A health check against a
  different copy of the program is a health check about a different program.
- **Mount the leaf, never the parent.** A tmpfs over `/root/.local/share` hides
  uv's tool store and makes a dozen tools vanish.
- **`git push` to a token URL does not update `refs/remotes/origin/main`.**
  `git status` then lies about what is unpushed.

---

## 9. Things not to do

- Do not weaken the six invariants in `CLAUDE.md`.
- Do not generate a `scope.yaml`. Ever.
- Do not add evasion capability — WAF bypass, TLS fingerprint spoofing,
  `--random-agent`. If a target blocks identified traffic, say so in the report.
- Do not commit engagement data. `scope.*.yaml`, `engagements/` and
  `.easyhunt-run` are gitignored for a reason: the last one leaked an engagement
  name into two commits before it was caught.
- Do not claim a capability that has not been demonstrated. The README describes
  the control plane, which is earned. It does not claim to out-hunt anything,
  because that has not been shown.

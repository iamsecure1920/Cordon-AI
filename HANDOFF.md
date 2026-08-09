# Handoff

Written for the next agent picking this up cold. Read `CLAUDE.md` first — it has
the invariants and they are not negotiable. This file is the rest: what exists,
how it was verified, what is actually true about its performance, and what to
build next.

**Verified 2026-08-08.** Every number here was measured, not recalled. Re-derive
before trusting: `easyhunt doctor`, `pytest -q`.

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
| Code | ~28,500 lines |
| MCP tools | 73 |
| Catalogued binaries | 82 |
| Tests | 1,378 across 36 files |
| Image | `easyhunt:latest`, 4.54 GB |
| Commits | 65 |

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

**Unit tests (1,378).** Mock the subprocess. Prove the wrapper's shape. Cannot
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

### 6c. A headless browser in the image

`dalfox` needs one for DOM XSS and fails silently without it. The negative
result now says so, but saying so is not covering it. Adding chromium closes
the most common modern XSS class.

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
- `identity_marker` on 6 of 82 specs. Only names with real installable
  impostors are covered (nuclei, slither, katana, kingfisher, amass, forge).
- `shuffledns` and `linkfinder` have specs and no call site.
- `RateLimiter` charges declared `estimated_requests`; many wrappers declare
  nothing and charge the floor of 1. Silent under-charge. Needs an audit pass.
- 24 of 82 tools ran on the host rather than the sandbox — mostly fixed, but
  re-check with `doctor`; a green tick prints `@image` when containerised.
- `bootstrap.sh` has never been run end to end on a genuinely clean machine
  beyond a Debian container with Docker skipped.

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

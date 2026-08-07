# Handoff

Written for the next agent picking this up cold. Read `CLAUDE.md` first — it has
the invariants and they are not negotiable. This file is the rest: what exists,
how it was verified, what is actually true about its performance, and what to
build next.

**Verified 2026-08-07.** Every number here was measured, not recalled. Re-derive
before trusting: `easyhunt doctor`, `pytest -q`.

---

## 1. What this is

An agentic VAPT orchestrator. Claude plans, an MCP server enforces, 81
catalogued tools execute. The value is not the tool count — it is that every
call passes one fixed sequence and no code path skips it:

```
scope → sanitize → budget → rate-limit → approval → sandbox → parse → audit
```

The model never holds a shell. A jailbroken prompt cannot reach the network.

| | |
|---|---|
| Code | ~26,200 lines |
| MCP tools | 67 |
| Catalogued binaries | 81 |
| Tests | 1,288 across 31 files |
| Image | `easyhunt:latest`, 4.54 GB |
| Commits | 65 |

---

## 2. The one thing to understand before changing anything

**Absence is not a clean result.** A killed scan, a tool that could not write
its config, a tool that rejected its own arguments, and a genuinely secure
target all produce *zero findings* — and zero findings reads as good news.

This defect has been found **~35 times** in this codebase. It is not a bug that
was fixed; it is a bug class that keeps recurring in new forms. Known faces:

1. **Never ran** — killed, crashed, or missing, reported as clean.
2. **Never wired up** — a tool with a spec, a binary, and no call site.
3. **Wrong mode** — a "passive" tool sending exploit payloads.
4. **Present but false** — 1,989 "open" loopback ports from a saturated oracle.
5. **Tuned below detection** — sqlmap at `--level 2` cannot find a textbook SQLi.
6. **Rejected its own flags** — commix exits 0 on a usage error.
7. **Checked in the wrong place** — health checks against the host for a tool
   that runs in a container.

If you change anything, assume you have introduced an instance of this. Two of
the bugs found on the last day were introduced by earlier fixes *in the same
session*.

---

## 3. How it is verified — three layers, each catches what the others cannot

**Unit tests (1,288).** Mock the subprocess. Prove the wrapper's shape. Cannot
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
  There is no session handling, no auth-aware crawling.
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

**Three of six were producing false negatives.** All would have reported "not
vulnerable" against a target that was.

---

## 5. What is left, in priority order

### 5a. Authenticated testing — the biggest gap by far

Nothing behind a login is reachable. IDOR, access control, privilege
escalation and business logic all live there, and they are what programs pay
for. Needs: session capture, auth-aware crawling, and two-session object
reference comparison. **Days, not hours.** This is the single change that would
alter what the tool can find rather than how honestly it reports.

### 5b. A headless browser in the image

`dalfox` needs one for DOM XSS and fails silently without it. The negative
result now says so, but saying so is not covering it. Adding chromium closes
the most common modern XSS class.

### 5c. `hunt_plan` has never run against a live model

Built to make the model hunt rather than only triage. It reads the observed
surface and groups it by why it matters — object-reference candidates,
server-side sinks, parameter vocabulary. On a real run it reduced 2,748 URLs to
46 actionable items.

Agent mode works (returns the surface for the calling agent). The internal-LLM
path is untested because no OpenRouter key was available. `openai` is also not
installed — `pip install 'easyhunt-ai[llm]'`. `doctor` now reports this.

### 5d. Known smaller items

- `ssrfmap` is ungovernable: ~8,283 requests through its own thread pool, no
  rate flag. Labelled honestly; not fixed.
- `identity_marker` on 6 of 81 specs. Only names with real installable
  impostors are covered (nuclei, slither, katana, kingfisher, amass, forge).
- `shuffledns` and `linkfinder` have specs and no call site.
- `RateLimiter` charges declared `estimated_requests`; many wrappers declare
  nothing and charge the floor of 1. Silent under-charge. Needs an audit pass.
- 24 of 81 tools ran on the host rather than the sandbox — mostly fixed, but
  re-check with `doctor`; a green tick prints `@image` when containerised.
- `bootstrap.sh` has never been run end to end on a genuinely clean machine
  beyond a Debian container with Docker skipped.

---

## 6. How to start

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

Phases are **per-target** (recon → js) or **global** (takeover, scan, plan,
report — once over everything found). Each phase must prove it did something:
exit 0 did its job, 2 produced nothing, 3 failed. Only `probe` is required.

Each phase appends to `status.jsonl` with `input=` showing where its targets
came from (`argument` or `assets:url[live](n)`). That is the audit trail for
"which hosts did this actually cover".

---

## 7. Traps that cost real time here

- **A tool that finishes a network scan in under a second did not do one.**
  Duration is a signal. Compare it against what the work would have to cost.
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

## 8. Things not to do

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

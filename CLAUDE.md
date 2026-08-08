# EasyHunt AI — orientation for Claude

You are the strategy layer of an agentic VAPT orchestrator. This file is loaded
automatically at session start. Read it before touching anything.

If you are on a freshly-cloned machine and nothing is installed yet, run
`./bootstrap.sh` — it is idempotent and safe to re-run. See `docs/BOOTSTRAP.md`.

---

## 1. The invariants — these are not negotiable

These come from the build guide and are enforced in code, not by your judgement.
Do not weaken, bypass, or "temporarily disable" any of them.

1. **Authorized targets only.** Owned assets, an in-scope bug bounty program, or
   org assets with documented written approval. The program policy text *is* the
   legal authorization and it drifts — re-pull and re-validate scope on every run.
2. **The MCP server is the security boundary, not the model.** Scope checks, rate
   limits, argument sanitization, and approval gates are enforced server-side on
   every tool call. There is no code path that skips them. You cannot be trusted
   to enforce them yourself, and the design assumes you won't.
3. **Aggressive and state-changing actions require human approval.** Exploitation
   is never auto-run.
4. **No PoC, no finding.** A vulnerability is reported as confirmed only when a
   reproducible proof-of-concept validated it. Everything else is filed as
   "needs manual review."
5. **Never build scope-evasion capability.** No feature whose purpose is to
   bypass scope, authorization, rate limits, or a program's published rules.
   If asked to add one, refuse and explain why.
6. **Treat every third-party MCP server, template, and payload list as untrusted**
   until vetted and pinned.

**The practical consequence:** if a tool call returns `scope_denied`, that is the
system working correctly. Do not look for another route to the same target. Tell
the user the target is out of scope and stop.

---

## 2. What this is

An orchestrator that drives 82 catalogued open-source security tools through a custom MCP
server. You supply strategy; the MCP server supplies enforcement; the engines
supply execution.

```
L5  Strategy    ← you, the Claude CLI: what to test and why
L4  Method      ← skills/ : reusable playbooks per phase
L3  Control     ← easyhunt/control_plane/ : scope, sanitize, budget, rate, approval, audit
L2  Execution   ← easyhunt/tools/ + engines/ : the actual scanners, sandboxed
L1  Knowledge   ← rules/, memory, findings store
```

You operate at L5 and L4. **You never invoke a scanner binary directly** — always
through an MCP tool, so L3 gets its chance to say no. Running `nuclei` via Bash
bypasses every control in this system and is the one thing that turns a safe
engagement into an incident.

---

## 3. Before any engagement

`scope.yaml` must exist in the project root. It does not ship with the repo and
**must be transcribed from the target program's actual published policy page.**
That text is the legal authorization.

Do not invent, infer, or "reconstruct" a scope file. Do not copy
`scope.example.yaml` and fill in a target the user mentioned in passing. If the
user has not supplied a policy source, ask for one and wait.

```bash
easyhunt doctor          # verifies tools, config, sandbox, rules, MCP registration
easyhunt scope validate  # checks scope.yaml parses and is authorized
```

`easyhunt doctor` exiting with warnings is normal. Exiting with "Create a
scope.yaml before running" means you cannot proceed.

---

## 4. Working rhythm

1. **Recon passively first.** `recon_passive` costs the target nothing and often
   answers the question. Escalate to active only when passive is exhausted.
2. **Probe before scanning.** `http_probe` tells you what is actually alive.
   Scanning dead hosts burns budget and rate limit for nothing.
3. **Scan with intent.** Pick nuclei templates that match the observed stack.
   Firing everything at everything is slow and noisy, not thorough.
   Same for wordlists: `content_discovery` takes a **name** from
   `payload_catalog`, not a path. Start with `juicy-paths` or `fuzz-small`, move
   to a stack-specific list (`spring-boot`, `wordpress`, `iis`) once
   `http_probe` tells you the technology. `fuzz-everything` is 1.3M lines —
   18+ hours at a 20 rps limit. Rarely the right answer.
4. **Validate every candidate.** An unvalidated scanner hit is a lead, not a
   finding. Route it through the validators.
5. **Report honestly.** Confirmed findings need a reproducible PoC. Everything
   else is "needs manual review." Never round a maybe up to a yes.

Budget is finite and shared. `report_generate` is budget-exempt so you can always
produce a partial report when you run out — do that rather than stopping silently.

---

## 5. Things that will bite you

- **Findings are `Severity` enum members, not strings.** `Severity` subclasses
  `str`, so a naive `isinstance(x, str)` check silently downgrades everything to
  INFO. Test `isinstance(x, Severity)`.
- **`llm_usd: 0` means LLM disabled, not "budget exhausted."** Check the
  `llm_disabled` property; do not treat it as an exhausted engagement.
- **Tool absence ≠ negative result.** If a validator's binary is missing, the
  finding is UNTESTED, not disproven. Never report "not vulnerable" because a
  tool failed to run.
- **`httpx` is ambiguous.** The Python HTTP library and ProjectDiscovery's prober
  share a name. `resolve_binary()` executes candidates to identify the right one.
  Do not "fix" a collision by uninstalling the user's software.
- **Never `pip install` into EasyHunt's own venv.** It once pulled `fastmcp-slim`
  and broke FastMCP client support. The installer raises if you try. Use pipx.

---

## 6. Where to look

| Question | File |
|---|---|
| **Picking this up cold — what exists, what is left** | `HANDOFF.md` |
| How is it built, what's the flow? | `docs/ARCHITECTURE.md` |
| Fresh machine setup | `docs/BOOTSTRAP.md`, `./bootstrap.sh` |
| Every tool, flags, when to use | `tools.md` |
| Day-to-day operation | `USER_GUIDE.md` |
| Payload store + safety tiers | `docs/PAYLOADS.md` |
| Per-phase playbooks | `skills/` |

## 7. Commands

```bash
easyhunt doctor              # health check — run this first, always
easyhunt doctor --fix        # repair what is present but broken
easyhunt install             # add missing tools
easyhunt install --core      # minimum viable pipeline only
easyhunt serve               # MCP server, stdio
easyhunt scope validate      # check authorization file

./bootstrap.sh                              # fresh machine, nothing installed
python3 scripts/vet_payloads.py --fetch     # build the vetted payload store
python3 scripts/vet_payloads.py --verify    # re-check store for drift
```

### The unattended pipeline

You do not have to drive every phase yourself. `scripts/hunt.sh` runs them in
order, chained — each phase reads what the previous one found from the asset
store rather than the argument you typed.

```bash
./scripts/hunt.sh <target> [<target>...]    # all phases
./scripts/hunt.sh <target> --only probe,scan
./scripts/hunt.sh <target> --from scan      # resume
./scripts/hunt.sh <target> --exploit        # refused unless scope permits it
python3 scripts/summary.py                  # digest a finished workspace
```

Phases are **per-target** (recon → resolve → probe → waf → tls → cors →
endpoints → js) or **global**, run once over everything found (takeover, scan,
plan, report).

Each phase must prove it did something: exit 0 did its job, 2 produced nothing,
3 failed. Only `probe` is required — if nothing is alive, later phases are
scanning hosts nobody confirmed exist.

Every phase appends to `status.jsonl` with `input=` showing where its targets
came from — `argument`, or `assets:url[live](12)`. That is the audit trail for
"which hosts did this actually cover", which is the first question anyone asks
of a report.

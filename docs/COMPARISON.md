# EasyHunt vs autopentest-ai

`github.com/bhavsec/autopentest-ai` (Apache-2.0) is the closest public analogue
to this project. Both are MCP servers driving an AI agent through a penetration
test. They are built from opposite ends, and the comparison is worth writing
down because the difference is architectural, not cosmetic.

**Everything below was re-derived from both codebases on 2026-08-03.** Numbers
that could not be verified are marked as such rather than repeated.

---

## The one difference everything else follows from

**Where do the tools execute?**

autopentest-ai's MCP server executes **no security tools at all**. Every one of
its seven `subprocess.run` calls is `git`, used for engagement checkpointing —
verified by reading them. Its 70 MCP tools are knowledge and state: WSTG lookup,
PortSwigger technique guides, a knowledge graph, a task tree, payload retrieval,
context compression, quality gates. **The model runs nuclei, ffuf and sqlmap
itself, through Bash.**

EasyHunt inverts this. Its 66 MCP tools *are* execution wrappers, and scope,
rate limiting, argument sanitization, approval and audit are enforced in code
before every subprocess spawn.

| | autopentest-ai | EasyHunt |
|---|---|---|
| Source LOC (excl. vendored) | 9,607 | ~25,300 |
| MCP tools | 70 | 66 |
| Security tools executed server-side | **0** | 81 catalogued, 77 working |
| Test suite | **none found** | 1,240 tests |
| WSTG tests indexed | 110 | 115 |
| PortSwigger technique guides | 31 | **0** |

---

## Where autopentest-ai is genuinely better

**Methodology guidance the model can consult mid-test.** 31 PortSwigger Academy
technique guides. EasyHunt has no equivalent and this is a real gap: EasyHunt can
tell you a parameter is injectable, but it has nothing that teaches the agent
*how a human would approach* a class of bug. (EasyHunt has since indexed 115 WSTG
tests, so the WSTG half of the original gap is closed — the PortSwigger half is not.)

**Engagement memory and resumption.** A knowledge graph, a task tree, context
compression, and git-backed checkpoint/resume. EasyHunt has a findings store, a
task graph and optional Neo4j graph memory, but nothing as deliberate as
context compression for long engagements.

**Role-specialised subagents.** Scout / Analyzer / Exploiter / Reporter with
phase gates and a zero-context final judge. EasyHunt's skills are playbooks, not
separate agents with enforced handoffs.

**WAF evasion.** `waf_evasion.py` (616 LOC) fingerprints 12 WAF vendors and
serves tailored bypass payloads graded basic/intermediate/advanced. EasyHunt's
invariants forbid building evasion capability at all.

This last one is **a risk-appetite difference, not a correctness one.** Bypassing
a WAF to demonstrate an underlying bug is normal authorized pentest work, and
refusing to build it is a choice with a real cost: EasyHunt will report a
protected endpoint as clean where autopentest-ai would find the bug behind the
filter. That is a defensible choice and it is still a cost.

---

## Where EasyHunt is genuinely better

**Enforcement is possible at all.** This is the whole architectural argument.
autopentest-ai's `register_scope()` is bookkeeping — its own docstring says
domains are *"used for grouping findings in the report and for cross-domain auth
flow tracking."* Nothing checks a target against it, because nothing is executed
server-side. The model's judgment is the only boundary.

The same follows for rate limiting: no engagement-wide limiter is possible when
the model runs the tools. A program publishing 5 rps is enforced by the model
choosing to obey it.

EasyHunt refuses out-of-scope targets in code, and its token bucket is enforced
server-side. (Honest caveat: the limiter is per-`Engagement`, so two EasyHunt
processes double the effective rate — and until very recently every tool was
charged one token regardless of whether it sent 1 request or 8,283.)

**Knowing whether a tool actually ran.** This is where most of EasyHunt's test
suite comes from, and it is not theoretical. Measured on this codebase: `commix`
discarded its `-u` argument on every invocation for the project's entire life
and reported "no injectable parameter"; `sstimap` crashed at import under the
sandbox's read-only root and its Python traceback was parsed as a clean scan.
A knowledge server has no way to catch either, because it never sees the process.

**Tool identity resolution.** `resolve_binary()` executes candidates and matches a
declared marker. `pip install nuclei` gets you a 2018 Kaggle package; the venv's
Python `httpx` shadows ProjectDiscovery's prober. Both produce empty output and
look exactly like a clean target.

**Scan sizing before execution.** Refusing a scan that cannot finish, rather than
truncating it silently and reporting the partial result as complete.

**A test suite.** 1,240 tests, most encoding a bug that actually happened. No
test files were found in autopentest-ai outside its vendored dependencies.

---

## What this comparison does *not* settle

**Which one finds more real bugs.** Nothing here measures that, and nothing here
can. The two have never been run head to head against the same target, and the
capability comparison above does not predict the outcome — a tool that enforces
rate limits perfectly and never finds a bug is worse than one that finds bugs
and needs supervision.

There are specific reasons to expect them to differ in ways this analysis cannot
resolve:

- autopentest-ai's WAF evasion may surface bugs EasyHunt structurally cannot reach.
- EasyHunt's honest-absence reporting may mean it *reports* fewer findings while
  being *wrong* less often — which of those a program values is not a property of
  the code.
- autopentest-ai's methodology guides may direct the agent better on unfamiliar
  stacks, where EasyHunt's advantage is in execution it has already been told to
  perform.

**What a real comparison would need.** A target both are authorized against, run
independently with no shared recon, with these recorded per tool: findings
reported, findings that survived triage, findings a human reproduced, total
requests sent, wall-clock and token cost, and every case where one reported
"clean" for a surface the other found a bug on. That last column is the
interesting one and it is the reason to run the test at all.

Until that exists, the honest position is: **EasyHunt is better at not lying to
you about what it did; autopentest-ai is better at telling the model what to try.
Neither has been shown to be better at finding bugs.**

---

## The lesson worth carrying

A knowledge server cannot enforce anything. A control plane does not, by itself,
know what to test.

The two are complementary, and EasyHunt's weakest area — methodology depth,
technique guidance — is precisely autopentest-ai's strongest. The WSTG index was
adopted for exactly this reason. The PortSwigger guides are the obvious next
thing to learn from, and they are permissively reusable only as *pointers*, not
as copied text.

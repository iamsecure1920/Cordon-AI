# EasyHunt AI — Build Status

**As of 2026-07-31.** Every number here was measured on the build machine, not
estimated. Re-run `easyhunt doctor` and `pytest -q` after moving machines — the
tool counts are environment-specific and will differ.

---

## 1. Headline

| Metric | Value |
|---|---|
| Build stages complete | **16 / 16** |
| Tests | **601 passing, 0 failing** |
| Tool coverage | **60 / 64 installed (94%)** |
| Broken / shadowed binaries | **0** |
| MCP tools registered | **50** (26 passive, 19 aggressive, 5 exploit) |
| Python modules / LOC | 66 files, ~19,100 lines |
| Sandbox images | **9 / 9 pulled**, Docker enabled at boot |
| Core pipeline | **complete** — recon → probe → scan → validate → report runs unaided |

---

## 2. What works

**Fully built and tested:**

- **Control plane** — scope, sanitize, budget, rate limit, approval, sandbox,
  audit, jobs, pins. All enforced server-side on every call, no bypass path.
- **OAuth 2.1 + PKCE** for remote transport — RFC 9728 protected-resource
  metadata, RFC 8707 resource indicators, S256 challenge. Non-loopback bind
  without auth is hard-refused.
- **50 MCP tools** across recon, DNS, ports, HTTP probing, endpoint discovery,
  JS analysis, secrets, takeover, cloud, exploitation validation, LLM security.
- **Vetted payload store** — 62 files from a pinned third-party commit, tiered
  A/B/C, with 34 tier A lists name-mapped to ffuf, feroxbuster, arjun, and
  katana in `config.yaml`. Quarantine is unreachable by construction.
- **6 engine adapters** — bbot (3.0 API), nuclei, jaeles, semgrep, osmedeus, strix.
- **Knowledge layer** — findings store, penetration task graph, Cartography
  attack paths, Neo4j graph memory, PoC store.
- **LLM layer** — OpenRouter 3-tier routing with fallbacks, price ceilings, and
  prompt-cache breakpoints; adversarial triage with canary defense.
- **Reporting** — synthesis, templates, graph rendering including PNG export.
- **Installer** — 66 recipes, dependency-ordered, idempotent, with verify + repair.

**Verified end-to-end this session:** `http_probe` executed inside a Docker
container against a loopback lab target, returned the correct page title, and
the audit log recorded `outcome: ok`. The sandbox path genuinely works — it is
not merely configured.

---

## 3. What does not work / is not present

Be precise about these. Do not report them as working.

### Blocking

| Gap | Impact | Fix |
|---|---|---|
| **`scope.yaml` absent** | EasyHunt refuses to run at all. | Transcribe from the target program's published policy page. It is the legal authorization — it cannot be generated, inferred, or copied from the example. |

### Degrading (system runs, features unavailable)

| Gap | Impact | Fix |
|---|---|---|
| **`$OPENROUTER_API_KEY` unset** | AI triage and report synthesis unavailable. Passive recon, scanning, and rule-based detection all still work. | Export the key. |
| **4 tools not installed** | See below. | Each needs manual setup. |

### The 4 uninstalled tools

None are in the core pipeline (`core_missing` is empty), so the main flow is
unaffected.

| Tool | Why it is not installed |
|---|---|
| `cloudpeass` | Needs operator cloud credentials — those belong to you, not to an automated installer. |
| `subdomainsleuth` | Needs authoritative zone files to be useful. Worth reaching for if you hold them: it catches lame NS delegations HTTP-only scanners never see. |
| `osmedeus` | Large framework, manual setup. Engine adapter exists and will pick it up once present. |
| `strix` | Manual install by design. Adapter exists. |

---

## 4. Known traps (already fixed — do not reintroduce)

These were real bugs found during the build. Each cost real debugging time; the
fix and its reasoning are recorded so a future change does not undo them.

| Trap | Consequence if reintroduced |
|---|---|
| `Severity` subclasses `str` | An `isinstance(x, str)` check re-parses enum members into `INFO` — silently downgrading every finding. Test `isinstance(x, Severity)`. |
| `llm_usd: 0` treated as exhausted | Bricks every tool in the engagement. It means *LLM disabled*; check `llm_disabled`. |
| `report_generate` behind a budget gate | Makes "abort cleanly with a partial report" impossible. It is `budget_exempt=True`. |
| Secrets masked in `masked` but not `context` | Leaked full credentials in the context field while appearing to mask. |
| `-c` in `GLOBAL_DENIED_FLAGS` | It is nuclei's concurrency flag. Short-flag meaning is per-tool; argv never reaches a shell. |
| Tool absence read as a clean result | An absent validator marked findings "not vulnerable". Absence ⇒ **UNTESTED**. |
| `pip install` into EasyHunt's own venv | Once pulled `fastmcp-slim` and removed FastMCP client support — the installer broke its own host. Guarded; use pipx. |
| `httpx` PATH collision | Python's `httpx` CLI shadows ProjectDiscovery's. Solved by `resolve_binary()` executing candidates to confirm identity — **never** by uninstalling the user's software. |
| Tests asserting a tool is absent | `test_llmsec.py` assumed garak was missing; installing garak flipped the assertion. Absence is now simulated via monkeypatch. |

---

## 5. Environment notes for the new machine

- **Docker** is `enabled` + `active` via systemd and starts on boot. If the
  service ever fails with a stale-pidfile error, `systemctl reset-failed
  docker.service` then start again.
- **Disk**: the build machine ran out of headroom at ~22 GB free. Sandbox images
  total ~7 GB for EasyHunt's 9; budget 30 GB+ for images and scan artifacts.
- **`~/.local/bin` and `/usr/local/bin` must be on PATH** before EasyHunt's venv,
  or wrapper scripts will not resolve.

---

## 6. Suggested next steps

1. **Write `scope.yaml`** from a real program policy. Nothing runs until this exists.
2. **Set `$OPENROUTER_API_KEY`** to unlock triage and report synthesis.
3. **Run the payload vetting pass** (`docs/PAYLOADS.md`) if you want the expanded
   wordlist coverage — with the safety tiers, not as a raw dump.
4. **Install the 4 remaining tools** only if you need them; supply credentials
   for `cloudpeass` and zone files for `subdomainsleuth` first.
5. **Do a dry run against your own asset** before pointing it at a program, to
   confirm the sandbox, rate limits, and approval gates behave as you expect.

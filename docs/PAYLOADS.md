# Payload Store

## 1. What this is

A **vetted, tiered, pinned** payload store built from third-party wordlists.
Source: [`coffinxp/payloads`](https://github.com/coffinxp/payloads), pinned at
commit `ff9bd2045961cbaba00bdc988db62edd2273dcd2`.

Build or rebuild it on any machine with:

```bash
python3 scripts/vet_payloads.py --fetch    # clone at pinned SHA, classify, write store
python3 scripts/vet_payloads.py --verify   # re-check hashes, detect drift
python3 scripts/vet_payloads.py --report   # classification only, writes nothing
```

The store is **not redistributed** with EasyHunt (see §5). The script and
manifest ship; the payloads are re-fetched locally.

---

## 2. Why it is not just a `git clone`

The invariant is *"treat every third-party template and payload list as
untrusted until vetted and pinned."* A payload list is executable content in
every sense that matters — a raw clone means whatever someone pushes to `main`
tomorrow is what you fire at a target next week.

Vetting the actual contents found real problems:

| Finding | Count | Why it matters |
|---|---|---|
| **Genuine RCE payloads** | 4 files | `'; exec master..xp_cmdshell 'ping ...'--` executes OS commands on the database host. Not a test — an intrusion. |
| **Hardcoded third-party callbacks** | 2 files | `xxx.burpcollaborator.net`, `GH0ST.xss.ht`. If one fires, **your target's data goes to infrastructure someone else controls.** That is exfiltration to a third party, and it is not yours to authorize. `xxx.burpcollaborator.net` is also a dead placeholder that would never resolve. |
| **Time-delay payloads** | 513 across 2 files | `SLEEP(5)`, `BENCHMARK(10000000)`, `WAITFOR DELAY`. Legitimate blind-SQLi detection, but they tarpit the engagement clock and look like a DoS from the target's side. |
| **No license** | whole repo | All rights reserved by default — a redistribution problem, not a usage one. |

---

## 3. The three tiers

```
payloads/
├── A/            38 files, 65 MB   discovery wordlists
├── B/            20 files, 5.9 MB  injection payloads
├── _quarantine/   4 files, 200 KB  never auto-run
└── manifest.json                   provenance, hashes, tool mapping
```

**Tier A — discovery wordlists.** Requesting a path is what a web client does.
Normal scope and rate limits apply, no extra gate. 38 files.

**Tier B — injection payloads.** These are attacks. Aggressive mode plus the
approval gate, same as any other aggressive tool. 20 files.

**Tier C — quarantined.** Destructive or exfiltrating. Copied intact so a human
can inspect them, never wired into any tool. 4 files:

| File | Reason |
|---|---|
| `SQL.txt` | 6 `xp_cmdshell` RCE statements |
| `all_attacks.txt` | 2 `xp_cmdshell` RCE statements |
| `sqli2.txt` | 7 RCE statements **and** a `burpcollaborator.net` callback |
| `xss.txt` | `GH0ST.xss.ht` callback — steals `document.domain` to a third party |

Note that quarantine **does not rewrite** anything. Silently "cleaning" an
attack string produces something that looks safe and isn't; the file is moved
intact and left for a human.

### The GET-only constraint

16 Tier A wordlists contain state-changing paths — `actuator/shutdown`,
`/restart`, `/reset`. The first pass of the classifier quarantined all of them,
which was wrong: **the danger is in the method, not the word.**

`GET /actuator/shutdown` returns 405 and is ordinary content discovery.
`POST /actuator/shutdown` takes the application down. So these files stay in
Tier A with `get_only: true` in the manifest, and the constraint belongs on the
HTTP method.

Getting this distinction right took the quarantine from 21 files down to 4 —
and the 21 included `everything.txt`, `api.txt`, and every large wordlist, i.e.
essentially all of the value.

---

## 4. Tool mapping

**34 tier A lists are mapped in `config.yaml` under `payloads.lists`.** Tools take
a list **name**, never a path:

```
content_discovery(target="https://example.com", wordlist="juicy-paths")
payload_catalog()                  # every list
payload_catalog(tool="arjun")      # just what arjun consumes
```

### Why names and not paths

`sanitize_path` refuses anything outside the engagement workspace, and the store
deliberately sits outside it. Resolving names server-side keeps the store
read-only and out of reach of anything the model can write to.

A name is also **tier-checkable in a way a path is not.** No name maps to tier C,
so quarantined payloads cannot be requested at all — and even a hand-edited
config that aliases one is refused at resolution time, with or without caller
opt-in.

### The mapping

| Use | Tools | Names |
|---|---|---|
| **Content discovery** | ffuf, feroxbuster | `admin` `config` `env` `juicy-paths` `juicy-files` `backups` `git-config` `extensions` `leaked-files` `zip` |
| **Stack-specific** *(after `http_probe` identifies the tech)* | ffuf, feroxbuster | `spring-boot` `phpmyadmin` `adminer` `kibana` `wordpress` `wp-content` `iis` `aspx` `jsp` `jsf` `cgi` `cgi-files` |
| **Parameter discovery** | arjun, ffuf | `params` `params-short` |
| **Vhost discovery** | ffuf | `vhosts` |
| **API surface** | ffuf, katana | `api-routes` `api-httparchive` |
| **General fuzzing** | ffuf, feroxbuster | `fuzz-small` `fuzz-medium` `fuzz-php` `fuzz-large` `fuzz-everything` |
| **Path traversal** | ffuf | `traversal-unix` `traversal-win` |

Start with `juicy-paths` or `fuzz-small`. Move to a stack-specific list once you
know the technology. `fuzz-large` and `fuzz-everything` are hours of traffic —
see §6.

### Tier B is deliberately unmapped

Injection payloads (`xss`, `allsqli`, `ssti`, …) have **no aliases**. They are not
discovery wordlists, and `content_discovery` must not be able to reach them by
naming one. They belong to the approval-gated exploitation tools, which pass
them to dalfox and sqlmap directly via `allow_tier_b=True`.

### The GET-only constraint is structural

16 mapped lists carry `get_only: true`. `content_discovery` satisfies this by
construction rather than by policy: **`-X` is not on ffuf's argument allowlist**,
so it cannot issue anything but a read method. The constraint cannot be violated
even deliberately.

---

## 5. Licensing

The upstream repo ships **no LICENSE file**, which means all rights reserved by
default. Using it locally is fine. Bundling it into a distributed copy of
EasyHunt is not.

So `payloads/*` is gitignored except the manifest. On a new machine, one command
rebuilds the store from the pinned commit. Nothing is lost and nothing is
redistributed.

---

## 6. An honest word on scale

The full store is **3.7 million lines**, of which ~3.1 M are unique — roughly
16% duplication across files. `everything.txt` alone is 1.3 M lines.

At a typical program rate limit of 20 rps, firing `everything.txt` at a *single
host* takes **over 18 hours**. The rate limiter will handle this correctly, in
the sense that it will not exceed the limit — but the engagement will simply
never finish.

**More payloads is not more coverage.** A curated nuclei template that
understands a response finds things a 1.3 M-line blind wordlist never will,
because it knows what it is looking at. The realistic value of this store is:

- Tier A small lists (admin, config, env, juicy-paths) — genuinely useful,
  fast, high signal.
- Tier A large lists — only worth it on a target you have time to grind, and
  usually only after the small lists have been exhausted.
- Tier B — supplementary payloads for dalfox and sqlmap, which already ship
  well-curated built-ins that are context-aware.

Use the small lists by default. Reach for the large ones deliberately, with the
budget to back it up.

---

## 7. Verification and drift

`manifest.json` records a SHA-256 for every file. `--verify` re-hashes the store
and reports anything missing or changed. Run it after any manual edit and before
relying on the store in an engagement.

To move to a newer upstream commit: update `SOURCE["commit"]` in
`scripts/vet_payloads.py`, re-run `--fetch`, and **read the new classification
report** before trusting it. The pin exists so that upstream changes are a
decision, not an accident.

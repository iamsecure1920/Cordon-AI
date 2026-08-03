# Working checklist

Live state of what is done, what is running, and what is next. Updated as work
lands, not at the end. If a session dies, this file is how the next one resumes.

Rule for this file: an item is only ticked when a **number** backs it. "Wired up"
is not done; "ran against the validation target, returned 3 endpoints, exit 0" is done. See
[[absence-is-not-a-clean-result]] — the whole point is that untested and clean
look identical.

---

## 1. Live-validate the 12 new tools  ✅ DONE

They pass unit tests. Most have never executed against a real host. Unit tests
mock the subprocess, so they prove the wrapper's shape, not that the binary
accepts the argv we build.

Target: `the validation target` (owned, `scope.yaml` loaded, 10 rps, exploitation allowed).

Each tool needs, recorded below: **ran / exit code / output non-empty / argv
accepted by the real binary / result parsed**.

| Tool | Mode | Ran | Notes |
|---|---|---|---|
| `tls_audit` | passive | ☑ | ran 84s, 170 checks, found TLS1.0/1.1 still offered |
| `cors_audit` | passive | ☑ | ran 8.7s, 7 origins tested, 0 permissive |
| `graphql_audit` | passive | ☑ | ran 3.0s, correctly reports `not_graphql` for a non-GraphQL path |
| `jwt_inspect` | passive | ☑ | ran 3.5s, parsed HS256, flagged missing `exp` |
| `websocket_probe` | passive | ☑ | ran 1.6s; misdiagnosed a 200 OK as a transport failure — fixed |
| `nikto_scan` | aggressive | ☑ | was auto-denied; now ran 50s, 18 items, tuning `123be` verified |
| `wapiti_scan` | aggressive | ☑ | was auto-denied; now ran 221s, crawled 142 pages, safe profile |
| `ssrf_probe` | exploit | ☑ | ran 305s; reported 1,989 open loopback ports as HIGH — saturation guard added |
| `ssti_probe` | exploit | ☑ | crashed in-sandbox, read as clean; scratch mount + crash guard → 167s, 1 HIGH on the lab |
| `cmdi_probe` | exploit | ☑ | commix discarded -u without `--ignore-stdin`; now 15s, 1 CRITICAL on the lab |
| `smuggling_probe` | exploit | ☑ | ran 30s, 416 lines, 0 desync — correct for a single-origin host |
| `nosqli_probe` | exploit | ☑ | ran 3.6s, 0 findings — no Mongo behind the validation target |

## 2. Doctor accuracy  — partly done

Execution-by-default already landed earlier. The remaining hole was *where*:
doctor probed the host while the engagement ran the tool in a container. Both
answers were about a file named `sstimap`; only one of them was the program.

- [x] Probe each tool in its container home, under the real run's constraints
      (read-only root, dropped caps, same user, same per-tool tmpfs)
- [x] Report the image in the tool line, so a green tick names what it is about
- [x] Found on the first run: `dalfox` absent from `hahwul/dalfox:latest`
      (binary at `/app/dalfox`, nothing on PATH — every sandboxed run exited
      127, and `xss_validate` is auto-approved), `semgrep` crashing on a
      read-only `/root/.semgrep`
- [ ] `identity_marker` still missing on 67 of 81 specs. Execution proves *a*
      binary of that name responds, not that it is the right program

## 3. Items 1-6 — status on 2026-08-03

All numbers below were re-derived today. Where another agent's work is still in
flight it says so rather than claiming a result.

### 3a. Four tools broken by Python 3.13  DONE
`dirsearch`, `dnsreaper`, `paramspider` (`pkg_resources`) and `deepteam`
(`nntplib`). All four were absent from `easyhunt:latest` entirely and existed
only on the host, where Python 3.13 broke them. The image runs 3.12.

- [x] All four added, each verified in a `python:3.12-slim` container first
- [x] `--with setuptools` does NOT fix dirsearch: setuptools 81+ dropped
      `pkg_resources`, so the newest release satisfies the flag and still fails
      the import. Master (0.5.0) needs neither.
- [x] Rebuilt and re-probed: **73 -> 77 working, 4 broken -> 0**

### 3b. Tools running outside the sandbox  DONE
Was 24 host-only tools. Now **75 of 81 have a container home**, 73 are present in
`easyhunt:latest`, and 6 fall back to the host — 4 of those are not installed
anywhere, `garak` is excluded deliberately (5.53 GB of PyTorch), `promptfoo` is
host-only.

- [x] All 24 added: 7 Go installs, 6 uv tools, 4 script repos, 5 prebuilt
      binaries, retire via npm
- [x] Four "known upstream failures" were nothing of the sort — `subzy` was a
      rename, `jsluice` needed CGO, `aderyn` publishes the binary it would not
      compile, `subdominator` just needed libpango. Every one had a written
      explanation that was wrong, which is why nobody retried them.
- [x] Confirmed after rebuild: all 24 execute, zero build failures
- [x] Image size **16.7 GB -> 4.54 GB** after fixing a `chmod -R` that cost
      6.6 GB in one layer and dropping garak's 5.53 GB dependency tree

### 3c. Rate flags that ignore the engagement ceiling  DONE
`gau --threads 5`, `waymore -p 5`, `arjun -t 10` with no delay at all,
`sqlmap --threads 2 --delay 1`, `sstimap`/`commix --delay 1`.

- [x] All six sourced from `scope.rules`, each clamped to its own policy
      `numeric_cap` — a value above the cap is refused by the sanitizer, so an
      uncapped conversion turns a rate fix into a tool that stops running
- [x] 18 regression tests, each varying the scope so a hardcoded expectation
      cannot pass

### 3d. `ssrfmap` is structurally ungovernable  DONE
- [x] Confirmed by reading its full argparse: no rate, delay, thread or
      concurrency flag exists. Staging a shorter port list also fails —
      `core/ssrf` calls `os.chdir` to its own install directory first.
- [x] `estimated_requests = 8283` (the real figure), so `budget.check` refuses
      the call when that many requests do not remain
- [x] `risk_notes` leads with **UNGOVERNABLE RATE**; the result carries a
      `rate_note`, because a report omitting it claims the run stayed inside its
      ceiling

### 3e. Identity markers  DONE
- [x] **6 added, not 71.** Every unmarked binary name was checked against Debian
      packages and PyPI; six have a real installable impostor. `pip install
      nuclei` gets a 2018 Kaggle package, `slither` a Scratch-for-Python toy,
      `katana` a bioinformatics read-clipper.
- [x] Reading real output first was not optional: `slither --version` prints a
      bare `0.11.6` and `amass -version` a bare `v5.1.1`. Guessing the obvious
      markers would have permanently broken two working tools.
- [ ] `strix` left unmarked on purpose — its PyPI impostor is real but the tool
      is not installed here, so its output could not be read. An unverified
      marker is the failure this avoids.

### 3f. `bootstrap.sh` on a clean machine  DONE
Run for the first time, in a `debian:bookworm-slim` container. It found two
things that had been shipping since the beginning:

- [x] **`install.sh` was fabricating an authorization record** — it copied
      `scope.example.yaml` to `scope.yaml`, so the operator got a file declaring
      `authorization: bug-bounty` and a `fetched_at` date they never wrote, with
      three green ticks confirming it. CLAUDE.md forbids the *agent* from doing
      exactly this; the installer was doing it on the agent's behalf.
- [x] **Debian ships Go 1.19; the toolchain needs 1.21+.** 16 tools failed to
      build on a clean bookworm box, including nuclei, httpx, subfinder, dnsx,
      naabu and katana. Unnoticed for the project's life because Kali ships a
      current Go. `bootstrap.sh` now installs a current toolchain from go.dev.
- [x] `Scope.validate()` warns when a hand-copied template is still unedited

### 3g. autopentest-ai comparison  DONE
Written from both codebases — see [COMPARISON.md](COMPARISON.md).

The honest conclusion: **EasyHunt is better at not lying to you about what it
did; autopentest-ai is better at telling the model what to try. Neither has been
shown to be better at finding bugs**, and that cannot be settled from the code.
What a real test would need is written down in that file.

---

## 4. Still open

- [ ] **`identity_verified` is hardcoded `False` for containerised tools**
      (`easyhunt/install/installer.py:269`). Every one of the 75 containerised
      tools counts as unverified regardless of its marker, so `doctor` reports
      *"76 declare no identity_marker"* when the true number is **62**. The
      markers are correct; the count is wrong. Fix: have the container probe
      match the marker against output it already captures.
- [ ] `subdominator -c` is not on its allowlist, so takeover detection runs at
      the tool's own concurrency (commented in `takeover.py`)
- [ ] `RateLimiter.slot()` accepts a `cost` parameter no caller passes — every
      tool is charged one token whether it sends 1 request or 8,283. *(Being
      addressed in a parallel change; confirm before relying on this line.)*
- [ ] Live validation of the 24 newly-sandboxed tools through the control plane.
      `doctor` proves they answer `--version` in the image; that is not proof a
      wrapper builds an argv the binary accepts. *(In flight.)*
- [ ] PortSwigger-style technique guidance — the one capability gap
      COMPARISON.md identifies as real and unaddressed

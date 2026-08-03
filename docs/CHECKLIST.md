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

## 3. Open, verified against the code today

Everything below was re-checked on 2026-08-03; the numbers are measured, not
remembered. Ordered by what it costs to leave alone.

### 3a. Four tools broken by Python 3.13  ✅ DONE
`dirsearch`, `dnsreaper`, `paramspider` (`pkg_resources`, removed in 3.12+ when
setuptools is absent) and `deepteam` (`nntplib`, removed in 3.13). All four are
**absent from `easyhunt:latest` entirely**, so they only exist on the host, where
Python 3.13 broke them. The image runs Python 3.12 — which still has `nntplib` —
so adding them there fixes the cause rather than patching the host.
Costs coverage on every run: dirsearch is content discovery, dnsreaper is
takeover detection.

- [x] All four added to the Dockerfile, each verified in a python:3.12-slim
      container first
- [x] Rebuilt and re-probed: **73 -> 77 working, 4 broken -> 0**

### 3b. 24 tools run on the host, outside the sandbox
46 of 81 catalogued tools are in `easyhunt:latest`; 48 have a container home once
the dedicated images are counted. The other 24 fall back to the host and run with
no read-only root, no dropped capabilities, no memory ceiling:

  aderyn, cloud_enum, cloudfox, findomain, garak, gitdorker, gobuster, jaeles,
  jsluice, kingfisher, kubescape, linkfinder, noseyparker, retire, s3scanner,
  secretfinder, shuffledns, subdominator, subjack, subzy, theHarvester, uncover,
  waymore, xsstrike

The sandbox is the isolation boundary, and a quarter of the toolchain is outside
it. `fallback_to_host: true` makes that silent by design — each fallback is
logged, but nobody reads the log.

- [ ] Add the ones that build cleanly to the image
- [ ] Decide explicitly, in config, which are allowed to run on the host

### 3c. Rate flags that ignore the engagement ceiling  ✅ DONE
Verified still hardcoded:
- `arjun` — `-t 10`, no delay, nothing derived from `scope.rules` (endpoints.py:293)
- `gau --threads 5` (endpoints.py:193)
- `waymore -p 5` (endpoints.py:195)
- `sqlmap --threads 2 --delay 1` (exploitation.py:455)
- `commix --delay 1` (injection.py:881), `nosqli` likewise (injection.py:1027)

Against a program publishing a low rate these exceed it, in the operator's name,
with the audit log showing one compliant tool call. Same class as the naabu/dnsx
breach already fixed — these are the files that fix missed.

- [x] All six sourced from `scope.rules`, each clamped to its own policy
      `numeric_cap` — a value above the cap is refused by the sanitizer, so an
      uncapped conversion would turn a rate fix into a tool that stops running
- [x] 18 regression tests, each varying the scope so a hardcoded expectation
      cannot pass

### 3d. `ssrfmap` is structurally ungovernable
~8,282 requests through its own thread pool, no rate flag at any price. Measured:
305s for one `ssrf_probe` call. The saturation guard now stops it producing a
false finding, but it still cannot be rate-limited.
- [ ] Either bound it (own image with a network cap) or name it in `risk_notes`
      so it stops looking governed

### 3e. Smaller, known, documented
- [ ] `subdominator -c` is not on its allowlist, so takeover detection runs at
      the tool's own concurrency (already commented in takeover.py:243)
- [ ] `identity_marker` on 67 of 81 specs — the `medusa` collision waiting to
      recur
- [ ] `bootstrap.sh` never run end to end on a clean machine
- [ ] autopentest-ai comparison run against AT&T

### 3f. Not code — but blocking
- [ ] **11 commits are unpushed.** `origin/main` is at `1f50e6e`; local `main` is
      at `aae3196`. Everything from "Make 12 shipped tools reachable" onward
      exists only on this machine.

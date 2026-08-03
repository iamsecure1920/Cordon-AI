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
- [ ] `identity_marker` still missing on 64 of 81 specs. Execution proves *a*
      binary of that name responds, not that it is the right program

## 3. Carried over, not started

- [ ] 29 tools the Dockerfile attempts are not in `easyhunt:latest`
      (failure-tolerant installs) — they silently fall back to the host
- [ ] `ssrfmap` is structurally ungovernable: ~8,282 requests via its own thread
      pool, no rate flag. Either wrap it or drop it; do not leave it looking
      governed
- [ ] Rate-limit flags still hardcoded past the scope ceiling: `arjun`
      (`--rate-limit` not passed at all), `gau --threads 5`, `waymore -p 5`,
      `sqlmap --threads 2 --delay 1`
- [ ] `subdominator` needs `-c` in its allowlist in `extra_specs.py`
- [ ] amass, jsluice, subzy, aderyn absent from the image (upstream build
      failures) — recorded, not hidden
- [ ] `bootstrap.sh` never run end to end on a clean machine
- [ ] autopentest-ai comparison run against AT&T

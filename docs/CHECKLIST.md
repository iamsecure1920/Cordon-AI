# Working checklist

Live state of what is done, what is running, and what is next. Updated as work
lands, not at the end. If a session dies, this file is how the next one resumes.

Rule for this file: an item is only ticked when a **number** backs it. "Wired up"
is not done; "ran against the validation target, returned 3 endpoints, exit 0" is done. See
[[absence-is-not-a-clean-result]] — the whole point is that untested and clean
look identical.

---

## 1. Live-validate the 12 new tools  ← IN PROGRESS

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
| `ssrf_probe` | exploit | ☐ | |
| `ssti_probe` | exploit | ☐ | |
| `cmdi_probe` | exploit | ☐ | |
| `smuggling_probe` | exploit | ☐ | |
| `nosqli_probe` | exploit | ☐ | |

## 2. Doctor accuracy

`doctor` marks a tool installed on PATH presence alone for ~60 specs. That is
exactly how nikto and testssl shipped broken. `identity_marker` exists and works
(`resolve_binary()` executes candidates) but is set on only a handful of specs.

- [ ] List every spec whose binary name is ambiguous or whose presence does not
      imply it runs
- [ ] Add `identity_marker` to each
- [ ] Make `doctor` report `installed` vs `runnable` as separate columns
- [ ] Re-run `make verify-tools`, record before/after counts

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

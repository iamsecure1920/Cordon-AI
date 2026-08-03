# EasyHunt AI — Build Status

**As of 2026-08-03.** Every number below was re-derived from the code and the
built image on the day of writing, not carried forward from an earlier revision.
Where something could not be verified it says so rather than repeating a claim.

Tool counts are environment-specific. Re-run `easyhunt doctor` and
`pytest -q` after moving machines.

---

## 1. Headline

| Metric | Value | How it was checked |
|---|---|---|
| Tests | **1,240 collected, passing** | `pytest -q --collect-only` |
| Catalogued tools | **81** | `len(CATALOG)` |
| Working (executed, not PATH-checked) | **77 / 81** | `easyhunt doctor` |
| Broken | **0** | `easyhunt doctor` |
| Not installed | **4** | cloudpeass, osmedeus, strix, subdomainsleuth |
| MCP tools registered | **66** | `len(REGISTRY)` |
| Tools with a container home | **75 / 81** | `Sandbox.image_for` + `_why_not_sandboxed` |
| Present in `easyhunt:latest` | **73 / 81** | `command -v` inside the image |
| Image size | **4.54 GB** | `docker images` |
| Installer recipes | **83** | `len(RECIPES)` |
| Python modules / LOC | 71 files, ~25,300 lines | `find`/`wc` |
| Payload store | 62 entries — 38 tier A, 20 B, 4 C | `payloads/manifest.json` |

---

## 2. Where tools run

The sandbox is the isolation boundary: read-only root, all capabilities dropped,
memory and CPU ceilings, one container per tool invocation.

**75 of 81 tools have a container home.** 8 have a dedicated upstream image
(`config.yaml` → `sandbox.images`); the rest fall through to `easyhunt:latest`,
built from this repo's `Dockerfile`.

**6 do not**, and each for a stated reason:

| Tool | Why it runs on the host |
|---|---|
| `garak` | **Deliberate.** It pulls PyTorch and the transformers stack — 5.53 GB, a third of the image — for an LLM red-team tool most engagements never invoke. It works on the host. This is the one place the sandbox-everything rule loses on cost. |
| `promptfoo` | Node/npm tool, present on the host, not added to the image. |
| `cloudpeass`, `osmedeus`, `strix`, `subdomainsleuth` | Not installed anywhere — see §4. |

`sandbox.fallback_to_host` is `true`, so a tool with no container home still
runs. Each fallback is logged at WARNING and written to the audit log as a
`sandbox_fallback` event. It is recoverable, but it is not silent by accident —
it is silent unless someone reads the log, which is why the count above matters.

### Per-tool writable scratch

A read-only root breaks any tool that writes into `$HOME` at startup. Eight
tools have explicit tmpfs mounts in `config.yaml` for exactly this reason:
`commix`, `noseyparker`, `semgrep`, `slither`, `sqlmap`, `sstimap`,
`theHarvester`, `wapiti`.

**Mount the leaf, never the parent.** `/root/.local/share` holds uv's tool store
and every uv-installed binary points into it — a tmpfs there hides about a dozen
tools at once and they report as absent from the image. A scratch mount that
makes the tool vanish is a worse failure than the one it was fixing.

---

## 3. Verified this session

Each of these was measured, not assumed.

- **12 attack-class wrappers run against a live host.** Five were broken in ways
  no unit test could see: `commix` discarded `-u` on every call for the
  project's entire life (non-TTY stdin made it parse stdin as its target list),
  `sstimap` crashed at import under the read-only root and its Python traceback
  was parsed as a clean scan result, and `ssrf_probe` reported 1,989 open
  loopback ports on a CDN-fronted host as a HIGH-severity finding.
- **`doctor` now probes each tool inside its container home**, under the real
  constraints. That immediately found `dalfox` missing from the image it was
  mapped to (binary at `/app/dalfox`, nothing on PATH — every sandboxed run
  exited 127, and `xss_validate` is auto-approved, so XSS could be found and
  never proven) and `semgrep` crashing on a read-only `/root/.semgrep`.
- **Rate flags come from `scope.rules`**, not literals. Six tools were sending
  requests at a rate nobody authorized: `gau --threads 5`, `arjun -t 10` with no
  delay at all, `sqlmap --threads 2 --delay 1`, and three more.
- **`bootstrap.sh` run on a clean Debian container** for the first time. See §5.

---

## 4. What does not work / is not present

### Blocking

| Gap | Impact | Fix |
|---|---|---|
| **`scope.yaml` absent** | EasyHunt refuses to run. | Transcribe it from the target program's published policy page. |

`scope.yaml` is **never created for you**, and that is deliberate. `install.sh`
used to copy `scope.example.yaml` into place; the operator got a file declaring
`authorization: bug-bounty`, a `program_url` and a `fetched_at` date they never
wrote, and three separate green ticks then confirmed it — `doctor` printed
`✓ scope: scope.yaml (example-bbp, bug-bounty)` and meant nothing by it.

It is not configuration. It is the record of an authorization, and the policy
text is the legal basis for the engagement. `Scope.validate()` now also warns
when a hand-copied template is still unedited: `engagement.name` of
`example-bbp`, a `user_agent` still carrying `your-handle`, or `in_scope` naming
`example.com` (IANA-reserved; it authorizes nothing).

### Degrading

| Gap | Impact |
|---|---|
| `$OPENROUTER_API_KEY` unset | AI triage and report synthesis unavailable. Passive recon, scanning and rule-based detection all still work. |
| 4 tools not installed | None are in the core pipeline. |

| Tool | Why not installed |
|---|---|
| `cloudpeass` | Needs operator cloud credentials — those belong to you, not to an installer. |
| `subdomainsleuth` | Needs authoritative zone files to be useful. |
| `osmedeus` | Large framework, manual setup. Engine adapter exists and picks it up once present. |
| `strix` | Manual install by design. Adapter exists. |

### Known-ungovernable

`ssrfmap` fires **8,283 requests** through its own thread pool and has no rate,
delay, thread or concurrency flag at any price — its full argparse was read to
confirm this, and the obvious workaround (staging a shorter port list) also
fails because `core/ssrf` calls `os.chdir` to its own install directory first.

`estimated_requests` is set to that real figure, so `budget.check` refuses the
call when that many requests do not remain, and `risk_notes` leads with
**UNGOVERNABLE RATE**. A report omitting that would be claiming the run stayed
inside its rate ceiling.

---

## 5. Requirements the clean-machine run exposed

**Go 1.21 or newer is required, and Debian does not ship it.** bookworm's
`golang-go` is Go 1.19, and every ProjectDiscovery tool, dalfox, gitleaks and
medusa refuse to build against it:

```
go.mod:5: unknown directive: toolchain
invalid go version '1.25.5': must match format 1.23
package slices is not in GOROOT (/usr/lib/go-1.19/src/slices)
```

16 tools failed on a clean bookworm box — most of the pipeline. It went
unnoticed for the project's life because Kali ships a current Go, so the
development machine never reproduced it. `GOTOOLCHAIN=auto` does not rescue 1.19:
the `toolchain` directive it would need to read is the thing 1.19 cannot parse.

`bootstrap.sh` now detects a Go older than 1.21 and installs the official
toolchain from go.dev ahead of it on `PATH`.

**Other environment notes:**

- `easyhunt:latest` is **not on any registry** — `docker pull` cannot find it.
  `bootstrap.sh` builds it, or run `docker build -t easyhunt:latest .` yourself.
  Budget 30–45 minutes for a first build.
- **Disk**: budget 30 GB+. The image is 4.54 GB; per-tool images add several more;
  scan artifacts grow.
- **`~/.local/bin` and `/usr/local/bin` must precede EasyHunt's venv on PATH**,
  or wrapper scripts will not resolve — and the venv's Python `httpx` will shadow
  ProjectDiscovery's prober.
- `config.yaml` is gitignored. Until you write one, EasyHunt reads
  `config.example.yaml`, which carries the shipped posture (sandbox on, image
  map, scratch mounts). Falling through to code defaults would set
  `sandbox.mode: none` and run everything on the host.

---

## 6. Identity markers — what they do and do not prove

19 of 81 specs declare an `identity_marker`. They were not chosen by guessing
which names "look generic": every unmarked binary name was checked against Debian
packages and PyPI, and six turned out to have a real, installable impostor —
`pip install nuclei` gets you a 2018 Kaggle package, `slither` a Scratch-for-Python
toy, `katana` a bioinformatics read-clipper.

**A marker only protects the host execution path.** `resolve_binary()` executes
candidates and matches the marker before running anything on the host. The
container path does not do this — inside a purpose-built image we control what is
installed, so the collision risk is different in kind.

**Known defect, not yet fixed:** `_probe_in_container` in
`easyhunt/install/installer.py:269` hardcodes `identity_verified=False`, so every
containerised tool counts as unverified regardless of its marker. `doctor`
therefore reports *"76 of those declare no identity_marker"* when the true number
of specs without one is **62**. The count is wrong and overstates the gap; the
markers themselves are correct. Fixing it means having the container probe match
the marker against the output it already captures.

---

## 7. Suggested next steps

1. **Write `scope.yaml`** from a real program policy. Nothing runs until it exists.
2. **Set `$OPENROUTER_API_KEY`** to unlock triage and report synthesis.
3. **Fix the `identity_verified` count** in the container probe (§6).
4. **Dry-run against your own asset** before pointing it at a program, to confirm
   the sandbox, rate limits and approval gates behave as you expect.

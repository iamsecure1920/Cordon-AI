# Bootstrap — moving EasyHunt to a new machine

## 1. The short version

```bash
# on the new machine
scp -r EasyHunt-AI/ user@newbox:~/          # or rsync, git clone, USB, whatever
cd ~/EasyHunt-AI
./bootstrap.sh                              # idempotent; safe to re-run
```

Then read `CLAUDE.md`. If you are Claude, it is loaded automatically.

`bootstrap.sh` handles the machine (system packages, Go, pipx, Docker, images).
`install.sh` handles the application (Python package, tool suite, skills, MCP
registration). Bootstrap calls install — you do not need to run both.

---

## 2. Requirements

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| Disk | 15 GB | **30 GB+** | Sandbox images ~7 GB, tool suite ~3 GB, scan artifacts grow without bound. The previous machine ran out at 22 GB free. |
| RAM | 4 GB | 8 GB | bbot and nuclei are memory-hungry at concurrency. |
| OS | Debian/Ubuntu/Kali | Kali | `bootstrap.sh` uses `apt-get`. Other distros need the §3 packages installed manually. |
| Network | outbound 443 | — | Tool downloads, template updates, OpenRouter. |
| Privileges | root or sudo | — | Docker, apt, and raw-socket tools (naabu/nmap/masscan) need it. |

---

## 3. What bootstrap.sh does, in order

1. **Disk check.** Warns under 30 GB, refuses to pull images under 15 GB.
2. **System packages** — `build-essential`, `libpcap-dev`, `git`, `curl`, `jq`,
   `python3-venv`, `pipx`, `golang-go`.
   `libpcap-dev` is not optional: naabu, nmap, and masscan need raw sockets.
   `build-essential` is needed because katana builds with `CGO_ENABLED=1` for
   headless support — without CGO it installs fine and silently lacks it.
3. **PATH ordering.** Appends `~/.local/bin`, `/usr/local/bin`, and `$GOPATH/bin`
   to `~/.profile`. Wrapper scripts live there; if they are not on PATH, tools
   appear "not installed" while sitting on disk.
4. **Docker** — installs, **unmasks** (Kali ships `docker.service` masked, and
   `enable` on a masked unit silently does nothing), enables at boot, starts.
   Recovers automatically from the stale-pidfile failure.
5. **`install.sh`** — Python package, tool suite, nuclei templates, skills, MCP
   registration.
6. **FastMCP guard** — verifies `import fastmcp` still works and force-reinstalls
   the pinned version if not. Some security tools pull `fastmcp-slim` as a
   transitive dependency, which removes client support and breaks the auth layer.
7. **Config** — copies `config.example.yaml` → `config.yaml` if absent.
8. **Sandbox images** — pulls the 9 configured images, skipping any already present.
9. **`easyhunt doctor`** — full verification.
10. **Tells you what is still missing** — `scope.yaml`, `OPENROUTER_API_KEY`.

Flags: `--no-docker`, `--no-images`, `--no-tools`. All are also environment
variables (`SKIP_DOCKER=yes` etc.).

---

## 4. After bootstrap

### Required before anything runs

**`scope.yaml`.** It does not ship and cannot be generated. Transcribe it from
the target program's published policy page — that text is the legal
authorization, and it drifts, so re-pull it before each engagement.

```bash
cp scope.example.yaml scope.yaml
$EDITOR scope.yaml
easyhunt scope validate
```

### Optional

```bash
export OPENROUTER_API_KEY=sk-or-...          # unlocks AI triage + report synthesis
python3 scripts/vet_payloads.py --fetch      # builds the vetted payload store
```

Without the API key, passive recon, scanning, and rule-based detection all still
work — only the AI triage and narrative report synthesis are unavailable.

---

## 5. Verifying the move actually worked

Do not trust "it installed". Check these four:

```bash
easyhunt doctor                    # 1. expect ~60/64 tools, 0 broken
```

```bash
.venv/bin/python -m pytest -q      # 2. expect 601 passed
```

```bash
# 3. sandbox is genuinely containerised, not silently falling back to the host
.venv/bin/python -c "
import tempfile; from pathlib import Path
from easyhunt.control_plane.sandbox import Sandbox, SandboxConfig
from easyhunt.config import Config
cfg = Config.load()
sb = Sandbox(SandboxConfig.from_dict(cfg.section('sandbox')),
             workspace=Path(tempfile.mkdtemp()), user_agent='x')
print('runtime:', sb.runtime_available(), '| mode:', sb.config.mode)
for t in ('nuclei','httpx','subfinder','katana','naabu','dalfox','trufflehog','semgrep','prowler'):
    i = sb.image_for(t)
    print(f'  {t:11} {\"PRESENT\" if sb.image_present(i) else \"MISSING\"}')
"
```

```bash
systemctl is-enabled docker        # 4. expect: enabled (survives reboot)
```

`doctor` reporting `✓ sandbox: docker` is the one that matters most — if it says
anything else, tools are running on the host with no isolation.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker.service is masked` | Kali ships it masked. | `systemctl unmask docker.service docker.socket` |
| `failed to start daemon ... PID N is still running` | Stale pidfile from a manually-started daemon. | `rm -f /var/run/docker.pid; systemctl reset-failed docker.service; systemctl start docker` |
| `Start request repeated too quickly` | systemd rate-limited after repeated failures. | `systemctl reset-failed docker.service` then start. |
| Tool installed but `doctor` says missing | PATH ordering, or a stale wrapper pointing at a deleted venv. | `source ~/.profile`; then `easyhunt doctor --fix` |
| `externally-managed-environment` from pip | Debian PEP 668. | Expected — the installer gives each cloned tool its own venv. Do not `--break-system-packages`. |
| FastMCP client import errors | `fastmcp-slim` displaced it. | `.venv/bin/pip install --force-reinstall fastmcp==3.4.5` |
| `httpx` resolves to the wrong binary | Python's `httpx` CLI shadows ProjectDiscovery's. | Already handled by `resolve_binary()`. **Do not uninstall the user's Python httpx.** |
| A test fails asserting a tool is absent | Test encoded an environment assumption. | Simulate absence with monkeypatch instead — see `tests/test_llmsec.py`. |

---

## 7. What to hand over with the folder

Everything needed is in the project directory. Nothing lives outside it except:

- `~/.claude/skills/` — deployed by `install.sh` from `skills/`, regenerated on
  the new machine.
- MCP registration — re-done by `install.sh`.
- `$OPENROUTER_API_KEY` — a secret; move it yourself, do not put it in the folder.
- `payloads/` — gitignored, rebuilt with one command (§4). Not redistributed
  because the upstream repo declares no license.

**Do not copy `scope.yaml` between engagements.** Each engagement gets its own,
re-pulled from the program's policy page at the time you run it.

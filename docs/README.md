# Cordon AI — documentation index

Start with **`../CLAUDE.md`** (project root). Claude CLI loads it automatically
at session start; a human should read it first too. It carries the hard
invariants, and those govern everything else here.

## The documents

| Document | Answers |
|---|---|
| [`../CLAUDE.md`](../CLAUDE.md) | What am I, what may I do, what will bite me? Loaded automatically. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | *Why* the system is shaped this way: where the security boundary sits and why, and how untrusted scanner output is defended against. The mechanics are in `USERMANUAL.md` §5–8. |
| [`BOOTSTRAP.md`](BOOTSTRAP.md) | How do I set up a new machine? Requirements, steps, verification, troubleshooting. |
| [`PAYLOADS.md`](PAYLOADS.md) | The vetted payload store — tiers, quarantine, tool mapping, licensing, and an honest note on scale. |
| [`../USERMANUAL.md`](../USERMANUAL.md) | The complete reference: install, configuration, provider API keys, how the modules interlink, running an engagement, troubleshooting. |
| [`../tools.md`](../tools.md) | Every tool: flags, when to reach for it, what it costs. |
| [`../HANDOFF.md`](../HANDOFF.md) | Picking this up cold: what exists, what is measured, what is left to build. |
| [`../README.md`](../README.md) | Project overview, install, extending, cost control. |

## Executables

| Path | Purpose |
|---|---|
| `../bootstrap.sh` | Bare-metal setup: system packages, Docker, images. Idempotent. |
| `../install.sh` | Application setup: package, tools, skills, MCP. Called by bootstrap. |
| `../scripts/vet_payloads.py` | Fetch, classify, and verify the third-party payload store. |

## Reading order for a fresh machine

1. `CLAUDE.md` — the invariants, first, before anything is run.
2. `BOOTSTRAP.md` — get it working.
3. `ARCHITECTURE.md` — understand *why* the boundary sits where it does, before changing it.
4. `USERMANUAL.md` / `tools.md` — reference, as needed.

## The one thing that blocks everything

`scope.yaml` must exist and must be transcribed from the target program's
**published policy page**. It does not ship with the repo, and it is not
something to generate, infer, or reuse from a previous engagement. That text is
the legal authorization for everything the tool does.

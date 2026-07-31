# EasyHunt AI — documentation index

Start with **`../CLAUDE.md`** (project root). Claude CLI loads it automatically
at session start; a human should read it first too. It carries the hard
invariants, and those govern everything else here.

## The documents

| Document | Answers |
|---|---|
| [`../CLAUDE.md`](../CLAUDE.md) | What am I, what may I do, what will bite me? Loaded automatically. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How is it built? Mind map, control-plane sequence, engagement flow, module map, why the security boundary sits where it does. |
| [`BUILD_STATUS.md`](BUILD_STATUS.md) | How far along is it? What works, what does not, what is left, which traps are already fixed. |
| [`BOOTSTRAP.md`](BOOTSTRAP.md) | How do I set up a new machine? Requirements, steps, verification, troubleshooting. |
| [`PAYLOADS.md`](PAYLOADS.md) | The vetted payload store — tiers, quarantine, tool mapping, licensing, and an honest note on scale. |
| [`../tools.md`](../tools.md) | Every tool: flags, when to reach for it, what it costs. 1,206 lines. |
| [`../USER_GUIDE.md`](../USER_GUIDE.md) | Day-to-day operation, configuration, tool categories. 1,086 lines. |
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
3. `BUILD_STATUS.md` — know what is actually done and what is not.
4. `ARCHITECTURE.md` — understand the flow before changing anything.
5. `tools.md` / `USER_GUIDE.md` — reference, as needed.

## The one thing that blocks everything

`scope.yaml` must exist and must be transcribed from the target program's
**published policy page**. It does not ship with the repo, and it is not
something to generate, infer, or reuse from a previous engagement. That text is
the legal authorization for everything the tool does.

# EasyHunt AI — Architecture

**Why the system is shaped this way.** The *what* — the layer diagram, the
control-plane sequence, the engagement pipeline, the module-by-module map —
lives in [`USERMANUAL.md`](../USERMANUAL.md) sections 5 to 8, and this file
used to carry a second copy that drifted. Read that first if you want the
mechanics; read this before changing them.

The one-paragraph version: EasyHunt is a **control plane wrapped around a
catalogue of open-source security tools**. The model decides *what* to test.
The MCP server decides *whether that is allowed* and enforces it in code. The
engines do the work inside a sandbox. Every call is audited. The security
properties live in the server, never in the prompt — because a prompt can be
talked out of its instructions and a function call cannot.

![The five layers, and where the security boundary sits](easyhunt-layers.svg)

---

## 1. Why the boundary sits where it does

The single most important design decision: **the MCP server is the security
boundary, not the model.**

A model can be argued with. It can be prompt-injected by a page it scrapes, a
JS file it reads, or a scanner banner it parses. If the scope check lived in the
system prompt, a crafted HTTP response could talk it into scanning a host it
was told not to touch.

So scope, rate limiting, sanitization, and approval are **functions that run
before the subprocess spawns**, and they do not consult the model. The model's
role is to choose well within a space that is already bounded. When it chooses
badly, the boundary holds.

This also means the correct response to `scope_denied` is to stop — not to find
another route. Any feature whose purpose is to work around the boundary is
refused by policy, no matter who asks.

---

## 2. Defense against untrusted input

Scanner output is attacker-influenced data. A page title, a JS comment, or an
HTTP header can carry text designed to hijack the model reading it.

- `_defang()` in `tools/base.py` strips prompt-injection patterns from tool output
  before it reaches the model.
- Triage uses **canary tokens** — if a canary appears in model output, the
  content hijacked the reasoning and the result is discarded.
- Third-party templates and payload lists are **pinned by commit SHA** and vetted
  before use (`control_plane/pins.py`, `docs/PAYLOADS.md`).
- Secrets are masked in *both* the `masked` field and the surrounding `context`
  field — an earlier version leaked full credentials in the context while
  dutifully masking the value.

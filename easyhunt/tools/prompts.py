"""Prompt-pack lookup as MCP tools.

The prompt packs in :mod:`easyhunt.knowledge.prompts` are the protocol for
LLM-mode testing of classes no scanner owns: the role, objective, scope (with
explicit denies), success criteria and evidence format a human expert would
apply. These tools expose them read-only — the caller gets instructions, and
the only thing that can act on them is the agent or human driving the session.

Nothing here sends a request. ``exploit_prompt`` and ``prompt_classes`` are
pure lookups, mirroring ``waf_bypass`` and ``technique_lookup``: knowledge the
agent can consult, not engines it can point at a target.
"""

from __future__ import annotations

from typing import Any

from easyhunt.knowledge import prompts
from easyhunt.tools.base import easyhunt_tool

__all__ = ["exploit_prompt", "prompt_classes"]


@easyhunt_tool(
    phase="exploit",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="exploit_prompt",
    tags={"knowledge", "prompts"},
    estimated_requests=0,
    budget_exempt=True,
    rationale=(
        "Fetch the per-class exploit/validation prompt pack — role, objective, "
        "scope, success criteria, evidence format — for LLM-mode testing of "
        "classes no scanner owns. Read-only knowledge; nothing is sent."
    ),
)
async def exploit_prompt(bug_class: str) -> dict[str, Any]:
    """The prompt pack for one vulnerability class.

    ``bug_class`` is one of: sqli, nosqli, xss, ssti, ssrf, cmdi, lfi, redirect,
    auth, authz, business_logic, cache_poisoning, race_condition, takeover,
    deserialization, file_upload, graphql, injection.

    The pack names the role, objective, scope (including what is *not* allowed),
    the success criteria a candidate must meet before it may be called a
    finding, and the evidence fields a reproducible PoC must fill. Use it before
    driving a live test or writing up a candidate: a finding that cannot fill
    the evidence fields is a lead, not a finding.
    """
    pack = prompts.get_prompt_pack(bug_class)
    if pack is None:
        return {
            "ok": False,
            "error": "unknown_class",
            "message": (
                f"{bug_class!r} is not a known class; known: "
                + ", ".join(prompts.prompt_pack_classes())
            ),
        }
    return {
        "ok": True,
        "bug_class": bug_class.strip().lower(),
        **pack,
        "note": (
            "Instructions only — nothing here sends a request. Live testing "
            "stays behind the exploit gate; a finding must fill every "
            "evidence_format field to be confirmed."
        ),
    }


@easyhunt_tool(
    phase="exploit",
    mode="passive",
    targets_arg=None,
    timeout=30,
    name="prompt_classes",
    tags={"knowledge", "prompts"},
    estimated_requests=0,
    budget_exempt=True,
    rationale=(
        "List the classes that have a prompt pack — discovery for the agent "
        "deciding which protocol applies to the endpoint it is looking at."
    ),
)
async def prompt_classes() -> dict[str, Any]:
    """List the vulnerability classes that have an exploit/validation prompt pack."""
    classes = prompts.prompt_pack_classes()
    return {
        "ok": True,
        "count": len(classes),
        "classes": classes,
        "note": (
            "Fetch a pack with exploit_prompt(bug_class=...) before driving a "
            "live test or writing up a candidate."
        ),
    }

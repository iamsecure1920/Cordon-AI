"""Research advisor: turn a candidate into a concrete testing playbook.

This is the tool that answers \\"the pipeline found something / scanned clean,
what do I do next\\" — the decision layer the user keeps asking for. Given a
vulnerability class (and optionally the asset, evidence, and observed stack),
``research_guidance`` assembles everything EasyHunt already knows into one
actionable answer:

* the **brain's learned experience** for this class on this shape of target
  (what actually paid off before, from :mod:`easyhunt.knowledge.neuron`),
* the **technique index** entry (PAT-derived payloads, tools, bypasses),
* **which validators to run next** (from the coverage matrix — the exact
  wrapper names, so the answer is directly actionable through MCP),
* WAF context when one was observed,
* an **evidence checklist** per class (what a submittable report needs), and
* **canonical resources** (PayloadsAllTheThings, PortSwigger, OWASP) for a
  human or an LLM to study before exploitation.

When the engagement has an LLM enabled, the advisor also asks it for a
step-by-step testing/exploitation plan *grounded in* the knowledge above —
never from a blank page. When the LLM is off, the knowledge playbook is the
answer (EasyHunt's own strategy layer is a model and reads it directly).

``guided_validate`` closes the loop the playbook opens: it assembles the same
knowledge, then *executes* the validators the playbook names against the asset
— the advisor says \\"run sqli_validate next\\", the chain does. Every dispatched
validator is independently approval-gated, so guidance never becomes an
unapproved action. Sends no traffic itself; the validators it drives do.
"""

from __future__ import annotations

import json
import re
from typing import Any

from easyhunt.control_plane.context import get_engagement
from easyhunt.knowledge import waf
from easyhunt.knowledge.coverage import COVERAGE
from easyhunt.knowledge.techniques import load_index
from easyhunt.tools.base import easyhunt_tool

__all__ = ["research_guidance", "guided_validate"]

#: Fuzzy class-name normalization: "sql injection" / "sqli" -> "sql-injection".
_CLASS_ALIASES = {
    "sqli": "sql-injection",
    "sql": "sql-injection",
    "xss": "xss-injection",
    "cross-site scripting": "xss-injection",
    "ssrf": "server-side-request-forgery",
    "ssti": "server-side-template-injection",
    "template injection": "server-side-template-injection",
    "cmdi": "command-injection",
    "command injection": "command-injection",
    "rce": "command-injection",
    "nosqli": "nosql-injection",
    "smuggling": "request-smuggling",
    "http request smuggling": "request-smuggling",
    "takeover": "subdomain-takeover",
    "subdomain takeover": "subdomain-takeover",
    "open redirect": "open-redirect",
    "lfi": "file-inclusion",
    "rfi": "file-inclusion",
    "xxe": "xxe-injection",
    "xml external entity": "xxe-injection",
    "crlf": "crlf-injection",
    "header injection": "crlf-injection",
    "jwt": "json-web-token",
    "graphql": "graphql-injection",
    "websocket": "web-sockets",
    "web socket": "web-sockets",
    "cors": "cors-misconfiguration",
    "idor": "insecure-direct-object-references",
    "mass assignment": "mass-assignment",
    "race condition": "race-condition",
    "cache poisoning": "web-cache-deception",
    "hpp": "http-parameter-pollution",
    "parameter pollution": "http-parameter-pollution",
    "file upload": "upload-insecure-files",
    "deserialization": "insecure-deserialization",
    "csrf": "cross-site-request-forgery",
    "path traversal": "file-inclusion",
    "traversal": "file-inclusion",
}

#: WAF bypass table keys (knowledge/waf.py) that map to coverage classes.
_WAF_CLASS_MAP = {
    "sql-injection": "sqli",
    "xss-injection": "xss",
    "command-injection": "cmdi",
    "server-side-template-injection": "ssti",
    "server-side-request-forgery": "ssrf",
    "file-inclusion": "path_traversal",  # path traversal lives under file inclusion
}

#: Coverage class -> ``web_injection_probe`` bug_class values (that probe takes
#: a different vocabulary than the coverage matrix).
_WEB_INJECTION_CLASS = {
    "xxe-injection": "xxe",
    "crlf-injection": "crlf",
    "file-inclusion": "lfi",
    "open-redirect": "open-redirect",
    "http-parameter-pollution": "hpp",
}

#: What a submittable report needs for each class. Baseline entries are
#: inherited by every class.
_EVIDENCE_BASELINE = [
    "exact request/response pair that proves it",
    "the payload as sent (so a triager can replay it)",
    "why this is a vulnerability, not a feature (impact)",
    "CVSS 3.1 vector + severity",
    "remediation advice",
]
_EVIDENCE: dict[str, list[str]] = {
    "sql-injection": [
        "DB banner or error output, or a measured time delta for blind",
        "confirm it reads/writes data you are authorized to test",
    ],
    "xss-injection": [
        "execution context (which browser, where the payload fires)",
        "a screenshot or alert() capture; note cookies/flags",
    ],
    "server-side-request-forgery": [
        "the internal endpoint reached or the OOB (interactsh) callback",
        "response of the internal resource if readable",
    ],
    "server-side-template-injection": [
        "engine identified (test with polyglot) and the payload that rendered",
        "read/write access demonstrated, or command execution if RCE",
    ],
    "command-injection": ["command output or OOB callback; which parameter and which shell"],
    "nosql-injection": ["operator-based payload and the altered query result"],
    "request-smuggling": ["the exact CL/TE discrepancy and the poisoned second request"],
    "open-redirect": ["destination URL; chain to OAuth token theft if you can"],
    "file-inclusion": ["file read proof (e.g. /etc/passwd excerpt) or LFI-to-RCE chain"],
    "xxe-injection": ["external entity resolved, ideally to a file you control or OOB"],
    "crlf-injection": ["injected header reaching the client (cache poisoning if you can chain it)"],
    "json-web-token": ["algorithm confusion / signature stripping proof, or the decoded token"],
    "graphql-injection": ["introspection-enabled proof or the query that leaks data"],
    "cors-misconfiguration": ["the exact Origin echoed and the sensitive response it can exfil"],
    "subdomain-takeover": ["dangling CNAME, the claimable-service fingerprint, and a harmless PoC"],
    "insecure-direct-object-references": [
        "two accounts, the object ID you accessed, and the data returned"
    ],
    "upload-insecure-files": [
        "the uploaded file's content type and whether the server executes it"
    ],
    "cross-site-request-forgery": [
        "the state-changing request replayed cross-origin, and the missing/weak token"
    ],
    "web-cache-deception": ["the cached authenticated response and the cache key that admitted it"],
    "business-logic-errors": ["the two-step flow and the step skipped or reordered"],
}

#: Canonical study resources per class — PAT tree folder, PortSwigger topic.
_RESOURCES: dict[str, tuple[str, str]] = {
    "sql-injection": ("SQL Injection", "sql-injection"),
    "xss-injection": ("XSS Injection", "cross-site-scripting"),
    "server-side-request-forgery": ("Server Side Request Forgery", "server-side-request-forgery"),
    "server-side-template-injection": (
        "Server Side Template Injection",
        "server-side-template-injection",
    ),
    "command-injection": ("Command Injection", "os-command-injection"),
    "nosql-injection": ("NoSQL Injection", "nosql-injection"),
    "request-smuggling": ("HTTP Request Smuggling", "request-smuggling"),
    "subdomain-takeover": ("Subdomain Takeover", "subdomain-takeover"),
    "open-redirect": ("Open Redirect", "open-redirect"),
    "file-inclusion": ("File Inclusion", "file-path-traversal"),
    "xxe-injection": ("XXE Injection", "xxe"),
    "crlf-injection": ("CRLF Injection", "request-smuggling"),
    "json-web-token": ("JWT", "json-web-token"),
    "graphql-injection": ("GraphQL Injection", "graphql"),
    "cors-misconfiguration": ("CORS Misconfiguration", "cross-origin-resource-sharing"),
    "insecure-direct-object-references": ("IDOR", "access-control"),
    "http-parameter-pollution": ("HTTP Parameter Pollution", "business-logic"),
    "web-cache-deception": ("Web Cache Deception", "web-cache-deception"),
    "race-condition": ("Race Condition", "race-conditions"),
    "upload-insecure-files": ("File Upload", "file-upload"),
    "insecure-deserialization": ("Insecure Deserialization", "insecure-deserialization"),
    "cross-site-request-forgery": ("CSRF Injection", "cross-site-request-forgery"),
    "web-sockets": ("WebSockets", "websockets"),
    "business-logic-errors": ("Business Logic Errors", "business-logic"),
}
_PAT_BASE = "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master"
_PS_BASE = "https://portswigger.net/web-security"


def _normalize_class(vuln_class: str) -> str | None:
    key = vuln_class.strip().lower()
    if key in _CLASS_ALIASES:
        return _CLASS_ALIASES[key]
    for row in COVERAGE:
        if row["class"] == key or row["title"].lower() == key:
            return row["class"]
    # loose: drop non-alphanumerics and compare
    flat = re.sub(r"[^a-z0-9]", "", key)
    for alias, canon in _CLASS_ALIASES.items():
        if re.sub(r"[^a-z0-9]", "", alias) == flat:
            return canon
    for row in COVERAGE:
        if re.sub(r"[^a-z0-9]", "", row["class"]) == flat:
            return row["class"]
    return None


def _coverage_row(class_name: str) -> dict[str, Any] | None:
    for row in COVERAGE:
        if row["class"] == class_name:
            return row
    return None


def _stack_tokens(stack: str) -> list[str]:
    return [t.strip() for t in (stack or "").split(",") if t.strip()][:12]


def _known_classes() -> list[str]:
    return [r["class"] for r in COVERAGE] + sorted(_CLASS_ALIASES)


def _assemble_playbook(
    vuln_class: str,
    asset: str = "",
    evidence: str = "",
    stack: str = "",
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Build the knowledge playbook for a class. ``(knowledge, error)``.

    Pure knowledge assembly shared by ``research_guidance`` (adds an LLM plan)
    and ``guided_validate`` (executes the named validators). Returns
    ``(None, error_dict)`` for an out-of-scope asset or an unknown class —
    callers surface the error unchanged.
    """
    engagement = get_engagement()
    class_name = _normalize_class(vuln_class)

    # If the caller named an asset that is out of scope, say so rather than
    # producing a playbook for a target the engagement cannot touch.
    if asset:
        try:
            engagement.scope.assert_all_in_scope([asset])
        except Exception:
            return None, {
                "ok": False,
                "error": "out_of_scope",
                "message": f"{asset} is not in scope — no playbook for out-of-scope assets.",
            }

    if class_name is None:
        return None, {
            "ok": False,
            "error": "unknown_class",
            "message": f"'{vuln_class}' is not a known class.",
            "known": _known_classes(),
        }

    techs = _stack_tokens(stack) or [str(t) for t in engagement.assets.values("technology")][:12]
    # WAF vendors surface as technology assets (httpx tech-detect reports
    # "Cloudflare", "Amazon CloudFront", …). Match them against the known
    # vendor table so the playbook can include vendor-tailored bypass payloads.
    known_waf = {str(k).lower() for k in waf.VENDOR_ALIASES} | {
        str(k).lower() for k in waf.WAF_BYPASSES
    }
    waf_vendors = []
    for t in techs:
        low = t.lower()
        if not (any(k in low for k in known_waf) or "waf" in low):
            continue
        canon = waf._normalize_vendor(low)
        if canon and canon not in waf_vendors:
            waf_vendors.append(canon)
        if len(waf_vendors) >= 3:
            break

    # 1. The brain's learned experience for this class on this stack.
    learned = engagement.brain.recall(
        vuln_class=class_name,
        technologies=techs,
        waf_vendors=waf_vendors,
        limit=8,
    )

    # 2. The technique index (PAT-derived) for the class.
    index = load_index()
    technique = index.get(class_name) if index.available else None

    # 3. Coverage matrix row — the exact validator/gf wiring.
    row = _coverage_row(class_name)
    validator = str(row["validation"]) if row else ""
    detection = str(row["detection"]) if row else ""
    gf_patterns = (row.get("gf") or []) if row else []

    # 4. WAF bypass payloads when a vendor is observed.
    waf_payloads: list[dict[str, Any]] = []
    waf_key = _WAF_CLASS_MAP.get(class_name)
    if waf_key and waf_vendors:
        for vendor in waf_vendors:
            waf_payloads.extend(waf.bypass_payloads(vendor, waf_key, "all", max_payloads=12))

    # 5. Evidence checklist.
    evidence_checklist = _EVIDENCE_BASELINE + _EVIDENCE.get(class_name, [])

    # 6. Resources.
    pat_folder, ps_topic = _RESOURCES.get(class_name, (class_name.replace("-", " ").title(), ""))
    resources = [
        f"{_PAT_BASE}/{pat_folder}",
        f"https://owasp.org/www-community/attacks/{pat_folder.replace(' ', '_')}",
    ]
    if ps_topic:
        resources.append(f"{_PS_BASE}/{ps_topic}")

    knowledge = {
        "class": class_name,
        "title": row["title"] if row else class_name,
        "asset": asset or None,
        "evidence_so_far": evidence or None,
        "stack": techs,
        "learned": [
            {
                "technique": item.get("technique"),
                "weight": round(float(item.get("weight") or 0), 2),
                "trials": item.get("trials"),
                "confidence": item.get("confidence"),
            }
            for item in learned
        ],
        "validators": {
            "run_next": [v.strip() for v in validator.split(",") if v.strip()],
            "detection": detection,
            "gf_patterns": gf_patterns,
        },
        "technique_index": (
            {
                "title": technique.get("title"),
                "summary": (technique.get("summary") or "")[:400],
                "tools": technique.get("tools", []),
                "payloads": (technique.get("payloads") or [])[:10],
                "keywords": (technique.get("keywords") or [])[:10],
            }
            if technique
            else None
        ),
        "waf_bypass_payloads": waf_payloads[:12],
        "evidence_checklist": evidence_checklist,
        "resources": resources,
    }
    return knowledge, None


def _validator_names(run_next: list[str]) -> list[str]:
    """Extract registry tool names from coverage ``validation`` strings.

    Handles notes and combinations: ``"sqli_validate (sqlmap)"`` →
    ``["sqli_validate"]``; ``"takeover_verify + takeover_confirm (subzy)"`` →
    ``["takeover_verify", "takeover_confirm"]``; ``"manual — no scanner"`` and
    ``"none — no validator"`` → ``[]`` (no tool name).
    """
    names: list[str] = []
    for item in run_next:
        # Strip parenthetical notes FIRST — they contain commas of their own
        # ("xss_validate (dalfox, xsstrike)"), so splitting on commas before
        # stripping would carve the note in half and lose the tool name.
        cleaned = re.sub(r"\s*\([^)]*\)", "", item)
        for part in re.split(r"[,\+]", cleaned):
            part = part.strip()
            match = re.match(r"^([a-z][a-z0-9_]*)$", part)
            if match:
                name = match.group(1)
                if name not in names:
                    names.append(name)
    return names


@easyhunt_tool(
    phase="method",
    mode="passive",
    targets_arg=None,
    timeout=180,
    name="research_guidance",
    tags={"strategy", "knowledge", "llm"},
    estimated_requests=0,
    budget_exempt=True,
    text_args=("evidence", "stack"),
    rationale=(
        "Turn a candidate finding (or a class you are about to test) into a "
        "concrete playbook: what to run next, which payloads, what evidence to "
        "collect — grounded in the brain's learned experience, the technique "
        "index, and the coverage matrix."
    ),
)
async def research_guidance(
    vuln_class: str,
    asset: str = "",
    evidence: str = "",
    stack: str = "",
) -> dict[str, Any]:
    """Research a vulnerability class and produce an actionable testing playbook.

    ``vuln_class`` is a bug class (\\"sql-injection\\", \\"xss\\", \\"ssrf\\", \\"idor\\",
    \\"request-smuggling\\", … — fuzzy names work). ``asset`` is the URL under
    test, ``evidence`` any observation so far (a 403, a parameter, a scanner
    hit), ``stack`` the observed technologies (comma-separated) to scope the
    brain's memory recall. Read-only: assembles knowledge, sends no traffic.
    To *execute* the validators it names, call ``guided_validate`` instead.
    """
    knowledge, error = _assemble_playbook(vuln_class, asset, evidence, stack)
    if error is not None:
        return error
    assert knowledge is not None  # noqa: S101 — error is None means knowledge

    engagement = get_engagement()
    class_name = knowledge["class"]

    # LLM mode: ask the model to turn the knowledge into a step plan. The
    # knowledge is passed in so the answer is grounded, never from a blank page.
    from easyhunt.llm.openrouter import LLMClient

    client = LLMClient(engagement)
    if not client.enabled:
        return {
            "ok": True,
            "mode": "agent",
            **knowledge,
            "note": (
                "No internal LLM configured — this playbook is the knowledge. "
                "The strategy agent (you) reads it and drives the validators."
            ),
        }

    try:
        response = await client.complete(
            [
                {"role": "system", "content": _SYSTEM},
                {
                    "role": "user",
                    "content": (
                        "Class: {class_name}\nAsset: {asset or '-'}\n"
                        "Evidence so far: {evidence or '-'}\n\nKnowledge:\n"
                        + json.dumps(knowledge, indent=1)[:18000]
                    ).format(class_name=class_name, asset=asset, evidence=evidence),
                },
            ],
            tier="t2",
            phase="method",
            purpose="research_guidance",
            json_mode=True,
            temperature=0.3,
        )
    except Exception:  # noqa: BLE001 — LLM failure must not sink the playbook
        return {
            "ok": True,
            "mode": "knowledge",
            **knowledge,
            "note": "LLM plan unavailable — knowledge playbook returned.",
        }

    try:
        plan = json.loads(response.text)
    except (json.JSONDecodeError, AttributeError):
        plan = {}

    steps = plan.get("steps") or []
    return {
        "ok": True,
        "mode": "llm",
        **knowledge,
        "llm_plan": {
            "strategy": plan.get("strategy", ""),
            "steps": steps[:10],
            "note": (
                "Ground truth is the knowledge fields above; the model's steps "
                "are a reading of them. Run the named validators and collect "
                "the evidence checklist."
            ),
        },
    }


@easyhunt_tool(
    phase="exploit",
    mode="aggressive",
    targets_arg="asset",
    timeout=1800,
    name="guided_validate",
    tags={"strategy", "knowledge", "validation", "chain"},
    estimated_requests=500,
    rationale=(
        "Close the research loop: assemble the playbook for a class, then "
        "EXECUTE the validators the playbook names against the asset. The "
        "advisor says 'run sqli_validate next' — this chain actually runs it. "
        "Each dispatched validator is independently approval-gated."
    ),
    risk_notes=(
        "Dispatches the class's auto-validators at the asset (sqlmap, dalfox, "
        "commix, sstimap, ssrfmap, nosqli, smuggler, web_injection_probe, "
        "cors/tls/graphql audit as applicable) — each is individually "
        "approval-gated and carries its own risk notes; guided_validate in "
        "auto_approve does not approve the validators it drives. Detection "
        "only: every validator's data-access flags stay denied on the tools.",
    ),
    text_args=("evidence", "stack"),
)
async def guided_validate(
    vuln_class: str,
    asset: str,
    evidence: str = "",
    stack: str = "",
    limit: int = 3,
) -> dict[str, Any]:
    """Run the validators the research playbook names for a class, on an asset.

    ``vuln_class`` (fuzzy names work) and ``asset`` (a URL in scope) are the
    same inputs ``research_guidance`` takes; this tool goes one step further and
    executes the validators the coverage matrix wires to the class, capped at
    ``limit`` tools. Classes whose validation row is ``manual``/``none`` return
    the evidence checklist instead of dispatching anything — the honest answer
    is \\"no scanner owns this\\", and the checklist is what a report needs.

    Every dispatched validator goes through the control plane again (scope,
    rate, budget, approval) — guidance never becomes an unapproved action.
    Returns the playbook plus a per-validator outcome summary; validators that
    prove something file their own findings.
    """
    knowledge, error = _assemble_playbook(vuln_class, asset, evidence, stack)
    if error is not None:
        return error
    assert knowledge is not None  # noqa: S101 — error is None means knowledge

    try:
        limit = max(1, min(int(limit), 8))
    except (TypeError, ValueError):
        limit = 3

    from easyhunt.mcp_server import load_capabilities
    from easyhunt.tools.base import REGISTRY

    load_capabilities()

    class_name = knowledge["class"]
    run_next = knowledge["validators"]["run_next"]
    names = _validator_names(
        run_next
    )  # Only tools that take a single URL-ish target are dispatchable here
    # (sqli_validate(target=...), cors_audit(url=...), ...). authz_compare needs
    # two identities, jwt_inspect needs a token, secret_validate a secret —
    # those stay as guidance, not dispatch.
    dispatchable = [
        n for n in names if n in REGISTRY and REGISTRY[n].targets_arg in {"target", "url", "asset"}
    ]
    skipped = [n for n in names if n not in dispatchable]
    # Rows that parse to NO tool name ("manual — …", "none — …") are also
    # reported, trimmed to their first line, so the answer is never an empty
    # silence: the class has no auto-validator and the checklist is the proof.
    skipped += [item.strip()[:80] for item in run_next if not _validator_names([item])]

    engagement = get_engagement()
    outcomes: list[dict[str, Any]] = []
    proven_any = False
    for name in dispatchable[:limit]:
        kwargs: dict[str, Any] = {}
        if name == "web_injection_probe":
            # The probe needs a bug_class and a parameter; the coverage row
            # names the class. Use the first query parameter of the asset, or
            # a neutral default — detection-only either way.
            from urllib.parse import parse_qs, urlsplit

            params = parse_qs(urlsplit(asset).query)
            bug_class = _WEB_INJECTION_CLASS.get(class_name)
            if bug_class is None:
                skipped.append(name)
                continue
            first_param = next(iter(params), "q")
            kwargs = {"parameter": first_param, "bug_class": bug_class}
        try:
            out = await REGISTRY[name].fn(target=asset, **kwargs)
            outcome: dict[str, Any] = {
                "tool": name,
                "ok": bool(out.get("ok")) if isinstance(out, dict) else False,
                "error": out.get("error") if isinstance(out, dict) else None,
                "count": out.get("count", 0) if isinstance(out, dict) else 0,
                "proven": bool(out.get("proven")) if isinstance(out, dict) else False,
                "observed": (out.get("observed") or "")[:300] if isinstance(out, dict) else "",
                "findings": len(out.get("findings") or []) if isinstance(out, dict) else 0,
            }
        except Exception as exc:  # noqa: BLE001 — one bad validator must not sink the chain
            outcome = {
                "tool": name,
                "ok": False,
                "error": str(exc)[:200],
                "count": 0,
                "proven": False,
                "observed": "",
                "findings": 0,
            }
        if outcome.get("proven") or outcome.get("count"):
            proven_any = True
        outcomes.append(outcome)

    # Brain + ledger learn from the dispatch regardless of outcome.
    techs = knowledge["stack"]
    engagement.brain.learn(
        vuln_class=class_name,
        technique="guided_validate",
        outcome="hit" if proven_any else "clean",
        technologies=techs,
        engagement=engagement.scope.name,
    )
    coverage = getattr(engagement, "coverage", None)
    if coverage is not None:
        coverage.record(
            class_name,
            "detected" if proven_any else ("validated" if outcomes else "not_attempted"),
            tool="guided_validate",
            note=f"dispatched {len(outcomes)} validator(s) on {asset}",
        )

    return {
        "ok": True,
        **{
            k: knowledge[k]
            for k in ("class", "title", "asset", "evidence_checklist", "waf_bypass_payloads")
        },
        "dispatch": {
            "ran": outcomes,
            "skipped": skipped,
            "note": (
                "Skipped tools either have no single-URL entry point "
                "(authz_compare, jwt_inspect, secret_validate) or the coverage "
                "row names a manual/none validation — the evidence checklist is "
                "the answer there."
            ),
        },
        "proven": proven_any,
        "count": len(outcomes),
        "note": (
            "Validators ran with their own approval gates and filed their own "
            "findings; the evidence checklist above is what a submittable "
            "report must carry."
        ),
    }


_SYSTEM = """You are the research director of an authorized penetration test.
Given a vulnerability class and the assembled knowledge (learned techniques,
validator wiring, payload sets, evidence checklist, resources), produce a
step-by-step testing plan as JSON:
{"strategy": "one-paragraph approach", "steps": [{"step": N, "action": "...",
"tool_or_technique": "...", "expected_evidence": "..."}]}
Rules:
- Only use the validators and techniques named in the knowledge; never invent
  tools the engagement does not have.
- Order by cheapest-first (passive -> active -> exploitation).
- Name the evidence each step must produce (a report needs proof, not noise).
- If exploitation is involved, it must be non-destructive and reversible.
- Return ONLY the JSON object, nothing else."""

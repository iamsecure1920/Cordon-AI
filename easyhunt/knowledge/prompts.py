"""Per-class exploit and validation prompt packs for LLM-mode testing.

The tool's validators answer "is this parameter injectable" with a scanner.
The classes no scanner owns — IDOR, business logic, race conditions, cache
poisoning — have no binary that proves them; they need a human's judgement
(or an LLM standing in for one) and a *protocol* for what counts as proof.
That protocol is what this module stores.

Structure is distilled from shannon (KeygraphHQ, AGPL-3.0) and reimplemented
here AGPL-clean: each pack names the role the tester plays, the objective, the
**scope** — including the explicit deny list, which is the reimplementation of
shannon's cross-cutting path-deny — the success criteria a candidate must meet
before it may be called a finding, and the evidence format the report must be
able to reproduce from. The evidence format is "No PoC, no finding" written as
fields: a finding that cannot fill them is not a finding.

Consumers are read-only (the ``exploit_prompt`` tool) or LLM-mode sessions.
Nothing here sends a request; the packs are instructions, not payloads.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PROMPT_PACKS",
    "get_prompt_pack",
    "prompt_pack_classes",
    "EVIDENCE_FIELDS",
]

#: Fields a reproducible PoC must fill, for every class. This is the invariant
#: "No PoC, no finding" expressed as a data structure: anything filed as
#: CONFIRMED must be reproducible from these four values.
EVIDENCE_FIELDS = [
    "asset",
    "exact_request",
    "exact_response",
    "reproduction_steps",
]

#: Cross-cutting deny patterns, applied to every pack regardless of class. A
#: tester that trips one of these is outside the proof, and the run stops.
#: Reimplementation of shannon's code-path deny as plain text rules.
_UNIVERSAL_DENY = [
    "No action outside the assets named in scope.yaml. A 'clever' detour to the "
    "same data through a different host is out of scope, not a bypass.",
    "No state-changing action beyond the minimal proof. No data extraction, no "
    "deletion, no fund movement, no account takeover beyond the single PoC account.",
    "No persistence, no privilege that survives the test, no lateral movement.",
    "No destructive or disruptive action: no DoS, no load testing, no "
    "stress-testing, no flooding a queue or exhausting a rate limit.",
    "No action against third parties: no out-of-band exfiltration, no callbacks "
    "that would hit another organization's infrastructure.",
    "Stop at the first proof. One reproducible reproduction is a finding; "
    "escalating an exploit to maximize impact is a violation of this pack.",
    "An unproven suspicion is 'needs manual review', never a finding. If the "
    "success criteria below cannot be met, file it as a lead and move on.",
]

#: Shared success criteria for scanner-driven classes: the scanner hit must be
#: hand-reproduced before it is called anything.
_SCANNER_REPRO = [
    "The candidate was produced by a scanner; a scanner output alone is not proof.",
    "The injection was replayed by hand (curl/httpx) and the differential "
    "(baseline vs injected) reproduced.",
    "The differential is attributable to the injected value, not to session, "
    "rate limiting, or a WAF block page.",
    "The finding is reproducible from the evidence fields, start to finish.",
]

#: Shared deny list for any class whose proof involves sending attack strings.
_ATTACK_DENY = [
    "Payloads prove execution only. Nothing is exfiltrated, no callback is made "
    "beyond the minimal proof (a benign marker the tester controls).",
    "No payload that touches other users' data, sessions, or accounts.",
]

#: The packs, keyed by canonical class name. ``pack_type`` is ``exploit`` (drive
#: a live test) or ``validate`` (confirm a candidate); every class gets a
#: validate pack, exploit packs exist where a live drive makes sense.
PROMPT_PACKS: dict[str, dict[str, Any]] = {
    "sqli": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "SQL injection",
        "role": (
            "Database-focussed penetration tester. You know how each DBMS "
            "behaves differently under the same payload, and you read error "
            "messages, timing deltas and boolean differentials as evidence."
        ),
        "objective": (
            "Confirm whether the parameter is injectable and — if it is — "
            "prove it with the smallest reproducible demonstration (boolean "
            "differential, time-based marker, or UNION column count). "
            "sqlmap is the primary engine; hand-verify its verdict."
        ),
        "scope": [
            "The parameter named by the caller, on the URL named by the caller.",
            "Detection and proof only: boolean, UNION count, or a time-based "
            "marker of a few seconds.",
            "WAF bypass payloads from the bypass tables only when the base pass "
            "was clean and the target is known to be behind that vendor.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No data extraction beyond proving the query executes: a version "
            "banner or a single-cell comparison is proof; dumping a table is not.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The DBMS name or a confirmed boolean/time differential appears in "
            "the replayed response.",
            "sqlmap's verdict agrees with the hand reproduction, or the hand "
            "reproduction is treated as the truth and the disagreement explained.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["dbms", "technique", "affected_parameter"],
        "reference_tools": ["sqli_validate", "web_injection_probe", "waf_bypass"],
    },
    "nosqli": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "NoSQL injection",
        "role": (
            "MongoDB/NoSQL-aware tester. You know operator injection ($ne, $gt, "
            "$where), JSON body injection and the JavaScript expression contexts."
        ),
        "objective": (
            "Confirm operator injection in JSON or URL parameters using nosqli, "
            "then hand-reproduce the authentication-bypass or boolean "
            "differential the operator produced."
        ),
        "scope": [
            "The named parameter or body field, on the named endpoint.",
            "Operator injection detection and auth-bypass proof with a benign "
            "comparison (e.g. password[$ne]=wrong).",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No $where payloads that execute code unless the objective "
            "explicitly requires an RCE proof.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The operator's effect (auth passed with a wrong value, or a "
            "differential response) reproduces by hand.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["operator", "affected_field"],
        "reference_tools": ["nosqli_probe"],
    },
    "xss": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "Cross-site scripting",
        "role": (
            "Client-side security tester. You reason about the injection "
            "context — HTML, attribute, script, URL — before choosing a payload."
        ),
        "objective": (
            "Confirm reflection and execution in the page's DOM using dalfox, "
            "then hand-reproduce with the smallest payload that fires in the "
            "confirmed context."
        ),
        "scope": [
            "The named URL and parameter.",
            "Proof of execution in the tester's own browser/session only.",
            "WAF-bypass payloads only when the base pass was blocked.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No payload that steals cookies, sessions, or data of other users. "
            "alert(1)/prompt(1) proves execution; that is the ceiling.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The payload fires in the tester's own browser (screenshot or "
            "console evidence), or the reflection is demonstrably unescaped in "
            "the exact context claimed.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["context", "payload", "browser_evidence"],
        "reference_tools": ["xss_validate", "waf_bypass"],
    },
    "ssti": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "Server-side template injection",
        "role": (
            "Template-engine specialist. You identify the engine (Jinja2, Twig, "
            "Freemarker, Velocity, ERB, Thymeleaf) from its polyglot response "
            "before escalating."
        ),
        "objective": (
            "Detect template evaluation with sstimap's benign probes (7*7), "
            "identify the engine, and confirm with the smallest arithmetic "
            "expression that renders evaluated."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Evaluation proof only: arithmetic or a read-only introspection "
            "expression (config, class hierarchy).",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No RCE proof unless the caller explicitly requests it and the "
            "engagement permits exploitation.",
            "No expression that touches the filesystem, network, or environment "
            "secrets.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The evaluated result (49 for 7*7) appears in the replayed response "
            "and not in the baseline.",
            "The engine is named, not guessed.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["engine", "expression", "evaluated_result"],
        "reference_tools": ["ssti_probe"],
    },
    "ssrf": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "Server-side request forgery",
        "role": (
            "Network-aware tester. You reason about the fetcher: does it follow "
            "redirects, which protocols does it allow, what is reachable from "
            "the server's network position."
        ),
        "objective": (
            "Confirm the server fetches attacker-controlled URLs using ssrfmap "
            "or a manual probe, and prove it with a benign callback the tester "
            "controls."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Proof via a tester-controlled endpoint: the server's request "
            "arrives (interactsh, a test listener) or a distinguishable "
            "response is fetched.",
            "Metadata-service probing only when the engagement's policy "
            "explicitly covers cloud metadata and the caller approves it.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No internal scan: enumerating the internal network through the "
            "vulnerability is a scan of infrastructure the program has not put "
            "in scope.",
            "No reading cloud credentials or secrets through the fetcher.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The tester-controlled endpoint received the server's request, or "
            "the server returned a response that only the attacker-chosen "
            "internal target could have produced.",
            "The repro does not depend on the target's own infrastructure "
            "responding.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["callback_received", "target_resolved"],
        "reference_tools": ["ssrf_probe", "interactsh"],
    },
    "cmdi": {
        "pack_type": "exploit",
        "phase": "exploit",
        "title": "Command injection",
        "role": (
            "OS-command tester. You know the shell separators, the quoting "
            "contexts, and how Windows differs from POSIX in each one."
        ),
        "objective": (
            "Confirm command execution with commix's detection pass, then "
            "hand-reproduce with the smallest benign command whose output is "
            "visible in the response (id, uname)."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Detection and output-visibility proof only.",
            "Time-based markers when output is not reflected.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No command that modifies the server, connects out, or touches "
            "other tenants' data.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The command's output (or its timing differential) reproduces by "
            "hand and is attributable to the injected value.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["command", "output_visible", "os"],
        "reference_tools": ["cmdi_probe"],
    },
    "lfi": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Local file inclusion / path traversal",
        "role": (
            "Filesystem-aware tester. You reason about normalization, encoding "
            "layers (the app, the WAF, the OS), and what file proves traversal "
            "without reading anything sensitive."
        ),
        "objective": (
            "Confirm the parameter reaches the filesystem and can escape its "
            "base directory, proven with a well-known world-readable file "
            "(/etc/passwd, /etc/hosts) or a distinguishable marker file."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Proof with a world-readable, non-secret file only.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No reading application secrets, source, or configuration beyond "
            "the minimal proof.",
            "No writing files to the server.",
        ],
        "success_criteria": _SCANNER_REPRO + [
            "The marker content appears in the replayed response and not in the "
            "baseline, and the encoding used to reach it is documented.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["file_read", "encoding_layer"],
        "reference_tools": ["web_injection_probe"],
    },
    "redirect": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Open redirect",
        "role": (
            "URL-parsing specialist. You reason about where the attacker value "
            "lands — Location header, meta refresh, JS redirect — and which "
            "parser (browser, app, WAF) gets the final say."
        ),
        "objective": (
            "Confirm the redirect target is attacker-controlled and lands on a "
            "host the attacker does not own, per the program's definition."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Proof with a benign, tester-controlled destination.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "Redirects to the target's own hosts are not findings: the value "
            "must flow to a destination outside the program's assets to be an "
            "open redirect at all.",
            "No redirect chains that land on a third party's page.",
        ],
        "success_criteria": [
            "The Location/meta-refresh target contains the attacker-controlled "
            "host, verified by hand replay.",
            "The target program's out-of-scope list does not name open redirects "
            "(some programs do; check the program page before filing).",
            "An additional impact (OAuth token theft, credential phishing chain) "
            "is demonstrated if the program only accepts open redirects with one.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["destination_host", "location_header"],
        "reference_tools": ["web_injection_probe"],
    },
    "auth": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Authentication bypass",
        "role": (
            "Identity-flow tester. You model the full chain — password reset, "
            "session issuance, token validation, MFA — and look for a step "
            "that can be skipped, replayed, or confused."
        ),
        "objective": (
            "Prove a way to reach an authenticated state or a protected action "
            "without the credentials or factor the flow requires, using the "
            "tester's own accounts only."
        ),
        "scope": [
            "The named flow (login, reset, OAuth, session), on the named host.",
            "Proof with the tester's own accounts: bypass a step, replay a "
            "token, swap a session identifier.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "No brute force, no credential stuffing, no password spraying — "
            "programs ban it and rate limits are out of scope.",
            "No account takeover of accounts the tester does not control, even "
            "as a proof, without the program's explicit prior approval.",
        ],
        "success_criteria": [
            "The protected action completes without the required credential or "
            "factor, reproduced twice from clean state.",
            "The bypass is attributable to a specific design flaw, not to "
            "misconfiguration of the test environment.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["flow", "bypassed_step", "accounts_used"],
        "reference_tools": ["auth_crawl", "auth_surface", "hunt_plan"],
    },
    "authz": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Access control / IDOR",
        "role": (
            "Authorization tester. You think in object graphs: which user can "
            "name which object, and what happens when the identifier in the "
            "URL, body, or header is swapped."
        ),
        "objective": (
            "Prove one user can read or act on another user's object — or an "
            "unauthenticated caller can reach an authenticated object — using "
            "the tester's own accounts and a benign object."
        ),
        "scope": [
            "The named endpoint and object type, on the named host.",
            "Proof between two tester-controlled accounts, or against a "
            "tester-created object.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "No access to real users' data, even for proof. Two test accounts "
            "are the whole demonstration.",
            "No mass enumeration: reading a handful of IDs to establish the "
            "pattern is proof; harvesting the range is data theft.",
        ],
        "success_criteria": [
            "The swapped identifier yields another account's object or a "
            "forbidden action, reproduced twice.",
            "The affected object is tester-controlled, and the response proving "
            "the flaw is captured verbatim.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["victim_object", "object_type", "accounts_used"],
        "reference_tools": ["hunt_plan", "auth_crawl"],
    },
    "business_logic": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Business logic flaw",
        "role": (
            "Application-logic tester. You model the intended state machine of "
            "the flow — checkout, coupon, transfer, refund — and probe each "
            "transition for one that violates the business rules."
        ),
        "objective": (
            "Prove a business rule can be violated — negative amount, double "
            "redemption, race between balance check and debit, step reordering "
            "— with a benign demonstration on the tester's own account."
        ),
        "scope": [
            "The named flow, on the named host, with the tester's own funds/items.",
            "Proof limited to the smallest amount/unit the flow allows.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "No real financial loss: any fund-movement proof must be reversible "
            "and within the tester's own account.",
            "No race that degrades service or exhausts a shared resource.",
        ],
        "success_criteria": [
            "The violated rule is named (the program's own policy or code "
            "states it), the violating sequence is reproduced twice, and the "
            "financial or access impact is quantified.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["violated_rule", "impact", "sequence"],
        "reference_tools": ["auth_crawl", "hunt_plan"],
    },
    "cache_poisoning": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Web cache poisoning",
        "role": (
            "Cache-aware tester. You model what the cache keys on, what it "
            "passes through, and who else will be served the poisoned copy."
        ),
        "objective": (
            "Confirm an unkeyed input reaches the response and the cache stores "
            "it, proven by a second (or unauthenticated) requester receiving "
            "the injected content."
        ),
        "scope": [
            "The named endpoint, on the named host.",
            "Proof with a benign injected value (a marker string) served to the "
            "tester's second request.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "No payload that poisons the cache for real users: a marker string "
            "is proof; a script that other visitors execute is an attack on them.",
            "The poisoned cache entry must be cleared or left with the benign "
            "marker, and the program informed if it persists.",
        ],
        "success_criteria": [
            "Request 2 (distinct requester, same cache key) receives the marker "
            "from request 1, reproduced twice.",
            "The unkeyed input is named (header, parameter, cookie).",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["unkeyed_input", "cache_key", "requester_2"],
        "reference_tools": ["fuzz_compare"],
    },
    "race_condition": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Race condition / TOCTOU",
        "role": (
            "Concurrency tester. You look for check-then-act pairs — balance "
            "then debit, redeem then mark-used, quota then consume — and test "
            "whether the window is real."
        ),
        "objective": (
            "Confirm a check-then-act window by racing the tester's own "
            "requests and showing both passed the check."
        ),
        "scope": [
            "The named action, on the named host, with the tester's own resources.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "The race must be bounded and against the tester's own account; no "
            "flooding shared infrastructure.",
        ],
        "success_criteria": [
            "Two racing requests both pass the check (double spend, double "
            "redemption), reproduced at least twice.",
            "The window is bounded and named (the two requests and their "
            "timing).",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["racing_requests", "window"],
        "reference_tools": ["auth_crawl", "hunt_plan"],
    },
    "takeover": {
        "pack_type": "validate",
        "phase": "takeover",
        "title": "Subdomain takeover",
        "role": (
            "DNS-and-cloud tester. You follow the record chain — CNAME, NS, MX — "
            "to the provider it points at, and check whether that resource is "
            "claimable."
        ),
        "objective": (
            "Confirm a dangling DNS record points at a claimable cloud resource "
            "(S3, Heroku, Azure, GitHub Pages...) by claiming the tester's own "
            "instance of that exact resource and serving benign content on it."
        ),
        "scope": [
            "The named subdomain, on the named host.",
            "Proof by registering the tester's own resource under the exact "
            "dangling target, serving a marker the tester controls.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "The claimed resource must be released and the DNS record reported "
            "to the program after the proof.",
            "No content on the claimed resource beyond the marker — it is "
            "served on the program's hostname, and anything else could be "
            "phishing on their brand.",
        ],
        "success_criteria": [
            "The tester's marker is served on the program's hostname via the "
            "claimed resource.",
            "The provider and the exact resource name are documented.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["provider", "resource_name", "marker"],
        "reference_tools": ["takeover_detect", "takeover_poc_plan"],
    },
    "deserialization": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Insecure deserialization",
        "role": (
            "Object-lifecycle tester. You reason about what gets unmarshalled "
            "from attacker-influenced input and what gadgets exist in the "
            "observed stack."
        ),
        "objective": (
            "Confirm the application deserializes attacker-controlled data by "
            "demonstrating a distinguishable side effect from a malformed or "
            "malicious object, without achieving code execution unless the "
            "caller requires it."
        ),
        "scope": [
            "The named endpoint and content type.",
            "Proof with a benign side effect: a timing differential, an error "
            "that reveals the deserializer, or a gadget that prints a marker.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No RCE proof without explicit caller approval and a permit from "
            "the engagement.",
        ],
        "success_criteria": [
            "The side effect is attributable to the serialized payload and "
            "reproduced twice.",
            "The deserializer and gadget chain (or its absence) are named.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["deserializer", "side_effect"],
        "reference_tools": ["web_injection_probe"],
    },
    "file_upload": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "File upload abuse",
        "role": (
            "Upload-path tester. You reason about content-type checks, extension "
            "filters, magic-byte validation, storage location, and whether an "
            "uploaded file is ever served or executed."
        ),
        "objective": (
            "Confirm a file that should be rejected is accepted and either "
            "served with attacker-controlled content or executed, proven with a "
            "benign marker file (e.g. a .txt whose content the tester set)."
        ),
        "scope": [
            "The named upload endpoint, on the named host.",
            "Proof with a benign, non-executable marker file that the server "
            "stores and serves back.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "No webshell, no executable content uploaded to the target, no "
            "persistence.",
            "Uploaded proof files must be deleted or disclosed to the program "
            "at the end.",
        ],
        "success_criteria": [
            "The marker file's content is retrievable at a URL the server "
            "controls, reproduced twice.",
            "If execution is claimed, it must be a benign command with visible "
            "output, and the engagement must permit it.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["file_type", "served_url"],
        "reference_tools": ["web_injection_probe"],
    },
    "graphql": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "GraphQL abuse",
        "role": (
            "API tester. You reason about the schema surface — introspection, "
            "batching, aliases, mutations — and where authorization is (or is "
            "not) applied."
        ),
        "objective": (
            "Confirm a schema or authorization gap — introspection enabled, "
            "batching beyond limits, a mutation callable without its "
            "authorization check — proven with a minimal query against the "
            "tester's own data."
        ),
        "scope": [
            "The named GraphQL endpoint, on the named host.",
            "Proof with benign queries: an introspection dump, a batched query "
            "that exceeds the documented limit, a cross-object query between "
            "tester accounts.",
        ],
        "constraints": _UNIVERSAL_DENY + [
            "No mass data harvest through batching or aliasing: proof with a "
            "handful of objects, not the whole store.",
        ],
        "success_criteria": [
            "The schema or authorization gap is demonstrated with a minimal "
            "query and reproduced twice.",
            "The program's documented limits are cited for limit violations.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["query", "gap"],
        "reference_tools": ["graphql_audit"],
    },
    "injection": {
        "pack_type": "validate",
        "phase": "exploit",
        "title": "Generic injection / parameter tampering",
        "role": (
            "Input-handling generalist. You model every parser between the "
            "attacker's bytes and the backend's interpretation, and look for a "
            "layer that interprets differently (HPP, CRLF, encoding)."
        ),
        "objective": (
            "Confirm a value is interpreted differently than the application "
            "intended — parameter pollution, header injection, encoding "
            "confusion — proven with a benign marker the backend echoes."
        ),
        "scope": [
            "The named parameter, on the named endpoint.",
            "Proof with marker values only.",
        ],
        "constraints": _UNIVERSAL_DENY + _ATTACK_DENY + [
            "A primitive alone (HPP that changes nothing) is not a finding: the "
            "misinterpretation must produce a distinguishable effect.",
        ],
        "success_criteria": [
            "The backend's response differs from the application's intended "
            "handling in a way attributable to the tampered value, reproduced "
            "twice.",
        ],
        "evidence_format": EVIDENCE_FIELDS + ["interpretation_delta"],
        "reference_tools": ["web_injection_probe"],
    },
}

#: Canonical class names, sorted, for discovery.
_CLASS_ORDER = (
    "sqli", "nosqli", "xss", "ssti", "ssrf", "cmdi", "lfi", "redirect",
    "auth", "authz", "business_logic", "cache_poisoning", "race_condition",
    "takeover", "deserialization", "file_upload", "graphql", "injection",
)


def prompt_pack_classes() -> list[str]:
    """The canonical class names in stable order."""
    return list(_CLASS_ORDER)


def get_prompt_pack(class_name: str) -> dict[str, Any] | None:
    """The prompt pack for one class, or None when unknown.

    The returned dict is a shallow copy: packs are immutable data and a caller
    that mutates one would corrupt every later consumer.
    """
    key = (class_name or "").strip().lower()
    pack = PROMPT_PACKS.get(key)
    return dict(pack) if pack else None

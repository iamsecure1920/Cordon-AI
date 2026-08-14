#!/usr/bin/env python3
"""Build a queryable technique index from PayloadsAllTheThings.

EasyHunt runs scanners well and is weak at knowing what to try next. The WSTG
index covers *what to check*; this covers *how to check it* — the concrete
techniques, bypass tables and payload shapes a human pentester reaches for when
a scanner comes back clean. swisskyrepo/PayloadsAllTheThings is the de-facto
reference for that, organised as one directory per bug class, each holding a
methodology README plus payload files.

This script does not vendor the payloads themselves. Two reasons:

* The payload files are dense attack strings — RCE statements, reverse shells,
  third-party callbacks. Firing them unvetted violates the first invariant
  ("treat every third-party payload list as untrusted until vetted and pinned").
* The vetted store already holds the payload classes (xsspollygots, allsqli,
  ssti, ssrf, crlf, lfi, xml, jwt-secrets, …), classified by
  ``scripts/vet_payloads.py``. Those names are what this index wires each
  technique to.

What ships is the *index* — MIT-licensed methodology metadata, pinned, with
attribution travelling on every record — exactly the same treatment the WSTG
index gets in ``scripts/fetch_wstg.py``.

    python3 scripts/fetch_pat.py --fetch     # clone at the pin, build the index
    python3 scripts/fetch_pat.py --verify    # check the index against the pin
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "knowledge" / "pat"
INDEX = STORE / "index.json"

SOURCE = {
    "repo": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    # Bump deliberately, and re-read the diff: technique content drifts.
    "commit": "3bff425aca2b020f7334f9d744eed3ca55de8cdf",
    "license": "MIT",
    "attribution": (
        "PayloadsAllTheThings — github.com/swisskyrepo/PayloadsAllTheThings "
        "(Swissky and contributors)"
    ),
    "redistribute": "MIT, with the copyright notice retained",
}

#: Bug class -> engagement phase. Lets the agent ask "what should I try now"
#: without knowing the repository's taxonomy.
PHASE = {
    "recon": "recon",
    "configuration": "configuration",
    "authentication": "authentication",
    "authorization": "authorization",
    "session": "session",
    "input_validation": "input_validation",
    "client_side": "client_side",
    "business_logic": "business_logic",
    "api": "api",
    "methodology": "methodology",
    "scan": "scan",
    "cloud": "cloud",
    "post_exploitation": "post_exploitation",
}

#: Directory name -> technique record. ``tools`` names EasyHunt tools that test
#: the class; ``payloads`` names lists in the vetted store (tier A/B); ``gf``
#: names pattern packs under rules/gf. Everything is a *reference*, not an
#: instruction to fire anything — the technique index is retrieval.
#
#: A directory absent from this table is still indexed (title + summary only);
#: a directory present here but not on disk is dropped with a warning, so a
#: rename upstream surfaces as a gap instead of a silently-wrong mapping.
CLASSES: dict[str, dict[str, Any]] = {
    "Account Takeover": {
        "phase": "authentication",
        "tools": ["auth_surface", "auth_crawl", "jwt_inspect", "secret_validate"],
    },
    "API Key Leaks": {
        "phase": "recon",
        "tools": ["secret_scan", "secret_validate", "trufflehog", "gitleaks"],
    },
    "Brute Force Rate Limit": {
        "phase": "authentication",
        "tools": ["auth_crawl", "auth_surface"],
    },
    "Business Logic Errors": {
        "phase": "business_logic",
        "tools": ["hunt_plan", "auth_crawl", "authz_compare"],
        "keywords": ["business logic", "logic flaw", "step bypass"],
    },
    "Clickjacking": {
        "phase": "client_side",
        "tools": ["http_probe"],
    },
    "Client Side Path Traversal": {
        "phase": "client_side",
        "tools": ["js_analyze"],
    },
    "Command Injection": {
        "phase": "input_validation",
        "tools": ["cmdi_probe", "commix", "pattern_scan"],
        "gf": ["rce"],
        "keywords": ["cmdi", "command injection", "rce", "os command"],
    },
    "CORS Misconfiguration": {
        "phase": "configuration",
        "tools": ["cors_audit", "corscanner"],
        "keywords": ["cors", "cross-origin"],
    },
    "CRLF Injection": {
        "phase": "input_validation",
        "payloads": ["crlf.txt"],
    },
    "Cross-Site Request Forgery": {
        "phase": "session",
        "tools": ["auth_crawl", "auth_surface"],
        "keywords": ["csrf"],
    },
    "CSS Injection": {
        "phase": "client_side",
        "tools": ["xss_validate"],
    },
    "CSV Injection": {
        "phase": "business_logic",
    },
    "CVE Exploits": {
        "phase": "scan",
        "tools": ["nuclei_scan", "semgrep_scan", "wapiti_scan"],
    },
    "Dependency Confusion": {
        "phase": "scan",
        "tools": ["contract_toolchain"],
    },
    "Denial of Service": {
        "phase": "methodology",
        # Deliberately unmapped: DoS is out of scope for essentially every
        # program and the technique index must not encourage it.
        "note": "not tested — DoS is out of scope for authorized programs",
    },
    "Directory Traversal": {
        "phase": "input_validation",
        "tools": ["ffuf", "feroxbuster", "pattern_scan"],
        "payloads": ["directory_traversal_unix.txt", "directory_traversal_win.txt", "lfi.txt"],
        "gf": ["lfi"],
        "keywords": ["path traversal", "dot dot slash", "../"],
    },
    "DNS Rebinding": {
        "phase": "recon",
        "tools": ["ssrf_probe"],
    },
    "DOM Clobbering": {
        "phase": "client_side",
        "tools": ["js_analyze", "xss_validate"],
    },
    "Encoding Transformations": {
        "phase": "methodology",
    },
    "External Variable Modification": {
        "phase": "methodology",
    },
    "File Inclusion": {
        "phase": "input_validation",
        "tools": ["ffuf", "pattern_scan"],
        "payloads": ["lfi.txt"],
        "gf": ["lfi"],
        "keywords": ["lfi", "local file inclusion", "rfi"],
    },
    "Google Web Toolkit": {
        "phase": "client_side",
        "tools": ["js_analyze"],
    },
    "GraphQL Injection": {
        "phase": "api",
        "tools": ["graphql_audit"],
        "keywords": ["graphql", "introspection"],
    },
    "Headless Browser": {
        "phase": "client_side",
        "tools": ["xss_validate", "xsstrike"],
    },
    "Hidden Parameters": {
        "phase": "recon",
        "tools": ["param_discovery", "arjun"],
    },
    "HTTP Parameter Pollution": {
        "phase": "input_validation",
        "tools": ["param_discovery", "arjun"],
    },
    "Insecure Deserialization": {
        "phase": "input_validation",
        "keywords": ["deserialization", "pickle", "ysoserial"],
    },
    "Insecure Direct Object References": {
        "phase": "authorization",
        "tools": ["hunt_plan", "authz_compare", "pattern_scan"],
        "gf": ["idor"],
        "keywords": ["idor", "object reference", "brola", "access control"],
    },
    "Insecure Management Interface": {
        "phase": "configuration",
        "tools": ["content_discovery", "http_probe"],
    },
    "Insecure Randomness": {
        "phase": "configuration",
    },
    "Insecure Source Code Management": {
        "phase": "recon",
        "tools": ["content_discovery", "secret_scan", "source_fetch", "gitdorker"],
        "payloads": ["git_config.txt"],
    },
    "Java RMI": {
        "phase": "recon",
        "tools": ["port_scan", "nmap"],
    },
    "JSON Web Token": {
        "phase": "session",
        "tools": ["jwt_inspect", "jwt_tool"],
        "payloads": ["jwt-secrets.txt"],
        "keywords": ["jwt", "jwt forgery", "alg none"],
    },
    "LaTeX Injection": {
        "phase": "input_validation",
    },
    "LDAP Injection": {
        "phase": "input_validation",
    },
    "Mass Assignment": {
        "phase": "authorization",
        "tools": ["hunt_plan", "authz_compare"],
    },
    "NoSQL Injection": {
        "phase": "input_validation",
        "tools": ["nosqli_probe", "nosqli"],
        "keywords": ["nosql", "nosqli", "mongodb", "$where"],
    },
    "OAuth Misconfiguration": {
        "phase": "authentication",
        "tools": ["auth_surface", "hunt_plan"],
        "keywords": ["oauth", "oauth2", "redirect_uri"],
    },
    "Open Redirect": {
        "phase": "input_validation",
        "tools": ["pattern_scan"],
        "gf": ["redirect"],
        "keywords": ["open redirect", "redirect"],
    },
    "ORM Leak": {
        "phase": "input_validation",
    },
    "Prompt Injection": {
        "phase": "api",
        "tools": ["llm_redteam", "promptfoo"],
    },
    "Prototype Pollution": {
        "phase": "client_side",
        "tools": ["js_analyze"],
    },
    "Race Condition": {
        "phase": "business_logic",
        "tools": ["authz_compare"],
    },
    "Regular Expression": {
        "phase": "input_validation",
    },
    "Request Smuggling": {
        "phase": "session",
        "tools": ["smuggling_probe", "smuggling_canary_probe", "smuggler"],
        "keywords": ["http request smuggling", "cl.te", "te.cl", "h2.c2"],
    },
    "Reverse Proxy Misconfigurations": {
        "phase": "configuration",
        "tools": ["http_probe"],
    },
    "SAML Injection": {
        "phase": "authentication",
    },
    "Server Side Include Injection": {
        "phase": "input_validation",
    },
    "Server Side Request Forgery": {
        "phase": "input_validation",
        "tools": ["ssrf_probe", "ssrfmap", "pattern_scan"],
        "payloads": ["ssrf.txt"],
        "gf": ["ssrf"],
        "keywords": ["ssrf", "server side request"],
    },
    "Server Side Template Injection": {
        "phase": "input_validation",
        "tools": ["ssti_probe", "sstimap", "pattern_scan"],
        "payloads": ["ssti.txt"],
        "gf": ["ssti"],
        "keywords": ["ssti", "template injection"],
    },
    "SQL Injection": {
        "phase": "input_validation",
        "tools": ["sqli_validate", "sqlmap", "pattern_scan"],
        "payloads": ["allsqli.txt", "blindsqli.txt"],
        "gf": ["sqli"],
        "keywords": ["sqli", "sql injection", "union select"],
    },
    "Tabnabbing": {
        "phase": "client_side",
    },
    "Type Juggling": {
        "phase": "input_validation",
    },
    "Upload Insecure Files": {
        "phase": "input_validation",
        "gf": ["upload"],
        "keywords": ["file upload", "upload bypass"],
    },
    "Virtual Hosts": {
        "phase": "recon",
        "tools": ["ffuf", "content_discovery"],
        "payloads": ["vhosts.txt"],
    },
    "Web Cache Deception": {
        "phase": "session",
    },
    "Web Sockets": {
        "phase": "api",
        "tools": ["websocket_probe", "websocat"],
    },
    "XPATH Injection": {
        "phase": "input_validation",
    },
    "XS-Leak": {
        "phase": "client_side",
    },
    "XSLT Injection": {
        "phase": "input_validation",
    },
    "XSS Injection": {
        "phase": "client_side",
        "tools": ["xss_validate", "dalfox", "xsstrike", "pattern_scan"],
        "payloads": ["xsspollygots.txt", "xsswafbypss.txt", "vulJs.txt"],
        "gf": ["xss"],
        "keywords": ["xss", "cross-site scripting", "reflected", "dom"],
    },
    "XXE Injection": {
        "phase": "input_validation",
        "payloads": ["xml.txt"],
        "keywords": ["xxe", "xml external entity"],
    },
    "Zip Slip": {
        "phase": "input_validation",
        "tools": ["secret_scan"],
    },
}

#: The red-team cheatsheets live in one directory whose files are mostly stubs —
#: upstream moved their bodies to ``swisskyrepo/InternalAllTheThings``. Indexed
#: as methodology so the planner knows the topic exists and where it moved; the
#: ``moved_to`` URL is recorded rather than a fake summary.
#:
#: ``tools`` is populated only where EasyHunt actually drives something
#: comparable. Post-exploitation topics (privilege escalation, persistence,
#: pivoting, credential dumping) are deliberately left tool-less — EasyHunt is
#: an external/cloud VAPT orchestrator and has no C2 or host-agent tooling, so
#: pretending otherwise would be a lie in the index.
CHEATSHEET_DIR = "Methodology and Resources"
CHEATSHEETS: dict[str, dict[str, Any]] = {
    "Cloud - AWS Pentest": {
        "phase": "cloud",
        "tools": ["cloud_audit", "cloud_attack_paths", "cloud_asset_discovery", "prowler", "cloud_enum"],
    },
    "Cloud - Azure Pentest": {
        "phase": "cloud",
        "tools": ["cloud_audit", "cloud_attack_paths"],
    },
    "Container - Kubernetes Pentest": {
        "phase": "cloud",
        "tools": ["kubescape", "k8s_posture"],
    },
    "Container - Docker Pentest": {
        "phase": "cloud",
    },
    "Network Discovery": {
        "phase": "recon",
        "tools": ["port_scan", "naabu", "nmap", "masscan", "service_scan"],
    },
    "Methodology and enumeration": {
        "phase": "recon",
        "tools": ["subdomain_enum", "endpoint_discovery", "http_probe", "content_discovery"],
    },
    "Web Attack Surface": {
        "phase": "recon",
        "tools": ["subdomain_enum", "endpoint_discovery", "http_probe", "js_analyze"],
    },
    "Source Code Management": {
        "phase": "recon",
        "tools": ["secret_scan", "source_fetch", "gitdorker", "gitleaks", "trufflehog"],
    },
    "Vulnerability Reports": {
        "phase": "methodology",
        "tools": ["report_generate", "triage_findings", "triage_taskflows"],
    },
    # Everything else in the directory is post-exploitation/red-team content.
    # Defaulted below, deliberately tool-less.
}

#: Filenames in CHEATSHEET_DIR that are post-exploitation and therefore have no
#: EasyHunt tool. Explicit so the "tool-less" default is a decision, not an
#: omission that reads as an index bug.
_POST_EXPLOITATION = {
    "Active Directory Attack", "Bind Shell Cheatsheet", "Cobalt Strike - Cheatsheet",
    "Escape Breakout", "Hash Cracking", "HTML Smuggling", "Initial Access",
    "Linux - Evasion", "Linux - Persistence", "Linux - Privilege Escalation",
    "Metasploit - Cheatsheet", "MSSQL Server - Cheatsheet",
    "Network Pivoting Techniques", "Office - Attacks", "Powershell - Cheatsheet",
    "Reverse Shell Cheatsheet", "Windows - AMSI Bypass", "Windows - Defenses",
    "Windows - Download and Execute", "Windows - DPAPI", "Windows - Mimikatz",
    "Windows - Persistence", "Windows - Privilege Escalation",
    "Windows - Using credentials",
}

#: slug for a directory name. Lowercase, punctuation -> hyphen, spaces -> hyphen.
_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    return _SLUG.sub("-", name.lower()).strip("-")


def _summary(text: str) -> str:
    """First blockquote after the title — PAT's one-line description."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(">"):
            out = stripped.lstrip("> ").strip()
            out = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", out)
            return out[:600]
    return ""


def parse_readme(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if not title_match:
        return None
    return {
        "title": title_match.group(1).strip(),
        "summary": _summary(text),
    }


def _moved_to(text: str) -> str | None:
    """Upstream moved most cheatsheets to InternalAllTheThings; record where."""
    match = re.search(
        r"moved to \[(?P<label>[^\]]+)\]\((?P<url>https?://[^)]+)\)",
        text, re.IGNORECASE,
    )
    return match.group("url") if match else None


def parse_cheatsheet(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if not title_match:
        return None
    moved = _moved_to(text)
    summary = _summary(text)
    if not summary and moved:
        summary = f"Content moved upstream: {moved}"
    return {"title": title_match.group(1).strip(), "summary": summary, "moved_to": moved}


def raw_url(rel: str) -> str:
    return (
        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/"
        + SOURCE["commit"]
        + "/"
        + rel
    )


def build(repo: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Walk the repo and emit one record per bug class, plus the cheatsheets."""
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    for child in sorted(repo.iterdir()):
        if not child.is_dir() or child.name.startswith((".", "_")):
            continue
        readme = child / "README.md"
        if not readme.is_file():
            continue
        parsed = parse_readme(readme)
        if parsed is None:
            warnings.append(f"{child.name}: no title in README, skipped")
            continue
        rel = str(child.relative_to(repo))
        mapping = CLASSES.get(child.name, {})
        if child.name not in CLASSES:
            warnings.append(f"{child.name}: no CLASSES entry — indexed as methodology only")
        record: dict[str, Any] = {
            "class": slugify(child.name),
            "kind": "technique",
            "title": parsed["title"],
            "phase": mapping.get("phase", "methodology"),
            "summary": parsed["summary"],
            "tools": mapping.get("tools", []),
            "payloads": mapping.get("payloads", []),
            "gf": mapping.get("gf", []),
            "keywords": mapping.get("keywords", []),
            "source_path": rel,
            "raw_url": raw_url(rel),
        }
        if mapping.get("note"):
            record["note"] = mapping["note"]
        records.append(record)

    # Cheatsheets: methodology stubs whose bodies moved to InternalAllTheThings.
    cheat_dir = repo / CHEATSHEET_DIR
    if cheat_dir.is_dir():
        for sheet in sorted(cheat_dir.glob("*.md")):
            parsed = parse_cheatsheet(sheet)
            if parsed is None:
                warnings.append(f"{CHEATSHEET_DIR}/{sheet.name}: no title, skipped")
                continue
            stem = sheet.stem
            mapping = CHEATSHEETS.get(stem, {})
            if stem in _POST_EXPLOITATION:
                phase = "post_exploitation"
            else:
                phase = mapping.get("phase", "methodology")
            rel = str(sheet.relative_to(repo))
            record = {
                "class": slugify(stem),
                "kind": "cheatsheet",
                "title": parsed["title"],
                "phase": phase,
                "summary": parsed["summary"],
                "tools": mapping.get("tools", []),
                "payloads": [],
                "gf": [],
                "source_path": rel,
                "raw_url": raw_url(rel),
            }
            if parsed.get("moved_to"):
                record["moved_to"] = parsed["moved_to"]
            records.append(record)
    return records, warnings


def fetch() -> Path:
    scratch = STORE / "_src"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.parent.mkdir(parents=True, exist_ok=True)
    print(f"cloning {SOURCE['repo']}")
    subprocess.run(["git", "clone", "-q", SOURCE["repo"], str(scratch)], check=True)  # noqa: S603
    print(f"checking out pinned commit {SOURCE['commit'][:12]}")
    subprocess.run(  # noqa: S603
        ["git", "-C", str(scratch), "checkout", "-q", SOURCE["commit"]], check=True
    )
    actual = subprocess.run(  # noqa: S603
        ["git", "-C", str(scratch), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if actual != SOURCE["commit"]:
        raise SystemExit(f"pin mismatch: expected {SOURCE['commit']}, got {actual}")
    print("pin verified\n")
    return scratch


def verify() -> int:
    if not INDEX.is_file():
        print(f"no index at {INDEX} — run --fetch first", file=sys.stderr)
        return 1
    data = json.loads(INDEX.read_text(encoding="utf-8"))
    pin = data.get("source", {}).get("commit", "")
    if pin != SOURCE["commit"]:
        print(f"index pin {pin[:12]} != current pin {SOURCE['commit'][:12]}", file=sys.stderr)
        return 1
    print(f"index verified against pin {pin[:12]}: {len(data.get('techniques', []))} techniques")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="clone at pinned SHA and build")
    group.add_argument("--verify", action="store_true", help="check the index against the pin")
    args = parser.parse_args()

    if args.verify:
        return verify()

    repo = fetch()
    records, warnings = build(repo)
    for warning in warnings:
        print(f"warning: {warning}")
    payload = {
        "source": SOURCE,
        "phases": PHASE,
        "techniques": records,
    }
    INDEX.write_text(json.dumps(payload, indent=2) + "\n")
    shutil.rmtree(repo, ignore_errors=True)
    print(f"\nindex written to {INDEX}")
    print(f"{len(records)} techniques indexed, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

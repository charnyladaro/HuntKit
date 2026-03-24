"""
Phase 3 - Vulnerability Scanning
Tools: nuclei, nikto, custom HTTP checks
"""
import re
import json
import urllib.request
import urllib.error
import ssl
import socket
from datetime import datetime
from utils import executor as ex
from utils import logger as log
from utils import storage


TOOLS_REQUIRED = ["nuclei"]
TOOLS_OPTIONAL = ["nikto"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def run_nuclei(urls: list[str], tags: list[str] = None) -> list[dict]:
    """Run nuclei templates against live URLs."""
    if not ex.is_installed("nuclei"):
        log.warn("nuclei not installed, skipping")
        return []
    if not urls:
        return []

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls[:200]))  # Cap at 200
        tmp = f.name

    cmd = [
        "nuclei",
        "-l", tmp,
        "-silent",
        "-json",
        "-severity", "critical,high,medium,low",
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", "50",
    ]

    if tags:
        cmd += ["-tags", ",".join(tags)]

    log.info(f"nuclei scanning {len(urls[:200])} URLs...")
    rc, out, _ = ex.run(cmd, timeout=600)
    os.unlink(tmp)

    findings = []
    for line in ex.lines_from(out):
        try:
            entry = json.loads(line)
            findings.append({
                "tool": "nuclei",
                "template_id": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", "info"),
                "url": entry.get("matched-at", entry.get("host", "")),
                "description": entry.get("info", {}).get("description", ""),
                "reference": entry.get("info", {}).get("reference", []),
                "matcher_name": entry.get("matcher-name", ""),
                "extracted_results": entry.get("extracted-results", []),
                "curl_command": entry.get("curl-command", ""),
                "timestamp": entry.get("timestamp", ""),
            })
        except Exception:
            pass

    return findings


def run_nikto(url: str) -> list[dict]:
    """Run nikto against a single URL."""
    if not ex.is_installed("nikto"):
        log.warn("nikto not installed, skipping")
        return []

    log.info(f"nikto → {url}")
    rc, out, _ = ex.run(
        ["nikto", "-h", url, "-Format", "txt", "-nointeractive", "-Tuning", "x6"],
        timeout=180
    )

    findings = []
    for line in ex.lines_from(out):
        if line.startswith("+") and "OSVDB" not in line and "Server:" not in line:
            findings.append({
                "tool": "nikto",
                "severity": "medium",
                "url": url,
                "name": "Nikto Finding",
                "description": line.lstrip("+ "),
            })
    return findings


def custom_checks(urls: list[str]) -> list[dict]:
    """Custom Python HTTP checks (no external tools needed)."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    interesting_headers = {
        "X-Frame-Options": ("missing", "info", "Clickjacking protection missing"),
        "Content-Security-Policy": ("missing", "medium", "No CSP header"),
        "X-Content-Type-Options": ("missing", "low", "MIME sniffing protection missing"),
        "Strict-Transport-Security": ("missing", "medium", "HSTS not enforced"),
        "X-XSS-Protection": ("missing", "low", "Legacy XSS protection header absent"),
        "Server": ("present", "info", "Server version disclosure"),
        "X-Powered-By": ("present", "low", "Technology disclosure via X-Powered-By"),
    }

    check_paths = [
        ("/.env", "medium", "Exposed .env file"),
        ("/.git/config", "high", "Exposed .git directory"),
        ("/robots.txt", "info", "robots.txt accessible"),
        ("/sitemap.xml", "info", "sitemap.xml accessible"),
        ("/phpinfo.php", "high", "PHP info page exposed"),
        ("/admin", "medium", "Admin panel accessible"),
        ("/wp-admin/", "medium", "WordPress admin panel"),
        ("/api/swagger", "info", "Swagger/OpenAPI docs exposed"),
        ("/api/docs", "info", "API docs exposed"),
        ("/.well-known/security.txt", "info", "Security.txt present"),
        ("/backup.zip", "critical", "Backup archive exposed"),
        ("/config.json", "high", "Config file exposed"),
        ("/.DS_Store", "low", "macOS metadata file exposed"),
        ("/crossdomain.xml", "low", "crossdomain.xml accessible"),
        ("/clientaccesspolicy.xml", "low", "Silverlight policy exposed"),
    ]

    checked_bases = set()
    for url in urls[:30]:
        base = url.rstrip("/")
        if base in checked_bases:
            continue
        checked_bases.add(base)

        # --- Security Headers Check ---
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, (condition, severity, desc) in interesting_headers.items():
                h_lower = header.lower()
                if condition == "missing" and h_lower not in headers:
                    findings.append({
                        "tool": "custom",
                        "severity": severity,
                        "url": url,
                        "name": f"Missing {header}",
                        "description": desc,
                        "template_id": f"missing-{h_lower}",
                    })
                elif condition == "present" and h_lower in headers:
                    findings.append({
                        "tool": "custom",
                        "severity": severity,
                        "url": url,
                        "name": f"{header} Header Disclosure",
                        "description": f"{desc}: {headers[h_lower]}",
                        "template_id": f"disclosure-{h_lower}",
                    })

            # SSL Check
            if url.startswith("https://"):
                pass  # No HSTS header already caught above

        except Exception:
            pass

        # --- Path Probing ---
        for path, severity, desc in check_paths:
            probe_url = base + path
            try:
                req = urllib.request.Request(probe_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=8, context=ctx)
                status = resp.status
                if status in (200, 301, 302, 403):
                    findings.append({
                        "tool": "custom",
                        "severity": severity,
                        "url": probe_url,
                        "name": desc,
                        "description": f"HTTP {status} returned for {path}",
                        "template_id": f"path-probe-{path.strip('/').replace('/', '-')}",
                    })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    findings.append({
                        "tool": "custom",
                        "severity": "info",
                        "url": probe_url,
                        "name": f"Forbidden path: {path}",
                        "description": f"HTTP 403 — resource exists but access denied",
                        "template_id": f"forbidden-{path.strip('/').replace('/', '-')}",
                    })
            except Exception:
                pass

    return findings


def run(target: str, discovery_data: dict, resume: bool = False) -> dict:
    log.banner("SCANNING — Vulnerability Detection", 3)

    if resume and storage.phase_done(target, "scanning"):
        log.info("Scanning already completed, loading from cache...")
        return storage.load_phase(target, "scanning")

    live_hosts = discovery_data.get("live_hosts", [])
    live_urls = [h["url"] for h in live_hosts]
    domain = discovery_data.get("domain", target)

    # Deduplicate and limit
    live_urls = list(dict.fromkeys(live_urls))

    results = {
        "domain": domain,
        "findings": [],
        "summary": {},
    }

    all_findings = []

    # --- Nuclei ---
    log.section("Nuclei Scan")
    nuclei_findings = run_nuclei(live_urls)
    all_findings.extend(nuclei_findings)
    log.success(f"nuclei: {len(nuclei_findings)} findings")

    # --- Nikto ---
    log.section("Nikto Scan")
    # Nikto on top 3 live hosts
    for url in live_urls[:3]:
        nikto_f = run_nikto(url)
        all_findings.extend(nikto_f)
    log.success(f"nikto: {sum(1 for f in all_findings if f.get('tool') == 'nikto')} findings")

    # --- Custom Checks ---
    log.section("Custom Security Checks")
    custom_f = custom_checks(live_urls)
    all_findings.extend(custom_f)
    log.success(f"custom checks: {len(custom_f)} findings")

    # --- Sort by severity ---
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "").lower(), 5))
    results["findings"] = all_findings

    # --- Summary ---
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in summary:
            summary[sev] += 1
        else:
            summary["info"] += 1
    results["summary"] = summary

    # --- Print findings ---
    log.section("Findings Summary")
    log.divider()
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary[sev]
        if count > 0:
            log.finding(sev, f"{count} {sev.upper()} finding(s)")

    log.divider()
    log.section("Top Findings")
    for f in all_findings[:15]:
        log.finding(
            f.get("severity", "info"),
            f.get("name", "Unknown"),
            f"{f.get('url', '')[:60]}"
        )

    storage.save_phase(target, "scanning", results)
    log.success("Scanning phase complete ✔")
    return results

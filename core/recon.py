"""
Phase 1 - Recon
Tools: subfinder, assetfinder, amass, dnsx, whois, python-whois
"""
import socket
import json
from utils import executor as ex
from utils import logger as log
from utils import storage


TOOLS_REQUIRED = ["subfinder", "assetfinder", "dnsx"]
TOOLS_OPTIONAL = ["amass", "whois"]


def run_subfinder(domain: str) -> list[str]:
    log.info(f"subfinder → {domain}")
    rc, out, _ = ex.run(["subfinder", "-d", domain, "-silent", "-all"], timeout=120)
    if rc != 0:
        log.warn("subfinder returned non-zero exit")
    return ex.lines_from(out)


def run_assetfinder(domain: str) -> list[str]:
    log.info(f"assetfinder → {domain}")
    rc, out, _ = ex.run(["assetfinder", "--subs-only", domain], timeout=60)
    return [l for l in ex.lines_from(out) if domain in l]


def run_amass(domain: str) -> list[str]:
    if not ex.is_installed("amass"):
        log.warn("amass not found, skipping")
        return []
    log.info(f"amass (passive) → {domain}")
    rc, out, _ = ex.run(
        ["amass", "enum", "-passive", "-d", domain, "-timeout", "3"],
        timeout=240
    )
    return ex.lines_from(out)


def run_dnsx(subdomains: list[str]) -> dict[str, str]:
    """Resolve subdomains to IPs using dnsx."""
    if not subdomains:
        return {}
    if not ex.is_installed("dnsx"):
        log.warn("dnsx not found, using Python socket fallback")
        return _socket_resolve(subdomains)

    log.info(f"dnsx resolving {len(subdomains)} subdomains...")
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        tmp = f.name

    rc, out, _ = ex.run(["dnsx", "-l", tmp, "-silent", "-resp"], timeout=120)
    os.unlink(tmp)

    resolved = {}
    for line in ex.lines_from(out):
        # dnsx output: subdomain [IP]
        parts = line.split()
        if len(parts) >= 2:
            host = parts[0]
            ip = parts[1].strip("[]")
            resolved[host] = ip
    return resolved


def _socket_resolve(subdomains: list[str]) -> dict[str, str]:
    resolved = {}
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            resolved[sub] = ip
        except Exception:
            pass
    return resolved


def run_whois(domain: str) -> dict:
    """WHOIS lookup using whois CLI or python-whois."""
    log.info(f"WHOIS → {domain}")

    # Try CLI whois first
    if ex.is_installed("whois"):
        rc, out, _ = ex.run(["whois", domain], timeout=30)
        if rc == 0 and out:
            return _parse_whois_cli(out, domain)

    # Fallback: python-whois
    try:
        import whois as pw
        w = pw.whois(domain)
        return {
            "domain": domain,
            "registrar": str(w.registrar or ""),
            "creation_date": str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "name_servers": list(w.name_servers or []),
            "emails": list(w.emails or []) if isinstance(w.emails, (list, set)) else [str(w.emails or "")],
            "org": str(w.org or ""),
            "country": str(w.country or ""),
            "raw": "",
        }
    except Exception as e:
        log.warn(f"WHOIS failed: {e}")
        return {"domain": domain, "error": str(e)}


def _parse_whois_cli(raw: str, domain: str) -> dict:
    result = {"domain": domain, "raw": raw[:2000]}
    field_map = {
        "Registrar:": "registrar",
        "Creation Date:": "creation_date",
        "Registry Expiry Date:": "expiration_date",
        "Registrant Organization:": "org",
        "Registrant Country:": "country",
        "Name Server:": "name_servers",
        "Registrant Email:": "emails",
    }
    result["name_servers"] = []
    result["emails"] = []
    for line in raw.splitlines():
        for key, field in field_map.items():
            if line.strip().startswith(key):
                val = line.split(":", 1)[1].strip()
                if field in ("name_servers", "emails"):
                    result[field].append(val)
                else:
                    result.setdefault(field, val)
    return result


def run(target: str, resume: bool = False) -> dict:
    log.banner("RECON — Subdomain Enumeration & WHOIS", 1)

    if resume and storage.phase_done(target, "recon"):
        log.info("Recon already completed, loading from cache...")
        return storage.load_phase(target, "recon")

    # Tool availability check
    avail = ex.check_tools(TOOLS_REQUIRED + TOOLS_OPTIONAL)
    for t, ok in avail.items():
        status = f"{'✔' if ok else '✘'} {t}"
        (log.success if ok else log.warn)(status)

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    results = {
        "domain": domain,
        "subdomains": [],
        "resolved": {},
        "whois": {},
    }

    # --- Subdomain Enumeration ---
    log.section("Subdomain Enumeration")
    all_subs = set()

    if avail.get("subfinder"):
        subs = run_subfinder(domain)
        all_subs.update(subs)
        log.success(f"subfinder: {len(subs)} subdomains")

    subs = run_assetfinder(domain)
    all_subs.update(subs)
    log.success(f"assetfinder: {len(subs)} subdomains")

    if avail.get("amass"):
        subs = run_amass(domain)
        all_subs.update(subs)
        log.success(f"amass: {len(subs)} subdomains")

    results["subdomains"] = sorted(all_subs)
    log.success(f"Total unique subdomains: {len(all_subs)}")

    # Print sample
    for s in list(all_subs)[:10]:
        log.result_line("subdomain", s)
    if len(all_subs) > 10:
        log.info(f"  ... and {len(all_subs) - 10} more")

    # --- DNS Resolution ---
    log.section("DNS Resolution")
    resolved = run_dnsx(list(all_subs))
    results["resolved"] = resolved
    log.success(f"Resolved {len(resolved)} / {len(all_subs)} subdomains")

    # --- WHOIS ---
    log.section("WHOIS Lookup")
    whois_data = run_whois(domain)
    results["whois"] = whois_data
    if "registrar" in whois_data:
        log.result_line("Registrar", whois_data.get("registrar", ""))
        log.result_line("Org", whois_data.get("org", ""))
        log.result_line("Expiry", whois_data.get("expiration_date", ""))
        log.result_line("Name Servers", ", ".join(whois_data.get("name_servers", [])[:3]))

    storage.save_phase(target, "recon", results)
    log.success("Recon phase complete ✔")
    return results

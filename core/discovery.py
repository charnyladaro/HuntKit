"""
Phase 2 - Asset Discovery
Tools: nmap, httpx, waybackurls, gau, whatweb
"""
import re
from utils import executor as ex
from utils import logger as log
from utils import storage


TOOLS_REQUIRED = ["nmap", "httpx"]
TOOLS_OPTIONAL = ["waybackurls", "gau", "whatweb"]


def run_nmap(hosts: list[str], fast: bool = True) -> dict[str, dict]:
    """Port scan live hosts."""
    if not hosts:
        return {}

    log.info(f"nmap port scanning {len(hosts)} hosts...")
    results = {}

    # Batch hosts (cap at 50 for speed)
    targets = hosts[:50]
    flags = ["-T4", "--open", "-p-"] if not fast else ["-T4", "--open", "--top-ports", "1000"]
    cmd = ["nmap"] + flags + ["-oG", "-"] + targets

    rc, out, _ = ex.run(cmd, timeout=600)
    if rc != 0 and rc != 1:
        log.warn(f"nmap exited with code {rc}")

    # Parse greppable output
    current_host = None
    for line in out.splitlines():
        if line.startswith("Host:"):
            parts = line.split()
            current_host = parts[1]
            results[current_host] = {"ports": [], "hostnames": []}
            # Extract hostname if present
            hostname_match = re.search(r'\(([^)]+)\)', line)
            if hostname_match:
                results[current_host]["hostnames"].append(hostname_match.group(1))
        elif line.startswith("Ports:") and current_host:
            port_section = line.replace("Ports:", "").strip()
            for entry in port_section.split(","):
                entry = entry.strip()
                parts = entry.split("/")
                if len(parts) >= 7 and parts[1] == "open":
                    results[current_host]["ports"].append({
                        "port": parts[0],
                        "state": parts[1],
                        "proto": parts[2],
                        "service": parts[4],
                        "version": parts[6],
                    })

    return results


def run_httpx(hosts: list[str]) -> list[dict]:
    """Probe hosts for live HTTP(S) services."""
    if not hosts:
        return []

    log.info(f"httpx probing {len(hosts)} hosts...")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        tmp = f.name

    cmd = [
        "httpx", "-l", tmp,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-json",
    ]
    rc, out, _ = ex.run(cmd, timeout=180)
    os.unlink(tmp)

    live = []
    for line in ex.lines_from(out):
        try:
            import json
            entry = json.loads(line)
            live.append({
                "url": entry.get("url", ""),
                "status_code": entry.get("status-code", 0),
                "title": entry.get("title", ""),
                "tech": entry.get("tech", []),
                "content_length": entry.get("content-length", 0),
                "webserver": entry.get("webserver", ""),
                "ip": entry.get("host", ""),
            })
        except Exception:
            pass

    return live


def run_waybackurls(domain: str) -> list[str]:
    """Pull URLs from Wayback Machine."""
    if not ex.is_installed("waybackurls"):
        log.warn("waybackurls not found, skipping")
        return []

    log.info(f"waybackurls → {domain}")
    rc, out, _ = ex.run(["waybackurls", domain], timeout=120)
    urls = ex.lines_from(out)
    log.success(f"waybackurls: {len(urls)} URLs")
    return urls


def run_gau(domain: str) -> list[str]:
    """Pull URLs from GetAllUrls."""
    if not ex.is_installed("gau"):
        log.warn("gau not found, skipping")
        return []

    log.info(f"gau → {domain}")
    rc, out, _ = ex.run(["gau", "--subs", domain], timeout=120)
    urls = ex.lines_from(out)
    log.success(f"gau: {len(urls)} URLs")
    return urls


def run_whatweb(urls: list[str]) -> dict[str, list]:
    """Tech fingerprinting with whatweb."""
    if not ex.is_installed("whatweb"):
        log.warn("whatweb not found, skipping")
        return {}

    results = {}
    # Run on first 20 live URLs
    for url in urls[:20]:
        rc, out, _ = ex.run(["whatweb", "--log-brief=-", url], timeout=30)
        if out.strip():
            # Parse plugins from output
            techs = re.findall(r'\[([^\[\]]+)\]', out)
            results[url] = techs
    return results


def categorize_urls(urls: list[str]) -> dict[str, list]:
    """Categorize URLs by type for manual testing focus."""
    categories = {
        "params": [],      # URLs with parameters
        "api": [],         # API endpoints
        "uploads": [],     # File upload endpoints
        "admin": [],       # Admin panels
        "auth": [],        # Auth endpoints
        "js": [],          # JavaScript files
        "interesting": [], # Other interesting paths
    }

    keywords = {
        "api":     ["api", "graphql", "rest", "v1", "v2", "v3", "endpoint"],
        "uploads": ["upload", "file", "attach", "import", "document"],
        "admin":   ["admin", "dashboard", "panel", "manage", "cms", "control"],
        "auth":    ["login", "logout", "signup", "register", "oauth", "token", "auth", "sso"],
        "interesting": ["redirect", "debug", "config", "backup", "test", "dev", "staging", "internal"],
    }

    for url in urls:
        url_lower = url.lower()
        if "?" in url:
            categories["params"].append(url)
        if url_lower.endswith(".js"):
            categories["js"].append(url)
        for cat, kws in keywords.items():
            if any(kw in url_lower for kw in kws):
                categories[cat].append(url)

    # Deduplicate
    for cat in categories:
        categories[cat] = list(dict.fromkeys(categories[cat]))

    return categories


def run(target: str, recon_data: dict, resume: bool = False) -> dict:
    log.banner("DISCOVERY — Ports, Live Hosts & URLs", 2)

    if resume and storage.phase_done(target, "discovery"):
        log.info("Discovery already completed, loading from cache...")
        return storage.load_phase(target, "discovery")

    domain = recon_data.get("domain", target)
    subdomains = recon_data.get("subdomains", [])
    resolved = recon_data.get("resolved", {})
    ips = list(set(resolved.values()))

    results = {
        "domain": domain,
        "live_hosts": [],
        "ports": {},
        "urls": [],
        "url_categories": {},
        "tech_stack": {},
    }

    # --- Port Scan ---
    log.section("Port Scanning")
    if ips:
        port_data = run_nmap(ips[:20])
        results["ports"] = port_data
        total_open = sum(len(v["ports"]) for v in port_data.values())
        log.success(f"Found {total_open} open ports across {len(port_data)} hosts")
        for ip, data in list(port_data.items())[:5]:
            ports = [p["port"] for p in data["ports"]]
            log.result_line(ip, ", ".join(ports[:10]))
    else:
        log.warn("No resolved IPs to scan")

    # --- Live Host Detection ---
    log.section("HTTP/S Live Host Detection")
    # Probe subdomains and add http/https prefixes
    probe_targets = []
    for sub in subdomains[:100]:
        probe_targets.append(f"http://{sub}")
        probe_targets.append(f"https://{sub}")

    if not probe_targets:
        probe_targets = [f"http://{domain}", f"https://{domain}"]

    live = run_httpx(probe_targets)
    results["live_hosts"] = live
    log.success(f"Live HTTP(S) hosts: {len(live)}")

    for host in live[:10]:
        status = host["status_code"]
        title = host.get("title", "")[:40]
        tech = ", ".join(host.get("tech", [])[:3])
        log.result_line(host["url"][:50], f"[{status}] {title} | {tech}")

    # --- URL Discovery ---
    log.section("URL Discovery (Wayback / GAU)")
    all_urls = set()

    wb_urls = run_waybackurls(domain)
    all_urls.update(wb_urls)

    gau_urls = run_gau(domain)
    all_urls.update(gau_urls)

    results["urls"] = list(all_urls)[:5000]  # Cap at 5000
    log.success(f"Total unique URLs: {len(all_urls)}")

    # --- Categorize URLs ---
    log.section("URL Categorization")
    categories = categorize_urls(list(all_urls))
    results["url_categories"] = categories
    for cat, urls in categories.items():
        if urls:
            log.result_line(cat, f"{len(urls)} URLs")

    # --- Tech Stack ---
    log.section("Tech Stack Fingerprinting")
    live_urls = [h["url"] for h in live[:20]]
    tech_data = run_whatweb(live_urls)
    results["tech_stack"] = tech_data

    # Aggregate tech from httpx
    all_tech = set()
    for host in live:
        all_tech.update(host.get("tech", []))
    log.success(f"Detected technologies: {', '.join(list(all_tech)[:15])}")

    storage.save_phase(target, "discovery", results)
    log.success("Discovery phase complete ✔")
    return results

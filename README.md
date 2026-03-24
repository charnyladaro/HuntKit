<div align="center">

```
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗██╗  ██╗██╗████████╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
 ███████║██║   ██║██╔██╗ ██║   ██║   █████╔╝ ██║   ██║   
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔═██╗ ██║   ██║   
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██╗██║   ██║   
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝  
```

**Full-pipeline Bug Bounty Automation Framework**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Parrot%20OS-brightgreen?style=flat-square&logo=linux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)]()
[![Author](https://img.shields.io/badge/Author-charnyladaro-blue?style=flat-square&logo=github)](https://github.com/charnyladaro)

*Recon → Discovery → Scanning → Manual Aid → Report — fully automated.*

</div>

---

## 📌 Overview

**HuntKit** is a modular, CLI-based bug bounty automation framework built in pure Python. Drop in your scope, run one command, and get a full security assessment — from subdomain enumeration all the way to a structured PDF/HTML report — with zero manual steps in between.

Built for hunters who want **speed without losing control**. Every phase stores its results as JSON, so you can resume interrupted scans, re-run individual phases, and regenerate reports without rescanning.

---

## ✨ Features

- 🔍 **Recon** — Subdomain enumeration via `subfinder`, `assetfinder`, `amass` + DNS resolution and WHOIS lookup
- 🌐 **Asset Discovery** — Port scanning with `nmap`, live host detection with `httpx`, URL harvesting via `waybackurls` & `gau`, tech fingerprinting with `whatweb`
- 🚨 **Vulnerability Scanning** — `nuclei` templates, `nikto`, and built-in custom Python HTTP checks (headers, exposed paths, misconfigs)
- 🛠️ **Manual Testing Aid** — Automatic parameter extraction, vuln-type classification, CSRF checklist, and a ready-to-use payload reference file
- 📄 **Report Generation** — Dark-themed HTML report, PDF export, and Markdown summary — all auto-generated
- ♻️ **Resume Mode** — Skip phases already completed; pick up exactly where you left off
- 🎯 **Scope File Support** — Run against multiple targets in one command

---

## 🖥️ Demo

```
  [1/5] RECON — Subdomain Enumeration & WHOIS
════════════════════════════════════════════════════════════
[08:01:12] [*] subfinder → target.com
[08:01:24] [+] subfinder: 143 subdomains
[08:01:24] [+] assetfinder: 52 subdomains
[08:01:38] [+] Total unique subdomains: 178
[08:01:39] [+] Resolved 161 / 178 subdomains

  ▶ WHOIS Lookup
    Registrar                 GoDaddy LLC
    Org                       Target Corp
    Expiry                    2026-03-14

  [2/5] DISCOVERY — Ports, Live Hosts & URLs
════════════════════════════════════════════════════════════
[08:02:01] [+] Live HTTP(S) hosts: 34
[08:02:45] [+] Total unique URLs: 12,841
    api                       847 URLs
    params                    3,204 URLs
    admin                     12 URLs

  [3/5] SCANNING — Vulnerability Detection
════════════════════════════════════════════════════════════
[08:04:22] [CRITICAL] 2 critical finding(s)
[08:04:22] [HIGH]     5 high finding(s)
[08:04:22] [MEDIUM]   18 medium finding(s)
```

---

## 📦 Installation

### Prerequisites
- Kali Linux or Parrot OS (recommended)
- Python 3.10+
- Go 1.21+ (for Go-based recon tools)

### Quick Install

```bash
git clone https://github.com/charnyladaro/huntkit.git
cd huntkit
chmod +x setup.sh && bash setup.sh
source venv/bin/activate
```

The `setup.sh` script automatically installs:

| Tool | Source | Purpose |
|------|--------|---------|
| `subfinder` | Go | Subdomain enumeration |
| `assetfinder` | Go | Subdomain enumeration |
| `amass` | apt | Subdomain enumeration |
| `dnsx` | Go | DNS resolution |
| `httpx` | Go | Live host detection |
| `nuclei` | Go | Vulnerability scanning |
| `waybackurls` | Go | URL discovery |
| `gau` | Go | URL discovery |
| `nmap` | apt | Port scanning |
| `nikto` | apt | Web vulnerability scan |
| `whois` | apt | Domain WHOIS |

> **Note:** HuntKit degrades gracefully — if a tool isn't installed, that step is skipped and the rest of the pipeline continues normally.

---

## 🚀 Usage

### Single target
```bash
python main.py run --target example.com
```

### Scope file (multiple targets)
```bash
python main.py run --scope scope.txt
```

### Resume an interrupted scan
```bash
python main.py run --target example.com --resume
```

### Run only a specific phase
```bash
python main.py run --target example.com --phase recon
python main.py run --target example.com --phase discovery
python main.py run --target example.com --phase scanning
python main.py run --target example.com --phase manual
python main.py run --target example.com --phase report
```

### Regenerate report from existing results
```bash
python main.py report --target example.com
```

### List previously scanned targets
```bash
python main.py list
```

### Print payloads by vulnerability type
```bash
python main.py payloads --type xss
python main.py payloads --type sqli
python main.py payloads --type ssrf
python main.py payloads --type lfi
python main.py payloads --type csrf
python main.py payloads --type ssti
python main.py payloads --type redirect
```

---

## 📁 Project Structure

```
huntkit/
├── main.py                  ← CLI entry point
├── setup.sh                 ← One-shot installer for Kali/Parrot
├── requirements.txt
├── scope.txt.example        ← Sample scope file
│
├── core/
│   ├── recon.py             ← Phase 1: Subdomain enum, DNS, WHOIS
│   ├── discovery.py         ← Phase 2: Ports, live hosts, URL harvesting
│   ├── scanner.py           ← Phase 3: Nuclei, Nikto, custom HTTP checks
│   ├── manual.py            ← Phase 4: Payload gen, param classification
│   └── reporter.py          ← Phase 5: HTML + PDF + Markdown report
│
├── utils/
│   ├── logger.py            ← Colored terminal output + severity banners
│   ├── executor.py          ← Subprocess wrapper with timeout handling
│   └── storage.py           ← Per-target JSON result persistence
│
├── templates/
│   └── report.html          ← Dark-theme Jinja2 report template
│
└── results/
    └── <target>/
        ├── recon.json
        ├── discovery.json
        ├── scanning.json
        ├── manual.json
        ├── payloads.txt     ← Ready-to-use payload reference
        ├── report.html
        ├── report.pdf
        └── report.md
```

---

## 🔬 Phase Breakdown

### Phase 1 — Recon
- Runs `subfinder`, `assetfinder`, and `amass` (passive mode) in parallel
- Resolves all discovered subdomains to IPs via `dnsx` (with Python socket fallback)
- Performs WHOIS lookup for registrar, org, expiry, name servers, and contact emails

### Phase 2 — Asset Discovery
- Port scans resolved IPs with `nmap` (top 1000 ports by default, `-T4 --open`)
- Probes all subdomains over HTTP and HTTPS using `httpx` for status codes, titles, and tech detection
- Harvests historical URLs from Wayback Machine and Common Crawl via `waybackurls` and `gau`
- Categorizes URLs into: `params`, `api`, `admin`, `auth`, `uploads`, `js`, `interesting`

### Phase 3 — Scanning
- Runs `nuclei` with critical/high/medium/low severity filters against all live URLs
- Runs `nikto` on the top live hosts
- Custom Python checks: security headers (CSP, HSTS, X-Frame-Options, etc.), exposed paths (`.env`, `.git/config`, `phpinfo.php`, `backup.zip`, etc.), and server disclosure

### Phase 4 — Manual Testing Aid
- Extracts all unique GET parameters from discovered URLs
- Classifies parameters by likely vulnerability type (SQLi, XSS, SSRF, LFI, SSTI, Open Redirect)
- Generates a CSRF test checklist for all live hosts
- Outputs a `payloads.txt` file containing all payload sets for Burp Suite use

### Phase 5 — Report
- Renders a full dark-themed HTML report with findings table, recon data, URL categories, and tech stack
- Exports to PDF via `weasyprint`, `wkhtmltopdf`, or headless Chromium (auto-detected)
- Generates a Markdown summary compatible with HackerOne/Bugcrowd report submissions

---

## 📄 Scope File Format

```bash
# scope.txt
# Lines starting with # are ignored

example.com
testsite.net
api.anothertarget.com
```

---

## 🧩 Payload Sets

HuntKit ships with built-in payloads for:

| Type | Count |
|------|-------|
| XSS | 12 |
| SQLi (basic + advanced) | 28 |
| SSRF | 15 |
| LFI | 12 |
| Open Redirect | 8 |
| SSTI (multi-engine) | 14 |
| CSRF tips | 8 |

---

## 🔧 Python Dependencies

```
jinja2>=3.1.0        # Report templating
python-whois>=0.8.0  # WHOIS fallback
weasyprint>=60.0     # PDF export (optional)
requests>=2.31.0     # HTTP utilities
```

Install manually:
```bash
pip install -r requirements.txt
```

---

## ⚠️ Legal Disclaimer

HuntKit is intended **exclusively for authorized security testing and bug bounty programs**. Only use this tool against targets you have **explicit written permission** to test. Unauthorized use against systems you do not own or have authorization for is illegal and unethical.

The author is not responsible for any misuse or damage caused by this tool.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add new scanning module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 📬 Contact

**charnyladaro** — [GitHub](https://github.com/charnyladaro)

---

<div align="center">

Made with ☕ and too many open Burp Suite tabs.

⭐ Star this repo if HuntKit helped you find a bug!

</div>

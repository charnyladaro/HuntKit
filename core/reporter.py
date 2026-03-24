"""
Phase 5 - Report Generation
Outputs: HTML report + PDF
"""
import os
import shutil
from datetime import datetime
from pathlib import Path
from utils import logger as log
from utils import storage


def render_html(target: str, all_data: dict) -> str:
    """Render Jinja2 HTML report."""
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        log.error("jinja2 not installed. Run: pip install jinja2")
        return ""

    recon = all_data.get("recon", {})
    discovery = all_data.get("discovery", {})
    scanning = all_data.get("scanning", {})
    manual = all_data.get("manual", {})

    summary = scanning.get("summary", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    total_findings = sum(summary.values())

    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    html = template.render(
        target=target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        recon=recon,
        discovery=discovery,
        scanning=scanning,
        manual=manual,
        summary=summary,
        total_findings=total_findings,
    )
    return html


def save_html(target: str, html: str) -> Path:
    d = storage.get_target_dir(target)
    fp = d / "report.html"
    with open(fp, "w", encoding="utf-8") as f:
        f.write(html)
    return fp


def generate_pdf(html_path: Path) -> Path | None:
    """Convert HTML report to PDF."""
    pdf_path = html_path.with_suffix(".pdf")

    # Try weasyprint
    try:
        import weasyprint
        log.info("Generating PDF with weasyprint...")
        weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path
    except ImportError:
        log.warn("weasyprint not installed, trying wkhtmltopdf...")
    except Exception as e:
        log.warn(f"weasyprint error: {e}, trying wkhtmltopdf...")

    # Try wkhtmltopdf
    if shutil.which("wkhtmltopdf"):
        from utils.executor import run
        rc, _, _ = run(["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)], timeout=60)
        if rc == 0:
            return pdf_path
        log.warn("wkhtmltopdf failed")

    # Try chromium headless
    for chrome_bin in ["chromium-browser", "chromium", "google-chrome", "google-chrome-stable"]:
        if shutil.which(chrome_bin):
            from utils.executor import run
            rc, _, _ = run([
                chrome_bin, "--headless", "--disable-gpu",
                "--no-sandbox",
                f"--print-to-pdf={pdf_path}",
                str(html_path)
            ], timeout=60)
            if rc == 0:
                return pdf_path

    log.warn("No PDF renderer available. Install weasyprint: pip install weasyprint")
    return None


def generate_markdown(target: str, all_data: dict) -> str:
    """Generate a markdown summary report."""
    recon = all_data.get("recon", {})
    discovery = all_data.get("discovery", {})
    scanning = all_data.get("scanning", {})
    summary = scanning.get("summary", {})
    findings = scanning.get("findings", [])

    lines = [
        f"# Bug Bounty Report: {target}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Executive Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {summary.get('critical', 0)} |",
        f"| 🟠 High | {summary.get('high', 0)} |",
        f"| 🟡 Medium | {summary.get('medium', 0)} |",
        f"| 🔵 Low | {summary.get('low', 0)} |",
        f"| ℹ️  Info | {summary.get('info', 0)} |",
        "",
        "## Recon",
        f"- **Subdomains found:** {len(recon.get('subdomains', []))}",
        f"- **Resolved:** {len(recon.get('resolved', {}))}",
    ]

    whois = recon.get("whois", {})
    if whois.get("registrar"):
        lines += [
            f"- **Registrar:** {whois['registrar']}",
            f"- **Org:** {whois.get('org', '—')}",
        ]

    lines += [
        "",
        "## Discovery",
        f"- **Live HTTP(S) hosts:** {len(discovery.get('live_hosts', []))}",
        f"- **URLs discovered:** {len(discovery.get('urls', []))}",
        "",
        "## Findings",
        "",
    ]

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").upper()
        name = f.get("name", "Unknown")
        url = f.get("url", "")
        desc = f.get("description", "")
        lines += [
            f"### [{i}] [{sev}] {name}",
            f"**URL:** `{url}`  ",
            f"**Description:** {desc}",
            f"**Tool:** {f.get('tool', '—')}",
            "",
        ]

    return "\n".join(lines)


def run(target: str, resume: bool = False) -> dict:
    log.banner("REPORT GENERATION", 5)

    all_data = storage.load_all_phases(target)

    results = {
        "target": target,
        "html_path": "",
        "pdf_path": "",
        "md_path": "",
        "generated_at": datetime.now().isoformat(),
    }

    # --- HTML ---
    log.section("Rendering HTML Report")
    html = render_html(target, all_data)
    if html:
        html_path = save_html(target, html)
        results["html_path"] = str(html_path)
        log.success(f"HTML report saved → {html_path}")

        # --- PDF ---
        log.section("Generating PDF")
        pdf_path = generate_pdf(html_path)
        if pdf_path:
            results["pdf_path"] = str(pdf_path)
            log.success(f"PDF report saved → {pdf_path}")
        else:
            log.warn("PDF not generated (no renderer available)")

    # --- Markdown ---
    log.section("Generating Markdown Summary")
    md = generate_markdown(target, all_data)
    d = storage.get_target_dir(target)
    md_path = d / "report.md"
    with open(md_path, "w") as f:
        f.write(md)
    results["md_path"] = str(md_path)
    log.success(f"Markdown report saved → {md_path}")

    storage.save_phase(target, "report_meta", results)
    log.success("Report generation complete ✔")

    # Final summary
    log.divider()
    log.success("All reports saved:")
    log.result_line("HTML", results["html_path"])
    log.result_line("PDF", results.get("pdf_path", "N/A"))
    log.result_line("Markdown", results["md_path"])
    log.divider()

    return results

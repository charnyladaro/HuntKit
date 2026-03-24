#!/usr/bin/env python3
"""
BugHunt Framework — CLI Entry Point
Usage:
    python main.py run --scope scope.txt
    python main.py run --target example.com
    python main.py run --target example.com --phase recon
    python main.py run --scope scope.txt --resume
    python main.py report --target example.com
    python main.py list
    python main.py payloads --type xss
"""
import argparse
import sys
import os
import time
from pathlib import Path
from datetime import datetime

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import logger as log
from utils import storage

PHASES = ["recon", "discovery", "scanning", "manual", "report"]


def run_full_pipeline(target: str, resume: bool = False, phase_filter: str = None, fast_scan: bool = True):
    """Run all 5 phases against a single target."""
    from core import recon, discovery, scanner, manual, reporter

    start_time = time.time()
    log.print_logo()
    log.info(f"Target: {target}")
    log.info(f"Resume mode: {resume}")
    log.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.divider()

    recon_data = {}
    disc_data = {}
    scan_data = {}

    try:
        # Phase 1: Recon
        if not phase_filter or phase_filter == "recon":
            recon_data = recon.run(target, resume=resume)
        else:
            recon_data = storage.load_phase(target, "recon") or {}

        # Phase 2: Discovery
        if not phase_filter or phase_filter == "discovery":
            disc_data = discovery.run(target, recon_data, resume=resume)
        else:
            disc_data = storage.load_phase(target, "discovery") or {}

        # Phase 3: Scanning
        if not phase_filter or phase_filter == "scanning":
            scan_data = scanner.run(target, disc_data, resume=resume)
        else:
            scan_data = storage.load_phase(target, "scanning") or {}

        # Phase 4: Manual Aid
        if not phase_filter or phase_filter == "manual":
            manual.run(target, disc_data, resume=resume)

        # Phase 5: Report
        if not phase_filter or phase_filter == "report":
            reporter.run(target, resume=resume)

    except KeyboardInterrupt:
        log.warn("\nScan interrupted by user. Partial results saved.")
        sys.exit(0)
    except Exception as e:
        log.error(f"Pipeline error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    elapsed = time.time() - start_time
    log.divider()
    log.success(f"Pipeline complete in {elapsed:.0f}s")
    log.success(f"Results in: results/{Path(target).name}/")


def run_from_scope_file(scope_file: str, resume: bool = False, phase_filter: str = None):
    """Run pipeline against all targets in scope file."""
    path = Path(scope_file)
    if not path.exists():
        log.error(f"Scope file not found: {scope_file}")
        sys.exit(1)

    with open(path) as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not targets:
        log.error("No targets found in scope file")
        sys.exit(1)

    log.print_logo()
    log.success(f"Loaded {len(targets)} target(s) from {scope_file}")

    for i, target in enumerate(targets, 1):
        log.divider()
        log.info(f"[{i}/{len(targets)}] Processing: {target}")
        run_full_pipeline(target, resume=resume, phase_filter=phase_filter)


def cmd_list(args):
    """List all previously scanned targets."""
    targets = storage.list_targets()
    if not targets:
        log.info("No targets scanned yet.")
        return

    log.print_logo()
    log.section("Previously Scanned Targets")
    for t in targets:
        phases_done = []
        for phase in PHASES[:-1]:  # skip report
            if storage.phase_done(t, phase):
                phases_done.append(phase)
        findings_count = 0
        scan = storage.load_phase(t, "scanning")
        if scan:
            findings_count = len(scan.get("findings", []))
        log.result_line(t, f"Phases: {', '.join(phases_done)} | Findings: {findings_count}")


def cmd_payloads(args):
    """Print payloads for a given vuln type."""
    from core.manual import (
        XSS_PAYLOADS, SQLI_PAYLOADS, SQLI_PAYLOADS_ADVANCED,
        SSRF_PAYLOADS, LFI_PAYLOADS, OPEN_REDIRECT_PAYLOADS, SSTI_PAYLOADS,
        CSRF_TIPS
    )

    ptype = args.type.lower()
    payload_map = {
        "xss": XSS_PAYLOADS,
        "sqli": SQLI_PAYLOADS + SQLI_PAYLOADS_ADVANCED,
        "ssrf": SSRF_PAYLOADS,
        "lfi": LFI_PAYLOADS,
        "redirect": OPEN_REDIRECT_PAYLOADS,
        "csrf": CSRF_TIPS,
    }

    if ptype == "ssti":
        print(f"\n{log.CYAN}{log.BOLD}SSTI Payloads{log.RESET}\n")
        for engine, payloads in SSTI_PAYLOADS.items():
            log.section(engine)
            for p in payloads:
                print(f"  {p}")
        return

    if ptype not in payload_map:
        log.error(f"Unknown type: {ptype}")
        log.info(f"Available: xss, sqli, ssrf, lfi, redirect, csrf, ssti")
        sys.exit(1)

    payloads = payload_map[ptype]
    print(f"\n{log.CYAN}{log.BOLD}{'─'*40}{log.RESET}")
    print(f"{log.CYAN}{log.BOLD} {ptype.upper()} Payloads ({len(payloads)}){log.RESET}")
    print(f"{log.CYAN}{log.BOLD}{'─'*40}{log.RESET}\n")
    for p in payloads:
        print(p)
    print()


def cmd_report(args):
    """Re-generate report from existing scan data."""
    from core import reporter
    log.print_logo()
    reporter.run(args.target)


def cmd_run(args):
    """Main run command handler."""
    if args.scope:
        run_from_scope_file(args.scope, resume=args.resume, phase_filter=args.phase)
    elif args.target:
        run_full_pipeline(args.target, resume=args.resume, phase_filter=args.phase)
    else:
        log.error("Provide --target or --scope")
        sys.exit(1)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bughunt",
        description="BugHunt Framework — Full-pipeline Bug Bounty Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py run --target example.com
  python main.py run --scope scope.txt
  python main.py run --target example.com --phase recon
  python main.py run --target example.com --resume
  python main.py report --target example.com
  python main.py list
  python main.py payloads --type xss
        """
    )

    subs = parser.add_subparsers(dest="command", required=True)

    # run
    run_p = subs.add_parser("run", help="Run the full pipeline")
    run_group = run_p.add_mutually_exclusive_group()
    run_group.add_argument("--target", "-t", metavar="DOMAIN", help="Single target domain")
    run_group.add_argument("--scope", "-s", metavar="FILE", help="Scope file (one target per line)")
    run_p.add_argument("--phase", "-p", choices=PHASES, metavar="PHASE", help="Run only a specific phase")
    run_p.add_argument("--resume", "-r", action="store_true", help="Skip phases already completed")
    run_p.add_argument("--full-port-scan", action="store_true", help="Full port scan instead of top 1000")
    run_p.set_defaults(func=cmd_run)

    # report
    rpt_p = subs.add_parser("report", help="Generate/regenerate report for a target")
    rpt_p.add_argument("--target", "-t", required=True, metavar="DOMAIN")
    rpt_p.set_defaults(func=cmd_report)

    # list
    lst_p = subs.add_parser("list", help="List previously scanned targets")
    lst_p.set_defaults(func=cmd_list)

    # payloads
    pay_p = subs.add_parser("payloads", help="Print payloads for a given vulnerability type")
    pay_p.add_argument("--type", required=True, choices=["xss","sqli","ssrf","lfi","redirect","csrf","ssti"])
    pay_p.set_defaults(func=cmd_payloads)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

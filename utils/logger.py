import sys
from datetime import datetime

# ANSI colors
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def banner(phase_name: str, phase_num: int, total: int = 5):
    width = 60
    print()
    print(f"{CYAN}{BOLD}{'═' * width}{RESET}")
    print(f"{CYAN}{BOLD}  [{phase_num}/{total}] {phase_name.upper()}{RESET}")
    print(f"{CYAN}{BOLD}{'═' * width}{RESET}")

def info(msg: str):
    print(f"{GRAY}[{_ts()}]{RESET} {BLUE}[*]{RESET} {msg}")

def success(msg: str):
    print(f"{GRAY}[{_ts()}]{RESET} {GREEN}[+]{RESET} {msg}")

def warn(msg: str):
    print(f"{GRAY}[{_ts()}]{RESET} {YELLOW}[!]{RESET} {msg}")

def error(msg: str):
    print(f"{GRAY}[{_ts()}]{RESET} {RED}[-]{RESET} {msg}", file=sys.stderr)

def finding(severity: str, title: str, detail: str = ""):
    colors = {
        "CRITICAL": RED,
        "HIGH":     RED,
        "MEDIUM":   YELLOW,
        "LOW":      BLUE,
        "INFO":     CYAN,
    }
    col = colors.get(severity.upper(), WHITE)
    sev_tag = f"{col}{BOLD}[{severity.upper()}]{RESET}"
    print(f"{GRAY}[{_ts()}]{RESET} {sev_tag} {BOLD}{title}{RESET}")
    if detail:
        print(f"         {GRAY}↳ {detail}{RESET}")

def section(title: str):
    print(f"\n{MAGENTA}{BOLD}  ▶ {title}{RESET}")

def result_line(key: str, val: str):
    print(f"    {CYAN}{key:<25}{RESET} {val}")

def divider():
    print(f"{GRAY}{'─' * 60}{RESET}")

def print_logo():
    logo = f"""
{RED}{BOLD}
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  
{RESET}{CYAN}  Bug Bounty Automation Framework  |  by charnyladaro{RESET}
{GRAY}  Recon → Discovery → Scan → Manual Aid → Report{RESET}
"""
    print(logo)

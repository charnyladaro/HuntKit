#!/usr/bin/env bash
# BugHunt Framework — Setup Script
# Compatible with: Kali Linux, Parrot OS
# Run as: bash setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; }

echo ""
echo -e "${RED}╔══════════════════════════════════════════╗${RESET}"
echo -e "${RED}║     BugHunt Framework — Setup Script     ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════╝${RESET}"
echo ""

# ── Check OS ──────────────────────────────────
if ! command -v apt-get &>/dev/null; then
    error "apt-get not found. This script is for Debian-based systems (Kali/Parrot)."
    exit 1
fi

# ── System packages ───────────────────────────
info "Updating package lists..."
sudo apt-get update -q

info "Installing system dependencies..."
sudo apt-get install -y -q \
    python3 python3-pip python3-venv \
    nmap \
    whois \
    nikto \
    golang-go \
    git \
    curl \
    wget \
    libssl-dev \
    libffi-dev \
    wkhtmltopdf 2>/dev/null || warn "Some packages may have failed"

success "System packages installed"

# ── Go tools ─────────────────────────────────
setup_go() {
    if ! command -v go &>/dev/null; then
        warn "Go not found, some tools will be skipped"
        return 1
    fi
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    return 0
}

if setup_go; then
    info "Installing Go-based tools..."

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        tool_name=$(basename $(echo $tool | cut -d@ -f1))
        if command -v "$tool_name" &>/dev/null; then
            success "$tool_name already installed"
        else
            info "Installing $tool_name..."
            go install "$tool" 2>/dev/null && success "$tool_name installed" || warn "$tool_name failed"
        fi
    done

    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        info "Updating nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || warn "Nuclei template update failed"
        success "Nuclei templates updated"
    fi
fi

# ── Python dependencies ───────────────────────
info "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

info "Installing Python packages..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt && success "Python packages installed" || warn "Some pip packages failed"

# ── amass (optional) ─────────────────────────
if ! command -v amass &>/dev/null; then
    info "Installing amass from apt..."
    sudo apt-get install -y -q amass 2>/dev/null && success "amass installed" || warn "amass install failed (optional)"
fi

# ── Verify installations ──────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║           Installation Summary           ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"

TOOLS=(subfinder assetfinder httpx dnsx nuclei nmap nikto waybackurls gau amass whois)
ALL_OK=true

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✔${RESET} $tool"
    else
        echo -e "  ${YELLOW}✘${RESET} $tool (optional or install failed)"
        if [[ "$tool" =~ ^(subfinder|httpx|nmap|nuclei)$ ]]; then
            ALL_OK=false
        fi
    fi
done

echo ""
if $ALL_OK; then
    success "Core tools are ready! Run: source venv/bin/activate"
    echo ""
    echo -e "  ${CYAN}Quick start:${RESET}"
    echo -e "  ${GREEN}python main.py run --target example.com${RESET}"
    echo -e "  ${GREEN}python main.py run --scope scope.txt${RESET}"
    echo -e "  ${GREEN}python main.py payloads --type xss${RESET}"
    echo -e "  ${GREEN}python main.py list${RESET}"
else
    warn "Some core tools failed. The framework will run with degraded functionality."
    warn "Install missing tools manually and re-run setup.sh"
fi

echo ""

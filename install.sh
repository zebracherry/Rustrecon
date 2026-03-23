#!/usr/bin/env bash
# RustRecon installer for Kali Linux
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "${CYAN}"
cat << 'BANNER'
  ____            _   ____
 |  _ \ _   _ ___| |_|  _ \ ___  ___ ___  _ __
 | |_) | | | / __| __| |_) / _ \/ __/ _ \| '_ \
 |  _ <| |_| \__ \ |_|  _ <  __/ (_| (_) | | | |
 |_| \_\\__,_|___/\__|_| \_\___|\___\___/|_| |_|
BANNER
echo -e "${NC}"
info "RustRecon Installer for Kali Linux"
echo ""

# ── Check we're on Kali ────────────────────────────────────────────────────
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    warn "Not detected as Kali Linux — installer may still work but is untested"
fi

# ── Install binary ─────────────────────────────────────────────────────────
BINARY="./target/release/rustrecon"
if [ ! -f "$BINARY" ]; then
    error "Binary not found at $BINARY — run 'cargo build --release' first"
fi

info "Installing binary to /usr/local/bin/rustrecon"
cp "$BINARY" /usr/local/bin/rustrecon
chmod +x /usr/local/bin/rustrecon
success "Binary installed: $(rustrecon --version)"

# ── apt tools ─────────────────────────────────────────────────────────────
info "Installing apt packages..."
apt-get update -qq 2>/dev/null
PACKAGES=(
    nmap smbclient smbmap enum4linux curl nikto whatweb wpscan
    sslscan dnsrecon dnsenum nbtscan onesixtyone snmp
    ldap-utils redis-tools rpcclient impacket-scripts
    feroxbuster gobuster ffuf
    seclists wordlists
    crackmapexec evil-winrm
)
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "  [already] $pkg"
    else
        apt-get install -y -qq "$pkg" 2>/dev/null && success "$pkg installed" || warn "$pkg failed (may need manual install)"
    fi
done

# ── pip tools ─────────────────────────────────────────────────────────────
info "Installing Python tools..."
PIP_TOOLS=("bloodhound" "impacket")
for tool in "${PIP_TOOLS[@]}"; do
    pip3 install "$tool" -q --break-system-packages 2>/dev/null && success "$tool pip installed" || warn "$tool pip install failed"
done

# ── Check for rustscan ─────────────────────────────────────────────────────
if ! command -v rustscan &>/dev/null; then
    info "Installing rustscan (fast port sweep)..."
    if command -v cargo &>/dev/null; then
        cargo install rustscan --quiet 2>/dev/null && success "rustscan installed" || \
        warn "rustscan install failed — will fall back to nmap sweep"
    else
        warn "cargo not found — install rustscan manually: https://github.com/RustScan/RustScan"
    fi
else
    success "rustscan already installed"
fi

# ── kerbrute ──────────────────────────────────────────────────────────────
if ! command -v kerbrute &>/dev/null; then
    info "Installing kerbrute..."
    KVER=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest 2>/dev/null \
        | grep '"tag_name"' | cut -d'"' -f4)
    if [ -n "$KVER" ]; then
        curl -sL "https://github.com/ropnop/kerbrute/releases/download/${KVER}/kerbrute_linux_amd64" \
            -o /usr/local/bin/kerbrute 2>/dev/null && \
        chmod +x /usr/local/bin/kerbrute && success "kerbrute $KVER installed" || \
        warn "kerbrute download failed"
    else
        warn "Could not fetch kerbrute release — install manually"
    fi
else
    success "kerbrute already installed"
fi

# ── nuclei ────────────────────────────────────────────────────────────────
if ! command -v nuclei &>/dev/null; then
    info "Installing nuclei..."
    if command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        success "nuclei installed" || warn "nuclei install failed"
    else
        warn "go not found — install nuclei manually: https://github.com/projectdiscovery/nuclei"
    fi
else
    success "nuclei already installed"
fi

# ── SecLists check ────────────────────────────────────────────────────────
if [ ! -d "/usr/share/seclists" ]; then
    warn "SecLists not found at /usr/share/seclists"
    info "Installing SecLists..."
    apt-get install -y -qq seclists 2>/dev/null || \
    git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null || \
    warn "SecLists install failed — some scans will use fallback wordlists"
else
    success "SecLists found at /usr/share/seclists"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
success "RustRecon installed! Usage:"
echo ""
echo "  rustrecon 10.10.10.1"
echo "  rustrecon 10.10.10.1 -d corp.local -u admin -p Password1"
echo "  rustrecon 10.10.10.1 --type ad -d corp.local"
echo "  sudo rustrecon 10.10.10.1           # sudo for SYN scan + UDP"
echo "  rustrecon -t targets.txt -m 3"
echo ""
echo -e "${YELLOW}Tip: run as sudo for SYN scanning and UDP enumeration${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

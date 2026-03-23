#!/usr/bin/env bash
# RustRecon uninstaller
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }

echo -e "${CYAN}"
cat << 'BANNER'
  ____            _   ____
 |  _ \ _   _ ___| |_|  _ \ ___  ___ ___  _ __
 | |_) | | | / __| __| |_) / _ \/ __/ _ \| '_ \
 |  _ <| |_| \__ \ |_|  _ <  __/ (_| (_) | | | |
 |_| \_\\__,_|___/\__|_| \_\___|\___\___/|_| |_|
BANNER
echo -e "${NC}"
info "RustRecon Uninstaller"
echo ""

# ── Confirm before doing anything ─────────────────────────────────────────
echo -e "${YELLOW}This will remove:${NC}"
echo "  • /usr/local/bin/rustrecon           (binary)"
echo "  • ~/.config/rustrecon/               (config, if it exists)"
echo ""
echo -e "${YELLOW}This will NOT remove:${NC}"
echo "  • Your results/ directory            (your scan output — kept safe)"
echo "  • System tools installed as deps     (nmap, feroxbuster, etc.)"
echo "    → those are standard Kali tools, removing them could break other things"
echo ""
read -rp "Are you sure you want to uninstall RustRecon? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    info "Uninstall cancelled."
    exit 0
fi
echo ""

# ── Remove binary ──────────────────────────────────────────────────────────
BINARY="/usr/local/bin/rustrecon"
if [ -f "$BINARY" ]; then
    rm -f "$BINARY"
    success "Removed $BINARY"
else
    warn "Binary not found at $BINARY (may have already been removed)"
fi

# ── Remove config directory ────────────────────────────────────────────────
CONFIG_DIR="$HOME/.config/rustrecon"
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    success "Removed $CONFIG_DIR"
else
    info "No config directory found at $CONFIG_DIR — nothing to remove"
fi

# ── Verify removal ─────────────────────────────────────────────────────────
if command -v rustrecon &>/dev/null; then
    error "rustrecon still found in PATH at: $(which rustrecon)"
    echo "  You may need to remove it manually."
    exit 1
else
    success "rustrecon successfully removed from PATH"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
success "RustRecon uninstalled."
echo ""
echo -e "  Your scan results in ${CYAN}results/${NC} are untouched."
echo -e "  To reinstall later: ${CYAN}cargo build --release && sudo ./install.sh${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

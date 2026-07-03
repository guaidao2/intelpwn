#!/usr/bin/env bash
# IntelPwn — dependency installer (Kali/Debian)
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}[+]${NC} ${BOLD}$1${NC}"; }
warn()  { echo -e "${YELLOW}[!]${NC} ${BOLD}$1${NC}"; }

echo -e "${CYAN}
    ╔═══════════════════════════════════════╗
    ║       IntelPwn — Installer             ║
    ║   智能二进制漏洞分析系统               ║
    ╚═══════════════════════════════════════╝${NC}"

# ── System Packages ───────────────────────────────────────────────────
info "Updating package lists (requires sudo)..."
sudo apt update -qq

info "Installing system packages..."
PACKAGES=(
    binutils          # objdump, readelf, strings
    gdb               # crash analysis (cyclic pattern + GEF)
    python3-dev
    python3-pip
    python3-setuptools
    build-essential
    libssl-dev
    libffi-dev
    gcc
    g++
    file
    xxd
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $pkg already installed"
    else
        info "Installing $pkg..."
        sudo apt install -y -qq "$pkg" 2>&1 | tail -1 || warn "Failed to install $pkg"
    fi
done

# ── Python Packages (with fallbacks) ──────────────────────────────────
info "Installing Python packages..."

pip_install() {
    if python3 -c "import $1" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $1 already installed"
    else
        info "Installing $1..."
        python3 -m pip install --quiet "$2" 2>&1 || \
            python3 -m pip install --quiet --user "$2" 2>&1 || \
            python3 -m pip install --quiet --break-system-packages "$2" 2>&1 || \
            warn "pip install $2 failed — try manually"
    fi
}

pip_install pwn       "pwntools>=4.9.0"
pip_install capstone  "capstone>=5.0"

# ── Verify ────────────────────────────────────────────────────────────
echo ""
info "Verifying installation..."
FAIL=0

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1: $(command -v $1)"
    else
        echo -e "  ${RED}✗${NC} $1: NOT FOUND"
        FAIL=1
    fi
}

check_cmd python3
check_cmd gdb
check_cmd objdump
check_cmd readelf

check_mod() {
    if python3 -c "import $1; print(getattr($1, '__version__', 'ok'))" &>/dev/null; then
        local ver=$(python3 -c "import $1; print(getattr($1, '__version__', 'ok'))" 2>/dev/null)
        echo -e "  ${GREEN}✓${NC} python3-$1: $ver"
    else
        echo -e "  ${RED}✗${NC} python3-$1: NOT FOUND"
        FAIL=1
    fi
}

check_mod pwn

if [ "$FAIL" = "0" ]; then
    echo ""
    echo -e "${GREEN}${BOLD}  ✓ All dependencies installed successfully!${NC}"
    echo -e "  Run ${CYAN}python3 intelpwn.py --help${NC} to get started."
else
    echo ""
    echo -e "${RED}${BOLD}  ✗ Some dependencies failed — check output above.${NC}"
fi

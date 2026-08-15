#!/usr/bin/env bash
# IntelPwn — dependency installer (Kali/Debian)
# 安装完成后可直接运行: python3 intelpwn.py analyze <binary>
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
    +=========================================+
    |          IntelPwn - Installer           |
    |       智能二进制漏洞分析系统             |
    +=========================================+${NC}"

# ── System Packages ───────────────────────────────────────────────────
info "Updating package lists (requires sudo)..."
sudo apt update -qq

info "Installing system packages..."
PACKAGES=(
    binutils          # objdump, readelf, strings
    gdb               # crash analysis (cyclic pattern)
    python3-dev
    python3-pip
    python3-setuptools
    build-essential
    libssl-dev
    libffi-dev
    gcc
    g++
    gcc-multilib      # 编译 x86 32 位靶子 (challenge_x86_vuln)
    file
    xxd
    checksec          # ELF 保护检查
    ROPgadget         # ROP gadget 搜索
    ruby              # one_gadget 依赖
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} $pkg already installed"
    else
        info "Installing $pkg..."
        sudo apt install -y -qq "$pkg" 2>&1 | tail -1 || warn "Failed to install $pkg"
    fi
done

# ── Python 依赖 (装入独立 venv, 不污染系统 python) ─────────────────
info "创建隔离 venv (~/.intelpwn-venv, 复用系统 python3 包)..."
if [ -x ~/.intelpwn-venv/bin/python3 ]; then
    echo -e "  ${GREEN}[+]${NC} venv 已存在"
else
    python3 -m venv --system-site-packages ~/.intelpwn-venv || {
        warn "venv 创建失败 — 将回退到系统 python 直接安装"
    }
fi

venv_pip() {
    local mod="$1" pkg="$2"
    if ~/.intelpwn-venv/bin/python -c "import $mod" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} $mod already installed (venv)"
    else
        info "Installing $mod ($pkg) into venv..."
        ~/.intelpwn-venv/bin/pip install --quiet "$pkg" 2>&1 | tail -1 || \
            warn "venv pip install $pkg failed — run manually"
    fi
}

if [ -x ~/.intelpwn-venv/bin/pip ]; then
    venv_pip pwn        "pwntools>=4.9.0"
    venv_pip capstone   "capstone>=5.0"
    venv_pip elftools   "pyelftools>=0.29"

    # angr: 符号执行扩展 (推荐 — 装了才有 angr_check 插件)
    if ~/.intelpwn-venv/bin/python -c "import angr" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} angr already installed (venv)"
    else
        info "Installing angr (符号执行, 推荐 — 体积较大, 请稍候)..."
        ~/.intelpwn-venv/bin/pip install --quiet "angr>=9.2" 2>&1 | tail -2 || \
            warn "angr 安装失败 — 工具仍可用, 仅 angr_check 插件会跳过"
    fi

    # 修正 system-site-packages 的干扰: 按 claripy 要求 pin z3, 并强制 venv 内 unicorn
    REQ_Z3=$(~/.intelpwn-venv/bin/pip show claripy 2>/dev/null | \
             grep -i requires | grep -o 'z3-solver==[0-9.]*' || echo "")
    if [ -n "$REQ_Z3" ]; then
        ~/.intelpwn-venv/bin/pip install --quiet --ignore-installed "$REQ_Z3" 2>&1 | tail -1 || true
    fi
    ~/.intelpwn-venv/bin/pip install --quiet --ignore-installed unicorn 2>&1 | tail -1 || true

    info "venv python 可直接运行: python3 intelpwn.py ... (已自动切换到 venv)"
else
    warn "venv 不可用, 回退到系统 python 安装 (可能触发 PEP 668)"
    pip_install_system() {
        local mod="$1" pkg="$2"
        if python3 -c "import $mod" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}[+]${NC} $mod already installed"
        else
            python3 -m pip install --quiet --break-system-packages "$pkg" 2>&1 | tail -1 || \
                warn "pip install $pkg failed"
        fi
    }
    pip_install_system pwn      "pwntools>=4.9.0"
    pip_install_system capstone "capstone>=5.0"
    pip_install_system elftools "pyelftools>=0.29"
    python3 -c "import angr" &>/dev/null || \
        python3 -m pip install --quiet --break-system-packages "angr>=9.2" 2>&1 | tail -1 || \
        warn "angr 安装失败 — 仅 angr_check 插件会跳过"
fi

# one_gadget: 自动定位 execve 偏移 (可选)
info "Installing one_gadget (可选)..."
if command -v one_gadget &>/dev/null; then
    echo -e "  ${GREEN}[+]${NC} one_gadget already installed"
else
    sudo gem install one_gadget --no-document 2>&1 | tail -1 || \
        warn "one_gadget 安装失败 — 工具会跳过 one_gadget 路径"
fi

# ── Verify ────────────────────────────────────────────────────────────
echo ""
info "Verifying installation..."
FAIL=0

# 模块检查用安装目标 python (venv 优先, 回退系统)
PY=python3
[ -x ~/.intelpwn-venv/bin/python3 ] && PY=~/.intelpwn-venv/bin/python3

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}[+]${NC} $1: $(command -v $1)"
    else
        echo -e "  ${RED}[x]${NC} $1: NOT FOUND"
        FAIL=1
    fi
}

check_cmd python3
check_cmd gdb
check_cmd objdump
check_cmd readelf
check_cmd checksec

check_mod() {
    if "$PY" -c "import $1; print(getattr($1, '__version__', 'ok'))" &>/dev/null; then
        local ver=$("$PY" -c "import $1; print(getattr($1, '__version__', 'ok'))" 2>/dev/null)
        echo -e "  ${GREEN}[+]${NC} python3-$1: $ver"
    else
        echo -e "  ${RED}[x]${NC} python3-$1: NOT FOUND"
        FAIL=1
    fi
}

check_mod pwn
check_mod capstone
check_mod elftools

if "$PY" -c "import angr" &>/dev/null 2>&1; then
    echo -e "  ${GREEN}[+]${NC} python3-angr: $("$PY" -c 'import angr; print(angr.__version__)')"
else
    echo -e "  ${YELLOW}[!]${NC} python3-angr: 未安装 (angr_check 插件将跳过)"
fi

if command -v one_gadget &>/dev/null; then
    echo -e "  ${GREEN}[+]${NC} one_gadget: $(command -v one_gadget)"
else
    echo -e "  ${YELLOW}[!]${NC} one_gadget: 未安装 (ret2libc 模板将跳过 one_gadget 路径)"
fi

if [ "$FAIL" = "0" ]; then
    echo ""
    echo -e "${GREEN}${BOLD}  [+] All dependencies installed successfully!${NC}"
    echo -e "  Run ${CYAN}python3 intelpwn.py --help${NC} to get started."
else
    echo ""
    echo -e "${RED}${BOLD}  [x] Some dependencies failed — check output above.${NC}"
fi

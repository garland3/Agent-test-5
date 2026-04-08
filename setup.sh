#!/usr/bin/env bash
# ============================================================
# setup.sh - Detect distro and install prerequisites
# Supports: Ubuntu (20.04+), RHEL/CentOS/Rocky/Alma (9+)
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ---- Detect distro ----
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop)
                DISTRO_FAMILY="debian"
                DISTRO_NAME="$PRETTY_NAME"
                PKG_MGR="apt"
                ;;
            rhel|centos|rocky|alma|fedora|ol)
                DISTRO_FAMILY="rhel"
                DISTRO_NAME="$PRETTY_NAME"
                PKG_MGR="dnf"
                ;;
            *)
                DISTRO_FAMILY="unknown"
                DISTRO_NAME="$PRETTY_NAME"
                PKG_MGR="unknown"
                ;;
        esac
    else
        DISTRO_FAMILY="unknown"
        DISTRO_NAME="Unknown"
        PKG_MGR="unknown"
    fi
    info "Detected: $DISTRO_NAME (family: $DISTRO_FAMILY)"
}

# ---- Check kernel version ----
check_kernel() {
    local kver
    kver=$(uname -r)
    local major minor
    major=$(echo "$kver" | cut -d. -f1)
    minor=$(echo "$kver" | cut -d. -f2)
    info "Kernel: $kver"

    if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 13 ]; }; then
        warn "Kernel $kver is below 5.13. Landlock will NOT work."
        warn "Seccomp and namespaces should still work."
    else
        ok "Kernel $kver supports Landlock (5.13+)"
    fi
}

# ---- Check kernel config for features ----
check_kernel_features() {
    echo ""
    info "=== Kernel Feature Check ==="

    # Landlock
    if [ -f /sys/kernel/security/landlock/abi_version ]; then
        local abi_ver
        abi_ver=$(cat /sys/kernel/security/landlock/abi_version)
        ok "Landlock: enabled (ABI version $abi_ver)"
    else
        # Check kernel config
        local kconfig="/boot/config-$(uname -r)"
        if [ -f "$kconfig" ]; then
            if grep -q "CONFIG_SECURITY_LANDLOCK=y" "$kconfig"; then
                ok "Landlock: compiled in (but /sys entry missing - may need LSM= boot param)"
            else
                warn "Landlock: NOT enabled in kernel config"
                warn "  On RHEL 9: may need kernel 5.14.0-162+ or a newer kernel"
                warn "  On Ubuntu: usually enabled by default in 22.04+"
            fi
        else
            warn "Landlock: cannot determine (no /sys entry, no kernel config)"
        fi
    fi

    # Seccomp
    local seccomp_status
    seccomp_status=$(grep -c "Seccomp:" /proc/self/status 2>/dev/null || echo "0")
    if [ "$seccomp_status" -gt 0 ]; then
        ok "Seccomp: available"
    else
        warn "Seccomp: NOT available in /proc/self/status"
    fi

    # User namespaces
    local max_userns
    max_userns=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "0")
    if [ "$max_userns" -gt 0 ]; then
        ok "User namespaces: enabled (max=$max_userns)"
    else
        warn "User namespaces: DISABLED (max_user_namespaces=$max_userns)"
        warn "  Fix: sudo sysctl -w user.max_user_namespaces=16384"
        warn "  Persist: echo 'user.max_user_namespaces = 16384' | sudo tee /etc/sysctl.d/99-userns.conf"
    fi

    # Network namespaces
    if unshare --net true 2>/dev/null; then
        ok "Network namespaces: available (unprivileged)"
    else
        warn "Network namespaces: may require privileges or user namespaces"
    fi

    # unshare command
    if command -v unshare &>/dev/null; then
        ok "unshare: $(unshare --version 2>&1 | head -1)"
    else
        fail "unshare: NOT found"
    fi
}

# ---- Install system packages ----
install_system_packages() {
    echo ""
    info "=== Installing System Packages ==="

    case "$DISTRO_FAMILY" in
        debian)
            info "Using apt..."
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                python3 python3-pip python3-venv \
                util-linux iproute2 iptables \
                strace libseccomp-dev \
                build-essential python3-dev
            ok "System packages installed (Ubuntu/Debian)"
            ;;
        rhel)
            info "Using dnf..."
            sudo dnf install -y -q \
                python3 python3-pip python3-devel \
                util-linux iproute iptables-nft \
                strace libseccomp-devel \
                gcc make
            ok "System packages installed (RHEL/CentOS)"
            ;;
        *)
            warn "Unknown distro family. Install manually:"
            warn "  python3, pip, util-linux, iproute2, strace, libseccomp-dev"
            ;;
    esac
}

# ---- Install Python packages ----
install_python_packages() {
    echo ""
    info "=== Installing Python Packages ==="

    # Create venv if it doesn't exist
    local VENV_DIR
    VENV_DIR="$(dirname "$0")/.venv"
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
        info "Created virtual environment at $VENV_DIR"
    fi

    source "$VENV_DIR/bin/activate"

    pip install --upgrade pip -q
    pip install pyyaml landlock -q

    ok "Python packages installed: pyyaml, landlock"
    info "Virtual environment: $VENV_DIR"
    info "Activate with: source $VENV_DIR/bin/activate"
}

# ---- Enable user namespaces if needed (RHEL) ----
enable_user_namespaces() {
    local max_userns
    max_userns=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "0")
    if [ "$max_userns" -eq 0 ]; then
        echo ""
        warn "User namespaces are disabled."
        echo -e "${YELLOW}To enable (requires sudo):${NC}"
        echo "  sudo sysctl -w user.max_user_namespaces=16384"
        echo "  echo 'user.max_user_namespaces = 16384' | sudo tee /etc/sysctl.d/99-userns.conf"
        echo "  sudo sysctl --system"
        echo ""
        read -rp "Enable now? [y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            sudo sysctl -w user.max_user_namespaces=16384
            echo "user.max_user_namespaces = 16384" | sudo tee /etc/sysctl.d/99-userns.conf
            sudo sysctl --system
            ok "User namespaces enabled"
        fi
    fi
}

# ---- Main ----
main() {
    echo "============================================================"
    echo " AI Agent Kernel Security Demo - Setup"
    echo "============================================================"
    echo ""

    detect_distro
    check_kernel
    check_kernel_features

    echo ""
    echo "------------------------------------------------------------"
    read -rp "Install required packages? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        install_system_packages
        install_python_packages
    else
        info "Skipping package installation."
        info "Make sure you have: python3, pip, pyyaml, landlock, util-linux, iproute2"
    fi

    enable_user_namespaces

    echo ""
    echo "============================================================"
    ok "Setup complete! Run the demos with:"
    echo "  ./run_all.sh          # Run all levels with comparison"
    echo "  ./demos/level_0.sh    # Individual level"
    echo "============================================================"
}

main "$@"

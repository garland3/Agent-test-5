#!/usr/bin/env bash
# ============================================================
# Bubblewrap Basic: Filesystem Sandbox
# ============================================================
# Uses bwrap to create a minimal sandbox with:
#   - /usr, /lib, /lib64, /bin, /sbin bound read-only
#   - /etc bound read-only (for DNS, SSL certs, etc.)
#   - workspace directory bound read-write
#   - /proc, /dev minimally available
#   - Network: isolated (--unshare-net, loopback only)
#   - PID namespace: isolated (--unshare-pid)
#   - No /home, /root, /var, /tmp from host
#
# This is the simplest useful bwrap invocation for an agent.
# Near-zero startup overhead compared to Docker/Podman.
#
# Requires: bubblewrap (apt install bubblewrap / dnf install bubblewrap)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " BUBBLEWRAP BASIC: Filesystem Sandbox"
echo "============================================================"
echo " Selective bind mounts — only what the agent needs."
echo " Network isolated (loopback only), PID namespace isolated."
echo "------------------------------------------------------------"

# Check bwrap
if ! command -v bwrap &>/dev/null; then
    echo "ERROR: bubblewrap not installed."
    echo "  Ubuntu: sudo apt install bubblewrap"
    echo "  RHEL:   sudo dnf install bubblewrap"
    exit 1
fi

cd "$PROJECT_DIR"
mkdir -p workspace

echo ""
echo "Bind mounts:"
echo "  RO: /usr /lib /lib64 /bin /sbin /etc"
echo "  RW: workspace/"
echo "  Isolated: /home /root /var /tmp (not visible)"
echo ""

# Find python3 binary — resolve symlinks to get the real path
PYTHON3_REAL=$(readlink -f "$(which python3)")
PYTHON3_DIR=$(dirname "$(dirname "$PYTHON3_REAL")")

bwrap \
    --clearenv \
    --setenv PATH /usr/bin:/bin:/usr/sbin:/sbin \
    --setenv PYTHONUNBUFFERED 1 \
    --setenv HOME /workspace \
    --setenv SANDBOX_DEMO 1 \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind /bin /bin \
    --ro-bind /sbin /sbin \
    --ro-bind /etc /etc \
    --ro-bind "$PROJECT_DIR" /project \
    --bind "$PROJECT_DIR/workspace" /workspace \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --unshare-net \
    --unshare-pid \
    --chdir /workspace \
    -- python3 /project/test_bwrap_agent.py --level bwrap_basic --json

echo ""
echo "Bubblewrap basic demo complete."

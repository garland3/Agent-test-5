#!/usr/bin/env bash
# ============================================================
# Bubblewrap + Seccomp: Filesystem + Syscall Sandbox
# ============================================================
# Layers seccomp on top of bwrap's namespace isolation.
# Bwrap handles: filesystem, PID ns, network ns
# Seccomp handles: blocking dangerous syscalls (ptrace, mount, bpf...)
#
# This is defense-in-depth: even if an agent escapes the
# filesystem sandbox, it can't use dangerous syscalls.
#
# Note: We apply seccomp inside the Python process (not via
# bwrap --seccomp) because our seccomp_helper.py builds the
# BPF filter dynamically and it's easier to debug.
#
# Requires: bubblewrap
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " BUBBLEWRAP + SECCOMP: Filesystem + Syscall Sandbox"
echo "============================================================"
echo " bwrap: filesystem isolation, PID ns, network ns"
echo " seccomp: dangerous syscall blocking (ptrace, mount, bpf...)"
echo "------------------------------------------------------------"

if ! command -v bwrap &>/dev/null; then
    echo "ERROR: bubblewrap not installed."
    exit 1
fi

cd "$PROJECT_DIR"
mkdir -p workspace

echo ""
echo "Layers:"
echo "  1. bwrap  — selective filesystem, isolated PID + network"
echo "  2. seccomp — syscall allowlist (applied inside Python)"
echo ""

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
    -- python3 /project/test_bwrap_agent.py --level bwrap_seccomp --json --seccomp

echo ""
echo "Bubblewrap + seccomp demo complete."

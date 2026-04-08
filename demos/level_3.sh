#!/usr/bin/env bash
# ============================================================
# Level 3: Seccomp Only (Syscall Filtering)
# ============================================================
# Applies a seccomp BPF filter that allows only safe syscalls.
# Dangerous syscalls (ptrace, mount, bpf, etc.) are blocked
# with EPERM.
#
# Uses pure Python/ctypes -- no pip seccomp package needed.
#
# What this blocks:
#   - ptrace (process tracing / debugging)
#   - mount / umount (filesystem manipulation)
#   - bpf (eBPF program loading)
#   - perf_event_open (performance monitoring)
#   - kexec_load (kernel replacement)
#   - init_module / finit_module (kernel module loading)
#   - reboot, swapon/swapoff
#   - io_uring (complex attack surface)
#   - unshare / setns (namespace manipulation)
#
# What this does NOT block:
#   - Filesystem access (can read/write normally)
#   - Network access (full internet)
#   - Normal process operations (fork, exec, etc.)
#
# Note: Seccomp is applied AFTER Python initializes (inside the
# running process) because glibc/Python startup needs syscalls
# that would be blocked by a strict allowlist. This is the
# standard real-world pattern.
#
# Requires: Linux kernel 3.5+ with seccomp support
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 3: Seccomp Only (Syscall Filtering)"
echo "============================================================"
echo " Blocks dangerous syscalls via BPF filter."
echo " Filesystem and network are NOT restricted."
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Run the test agent with --seccomp flag
# Seccomp is applied inside the running Python process, after
# imports are done but before the agent tests execute.
cd workspace
python3 "$PROJECT_DIR/test_agent.py" --level 3 --json --seccomp

echo ""
echo "Level 3 complete."

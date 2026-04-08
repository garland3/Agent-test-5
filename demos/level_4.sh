#!/usr/bin/env bash
# ============================================================
# Level 4: Landlock + Network Namespace (Combined)
# ============================================================
# Combines filesystem restrictions (Landlock) with network
# isolation (netns with only loopback).
#
# What this blocks:
#   - Filesystem: access outside allowed paths
#   - Network: all external connections (only loopback)
#
# What this does NOT block:
#   - Dangerous syscalls (ptrace, mount, etc.)
#   - Process visibility
#
# This is a practical middle-ground for many agent use cases.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 4: Landlock + Network Namespace"
echo "============================================================"
echo " Filesystem restricted via Landlock."
echo " Network isolated to loopback only."
echo " Syscalls are NOT filtered at this level."
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Check user namespaces
if ! unshare --user --map-root-user -- true 2>/dev/null; then
    echo "ERROR: User namespaces not available."
    echo "On RHEL 9: sudo sysctl -w user.max_user_namespaces=16384"
    exit 1
fi

echo "Setting up Landlock + network namespace..."
echo ""

# We apply Landlock in Python, then exec into unshare for netns
# Note: Landlock is applied in the parent, so the child inherits it.
# But unshare replaces the process, so we need to apply Landlock
# INSIDE the namespace instead. We use a two-stage approach:
# 1. unshare creates the namespace
# 2. Python script inside applies Landlock then runs agent

unshare \
    --user --map-root-user \
    --net \
    -- sh -c "
        # Bring up loopback
        ip link set lo up 2>/dev/null || true

        echo '  Network: only loopback'
        echo '  Applying Landlock inside namespace...'
        echo ''

        # Apply Landlock + run agent
        cd '$PROJECT_DIR'
        python3 - <<'INNERPY'
import os
import sys
import yaml
from pathlib import Path

sys.path.insert(0, '$PROJECT_DIR')

try:
    from landlock import Ruleset
except ImportError:
    print('ERROR: pip install landlock')
    sys.exit(1)

# Load config
with open('sandbox_config.yaml') as f:
    config = yaml.safe_load(f)

rs = Ruleset()
for path in config.get('ro_paths', []):
    p = Path(path).resolve()
    if p.exists():
        rs.allow(str(p))
        print(f'  Landlock allowed: {p}')

for path in config.get('rw_paths', []):
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    rs.allow(str(p))
    print(f'  Landlock allowed (RW): {p}')

for extra in ['/proc', '/dev']:
    p = Path(extra)
    if p.exists():
        rs.allow(str(p))

try:
    rs.apply()
    print('  Landlock applied!')
except Exception as e:
    print(f'  Landlock failed: {e}')

print()
os.chdir('workspace')
os.execvp('python3', ['python3', '$PROJECT_DIR/test_agent.py', '--level', '4', '--json'])
INNERPY
    "

echo ""
echo "Level 4 complete."

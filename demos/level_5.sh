#!/usr/bin/env bash
# ============================================================
# Level 5: Full Kernel Sandwich
# ============================================================
# All three layers combined:
#   1. Landlock  - filesystem access control
#   2. netns     - network isolation (loopback only)
#   3. seccomp   - syscall filtering (allowlist)
#
# Plus additional namespace isolation:
#   - User namespace  (unprivileged, maps to root inside)
#   - PID namespace   (isolated process tree)
#   - Mount namespace (private mount table)
#
# This is the maximum unprivileged isolation achievable
# without containers or VMs.
#
# What this blocks:
#   - Filesystem: only allowed paths accessible
#   - Network: only loopback (no internet)
#   - Syscalls: only safe set allowed
#   - PIDs: isolated process tree
#   - Mounts: private mount table
#
# Requires:
#   - Kernel 5.13+ (for Landlock)
#   - user.max_user_namespaces > 0
#   - unshare (util-linux)
#   - pip install landlock pyyaml
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 5: Full Kernel Sandwich"
echo "============================================================"
echo " Landlock (filesystem) + netns (network) + seccomp (syscalls)"
echo " + User/PID/Mount namespaces"
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Check user namespaces
if ! unshare --user --map-root-user -- true 2>/dev/null; then
    echo "ERROR: User namespaces not available."
    echo "On RHEL 9: sudo sysctl -w user.max_user_namespaces=16384"
    exit 1
fi

echo "Creating fully isolated sandbox..."
echo ""

# Full namespace isolation:
#   --user --map-root-user : user namespace
#   --pid --fork           : PID namespace (agent sees itself as PID 1)
#   --mount                : mount namespace (private mounts)
#   --net                  : network namespace (only lo)
unshare \
    --user --map-root-user \
    --pid --fork \
    --mount \
    --net \
    -- sh -c "
        # Inside all namespaces:

        # 1. Network: bring up only loopback
        ip link set lo up 2>/dev/null || true
        echo '  Network namespace: only loopback'

        # 2. Mount namespace: make /proc private so PID ns works correctly
        mount -t proc proc /proc 2>/dev/null || true
        echo '  Mount namespace: private /proc'

        echo '  PID namespace: isolated process tree'
        echo ''

        # 3. Apply Landlock in Python, then run agent with --seccomp flag
        cd '$PROJECT_DIR'
        python3 - <<'INNERPY'
import os
import sys
import yaml
from pathlib import Path

project_dir = '$PROJECT_DIR'
sys.path.insert(0, project_dir)

try:
    from landlock import Ruleset
except ImportError:
    print('ERROR: pip install landlock')
    sys.exit(1)

# --- Landlock ---
print('Applying Landlock filesystem restrictions...')
with open('sandbox_config.yaml') as f:
    config = yaml.safe_load(f)

rs = Ruleset()
for path in config.get('ro_paths', []):
    p = Path(path).resolve()
    if p.exists():
        rs.allow(str(p))
        print(f'  Allowed: {p}')

for path in config.get('rw_paths', []):
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    rs.allow(str(p))
    print(f'  Allowed (RW): {p}')

for extra in ['/proc', '/dev', '$PROJECT_DIR']:
    p = Path(extra)
    if p.exists():
        rs.allow(str(p))

try:
    rs.apply()
    print('  Landlock: applied\n')
except Exception as e:
    print(f'  Landlock: failed ({e})\n')

# --- Seccomp is applied inside the test agent via --seccomp flag ---
# This avoids issues with glibc needing syscalls during execve/import.
print('Launching agent (seccomp will be applied inside)...\n')
os.chdir('workspace')
os.execvp('python3', ['python3', os.path.join(project_dir, 'test_agent.py'),
                       '--level', '5', '--json', '--seccomp'])
INNERPY
    "

echo ""
echo "Level 5 complete. This is the maximum unprivileged sandbox."

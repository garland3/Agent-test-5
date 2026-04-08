#!/usr/bin/env bash
# ============================================================
# Level 2: Network Namespace Only (Network Isolation)
# ============================================================
# Creates a new network namespace with ONLY the loopback
# interface. The agent has no access to the internet or
# any host network interfaces.
#
# What this blocks:
#   - All external network connections
#   - DNS resolution (no nameserver reachable)
#   - Access to host network services
#
# What this does NOT block:
#   - Filesystem access (can read/write anything user can)
#   - Dangerous syscalls
#   - Loopback (127.0.0.1) still works
#
# Requires: unshare (util-linux), user namespaces enabled
#   RHEL 9: sudo sysctl -w user.max_user_namespaces=16384
#   Ubuntu: usually enabled by default
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 2: Network Namespace Only"
echo "============================================================"
echo " Agent runs in an isolated network namespace."
echo " Only loopback (127.0.0.1) is available."
echo " Filesystem and syscalls are NOT restricted."
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Check if user namespaces work
if ! unshare --user --map-root-user -- true 2>/dev/null; then
    echo "ERROR: User namespaces not available."
    echo "On RHEL 9: sudo sysctl -w user.max_user_namespaces=16384"
    echo "On Ubuntu: usually enabled by default"
    exit 1
fi

echo "Creating network namespace with only loopback..."
echo ""

# unshare creates:
#   --user --map-root-user : user namespace (current user mapped to root inside)
#   --net                  : new network namespace (only lo exists, need to bring it up)
unshare \
    --user --map-root-user \
    --net \
    -- sh -c "
        # Inside the new network namespace:
        # Bring up loopback
        ip link set lo up 2>/dev/null || true

        echo '  Network interfaces inside namespace:'
        ip link show 2>/dev/null || echo '  (ip command not available)'
        echo ''

        # Run the test agent
        cd '$PROJECT_DIR/workspace'
        python3 '$PROJECT_DIR/test_agent.py' --level 2 --json
    "

echo ""
echo "Level 2 complete."

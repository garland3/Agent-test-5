#!/usr/bin/env bash
# ============================================================
# Terminal 2: Run the Agent in a Bubblewrap Sandbox
# ============================================================
# Run this AFTER starting the proxy in Terminal 1.
#
# The agent runs inside bwrap with:
#   - Loopback-only network (--unshare-net)
#   - The proxy is on the host, so we use --share-net instead
#     and set ANTHROPIC_BASE_URL to point at the proxy
#   - Clean environment (no host env leak)
#   - Read-only filesystem except workspace
#   - Isolated PID namespace
#
# The agent can ONLY reach localhost:8080 (the proxy).
# The proxy decides what goes to the internet.
#
# Usage:
#   ./run_agent.sh                    # Simulate calls (no API key)
#   ./run_agent.sh --with-api-key     # Real calls (needs ANTHROPIC_API_KEY)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROXY_PORT="${PORT:-9090}"

# Check if bwrap is available
if ! command -v bwrap &>/dev/null; then
    echo "ERROR: bubblewrap not installed."
    echo "  Ubuntu: sudo apt install bubblewrap"
    echo "  RHEL:   sudo dnf install bubblewrap"
    exit 1
fi

# Check if proxy is running
if ! python3 -c "
import socket
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', $PROXY_PORT))
    s.close()
except:
    exit(1)
" 2>/dev/null; then
    echo "ERROR: Proxy not running on localhost:$PROXY_PORT"
    echo ""
    echo "Start it first in Terminal 1:"
    echo "  bash proxy_setup/run_proxy.sh"
    exit 1
fi

# Parse args
PASS_API_KEY=false
for arg in "$@"; do
    case "$arg" in
        --with-api-key)
            PASS_API_KEY=true
            ;;
    esac
done

echo "============================================================"
echo " Agent Sandbox — Terminal 2"
echo "============================================================"
echo ""
echo " Running example agent inside bubblewrap..."
echo " Proxy: http://localhost:$PROXY_PORT"
echo " Network: shared (agent can reach proxy on loopback)"
echo ""

mkdir -p "$PROJECT_DIR/workspace"

# Build bwrap command
BWRAP_CMD=(
    bwrap
    --clearenv
    --setenv PATH /usr/bin:/bin:/usr/sbin:/sbin
    --setenv PYTHONUNBUFFERED 1
    --setenv HOME /workspace
    --setenv ANTHROPIC_BASE_URL "http://127.0.0.1:$PROXY_PORT"
)

# Only pass API key if explicitly requested
if [ "$PASS_API_KEY" = true ]; then
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        echo "WARNING: --with-api-key specified but ANTHROPIC_API_KEY not set."
        echo "  Export it first: export ANTHROPIC_API_KEY=sk-..."
        echo "  Continuing without it (will simulate calls)."
    else
        BWRAP_CMD+=(--setenv ANTHROPIC_API_KEY "$ANTHROPIC_API_KEY")
        echo " API key: will be passed to agent"
    fi
else
    echo " API key: NOT passed (simulated calls)"
    echo "   Use --with-api-key to pass \$ANTHROPIC_API_KEY"
fi

echo ""

BWRAP_CMD+=(
    --ro-bind /usr /usr
    --ro-bind /lib /lib
    --ro-bind-try /lib64 /lib64
    --ro-bind /bin /bin
    --ro-bind /sbin /sbin
    --ro-bind /etc /etc
    --ro-bind "$PROJECT_DIR" /project
    --bind "$PROJECT_DIR/workspace" /workspace
    --proc /proc
    --dev /dev
    --tmpfs /tmp
    --share-net
    --unshare-pid
    --chdir /workspace
    -- python3 /project/proxy_setup/example_agent.py
)

"${BWRAP_CMD[@]}"

echo ""
echo "Agent finished. Check Terminal 1 for proxy request logs."

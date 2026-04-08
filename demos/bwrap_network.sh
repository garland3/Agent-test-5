#!/usr/bin/env bash
# ============================================================
# Bubblewrap + Network Filtering: Domain Whitelist
# ============================================================
# Demonstrates selective network access for sandboxed agents.
#
# Architecture:
#   agent (in bwrap) --share-net--> proxy (on host) --> internet
#
# The agent gets network access, but all HTTP/HTTPS traffic
# is forced through a filtering proxy that only allows
# whitelisted domains. Direct TCP connections to non-proxy
# destinations still work (for defense-in-depth, combine
# with iptables or netns — see comments below).
#
# This demo:
#   1. Starts a Python filtering proxy on 127.0.0.1:8888
#   2. Configures allowed domains: pypi.org, github.com
#   3. Runs the agent inside bwrap with proxy env vars set
#   4. Agent tests various domains — allowed ones succeed,
#      blocked ones get 403
#
# For stronger enforcement (agent can't bypass proxy):
#   Use --unshare-net + veth pair routing only to proxy.
#   This demo uses --share-net for simplicity.
#
# Requires: bubblewrap
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " BUBBLEWRAP + NETWORK: Domain Whitelist via Proxy"
echo "============================================================"
echo " Agent gets network, but HTTP/HTTPS filtered by proxy."
echo " Allowed: pypi.org, github.com"
echo " Blocked: everything else"
echo "------------------------------------------------------------"

if ! command -v bwrap &>/dev/null; then
    echo "ERROR: bubblewrap not installed."
    exit 1
fi

cd "$PROJECT_DIR"
mkdir -p workspace

PROXY_PORT=8888
PROXY_PID=""

cleanup() {
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        echo "  Proxy stopped."
    fi
}
trap cleanup EXIT

# Start the filtering proxy in the background
echo ""
echo "Starting filtering proxy..."
python3 "$PROJECT_DIR/proxy_filter.py" \
    --port "$PROXY_PORT" \
    --allow pypi.org \
    --allow github.com \
    --allow api.github.com \
    &
PROXY_PID=$!

# Wait for proxy to start listening
for i in $(seq 1 20); do
    if python3 -c "
import socket
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(('127.0.0.1', $PROXY_PORT))
    s.close()
    exit(0)
except:
    exit(1)
" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

echo ""
echo "Proxy ready on 127.0.0.1:$PROXY_PORT"
echo "Whitelisted domains: pypi.org, github.com, api.github.com"
echo ""

# Run agent with --share-net (network available) but proxy env vars
# set so urllib/requests/curl use the filtering proxy
bwrap \
    --clearenv \
    --setenv PATH /usr/bin:/bin:/usr/sbin:/sbin \
    --setenv PYTHONUNBUFFERED 1 \
    --setenv HOME /workspace \
    --setenv SANDBOX_DEMO 1 \
    --setenv http_proxy "http://127.0.0.1:$PROXY_PORT" \
    --setenv https_proxy "http://127.0.0.1:$PROXY_PORT" \
    --setenv HTTP_PROXY "http://127.0.0.1:$PROXY_PORT" \
    --setenv HTTPS_PROXY "http://127.0.0.1:$PROXY_PORT" \
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
    --share-net \
    --unshare-pid \
    --chdir /workspace \
    -- python3 /project/test_bwrap_agent.py --level bwrap_network --json

echo ""
echo "Proxy access log:"
echo "  (see output above for [ALLOW]/[DENY] lines)"
echo ""
echo "Bubblewrap + network filtering demo complete."

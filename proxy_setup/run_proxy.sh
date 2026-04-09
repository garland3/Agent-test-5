#!/usr/bin/env bash
# ============================================================
# Terminal 1: Start the LLM API Proxy
# ============================================================
# Run this first, then run_agent.sh in a second terminal.
#
# The proxy listens on localhost:9090 (plain HTTP) and forwards
# to the real LLM API (HTTPS). No TLS issues on the local leg.
#
# Auth header is auto-detected from the upstream URL:
#   - api.anthropic.com → x-api-key
#   - api.openai.com    → Authorization: Bearer
#
# Options:
#   --upstream URL   Which LLM API to forward to
#   --api-key KEY    Inject API key (keeps it out of the sandbox)
#   --port PORT      Local port (default 9090)
#
# Usage:
#   # Anthropic (default):
#   ./run_proxy.sh --api-key $ANTHROPIC_API_KEY
#
#   # OpenAI:
#   ./run_proxy.sh --upstream https://api.openai.com --api-key $OPENAI_API_KEY
#
#   # Agent provides its own key (no injection):
#   ./run_proxy.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
UPSTREAM="${UPSTREAM:-https://api.anthropic.com}"
PORT="${PORT:-9090}"

echo "============================================================"
echo " LLM Proxy — Terminal 1"
echo "============================================================"
echo ""
echo " This proxy sits between the sandboxed agent and the LLM API."
echo " The agent connects via plain HTTP (no TLS issues)."
echo " The proxy connects to the real API via HTTPS."
echo ""
echo " Architecture:"
echo "   agent (bwrap) → http://localhost:$PORT → $UPSTREAM"
echo ""
echo " Now open a SECOND terminal and run:"
echo "   cd $(dirname "$SCRIPT_DIR")"
echo "   bash proxy_setup/run_agent.sh"
echo ""
echo " Press Ctrl+C to stop."
echo "============================================================"
echo ""

python3 "$SCRIPT_DIR/llm_proxy.py" \
    --upstream "$UPSTREAM" \
    --port "$PORT" \
    "$@"

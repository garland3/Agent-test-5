#!/usr/bin/env bash
# ============================================================
# run_cline_sandbox.sh — one-command launcher for the
# cline_sandbox FastAPI wrapper.
#
# Starts:
#   1. The LLM API reverse proxy (proxy_setup/llm_proxy.py) on :9090
#   2. The FastAPI control plane on :8080 (serves the dashboard too)
#
# Both processes are supervised inside the Python launcher, so a
# single Ctrl+C tears everything down cleanly.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v bwrap >/dev/null 2>&1; then
    echo "ERROR: bubblewrap is required." >&2
    echo "  Ubuntu: sudo apt install bubblewrap" >&2
    echo "  RHEL:   sudo dnf install bubblewrap" >&2
    exit 1
fi

# Load a local .env if present (for ANTHROPIC_API_KEY etc.)
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    . .env
    set +a
fi
if [ -f "proxy_setup/.env" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    set -a
    # shellcheck disable=SC1091
    . proxy_setup/.env
    set +a
fi

PY="${PY:-uv run python}"

exec $PY -m cline_sandbox "$@"

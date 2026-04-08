#!/usr/bin/env bash
# ============================================================
# Level 0: No Sandbox (Baseline)
# ============================================================
# Runs the test agent with ZERO restrictions.
# This establishes the baseline: what can an unrestricted
# process do on this system?
#
# Purpose: Compare this output against sandboxed levels to
#          see exactly what each layer blocks.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 0: No Sandbox (Baseline)"
echo "============================================================"
echo " This process runs with NO restrictions."
echo " Everything the test agent tries should succeed"
echo " (except things that require root)."
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Run the test agent directly — no sandbox at all
cd workspace
python3 "$PROJECT_DIR/test_agent.py" --level 0 --json

echo ""
echo "Level 0 complete. This is your unrestricted baseline."

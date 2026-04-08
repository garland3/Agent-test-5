#!/usr/bin/env bash
# ============================================================
# run_all.sh - Run all sandbox levels and produce a comparison
# ============================================================
# Runs levels 0-5, captures JSON results from each, then
# prints a side-by-side comparison showing what each level
# blocks vs allows.
#
# Usage:
#   ./run_all.sh           # Run all levels
#   ./run_all.sh 0 1 3     # Run specific levels only
#   ./run_all.sh --quick   # Skip levels that need namespaces
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/workspace"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Parse arguments ----
LEVELS_TO_RUN=()
QUICK=false

if [ $# -eq 0 ]; then
    LEVELS_TO_RUN=(0 1 2 3 4 5)
else
    for arg in "$@"; do
        case "$arg" in
            --quick)
                QUICK=true
                LEVELS_TO_RUN=(0 1 3)  # Skip namespace-dependent levels
                ;;
            [0-5])
                LEVELS_TO_RUN+=("$arg")
                ;;
            *)
                echo "Usage: $0 [0-5...] [--quick]"
                exit 1
                ;;
        esac
    done
fi

# ---- Preflight checks ----
preflight() {
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} AI Agent Kernel Security Demo - Full Comparison${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    # Detect distro
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "  Distro:  ${CYAN}$PRETTY_NAME${NC}"
    fi
    echo -e "  Kernel:  ${CYAN}$(uname -r)${NC}"
    echo -e "  Python:  ${CYAN}$(python3 --version 2>&1)${NC}"
    echo -e "  Date:    ${CYAN}$(date)${NC}"

    # Check Landlock
    if [ -f /sys/kernel/security/landlock/abi_version ]; then
        echo -e "  Landlock: ${GREEN}ABI v$(cat /sys/kernel/security/landlock/abi_version)${NC}"
    else
        echo -e "  Landlock: ${RED}NOT available (levels 1,4,5 will skip it)${NC}"
    fi

    # Check seccomp
    if grep -q "Seccomp:" /proc/self/status 2>/dev/null; then
        echo -e "  Seccomp:  ${GREEN}available${NC}"
    else
        echo -e "  Seccomp:  ${RED}NOT available${NC}"
    fi

    # Check user namespaces
    local max_userns
    max_userns=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "0")
    if [ "$max_userns" -gt 0 ]; then
        echo -e "  User NS:  ${GREEN}enabled (max=$max_userns)${NC}"
    else
        echo -e "  User NS:  ${RED}DISABLED${NC}"
        echo -e "  ${YELLOW}Levels 2, 4, 5 require user namespaces.${NC}"
        echo -e "  ${YELLOW}Fix: sudo sysctl -w user.max_user_namespaces=16384${NC}"
    fi

    echo ""
}

# ---- Run a single level ----
run_level() {
    local level=$1
    local script="$SCRIPT_DIR/demos/level_${level}.sh"

    if [ ! -f "$script" ]; then
        echo -e "${RED}Script not found: $script${NC}"
        return 1
    fi

    echo -e "\n${BOLD}${CYAN}############################################################${NC}"
    echo -e "${BOLD}${CYAN}# RUNNING LEVEL $level${NC}"
    echo -e "${BOLD}${CYAN}############################################################${NC}\n"

    # Clean previous results
    rm -f "$RESULTS_DIR/results_level_${level}.json"

    # Run the level script, capture output
    local logfile="$RESULTS_DIR/output_level_${level}.log"
    if bash "$script" 2>&1 | tee "$logfile"; then
        echo -e "\n${GREEN}Level $level completed successfully.${NC}"
    else
        echo -e "\n${YELLOW}Level $level exited with errors (see above).${NC}"
    fi

    echo ""
}

# ---- Generate comparison report ----
generate_comparison() {
    echo -e "\n${BOLD}============================================================${NC}"
    echo -e "${BOLD} COMPARISON REPORT${NC}"
    echo -e "${BOLD}============================================================${NC}"

    # Use Python to parse JSON results and build a comparison table
    python3 - "$RESULTS_DIR" "${LEVELS_TO_RUN[@]}" <<'PYEOF'
import json
import os
import sys

results_dir = sys.argv[1]
levels = [int(x) for x in sys.argv[2:]]

# Load results
all_results = {}
for level in levels:
    path = os.path.join(results_dir, f"results_level_{level}.json")
    if os.path.exists(path):
        with open(path) as f:
            all_results[level] = json.load(f)
    else:
        all_results[level] = None

if not any(v is not None for v in all_results.values()):
    print("\n  No JSON results found. Levels may have failed or JSON output was blocked.")
    print("  Check the log files in workspace/output_level_*.log")
    sys.exit(0)

# Collect all unique tests
all_tests = {}
for level, results in all_results.items():
    if results:
        for r in results:
            key = f"{r['category']}/{r['test']}"
            if key not in all_tests:
                all_tests[key] = {"category": r["category"], "test": r["test"]}

# Build comparison table
print()
print(f"{'Test':<55}", end="")
for level in levels:
    print(f" L{level:<5}", end="")
print()
print("-" * (55 + 7 * len(levels)))

current_category = ""
for key in sorted(all_tests.keys()):
    info = all_tests[key]
    cat = info["category"]
    test = info["test"]

    if cat != current_category:
        current_category = cat
        print(f"\n  [{cat.upper()}]")

    # Truncate test name
    display = test[:52] + "..." if len(test) > 55 else test
    print(f"  {display:<53}", end="")

    for level in levels:
        if all_results[level]:
            match = [r for r in all_results[level]
                     if r["category"] == cat and r["test"] == test]
            if match:
                if match[0]["allowed"]:
                    print(f" \033[0;32m OK  \033[0m", end="")
                else:
                    print(f" \033[0;31mBLOCK\033[0m", end="")
            else:
                print(f"  --  ", end="")
        else:
            print(f"  N/A ", end="")
    print()

print()
print("Legend:  OK = operation succeeded (allowed)")
print("       BLOCK = operation was blocked by sandbox")
print()

# Summary
print("Security Score (higher = more restricted):")
for level in levels:
    if all_results[level]:
        total = len(all_results[level])
        blocked = sum(1 for r in all_results[level] if not r["allowed"])
        pct = (blocked / total * 100) if total > 0 else 0
        bar = "#" * int(pct / 2) + "-" * (50 - int(pct / 2))
        print(f"  Level {level}: [{bar}] {pct:.0f}% blocked ({blocked}/{total} tests)")
    else:
        print(f"  Level {level}: [no data]")

print()
PYEOF
}

# ---- Main ----
preflight

# Copy test_agent.py to workspace so it's accessible even under Landlock
cp "$SCRIPT_DIR/test_agent.py" "$RESULTS_DIR/test_agent.py" 2>/dev/null || true

echo -e "Running levels: ${BOLD}${LEVELS_TO_RUN[*]}${NC}"
echo ""

for level in "${LEVELS_TO_RUN[@]}"; do
    run_level "$level"
done

generate_comparison

echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} Demo complete!${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo "  Results:     workspace/results_level_*.json"
echo "  Logs:        workspace/output_level_*.log"
echo ""
echo "  Individual:  ./demos/level_N.sh"
echo "  Setup:       ./setup.sh"
echo ""

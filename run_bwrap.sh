#!/usr/bin/env bash
# ============================================================
# run_bwrap.sh - Run bubblewrap demos and produce a comparison
# ============================================================
# Runs the three bwrap demos (basic, seccomp, network), captures
# JSON results, then prints a side-by-side comparison.
#
# Usage:
#   ./run_bwrap.sh                        # Run all three
#   ./run_bwrap.sh basic seccomp          # Run specific demos
#   ./run_bwrap.sh --no-network           # Skip network demo
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

ALL_DEMOS=(basic seccomp network)
DEMOS_TO_RUN=()

# ---- Parse arguments ----
if [ $# -eq 0 ]; then
    DEMOS_TO_RUN=("${ALL_DEMOS[@]}")
else
    for arg in "$@"; do
        case "$arg" in
            basic|seccomp|network)
                DEMOS_TO_RUN+=("$arg")
                ;;
            --no-network)
                DEMOS_TO_RUN=(basic seccomp)
                ;;
            --help|-h)
                echo "Usage: $0 [basic] [seccomp] [network] [--no-network]"
                echo ""
                echo "Demos:"
                echo "  basic    Filesystem + PID ns + network ns (no internet)"
                echo "  seccomp  Above + seccomp syscall filtering"
                echo "  network  Filesystem + PID ns + domain whitelist via proxy"
                echo ""
                echo "Options:"
                echo "  --no-network  Skip the network demo (requires proxy)"
                exit 0
                ;;
            *)
                echo "Unknown argument: $arg"
                echo "Usage: $0 [basic] [seccomp] [network] [--no-network]"
                exit 1
                ;;
        esac
    done
fi

# ---- Preflight checks ----
preflight() {
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} Bubblewrap Sandbox Demos${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "  Distro:    ${CYAN}$PRETTY_NAME${NC}"
    fi
    echo -e "  Kernel:    ${CYAN}$(uname -r)${NC}"
    echo -e "  Python:    ${CYAN}$(python3 --version 2>&1)${NC}"
    echo -e "  Date:      ${CYAN}$(date)${NC}"

    # Check bubblewrap
    if command -v bwrap &>/dev/null; then
        echo -e "  Bubblewrap: ${GREEN}$(bwrap --version 2>&1)${NC}"
    else
        echo -e "  Bubblewrap: ${RED}NOT installed${NC}"
        echo -e "  ${YELLOW}Install: sudo apt install bubblewrap  (or)  sudo dnf install bubblewrap${NC}"
        exit 1
    fi

    # Check seccomp
    if grep -q "Seccomp:" /proc/self/status 2>/dev/null; then
        echo -e "  Seccomp:   ${GREEN}available${NC}"
    else
        echo -e "  Seccomp:   ${RED}NOT available${NC}"
    fi

    echo ""
}

# ---- Run a single bwrap demo ----
run_demo() {
    local name=$1
    local script="$SCRIPT_DIR/demos/bwrap_${name}.sh"

    if [ ! -f "$script" ]; then
        echo -e "${RED}Script not found: $script${NC}"
        return 1
    fi

    echo -e "\n${BOLD}${CYAN}############################################################${NC}"
    echo -e "${BOLD}${CYAN}# BWRAP DEMO: ${name}${NC}"
    echo -e "${BOLD}${CYAN}############################################################${NC}\n"

    # Clean previous results
    rm -f "$RESULTS_DIR/results_bwrap_${name}.json"

    # Run the demo, capture output
    local logfile="$RESULTS_DIR/output_bwrap_${name}.log"
    if bash "$script" 2>&1 | tee "$logfile"; then
        echo -e "\n${GREEN}bwrap_${name} completed successfully.${NC}"
    else
        echo -e "\n${YELLOW}bwrap_${name} exited with errors (see above).${NC}"
    fi

    echo ""
}

# ---- Generate comparison report ----
generate_comparison() {
    echo -e "\n${BOLD}============================================================${NC}"
    echo -e "${BOLD} BUBBLEWRAP COMPARISON REPORT${NC}"
    echo -e "${BOLD}============================================================${NC}"

    python3 - "$RESULTS_DIR" "${DEMOS_TO_RUN[@]}" <<'PYEOF'
import json
import os
import sys

results_dir = sys.argv[1]
demos = sys.argv[2:]

# Load results
all_results = {}
for name in demos:
    path = os.path.join(results_dir, f"results_bwrap_{name}.json")
    if os.path.exists(path):
        with open(path) as f:
            all_results[name] = json.load(f)
    else:
        all_results[name] = None

if not any(v is not None for v in all_results.values()):
    print("\n  No JSON results found. Demos may have failed.")
    print("  Check the log files in workspace/output_bwrap_*.log")
    sys.exit(0)

# Collect all unique tests across all demos
all_tests = {}
for name, results in all_results.items():
    if results:
        for r in results:
            key = f"{r['category']}/{r['test']}"
            if key not in all_tests:
                all_tests[key] = {"category": r["category"], "test": r["test"]}

# Column headers
col_width = 8
print()
print(f"{'Test':<50}", end="")
for name in demos:
    label = name[:col_width]
    print(f" {label:<{col_width}}", end="")
print()
print("-" * (50 + (col_width + 1) * len(demos)))

current_category = ""
for key in sorted(all_tests.keys()):
    info = all_tests[key]
    cat = info["category"]
    test = info["test"]

    if cat != current_category:
        current_category = cat
        print(f"\n  [{cat.upper()}]")

    display = test[:47] + "..." if len(test) > 50 else test
    print(f"  {display:<48}", end="")

    for name in demos:
        if all_results[name]:
            match = [r for r in all_results[name]
                     if r["category"] == cat and r["test"] == test]
            if match:
                if match[0]["allowed"]:
                    print(f" \033[0;32m  OK   \033[0m", end="")
                else:
                    print(f" \033[0;31m BLOCK \033[0m", end="")
            else:
                print(f"   --   ", end="")
        else:
            print(f"  N/A   ", end="")
    print()

print()
print("Legend:  OK = operation succeeded (allowed)")
print("       BLOCK = operation was blocked by sandbox")
print()

# Security scores
print("Security Score (higher = more restricted):")
for name in demos:
    if all_results[name]:
        total = len(all_results[name])
        blocked = sum(1 for r in all_results[name] if not r["allowed"])
        pct = (blocked / total * 100) if total > 0 else 0
        bar = "#" * int(pct / 2) + "-" * (50 - int(pct / 2))
        print(f"  bwrap_{name:<8}: [{bar}] {pct:.0f}% blocked ({blocked}/{total} tests)")
    else:
        print(f"  bwrap_{name:<8}: [no data]")

# Highlight differences
print()
print("Key differences:")
for key in sorted(all_tests.keys()):
    info = all_tests[key]
    cat = info["category"]
    test = info["test"]
    states = {}
    for name in demos:
        if all_results[name]:
            match = [r for r in all_results[name]
                     if r["category"] == cat and r["test"] == test]
            if match:
                states[name] = "OK" if match[0]["allowed"] else "BLOCK"
    if len(set(states.values())) > 1:
        parts = ", ".join(f"{n}={s}" for n, s in states.items())
        print(f"  {test[:55]}: {parts}")

print()
PYEOF
}

# ---- Main ----
preflight

mkdir -p "$RESULTS_DIR"

echo -e "Running demos: ${BOLD}${DEMOS_TO_RUN[*]}${NC}"
echo ""

for demo in "${DEMOS_TO_RUN[@]}"; do
    run_demo "$demo"
done

generate_comparison

echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} Bubblewrap demos complete!${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo "  Results:     workspace/results_bwrap_*.json"
echo "  Logs:        workspace/output_bwrap_*.log"
echo ""
echo "  Individual:  bash demos/bwrap_basic.sh"
echo "               bash demos/bwrap_seccomp.sh"
echo "               bash demos/bwrap_network.sh"
echo ""
echo "  LLM proxy:   See proxy_setup/README.md"
echo ""

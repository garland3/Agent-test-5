#!/usr/bin/env bash
# ============================================================
# Level 1: Landlock Only (Filesystem Restrictions)
# ============================================================
# Applies Landlock LSM to restrict filesystem access.
# The agent can only access paths listed in sandbox_config.yaml.
#
# What this blocks:
#   - Writing outside the workspace
#   - Reading sensitive files not in the allow list
#   - Accessing paths not explicitly granted
#
# What this does NOT block:
#   - Network access (full internet still available)
#   - Dangerous syscalls (ptrace, mount, etc.)
#   - Process visibility (/proc, other PIDs)
#
# Requires: kernel 5.13+ with CONFIG_SECURITY_LANDLOCK=y
#           pip install landlock pyyaml
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo " LEVEL 1: Landlock Only (Filesystem Restrictions)"
echo "============================================================"
echo " Landlock restricts which files/dirs the process can access."
echo " Network and syscalls are NOT restricted at this level."
echo "------------------------------------------------------------"

cd "$PROJECT_DIR"
mkdir -p workspace

# Use the Python Landlock wrapper to apply restrictions then exec the agent
python3 - <<'PYEOF'
import os
import sys
import yaml
from pathlib import Path

# Add project dir to path
sys.path.insert(0, os.environ.get("PROJECT_DIR", "."))

try:
    from landlock import Ruleset
except ImportError:
    print("ERROR: pip install landlock")
    sys.exit(1)

# Load config
config_path = "sandbox_config.yaml"
with open(config_path) as f:
    config = yaml.safe_load(f)

print("\nApplying Landlock filesystem restrictions...")
rs = Ruleset()

# Allow read-only paths
for path in config.get("ro_paths", []):
    p = Path(path).resolve()
    if p.exists():
        rs.allow(str(p))
        print(f"  Allowed: {p}")

# Allow read-write paths
for path in config.get("rw_paths", []):
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    rs.allow(str(p))
    print(f"  Allowed (RW): {p}")

# Also allow /proc, /dev, and the project dir (for venv) for basic operation
project_dir = os.getcwd()
for extra in ["/proc", "/dev", project_dir]:
    p = Path(extra).resolve()
    if p.exists():
        rs.allow(str(p))

try:
    rs.apply()
    print("Landlock applied successfully!\n")
except Exception as e:
    print(f"Landlock failed: {e}")
    print("Continuing without Landlock (kernel may not support it).\n")

# Now run the test agent (Landlock restrictions are inherited)
project_dir = os.getcwd()
os.chdir("workspace")
agent_path = os.path.join(project_dir, "test_agent.py")
os.execvp("python3", ["python3", agent_path, "--level", "1", "--json"])
PYEOF

echo ""
echo "Level 1 complete."

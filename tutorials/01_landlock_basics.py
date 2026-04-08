#!/usr/bin/env python3
"""
Tutorial 1: Understanding Landlock Filesystem Sandboxing
=========================================================

Landlock is a Linux Security Module (LSM) that lets an UNPRIVILEGED process
restrict its own future filesystem access. Once applied, restrictions:
  - Cannot be loosened
  - Are inherited by child processes
  - Work without root / sudo

This tutorial walks you through Landlock step by step.

Prerequisites:
  - Linux kernel 5.13+ with CONFIG_SECURITY_LANDLOCK=y
  - pip install landlock pyyaml
  - No root needed!

Run this tutorial:
  python3 tutorials/01_landlock_basics.py
"""

import os
import sys
import tempfile
import time

# ================================================================
# EXERCISE 1: Check if Landlock is available
# ================================================================

def exercise_1():
    """
    Before using Landlock, we need to check if the kernel supports it.

    Landlock support depends on:
    1. Kernel version >= 5.13
    2. CONFIG_SECURITY_LANDLOCK=y in kernel config
    3. The landlock LSM being enabled (check /sys/kernel/security/landlock/)

    TRY IT: Run this exercise and see what your system reports.
    """
    print("=" * 60)
    print("EXERCISE 1: Is Landlock available?")
    print("=" * 60)

    # Method 1: Check the sysfs entry
    abi_path = "/sys/kernel/security/landlock/abi_version"
    if os.path.exists(abi_path):
        with open(abi_path) as f:
            version = f.read().strip()
        print(f"  Landlock ABI version: {version}")
        print(f"  Status: AVAILABLE")

        # ABI versions and what they add:
        # v1 (kernel 5.13): Basic filesystem access control
        # v2 (kernel 5.19): File renaming/linking restrictions
        # v3 (kernel 6.2):  File truncation restriction
        # v4 (kernel 6.7):  TCP bind/connect network rules
        # v5 (kernel 6.10): IOCTL restrictions
        print(f"\n  ABI version meanings:")
        print(f"    v1 = filesystem basics (read/write/exec)")
        print(f"    v2 = + file rename/link control")
        print(f"    v3 = + file truncation control")
        print(f"    v4 = + TCP bind/connect rules")
        print(f"    v5 = + IOCTL restrictions")
    else:
        print(f"  Landlock: NOT AVAILABLE on this kernel")
        print(f"  The /sys/kernel/security/landlock/ directory doesn't exist.")
        print(f"\n  Possible fixes:")
        print(f"    - Upgrade kernel to 5.13+")
        print(f"    - Enable CONFIG_SECURITY_LANDLOCK=y")
        print(f"    - Add 'landlock' to the LSM boot parameter")

    # Method 2: Try using the Python library
    print(f"\n  Checking Python landlock library...")
    try:
        from landlock import Ruleset
        print(f"  landlock Python package: installed")
    except ImportError:
        print(f"  landlock Python package: NOT installed")
        print(f"  Fix: pip install landlock")

    print()
    input("Press Enter to continue to Exercise 2...")


# ================================================================
# EXERCISE 2: Your first Landlock sandbox
# ================================================================

def exercise_2():
    """
    Let's create a minimal Landlock sandbox.

    The pattern is always:
    1. Create a Ruleset (starts with everything denied)
    2. Add rules for paths you want to allow
    3. Apply the ruleset (irreversible!)

    IMPORTANT: After apply(), the restrictions are PERMANENT for this
    process and all its children. You can never loosen them.
    That's why we run this in a subprocess.
    """
    print("=" * 60)
    print("EXERCISE 2: Your First Landlock Sandbox")
    print("=" * 60)

    print("""
    We'll demonstrate Landlock by:
    1. Creating a temp file BEFORE sandboxing
    2. Applying Landlock that only allows /tmp and /proc
    3. Trying to read files inside and outside the sandbox

    Since Landlock is irreversible, we run the sandboxed code
    in a subprocess so our tutorial process stays unrestricted.
    """)

    import subprocess

    # Create a test file
    test_file = "/tmp/landlock_tutorial_test.txt"
    with open(test_file, "w") as f:
        f.write("Hello from inside the sandbox!\n")

    # This code runs in a CHILD process with Landlock applied
    child_code = '''
import os
import sys

# ------ STEP 1: Before Landlock ------
print("BEFORE Landlock:")
print(f"  Can read /etc/hostname: ", end="")
try:
    open("/etc/hostname").read()
    print("YES")
except Exception as e:
    print(f"NO ({e})")

# ------ STEP 2: Apply Landlock ------
print("\\nApplying Landlock (allowing only /tmp and /proc)...")
from landlock import Ruleset
rs = Ruleset()
rs.allow("/tmp")     # Allow access to /tmp
rs.allow("/proc")    # Allow access to /proc (needed for basic ops)
rs.apply()           # <-- IRREVERSIBLE from this point!
print("Landlock applied!\\n")

# ------ STEP 3: After Landlock ------
print("AFTER Landlock:")

# This should SUCCEED (we allowed /tmp)
print(f"  Can read /tmp/landlock_tutorial_test.txt: ", end="")
try:
    content = open("/tmp/landlock_tutorial_test.txt").read().strip()
    print(f"YES -> '{content}'")
except Exception as e:
    print(f"NO ({e})")

# This should FAIL (we did NOT allow /etc)
print(f"  Can read /etc/hostname: ", end="")
try:
    open("/etc/hostname").read()
    print("YES  <-- UNEXPECTED! Landlock should have blocked this")
except Exception as e:
    print(f"NO ({type(e).__name__}: {e})")

# This should FAIL (we did NOT allow /usr)
print(f"  Can read /usr/bin/python3: ", end="")
try:
    open("/usr/bin/python3", "rb").read(1)
    print("YES  <-- UNEXPECTED!")
except Exception as e:
    print(f"NO ({type(e).__name__})")

# Write test - should succeed in /tmp
print(f"  Can write /tmp/landlock_output.txt: ", end="")
try:
    with open("/tmp/landlock_output.txt", "w") as f:
        f.write("Written from inside sandbox")
    print("YES")
except Exception as e:
    print(f"NO ({type(e).__name__})")

# Write outside sandbox - should FAIL
print(f"  Can write /var/tmp/escape.txt: ", end="")
try:
    with open("/var/tmp/escape.txt", "w") as f:
        f.write("escape attempt")
    print("YES  <-- UNEXPECTED!")
except Exception as e:
    print(f"NO ({type(e).__name__})")
'''

    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)
    if result.stderr:
        print(f"  [stderr]: {result.stderr.strip()}")

    # Clean up
    os.unlink(test_file)
    try:
        os.unlink("/tmp/landlock_output.txt")
    except FileNotFoundError:
        pass

    print("""
    KEY TAKEAWAY:
    After rs.apply(), the process can ONLY access paths that were
    explicitly allowed. Everything else returns Permission denied.

    The child process was sandboxed, but our tutorial process
    (the parent) is still unrestricted!
    """)

    input("Press Enter to continue to Exercise 3...")


# ================================================================
# EXERCISE 3: The "deny by default" mental model
# ================================================================

def exercise_3():
    """
    Landlock uses a DENY BY DEFAULT model.

    Think of it like a whitelist firewall:
    - Start: everything is denied
    - You explicitly allow specific paths
    - Anything you don't allow stays denied

    This exercise shows what happens with different allow patterns.
    """
    print("=" * 60)
    print("EXERCISE 3: Deny by Default")
    print("=" * 60)

    print("""
    Common patterns for AI agent sandboxing:

    Pattern 1: "Read system, write workspace"
      rs.allow("/usr")           # system binaries (read)
      rs.allow("/lib")           # shared libraries (read)
      rs.allow("/etc")           # config files (read)
      rs.allow("/proc")          # process info
      rs.allow("/dev")           # devices (null, random, etc.)
      rs.allow("./workspace")    # agent workspace (read+write)

    Pattern 2: "Minimal read-only"
      rs.allow("/usr/lib/python3")  # just Python stdlib
      rs.allow("./workspace")       # just the workspace

    Pattern 3: "Almost everything except secrets"
      # Allow everything...
      rs.allow("/")
      # But Landlock can't deny subdirectories after allowing parent!
      # This pattern DOESN'T WORK for exclusions.

    GOTCHA: Landlock is ADDITIVE (allow-only).
    You CANNOT deny a subdirectory after allowing the parent.
    To protect /home/user/.ssh, you must NOT allow /home/user/.
    Instead, allow specific subdirectories you need.
    """)

    print("  Let's test Pattern 1 in a subprocess...\n")

    import subprocess

    child_code = '''
import os, sys
try:
    from landlock import Ruleset
except ImportError:
    print("  ERROR: pip install landlock")
    sys.exit(1)

# Pattern 1: Read system, write workspace
os.makedirs("/tmp/tutorial_workspace", exist_ok=True)
with open("/tmp/tutorial_workspace/data.txt", "w") as f:
    f.write("pre-existing data")

rs = Ruleset()
# System paths (will be effectively read-only for the agent)
for path in ["/usr", "/lib", "/lib64", "/etc", "/proc", "/dev"]:
    if os.path.exists(path):
        rs.allow(path)
# Workspace (read + write)
rs.allow("/tmp/tutorial_workspace")
rs.apply()

# Test results
tests = [
    ("Read /etc/os-release",   lambda: open("/etc/os-release").readline().strip()),
    ("Read /usr/bin/python3",  lambda: "OK" if open("/usr/bin/python3","rb").read(4) else "empty"),
    ("Read workspace file",    lambda: open("/tmp/tutorial_workspace/data.txt").read()),
    ("Write to workspace",     lambda: open("/tmp/tutorial_workspace/output.txt","w").write("new data") and "OK"),
    ("Write to /tmp directly", lambda: open("/tmp/escape.txt","w").write("nope")),
    ("Read /root/.bashrc",     lambda: open("/root/.bashrc").read()),
    ("Read /home",             lambda: str(os.listdir("/home"))),
]

for name, fn in tests:
    try:
        result = fn()
        print(f"    [ALLOWED] {name} -> {str(result)[:50]}")
    except Exception as e:
        print(f"    [BLOCKED] {name} -> {type(e).__name__}")
'''

    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)
    if result.stderr:
        print(f"  [stderr]: {result.stderr.strip()}")

    # Clean up
    import shutil
    shutil.rmtree("/tmp/tutorial_workspace", ignore_errors=True)

    print("""
    EXERCISES FOR YOU:

    1. Modify the child_code above to allow /home but not /root.
       What happens when you try to read files in each?

    2. Try allowing "/" (root). Does it make everything accessible?
       (Hint: yes, because Landlock is additive)

    3. What's the minimum set of paths a Python script needs?
       Try removing /lib from the allow list and see what breaks.
    """)


# ================================================================
# EXERCISE 4: Inheritance - child processes stay sandboxed
# ================================================================

def exercise_4():
    """
    One of Landlock's most important properties: INHERITANCE.

    When you apply Landlock to a process:
    - All child processes (fork/exec) inherit the restrictions
    - Children CANNOT loosen the restrictions
    - Children CAN add MORE restrictions (tighten further)

    This is critical for AI agents that spawn subprocesses
    (running compilers, test suites, shell commands, etc.)
    """
    print("=" * 60)
    print("EXERCISE 4: Inheritance")
    print("=" * 60)

    import subprocess

    child_code = '''
import os, sys, subprocess

try:
    from landlock import Ruleset
except ImportError:
    print("  ERROR: pip install landlock")
    sys.exit(1)

# Apply Landlock in this process
os.makedirs("/tmp/tutorial_inherit", exist_ok=True)
rs = Ruleset()
rs.allow("/tmp/tutorial_inherit")
rs.allow("/usr")
rs.allow("/lib")
rs.allow("/lib64")
rs.allow("/proc")
rs.allow("/dev")
rs.apply()

print("  Parent process: Landlock applied (only /tmp/tutorial_inherit + system)")
print(f"  Parent PID: {os.getpid()}")

# Now spawn a CHILD process - it inherits the Landlock restrictions
grandchild_code = """
import os
print(f"    Child PID: {os.getpid()}")

# Try to escape the sandbox from the child
print(f"    Child can read /tmp/tutorial_inherit: ", end="")
try:
    os.listdir("/tmp/tutorial_inherit")
    print("YES")
except:
    print("NO")

print(f"    Child can read /etc/hostname: ", end="")
try:
    open("/etc/hostname").read()
    print("YES  <-- sandbox escaped!")
except Exception as e:
    print(f"NO (inherited restriction: {type(e).__name__})")

print(f"    Child can write /tmp/outside: ", end="")
try:
    open("/tmp/outside.txt", "w").write("escape")
    print("YES  <-- sandbox escaped!")
except Exception as e:
    print(f"NO (inherited restriction: {type(e).__name__})")
"""

result = subprocess.run(
    [sys.executable, "-c", grandchild_code],
    capture_output=True, text=True, timeout=5
)
print(result.stdout.rstrip())
if result.stderr:
    print(f"    [child stderr]: {result.stderr.strip()}")
'''

    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)
    if result.stderr:
        print(f"  [stderr]: {result.stderr.strip()}")

    # Clean up
    import shutil
    shutil.rmtree("/tmp/tutorial_inherit", ignore_errors=True)

    print("""
    KEY TAKEAWAY:
    The child process inherited the parent's Landlock restrictions.
    It could NOT read /etc/hostname or write outside the allowed paths,
    even though it didn't apply any Landlock rules itself.

    This is why Landlock is great for AI agents: even if the agent
    spawns subprocesses (shell commands, compilers, etc.), they
    ALL stay sandboxed.
    """)


# ================================================================
# Main - Run all exercises
# ================================================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║  Tutorial 1: Understanding Landlock                 ║
    ║  Filesystem Sandboxing for AI Agents                ║
    ╚══════════════════════════════════════════════════════╝

    This tutorial has 4 exercises:
      1. Check if Landlock is available
      2. Your first Landlock sandbox
      3. The "deny by default" mental model
      4. Inheritance - child processes stay sandboxed

    Each exercise runs sandboxed code in a subprocess
    so your tutorial process stays unrestricted.
    """)

    exercises = [exercise_1, exercise_2, exercise_3, exercise_4]

    for i, exercise in enumerate(exercises, 1):
        try:
            exercise()
        except KeyboardInterrupt:
            print(f"\n\nSkipping to next exercise...")
        except Exception as e:
            print(f"\n  Exercise {i} error: {e}")
            print(f"  (This may be expected if Landlock isn't available)\n")

    print("=" * 60)
    print("Tutorial 1 complete!")
    print()
    print("Next: tutorials/02_network_namespaces.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

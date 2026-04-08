#!/usr/bin/env python3
"""
Tutorial 4: Combining Layers - The Kernel Sandwich
====================================================

Each security layer blocks a different category of attack:
  - Landlock: controls WHAT files/dirs the process can access
  - netns:    controls WHERE the process can connect (network)
  - seccomp:  controls HOW the process talks to the kernel (syscalls)

No single layer is sufficient. Together they cover each other's gaps.

This tutorial demonstrates WHY you need all three layers and
how to combine them correctly.

Run this tutorial:
  python3 tutorials/04_combining_layers.py
"""

import os
import sys
import subprocess
import socket


# ================================================================
# EXERCISE 1: Why one layer isn't enough
# ================================================================

def exercise_1():
    """
    Each layer has blind spots. Let's see what each one misses.
    """
    print("=" * 60)
    print("EXERCISE 1: Why One Layer Isn't Enough")
    print("=" * 60)

    print("""
    ┌──────────────────────────────────────────────────────────┐
    │  ATTACK              │ Landlock │ netns │ seccomp        │
    ├──────────────────────┼──────────┼───────┼────────────────┤
    │  Read /etc/shadow    │  BLOCKS  │  ---  │  ---           │
    │  Write outside wdir  │  BLOCKS  │  ---  │  ---           │
    │  Exfiltrate via HTTP │  ---     │ BLOCKS│  ---           │
    │  DNS data leak       │  ---     │ BLOCKS│  ---           │
    │  ptrace other proc   │  ---     │  ---  │  BLOCKS        │
    │  Load kernel module  │  ---     │  ---  │  BLOCKS        │
    │  Mount filesystem    │  ---     │  ---  │  BLOCKS        │
    │  Raw socket (ICMP)   │  ---     │  ---  │  BLOCKS*       │
    │  Symlink escape      │  BLOCKS  │  ---  │  ---           │
    │  Fork bomb           │  ---     │  ---  │  cgroups**     │
    └──────────────────────┴──────────┴───────┴────────────────┘

    *  seccomp can block socket() with SOCK_RAW
    ** fork bombs need cgroups limits (not covered here)

    EXAMPLES OF ESCAPES WITH ONLY ONE LAYER:

    Only Landlock:
      Agent can still connect to the internet, exfiltrate your code
      via HTTP POST to an external server. Landlock doesn't touch
      network at all.

    Only netns:
      Agent can't reach the internet, but can read /etc/shadow,
      ~/.ssh/id_rsa, browser cookies, and write anywhere on disk.

    Only seccomp:
      Agent can still read any file and connect to the internet.
      Seccomp only blocks specific syscalls, not file paths or
      network destinations.
    """)

    input("Press Enter to continue to Exercise 2...")


# ================================================================
# EXERCISE 2: Correct layering order
# ================================================================

def exercise_2():
    """
    The ORDER in which you apply layers matters.
    """
    print("=" * 60)
    print("EXERCISE 2: Correct Layering Order")
    print("=" * 60)

    print("""
    RECOMMENDED ORDER:
    ──────────────────

    1. Create namespaces (user + net + pid + mount)
       WHY FIRST: unshare() requires certain syscalls that
       seccomp might block. Do this before filtering.

    2. Configure network (bring up loopback)
       WHY HERE: needs ip/netlink which may be blocked later.

    3. Apply Landlock (filesystem restrictions)
       WHY BEFORE SECCOMP: Landlock setup uses landlock_*
       syscalls that you might not include in your seccomp
       allowlist.

    4. Apply Seccomp (syscall filtering)
       WHY LAST: Once seccomp is active, it filters ALL
       subsequent syscalls. If you haven't finished setup,
       your setup code might be blocked.

    VISUAL:
    ┌─────────────────────────────────┐
    │ 1. unshare (namespaces)         │  <-- needs clone/unshare syscalls
    │ 2. ip link set lo up            │  <-- needs netlink syscalls
    │ 3. Landlock.apply()             │  <-- needs landlock_* syscalls
    │ 4. seccomp.apply()              │  <-- locks down syscall access
    │ ================================│
    │ 5. Run the AI agent             │  <-- fully sandboxed
    └─────────────────────────────────┘

    COMMON MISTAKE:
    Applying seccomp BEFORE Landlock. If your seccomp filter
    doesn't include landlock_create_ruleset (nr=444),
    landlock_add_rule (nr=445), landlock_restrict_self (nr=446),
    then Landlock setup will fail with EPERM.

    ANOTHER MISTAKE:
    Applying seccomp before creating namespaces. The unshare()
    syscall might be blocked by your seccomp filter.
    """)

    input("Press Enter to continue to Exercise 3...")


# ================================================================
# EXERCISE 3: Live demo - building up layers
# ================================================================

def exercise_3():
    """
    Let's build up layers one at a time and see how the
    security posture improves.
    """
    print("=" * 60)
    print("EXERCISE 3: Building Up Layers (Live Demo)")
    print("=" * 60)

    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Test code that tries several operations
    probe = '''
import socket, os, sys, ctypes

results = []

def test(name, fn):
    try:
        fn()
        results.append(f"  ALLOWED: {name}")
    except Exception as e:
        results.append(f"  BLOCKED: {name} ({type(e).__name__})")

# Filesystem tests
test("Read /etc/shadow",      lambda: open("/etc/shadow").read(1))
test("Write /tmp/escape.txt", lambda: open("/tmp/escape.txt","w").write("x"))

# Network tests
def try_connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect(("8.8.8.8", 53))
    s.close()
test("Connect to internet",   try_connect)

# Syscall tests
def try_mount():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ctypes.set_errno(0)
    ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
    if ctypes.get_errno() != 0:
        raise OSError(ctypes.get_errno(), "mount failed")
test("mount(tmpfs)",           try_mount)

for r in results:
    print(r)
'''

    # --- Layer 0: No sandbox ---
    print("\n  --- Layer 0: No sandbox ---")
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout.rstrip())

    # --- Layer 1: + Landlock ---
    print("\n  --- Layer 1: + Landlock ---")
    landlock_probe = f'''
import sys, os
from pathlib import Path
sys.path.insert(0, "{project_dir}")
try:
    from landlock import Ruleset
    rs = Ruleset()
    for p in ["/usr","/lib","/lib64","/proc","/dev","/etc"]:
        if Path(p).exists(): rs.allow(p)
    # Note: /tmp and workspace NOT allowed
    rs.apply()
except Exception as e:
    print(f"  (Landlock failed: {{e}})")
''' + probe

    result = subprocess.run(
        [sys.executable, "-c", landlock_probe],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout.rstrip())

    # --- Layer 2: + netns ---
    print("\n  --- Layer 2: + Landlock + netns ---")
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         "sh", "-c", f"ip link set lo up 2>/dev/null; {sys.executable} -c '{landlock_probe}'"],
        capture_output=True, text=True, timeout=15
    )
    print(result.stdout.rstrip())

    # --- Layer 3: + seccomp ---
    print("\n  --- Layer 3: + Landlock + netns + seccomp (full sandwich) ---")
    full_probe = f'''
import sys, os
from pathlib import Path
sys.path.insert(0, "{project_dir}")
try:
    from landlock import Ruleset
    rs = Ruleset()
    for p in ["/usr","/lib","/lib64","/proc","/dev","/etc"]:
        if Path(p).exists(): rs.allow(p)
    rs.apply()
except Exception as e:
    print(f"  (Landlock failed: {{e}})")
from seccomp_helper import apply_seccomp_filter, SAFE_SYSCALLS
apply_seccomp_filter(allowed_syscalls=SAFE_SYSCALLS, mode="permissive")
''' + probe

    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         "sh", "-c", f"ip link set lo up 2>/dev/null; {sys.executable} -c '{full_probe}'"],
        capture_output=True, text=True, timeout=15
    )
    print(result.stdout.rstrip())

    print(f"""

    PROGRESSION:
    Layer 0 (none):                All 4 operations may succeed
    Layer 1 (Landlock):            Write blocked, but network+mount work
    Layer 2 (Landlock+netns):      Write+network blocked, mount still works
    Layer 3 (Landlock+netns+secc): ALL dangerous operations blocked!

    Each layer plugs the gaps left by the others.
    """)

    input("Press Enter to continue to Exercise 4...")


# ================================================================
# EXERCISE 4: The full sandwich script
# ================================================================

def exercise_4():
    """
    Putting it all together in a reusable pattern.
    """
    print("=" * 60)
    print("EXERCISE 4: The Full Sandwich Pattern")
    print("=" * 60)

    print("""
    Here's the complete pattern for sandboxing an AI agent:

    ┌─────────────────────────────────────────────────────┐
    │  #!/bin/bash                                        │
    │  # 1. Create isolated namespaces                    │
    │  unshare --user --map-root-user \\                   │
    │          --net \\                                    │
    │          --pid --fork \\                             │
    │          --mount \\                                  │
    │  -- sh -c '                                         │
    │      # 2. Configure network (loopback only)         │
    │      ip link set lo up                              │
    │                                                     │
    │      # 3. Apply Landlock + Seccomp, then run agent  │
    │      python3 sandbox_wrapper.py agent.py             │
    │  '                                                  │
    └─────────────────────────────────────────────────────┘

    Where sandbox_wrapper.py does:
    ┌─────────────────────────────────────────────────────┐
    │  from landlock import Ruleset                       │
    │  from seccomp_helper import apply_seccomp_filter    │
    │                                                     │
    │  # 3a. Landlock (filesystem)                        │
    │  rs = Ruleset()                                     │
    │  rs.allow("/usr")                                   │
    │  rs.allow("/lib")                                   │
    │  rs.allow("./workspace")  # agent workspace         │
    │  rs.apply()                                         │
    │                                                     │
    │  # 3b. Seccomp (syscalls) - MUST BE LAST            │
    │  apply_seccomp_filter(mode="permissive")            │
    │                                                     │
    │  # 3c. Run the agent                                │
    │  os.execvp("python3", ["python3", "agent.py"])      │
    └─────────────────────────────────────────────────────┘

    This is exactly what demos/level_5.sh does!
    Try it:  ./demos/level_5.sh

    The agent runs with:
      - Only allowed filesystem paths accessible
      - Only loopback network
      - Only safe syscalls permitted
      - Isolated PID tree (can't see/signal host processes)
      - Private mount table
      - Non-root on the host (even though UID=0 inside ns)
    """)


# ================================================================
# Main
# ================================================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║  Tutorial 4: Combining Layers                       ║
    ║  The Kernel Sandwich for AI Agent Security           ║
    ╚══════════════════════════════════════════════════════╝

    This tutorial has 4 exercises:
      1. Why one layer isn't enough
      2. Correct layering order
      3. Live demo - building up layers
      4. The full sandwich pattern
    """)

    exercises = [exercise_1, exercise_2, exercise_3, exercise_4]

    for i, exercise in enumerate(exercises, 1):
        try:
            exercise()
        except KeyboardInterrupt:
            print("\n\nSkipping...")
        except Exception as e:
            print(f"\n  Exercise {i} error: {e}\n")

    print("\n" + "=" * 60)
    print("Tutorial 4 complete!")
    print()
    print("Next: tutorials/05_sandbox_your_agent.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

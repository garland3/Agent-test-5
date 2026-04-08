#!/usr/bin/env python3
"""
Tutorial 5: Sandbox Your Own AI Agent
=======================================

This tutorial walks you through adapting the sandbox for YOUR
specific AI agent or application. It covers:

1. Profiling what your agent actually needs
2. Building a minimal sandbox config
3. Debugging sandbox failures
4. Production hardening tips

Run this tutorial:
  python3 tutorials/05_sandbox_your_agent.py
"""

import os
import sys
import subprocess
import shlex


# ================================================================
# EXERCISE 1: Profile your agent's needs
# ================================================================

def exercise_1():
    """
    Before sandboxing, you need to know what your agent does:
    - What files does it read/write?
    - Does it need network access?
    - What syscalls does it use?
    """
    print("=" * 60)
    print("EXERCISE 1: Profile Your Agent's Needs")
    print("=" * 60)

    print("""
    STEP 1: Trace filesystem access
    ────────────────────────────────
    Run your agent with strace to see all file operations:

      strace -f -e trace=openat,access,stat -o /tmp/fs_trace.log \\
          python3 your_agent.py

    Then extract unique paths:

      grep 'openat\\|access' /tmp/fs_trace.log \\
          | grep -oP '"[^"]+"' | sort -u > /tmp/paths_needed.txt

    Common paths your agent will need:
      /usr/lib/python3.*     Python standard library
      /usr/local/lib/python* Pip-installed packages
      /usr/lib/x86_64*/      Shared libraries (libc, libssl, etc.)
      /etc/ssl/              SSL certificates
      /etc/resolv.conf       DNS config (if network allowed)
      /proc/self/            Process self-info
      /dev/null, /dev/urandom  Standard devices


    STEP 2: Trace network access
    ─────────────────────────────
    See what your agent connects to:

      strace -f -e trace=connect,sendto -o /tmp/net_trace.log \\
          python3 your_agent.py

    Questions to answer:
      - Does it need external APIs? (LLM endpoints, etc.)
      - Does it run local servers? (test servers, etc.)
      - Does it do DNS lookups?

    Decision matrix:
      No network needed       -> netns with lo DOWN
      Only loopback            -> netns with lo UP
      Specific endpoints only  -> netns + proxy (advanced)
      Full internet needed     -> no netns (use other layers)


    STEP 3: Trace syscalls
    ──────────────────────
    Get the full syscall profile:

      strace -f -c python3 your_agent.py 2>syscall_summary.txt

    This gives you a table of all syscalls and how often each
    is called. Use this to build your seccomp allowlist.
    """)

    # Let's demo the strace approach
    print("  DEMO: Tracing a simple Python script...\n")
    try:
        result = subprocess.run(
            ["strace", "-f", "-c", sys.executable, "-c",
             "import json; print(json.dumps({'hello': 'world'}))"],
            capture_output=True, text=True, timeout=10
        )
        # Show just the syscall summary
        lines = result.stderr.strip().split("\n")
        for line in lines[-20:]:
            print(f"    {line}")
    except FileNotFoundError:
        print("    (strace not installed - install with: apt/dnf install strace)")

    print()
    input("Press Enter to continue to Exercise 2...")


# ================================================================
# EXERCISE 2: Build your sandbox config
# ================================================================

def exercise_2():
    """
    Now let's build a sandbox_config.yaml for your agent.
    """
    print("=" * 60)
    print("EXERCISE 2: Build Your Sandbox Config")
    print("=" * 60)

    print("""
    Based on your profiling, fill in this template:

    ┌─────────────────────────────────────────────────────────┐
    │  # sandbox_config.yaml                                  │
    │                                                         │
    │  # Paths your agent can READ (system libs, etc.)        │
    │  ro_paths:                                              │
    │    - /usr                   # Python, system binaries   │
    │    - /lib                   # Shared libraries          │
    │    - /lib64                 # Shared libraries (64-bit) │
    │    - /etc                   # Config files              │
    │    # Add your agent's read-only paths here:             │
    │    # - /opt/myapp/models                                │
    │    # - /data/readonly                                   │
    │                                                         │
    │  # Paths your agent can READ AND WRITE                  │
    │  rw_paths:                                              │
    │    - ./workspace            # Agent's working directory │
    │    # Add your agent's write paths here:                 │
    │    # - /tmp/agent-cache                                 │
    │    # - ./output                                         │
    │                                                         │
    │  # Network mode                                         │
    │  network:                                               │
    │    mode: loopback_only      # or: none, filtered        │
    │                                                         │
    │  # Command to run your agent                            │
    │  command:                                               │
    │    - python3                                            │
    │    - your_agent.py                                      │
    │    - --some-flag                                        │
    │                                                         │
    │  working_dir: ./workspace                               │
    │                                                         │
    │  env:                                                   │
    │    PYTHONUNBUFFERED: "1"                                │
    │    # Add your agent's env vars here                     │
    └─────────────────────────────────────────────────────────┘

    TIPS:
    - Start BROAD (allow more paths) and tighten gradually
    - Test each change to make sure your agent still works
    - The workspace should be the ONLY writable path
    """)

    input("Press Enter to continue to Exercise 3...")


# ================================================================
# EXERCISE 3: Debug sandbox failures
# ================================================================

def exercise_3():
    """
    When your agent fails inside the sandbox, here's how to debug it.
    """
    print("=" * 60)
    print("EXERCISE 3: Debugging Sandbox Failures")
    print("=" * 60)

    print("""
    SYMPTOM 1: "Permission denied" or "Operation not permitted"
    ────────────────────────────────────────────────────────────
    Cause: Landlock or seccomp is blocking an operation.

    Debug steps:
    a) Check if it's a FILE operation:
       - Add the path to ro_paths or rw_paths in config
       - Run with strace to see which path: strace -e openat ...

    b) Check if it's a SYSCALL:
       - Switch seccomp to "log" mode (log but don't block)
       - Check dmesg or audit log: dmesg | grep seccomp
       - Add the missing syscall to SAFE_SYSCALLS

    c) Check if it's NETWORK:
       - Try with --net removed from unshare
       - If it works without netns, your agent needs network


    SYMPTOM 2: Agent killed with signal 31 (SIGSYS)
    ─────────────────────────────────────────────────
    Cause: Seccomp in STRICT mode killed the process.

    Fix: Switch to permissive mode first (returns EPERM instead
    of killing). Then find the missing syscall:
      dmesg | grep -i seccomp
    Look for: "seccomp: audit: ... syscall=NNN"
    Map NNN to a name using: ausyscall NNN

    Or use our helper in log mode:
      apply_seccomp_filter(mode="log")  # logs but doesn't block


    SYMPTOM 3: "Cannot allocate TLS block" or "codec" error
    ────────────────────────────────────────────────────────
    Cause: Seccomp applied BEFORE Python finished initializing.

    Fix: Apply seccomp INSIDE the Python process (after all
    imports) using the --seccomp flag in test_agent.py,
    not before execve.


    SYMPTOM 4: "Network is unreachable" for loopback
    ──────────────────────────────────────────────────
    Cause: The loopback interface (lo) wasn't brought up.

    Fix: Add 'ip link set lo up' after entering the netns.
    If 'ip' isn't available, try:
      echo 1 > /proc/sys/net/ipv4/conf/lo/accept_local
    Or install iproute2: apt/dnf install iproute2


    SYMPTOM 5: "unshare: cannot open /proc/self/uid_map"
    ─────────────────────────────────────────────────────
    Cause: User namespaces disabled (common on RHEL 9).

    Fix: sudo sysctl -w user.max_user_namespaces=16384
    """)

    # Live demo: show what dmesg looks like for seccomp violations
    print("  DEMO: Checking for seccomp violations in kernel logs...\n")
    try:
        result = subprocess.run(
            ["dmesg", "--color=never"],
            capture_output=True, text=True, timeout=5
        )
        seccomp_lines = [l for l in result.stdout.split("\n") if "seccomp" in l.lower()]
        if seccomp_lines:
            for line in seccomp_lines[-5:]:
                print(f"    {line}")
        else:
            print("    (no seccomp messages in dmesg - good, no violations)")
    except Exception as e:
        print(f"    (cannot read dmesg: {e})")

    print()
    input("Press Enter to continue to Exercise 4...")


# ================================================================
# EXERCISE 4: Production hardening
# ================================================================

def exercise_4():
    """
    Tips for using this in production.
    """
    print("=" * 60)
    print("EXERCISE 4: Production Hardening")
    print("=" * 60)

    print("""
    HARDENING CHECKLIST:

    [ ] 1. SECCOMP MODE
        Switch from "permissive" to "strict" once your agent runs
        cleanly. Strict mode KILLS the process on violation
        (no chance for the agent to catch the error and try again).

    [ ] 2. RESOURCE LIMITS (cgroups v2)
        Prevent fork bombs and resource exhaustion:
          # Create a cgroup for the agent
          mkdir /sys/fs/cgroup/agent_sandbox
          echo "10" > /sys/fs/cgroup/agent_sandbox/pids.max
          echo "512M" > /sys/fs/cgroup/agent_sandbox/memory.max
          echo "100000 100000" > /sys/fs/cgroup/agent_sandbox/cpu.max

    [ ] 3. TIMEOUT
        Always set a maximum execution time:
          timeout 300 ./demos/level_5.sh
        Or in Python: subprocess.run(..., timeout=300)

    [ ] 4. READ-ONLY ROOT
        If possible, mount the root filesystem read-only:
          unshare --mount -- sh -c '
              mount --bind -o ro / /
              ...'

    [ ] 5. DROP CAPABILITIES
        Even inside a user namespace, drop all capabilities:
          capsh --drop=all -- -c 'your_agent'
        Or in Python after setup:
          prctl(PR_SET_NO_NEW_PRIVS, 1)  # already done by seccomp

    [ ] 6. PRIVATE /tmp
        Give the agent its own /tmp:
          unshare --mount -- sh -c '
              mount -t tmpfs tmpfs /tmp
              ...'

    [ ] 7. SEPARATE USER
        Run the agent as a dedicated non-root user (even before
        the user namespace maps it to root inside).

    [ ] 8. AUDIT LOGGING
        Enable seccomp audit logging in production:
          auditctl -a always,exit -F arch=b64 -S all -F key=seccomp
        Check with: ausearch -k seccomp


    FOR MAXIMUM ISOLATION (beyond this demo):
    ──────────────────────────────────────────
    If you need even stronger isolation:

    - gVisor:    User-space kernel (intercepts ALL syscalls)
    - Firecracker: Lightweight microVM (full VM isolation)
    - Kata:      Container runtime using VMs
    - nsjail:    Google's process isolation tool
    - bubblewrap: Unprivileged container tool (used by Flatpak)

    These provide kernel-level isolation where a kernel zero-day
    can't escape the sandbox (unlike Landlock/seccomp/namespaces
    which all run on the same kernel).
    """)


# ================================================================
# EXERCISE 5: Quick reference
# ================================================================

def exercise_5():
    """
    Quick reference card for sandboxing an AI agent.
    """
    print("=" * 60)
    print("EXERCISE 5: Quick Reference Card")
    print("=" * 60)

    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║  AI AGENT SANDBOX QUICK REFERENCE                       ║
    ╠══════════════════════════════════════════════════════════╣
    ║                                                          ║
    ║  1-LINE SANDBOX (bash):                                  ║
    ║  unshare --user --map-root-user --net --pid --fork \\     ║
    ║    --mount -- sh -c 'ip link set lo up; python3 agent.py'║
    ║                                                          ║
    ║  ADD LANDLOCK (python, before running agent):            ║
    ║    from landlock import Ruleset                          ║
    ║    rs = Ruleset()                                        ║
    ║    rs.allow("/usr"); rs.allow("./workspace")             ║
    ║    rs.apply()                                            ║
    ║                                                          ║
    ║  ADD SECCOMP (python, after imports, before agent runs): ║
    ║    from seccomp_helper import apply_seccomp_filter       ║
    ║    apply_seccomp_filter(mode="permissive")               ║
    ║                                                          ║
    ║  RHEL 9 PREREQUISITE:                                    ║
    ║    sudo sysctl -w user.max_user_namespaces=16384         ║
    ║                                                          ║
    ║  DEBUG:                                                  ║
    ║    strace -f python3 agent.py        # trace syscalls    ║
    ║    dmesg | grep seccomp              # seccomp violations║
    ║    mode="log" in seccomp_helper      # log, don't block  ║
    ║                                                          ║
    ║  RUN ALL DEMOS:                                          ║
    ║    ./run_all.sh                                          ║
    ║                                                          ║
    ║  FILES:                                                  ║
    ║    setup.sh           - Install prerequisites            ║
    ║    sandbox_config.yaml - Configure allowed paths/network ║
    ║    test_agent.py      - Probe that tests all boundaries  ║
    ║    seccomp_helper.py  - Pure-Python seccomp (ctypes/BPF) ║
    ║    demos/level_N.sh   - Individual demo levels (0-5)     ║
    ║    tutorials/         - These tutorials                  ║
    ╚══════════════════════════════════════════════════════════╝
    """)


# ================================================================
# Main
# ================================================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║  Tutorial 5: Sandbox Your Own AI Agent              ║
    ║  From Profiling to Production                       ║
    ╚══════════════════════════════════════════════════════╝

    This tutorial has 5 exercises:
      1. Profile your agent's needs
      2. Build your sandbox config
      3. Debug sandbox failures
      4. Production hardening
      5. Quick reference card
    """)

    exercises = [exercise_1, exercise_2, exercise_3, exercise_4, exercise_5]

    for i, exercise in enumerate(exercises, 1):
        try:
            exercise()
        except KeyboardInterrupt:
            print("\n\nSkipping...")
        except Exception as e:
            print(f"\n  Exercise {i} error: {e}\n")

    print("\n" + "=" * 60)
    print("All tutorials complete!")
    print()
    print("You now understand:")
    print("  1. Landlock  - filesystem access control")
    print("  2. netns     - network isolation")
    print("  3. seccomp   - syscall filtering")
    print("  4. How to combine them (the kernel sandwich)")
    print("  5. How to adapt this for your own agent")
    print()
    print("Run the demos:  ./run_all.sh")
    print("=" * 60)


if __name__ == "__main__":
    main()

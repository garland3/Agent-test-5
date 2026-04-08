#!/usr/bin/env python3
"""
Tutorial 3: Building Seccomp BPF Filters from Scratch
======================================================

Seccomp (Secure Computing) filters syscalls using BPF programs.
Every operation a process does - reading files, opening sockets,
forking - requires a SYSCALL to the kernel. Seccomp lets you
control exactly which syscalls are allowed.

This tutorial builds a seccomp filter from scratch using only
Python ctypes. No external packages needed.

This is the DEEPEST layer of the kernel sandwich:
  - Landlock controls WHAT the process can access (files)
  - Netns controls WHERE the process can connect (network)
  - Seccomp controls HOW the process can talk to the kernel (syscalls)

Prerequisites:
  - Linux kernel 3.5+ (seccomp filter mode)
  - No packages needed (pure ctypes)

Run this tutorial:
  python3 tutorials/03_seccomp_bpf.py
"""

import ctypes
import ctypes.util
import os
import struct
import sys
import subprocess


# ================================================================
# EXERCISE 1: Understanding syscalls
# ================================================================

def exercise_1():
    """
    Every operation a program does ultimately becomes a SYSCALL.
    Let's see which syscalls a simple Python program uses.
    """
    print("=" * 60)
    print("EXERCISE 1: Understanding Syscalls")
    print("=" * 60)

    print("""
    A syscall is a request from a program to the kernel.

    Examples:
      open("/etc/passwd")     -> syscall: openat (nr=257)
      read(fd, buf, count)    -> syscall: read   (nr=0)
      socket(AF_INET, ...)    -> syscall: socket (nr=41)
      fork()                  -> syscall: clone  (nr=56)

    Each syscall has a NUMBER. On x86_64 Linux:
      read    = 0       write   = 1       open    = 2
      close   = 3       stat    = 4       fstat   = 5
      mmap    = 9       mprotect = 10     execve  = 59
      socket  = 41      connect = 42      ptrace  = 101
      mount   = 165     reboot  = 169     bpf     = 321

    Seccomp filters work on these NUMBERS. When a process makes
    a syscall, the kernel checks the seccomp filter to decide:
      ALLOW  = let it through
      ERRNO  = return an error (e.g., EPERM)
      KILL   = terminate the process immediately
      LOG    = allow but log it (for debugging)
    """)

    # Use strace to show syscalls of a simple command
    print("  Let's see what syscalls 'echo hello' uses:\n")
    try:
        result = subprocess.run(
            ["strace", "-c", "-f", sys.executable, "-c", "print('hello')"],
            capture_output=True, text=True, timeout=10
        )
        # Parse the summary table from strace
        lines = result.stderr.strip().split("\n")
        # Find the table header
        in_table = False
        for line in lines:
            if "syscall" in line and "calls" in line:
                in_table = True
                print(f"    {line}")
                continue
            if in_table:
                if line.startswith("--") or line.strip() == "":
                    print(f"    {line}")
                    if "total" in line:
                        break
                    continue
                print(f"    {line}")
    except FileNotFoundError:
        print("    (strace not installed - install with: apt/dnf install strace)")
        print("    Showing common syscalls for a Python 'print(hello)' instead:\n")
        common = [
            ("execve", 59, 1, "Start the Python interpreter"),
            ("openat", 257, 30, "Open Python files, libraries, etc."),
            ("read", 0, 20, "Read file contents"),
            ("write", 1, 2, "Write output to stdout"),
            ("mmap", 9, 25, "Map memory for libraries"),
            ("close", 3, 25, "Close file descriptors"),
            ("fstat", 5, 30, "Get file metadata"),
            ("rt_sigaction", 13, 60, "Set up signal handlers"),
            ("brk", 12, 8, "Allocate heap memory"),
        ]
        print(f"    {'syscall':<18} {'nr':<6} {'~calls':<8} {'purpose'}")
        print(f"    {'-'*18} {'-'*6} {'-'*8} {'-'*30}")
        for name, nr, calls, purpose in common:
            print(f"    {name:<18} {nr:<6} {calls:<8} {purpose}")

    print(f"""
    OBSERVATION:
    Even a simple 'print(hello)' uses ~20+ different syscalls.
    A seccomp filter that's TOO restrictive will crash the program.

    Strategy: ALLOW most safe syscalls, DENY specific dangerous ones.
    """)

    input("Press Enter to continue to Exercise 2...")


# ================================================================
# EXERCISE 2: The BPF filter format
# ================================================================

def exercise_2():
    """
    Seccomp uses BPF (Berkeley Packet Filter) programs to filter
    syscalls. Let's understand the BPF instruction format.
    """
    print("=" * 60)
    print("EXERCISE 2: BPF Filter Format")
    print("=" * 60)

    print("""
    A BPF program is a sequence of INSTRUCTIONS. Each instruction
    is 8 bytes:

    struct sock_filter {
        __u16 code;    // Operation (load, jump, return)
        __u8  jt;      // Jump if TRUE (for conditionals)
        __u8  jf;      // Jump if FALSE
        __u32 k;       // Constant value
    };

    The filter examines a 'seccomp_data' struct for each syscall:

    struct seccomp_data {
        int   nr;               // offset 0: syscall number
        __u32 arch;             // offset 4: architecture
        __u64 instruction_pointer;  // offset 8
        __u64 args[6];          // offset 16: syscall arguments
    };

    Common BPF instructions:
    ─────────────────────────────────────────
    BPF_LD | BPF_W | BPF_ABS    Load 32-bit word from seccomp_data
    BPF_JMP | BPF_JEQ | BPF_K   Jump if equal to constant
    BPF_RET | BPF_K              Return (allow/deny/kill)
    """)

    # Build a simple BPF program and explain each instruction
    print("  Example: Block only the 'mount' syscall (nr=165)\n")

    # Constants
    BPF_LD  = 0x00; BPF_W = 0x00; BPF_ABS = 0x20
    BPF_JMP = 0x05; BPF_JEQ = 0x10; BPF_K = 0x00
    BPF_RET = 0x06

    SECCOMP_RET_ALLOW = 0x7FFF0000
    SECCOMP_RET_ERRNO = 0x00050000 | 1  # Return EPERM

    AUDIT_ARCH_X86_64 = 0xC000003E
    OFFSET_ARCH = 4
    OFFSET_NR = 0
    MOUNT_NR = 165

    instructions = []

    # Instruction 0: Load architecture
    code = BPF_LD | BPF_W | BPF_ABS
    inst = struct.pack("HBBI", code, 0, 0, OFFSET_ARCH)
    instructions.append(inst)
    print(f"    [0] LOAD arch from seccomp_data[4]")
    print(f"        code=0x{code:04x} jt=0 jf=0 k={OFFSET_ARCH}")

    # Instruction 1: Check architecture (must be x86_64)
    code = BPF_JMP | BPF_JEQ | BPF_K
    inst = struct.pack("HBBI", code, 1, 0, AUDIT_ARCH_X86_64)
    instructions.append(inst)
    print(f"    [1] JUMP if arch == x86_64: skip 1 (to [3])")
    print(f"        if arch != x86_64: fall through to [2] (kill)")

    # Instruction 2: Kill if wrong architecture
    code = BPF_RET | BPF_K
    inst = struct.pack("HBBI", code, 0, 0, 0x80000000)  # KILL_PROCESS
    instructions.append(inst)
    print(f"    [2] RETURN KILL_PROCESS (wrong architecture)")

    # Instruction 3: Load syscall number
    code = BPF_LD | BPF_W | BPF_ABS
    inst = struct.pack("HBBI", code, 0, 0, OFFSET_NR)
    instructions.append(inst)
    print(f"    [3] LOAD syscall number from seccomp_data[0]")

    # Instruction 4: Check if it's mount (165)
    code = BPF_JMP | BPF_JEQ | BPF_K
    inst = struct.pack("HBBI", code, 0, 1, MOUNT_NR)
    instructions.append(inst)
    print(f"    [4] JUMP if nr == 165 (mount): fall through to [5] (deny)")
    print(f"        if nr != 165: skip 1 to [6] (allow)")

    # Instruction 5: Return ERRNO for mount
    code = BPF_RET | BPF_K
    inst = struct.pack("HBBI", code, 0, 0, SECCOMP_RET_ERRNO)
    instructions.append(inst)
    print(f"    [5] RETURN ERRNO(1) (EPERM - mount blocked)")

    # Instruction 6: Allow everything else
    code = BPF_RET | BPF_K
    inst = struct.pack("HBBI", code, 0, 0, SECCOMP_RET_ALLOW)
    instructions.append(inst)
    print(f"    [6] RETURN ALLOW (everything else passes)")

    prog = b"".join(instructions)
    print(f"\n    Total: {len(instructions)} instructions, {len(prog)} bytes")
    print(f"    Raw bytes: {prog.hex()}")

    print(f"""
    FLOW:
    syscall arrives -> check arch -> load syscall nr
    -> is it mount? -> YES: EPERM
                    -> NO:  ALLOW

    This is a DENYLIST approach (block specific syscalls).
    The opposite (ALLOWLIST) blocks everything by default
    and only allows specific syscalls. An allowlist is safer
    but harder to get right.
    """)

    input("Press Enter to continue to Exercise 3...")


# ================================================================
# EXERCISE 3: Apply a seccomp filter
# ================================================================

def exercise_3():
    """
    Now let's actually APPLY a seccomp filter and see it work.
    We'll block mount, ptrace, and reboot using pure ctypes.
    """
    print("=" * 60)
    print("EXERCISE 3: Apply a Seccomp Filter")
    print("=" * 60)

    print("  We'll apply a denylist filter in a subprocess and test it.\n")

    child_code = '''
import ctypes
import ctypes.util
import os
import struct
import sys

# ---- Constants ----
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

BPF_LD  = 0x00; BPF_W = 0x00; BPF_ABS = 0x20
BPF_JMP = 0x05; BPF_JEQ = 0x10; BPF_K = 0x00
BPF_RET = 0x06

SECCOMP_RET_ALLOW        = 0x7FFF0000
SECCOMP_RET_ERRNO_EPERM  = 0x00050000 | 1
SECCOMP_RET_KILL_PROCESS = 0x80000000

AUDIT_ARCH_X86_64 = 0xC000003E

# Syscalls we want to block
BLOCKED = {
    "ptrace":  101,
    "mount":   165,
    "reboot":  169,
    "bpf":     321,
}

# ---- Build BPF program ----
instructions = []

def stmt(code, k):
    return struct.pack("HBBI", code, 0, 0, k)

def jump(code, k, jt, jf):
    return struct.pack("HBBI", code, jt, jf, k)

# 1. Load arch, verify x86_64
instructions.append(stmt(BPF_LD | BPF_W | BPF_ABS, 4))
instructions.append(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0))
instructions.append(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

# 2. Load syscall number
instructions.append(stmt(BPF_LD | BPF_W | BPF_ABS, 0))

# 3. For each blocked syscall, add a check
blocked_list = list(BLOCKED.values())
for i, nr in enumerate(blocked_list):
    # If this syscall matches, jump to the DENY return
    # jt = (len(blocked_list) - i) = distance to DENY instruction
    # jf = 0 = continue to next check
    instructions.append(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, len(blocked_list) - i, 0))

# 4. Default: ALLOW
instructions.append(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

# 5. DENY return (reached by jump from any blocked syscall)
instructions.append(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_EPERM))

prog_bytes = b"".join(instructions)
n_inst = len(instructions)

print(f"  Built BPF filter: {n_inst} instructions, {len(prog_bytes)} bytes")
print(f"  Blocking: {list(BLOCKED.keys())}")

# ---- Apply the filter ----

class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                 ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort),
                 ("filter", ctypes.POINTER(SockFilter))]

FilterArray = SockFilter * n_inst
filters = FilterArray()
for i in range(n_inst):
    offset = i * 8
    code, jt, jf, k = struct.unpack("HBBI", prog_bytes[offset:offset+8])
    filters[i].code = code
    filters[i].jt = jt
    filters[i].jf = jf
    filters[i].k = k

prog = SockFprog()
prog.len = n_inst
prog.filter = ctypes.cast(filters, ctypes.POINTER(SockFilter))

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Step 1: PR_SET_NO_NEW_PRIVS (required before seccomp)
ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
if ret != 0:
    print(f"  ERROR: PR_SET_NO_NEW_PRIVS failed: errno={ctypes.get_errno()}")
    sys.exit(1)
print("  Set NO_NEW_PRIVS: OK")

# Step 2: Install the filter
ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
if ret != 0:
    print(f"  ERROR: PR_SET_SECCOMP failed: errno={ctypes.get_errno()}")
    sys.exit(1)
print("  Seccomp filter installed: OK")

# Check /proc/self/status
with open("/proc/self/status") as f:
    for line in f:
        if line.startswith("Seccomp"):
            print(f"  {line.strip()}")

# ---- Test the filter ----
print("\\n  --- Testing blocked syscalls ---")

# Test mount (should fail with EPERM)
print("  mount('/tmp/test_mnt', tmpfs): ", end="")
ctypes.set_errno(0)
ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
errno = ctypes.get_errno()
if ret == -1 and errno == 1:
    print(f"BLOCKED (EPERM) - seccomp working!")
elif ret == -1:
    print(f"BLOCKED (errno={errno})")
else:
    print("ALLOWED - seccomp NOT working!")

# Test ptrace (should fail with EPERM)
print("  ptrace(PEEKDATA, self): ", end="")
ctypes.set_errno(0)
ret = libc.ptrace(2, os.getpid(), 0, 0)  # PTRACE_PEEKDATA
errno = ctypes.get_errno()
if errno == 1:
    print(f"BLOCKED (EPERM) - seccomp working!")
elif errno != 0:
    print(f"BLOCKED (errno={errno})")
else:
    print("ALLOWED")

# Test normal operations (should still work)
print("\\n  --- Testing allowed syscalls ---")
print(f"  getpid(): {os.getpid()} - OK")
print(f"  getcwd(): {os.getcwd()} - OK")
try:
    open("/etc/hostname").read()
    print(f"  open(/etc/hostname): OK")
except Exception as e:
    print(f"  open(/etc/hostname): {e}")
'''

    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)
    if result.returncode != 0 and result.stderr:
        print(f"  [stderr]: {result.stderr.strip()[:200]}")

    print("""
    KEY TAKEAWAYS:
    1. PR_SET_NO_NEW_PRIVS must be set FIRST (prevents privilege escalation)
    2. The BPF filter runs in kernel space - very fast, ~zero overhead
    3. Blocked syscalls return EPERM (not crash, in permissive mode)
    4. Normal operations (file I/O, memory, etc.) are unaffected
    5. The filter is INHERITED by child processes

    IMPORTANT: We used a DENYLIST (block specific syscalls).
    An ALLOWLIST (only permit specific syscalls) is stronger
    but requires knowing exactly which syscalls your program needs.
    """)

    input("Press Enter to continue to Exercise 4...")


# ================================================================
# EXERCISE 4: Allowlist vs Denylist
# ================================================================

def exercise_4():
    """
    Two strategies for seccomp filtering:

    DENYLIST: Allow everything, block specific dangerous syscalls
      + Easy to set up
      + Won't break your program
      - New/unknown syscalls are allowed by default
      - Less secure (you might miss something)

    ALLOWLIST: Block everything, allow only what's needed
      + Maximum security (unknown syscalls blocked)
      + Defense against new kernel syscalls
      - Hard to get right (programs need many syscalls)
      - May break programs if you miss a needed syscall

    Real-world choice depends on your threat model.
    """
    print("=" * 60)
    print("EXERCISE 4: Allowlist vs Denylist")
    print("=" * 60)

    print("""
    DENYLIST approach (what we did in Exercise 3):
    ──────────────────────────────────────────────
    Default: ALLOW everything
    Block: ptrace, mount, reboot, bpf, kexec_load, ...

    Good for: "I trust the program but want to prevent specific
    dangerous operations"

    Example use: Sandboxing an AI coding agent that needs to
    run compilers, test suites, etc. You don't know exactly
    which syscalls gcc or pytest will use, but you know you
    want to prevent ptrace/mount/bpf.


    ALLOWLIST approach (used in our seccomp_helper.py):
    ──────────────────────────────────────────────────
    Default: KILL or ERRNO for everything
    Allow: read, write, openat, close, mmap, brk, ...
    (~150 syscalls typically needed for Python + shell)

    Good for: "I don't trust this program. Only let it do
    the bare minimum."

    Example use: Running completely untrusted code from an
    AI agent's output. You only allow file I/O, memory
    management, and basic process control.


    COMPARISON:
    ┌─────────────┬────────────────┬────────────────────┐
    │             │ Denylist       │ Allowlist           │
    ├─────────────┼────────────────┼────────────────────┤
    │ Default     │ ALLOW          │ KILL/ERRNO          │
    │ Ease        │ Easy           │ Hard                │
    │ Safety      │ Moderate       │ High                │
    │ Breakage    │ Low            │ High (if incomplete)│
    │ New syscalls│ Auto-allowed   │ Auto-blocked        │
    │ Debugging   │ Simple         │ Use LOG mode first  │
    └─────────────┴────────────────┴────────────────────┘
    """)

    print("  TIP: To build an allowlist, use this workflow:")
    print("""
    1. Run your program with strace to capture all syscalls:
       strace -f -c python3 your_agent.py 2>syscalls.log

    2. Extract the unique syscall names from the output

    3. Start with SECCOMP_RET_LOG mode (log but don't block)
       to verify your list is complete

    4. Switch to SECCOMP_RET_ERRNO for testing (returns EPERM)

    5. Finally, switch to SECCOMP_RET_KILL_PROCESS for production
       (immediately terminates on violation)
    """)

    input("Press Enter to continue to Exercise 5...")


# ================================================================
# EXERCISE 5: The seccomp_helper.py deep dive
# ================================================================

def exercise_5():
    """
    Our project includes seccomp_helper.py - a complete implementation.
    Let's walk through how it works.
    """
    print("=" * 60)
    print("EXERCISE 5: Using seccomp_helper.py")
    print("=" * 60)

    # Check if seccomp_helper is available
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, project_dir)

    try:
        from seccomp_helper import (
            apply_seccomp_filter, get_seccomp_status,
            SAFE_SYSCALLS, DANGEROUS_SYSCALLS,
            build_allowlist_filter
        )
        print("  seccomp_helper.py loaded successfully!\n")
    except ImportError:
        print("  Could not import seccomp_helper.py")
        print(f"  Expected at: {project_dir}/seccomp_helper.py")
        return

    print(f"  SAFE_SYSCALLS count:      {len(SAFE_SYSCALLS)}")
    print(f"  DANGEROUS_SYSCALLS count: {len(DANGEROUS_SYSCALLS)}")
    print(f"\n  Dangerous syscalls that will be blocked:")
    for sc in DANGEROUS_SYSCALLS:
        print(f"    - {sc}")

    print(f"""
    The seccomp_helper.py provides:

    1. apply_seccomp_filter(allowed_syscalls, mode)
       - mode="strict":     KILL on violation
       - mode="permissive": EPERM on violation
       - mode="log":        log but allow (for debugging)

    2. get_seccomp_status()
       - Returns dict with current seccomp mode and filter count

    3. SAFE_SYSCALLS
       - Pre-built list of ~150 syscalls needed for Python + shell

    4. DANGEROUS_SYSCALLS
       - List of syscalls you should block for AI agents

    5. build_allowlist_filter(allowed, default_action)
       - Returns raw BPF program bytes

    USAGE IN YOUR OWN CODE:
    ────────────────────────
    from seccomp_helper import apply_seccomp_filter, SAFE_SYSCALLS

    # Apply before running untrusted code
    apply_seccomp_filter(
        allowed_syscalls=SAFE_SYSCALLS,
        mode="permissive"  # start here, switch to "strict" later
    )

    # Now dangerous syscalls return EPERM
    # ptrace, mount, bpf, kexec_load etc. are all blocked
    """)

    # Quick demo
    print("  Quick demo (in subprocess):\n")

    child_code = f'''
import sys
sys.path.insert(0, "{project_dir}")
from seccomp_helper import apply_seccomp_filter, get_seccomp_status, SAFE_SYSCALLS
import ctypes, os

print(f"    Before: {{get_seccomp_status()}}")
apply_seccomp_filter(allowed_syscalls=SAFE_SYSCALLS, mode="permissive")
print(f"    After:  {{get_seccomp_status()}}")

# Test: mount should fail
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ctypes.set_errno(0)
libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
errno = ctypes.get_errno()
print(f"    mount() errno: {{errno}} (1=EPERM=blocked)")

# Test: normal ops should work
print(f"    getpid(): {{os.getpid()}} (still works)")
'''

    result = subprocess.run(
        [sys.executable, "-c", child_code],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)


# ================================================================
# Main
# ================================================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║  Tutorial 3: Building Seccomp BPF Filters           ║
    ║  Syscall Filtering for AI Agent Containment          ║
    ╚══════════════════════════════════════════════════════╝

    This tutorial has 5 exercises:
      1. Understanding syscalls (what are they?)
      2. BPF filter format (how filters are structured)
      3. Apply a seccomp filter (block mount/ptrace/reboot)
      4. Allowlist vs Denylist strategies
      5. Using our seccomp_helper.py
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
    print("Tutorial 3 complete!")
    print()
    print("Next: tutorials/04_combining_layers.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Pure-Python seccomp filter using ctypes + prctl + BPF.

No pip packages needed. Works on any Linux with kernel 3.5+ and seccomp support.
This uses seccomp mode 2 (BPF filter) via prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...).

Reference:
  - https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
  - <linux/seccomp.h>, <linux/filter.h>, <linux/audit.h>

Supports x86_64 only. Extend AUDIT_ARCH and syscall numbers for other architectures.
"""

import ctypes
import ctypes.util
import os
import struct
import sys

# ---- Constants ----

# prctl operations
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22

# Seccomp modes
SECCOMP_MODE_FILTER = 2

# Seccomp return values (32-bit)
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD  = 0x00000000
SECCOMP_RET_ERRNO        = 0x00050000  # | errno value
SECCOMP_RET_LOG          = 0x7FFC0000  # log but allow (for debugging)
SECCOMP_RET_ALLOW        = 0x7FFF0000

# BPF instruction classes
BPF_LD   = 0x00
BPF_JMP  = 0x05
BPF_RET  = 0x06

# BPF sizes
BPF_W = 0x00  # 32-bit word

# BPF sources
BPF_ABS = 0x20  # absolute offset
BPF_K   = 0x00  # constant

# BPF jump codes
BPF_JEQ = 0x10

# Architecture
AUDIT_ARCH_X86_64 = 0xC000003E

# seccomp_data offsets (struct seccomp_data in <linux/seccomp.h>)
# struct seccomp_data {
#     int   nr;         // offset 0:  syscall number
#     __u32 arch;       // offset 4:  architecture
#     __u64 instruction_pointer;  // offset 8
#     __u64 args[6];    // offset 16: syscall arguments
# };
OFFSET_NR   = 0
OFFSET_ARCH = 4

# ---- x86_64 Syscall Numbers ----
# From: /usr/include/asm/unistd_64.h or ausyscall --dump
SYSCALL_NUMBERS_X86_64 = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4,
    "fstat": 5, "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9,
    "mprotect": 10, "munmap": 11, "brk": 12, "rt_sigaction": 13,
    "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
    "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
    "access": 21, "pipe": 22, "select": 23, "sched_yield": 24,
    "mremap": 25, "msync": 26, "mincore": 27, "madvise": 28,
    "dup": 32, "dup2": 33, "pause": 34, "nanosleep": 35,
    "getitimer": 36, "alarm": 37, "setitimer": 38, "getpid": 39,
    "sendfile": 40, "socket": 41, "connect": 42, "accept": 43,
    "sendto": 44, "recvfrom": 45, "sendmsg": 46, "recvmsg": 47,
    "shutdown": 48, "bind": 49, "listen": 50, "getsockname": 51,
    "getpeername": 52, "socketpair": 53, "setsockopt": 54,
    "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58,
    "execve": 59, "exit": 60, "wait4": 61, "kill": 62,
    "uname": 63, "fcntl": 64, "flock": 73, "fsync": 74,
    "fdatasync": 75, "truncate": 76, "ftruncate": 77,
    "getdents": 78, "getcwd": 79, "chdir": 80, "fchdir": 81,
    "rename": 82, "mkdir": 83, "rmdir": 84, "creat": 85,
    "link": 86, "unlink": 87, "symlink": 88, "readlink": 89,
    "chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93,
    "lchown": 94, "umask": 95, "gettimeofday": 96,
    "getrlimit": 97, "getrusage": 98, "sysinfo": 99,
    "times": 100, "ptrace": 101, "getuid": 102, "getgid": 104,
    "setuid": 105, "setgid": 106, "geteuid": 107, "getegid": 108,
    "gettid": 186,
    "setpgid": 109, "getppid": 110, "getpgrp": 111, "setsid": 112,
    "setreuid": 113, "setregid": 114, "getgroups": 115,
    "setgroups": 116, "setresuid": 117, "getresuid": 118,
    "setresgid": 119, "getresgid": 120, "getpgid": 121,
    "setfsuid": 122, "setfsgid": 123, "getsid": 124,
    "capget": 125, "capset": 126, "sigaltstack": 131,
    "personality": 135, "exit_group": 231, "epoll_wait": 232,
    "epoll_ctl": 233, "tgkill": 234, "utimes": 235,
    "openat": 257, "mkdirat": 258, "fchownat": 260,
    "newfstatat": 262, "unlinkat": 263, "renameat": 264,
    "linkat": 265, "symlinkat": 266, "readlinkat": 267,
    "fchmodat": 268, "faccessat": 269, "pselect6": 270,
    "ppoll": 271, "set_robust_list": 273, "get_robust_list": 274,
    "splice": 275, "tee": 276, "sync_file_range": 277,
    "epoll_pwait": 281, "signalfd": 282, "timerfd_create": 283,
    "eventfd": 284, "fallocate": 285, "timerfd_settime": 286,
    "timerfd_gettime": 287, "accept4": 288, "signalfd4": 289,
    "eventfd2": 290, "epoll_create1": 291, "dup3": 292,
    "pipe2": 293, "inotify_init1": 294, "preadv": 295,
    "pwritev": 296, "recvmmsg": 299, "clock_gettime": 228,
    "clock_nanosleep": 230, "clock_getres": 229,
    "prlimit64": 302, "sendmmsg": 307,
    "getrandom": 318, "memfd_create": 319,
    "statx": 332, "rseq": 334,
    "close_range": 436, "openat2": 437, "faccessat2": 439,
    # glibc / threading / dynamic linker essentials
    "arch_prctl": 158, "set_tid_address": 218, "futex": 202,
    "sched_getaffinity": 204, "sched_setaffinity": 203,
    "set_thread_area": 205, "get_thread_area": 211,
    "prctl": 157, "mlock": 149, "munlock": 150,
    "mlock2": 325, "copy_file_range": 326,
    "getdents64": 217, "fadvise64": 221,
    "epoll_create": 213, "waitid": 247,
    "kcmp": 312, "sched_getparam": 143, "sched_setparam": 142,
    "sched_getscheduler": 145, "sched_setscheduler": 144,
    "sched_get_priority_max": 146, "sched_get_priority_min": 147,
    # Dangerous ones we want to identify
    "mount": 165, "umount2": 166, "pivot_root": 155,
    "kexec_load": 246, "kexec_file_load": 320,
    "bpf": 321, "perf_event_open": 298,
    "userfaultfd": 323, "init_module": 175,
    "finit_module": 313, "delete_module": 176,
    "reboot": 169, "swapon": 167, "swapoff": 168, "acct": 163,
    "unshare": 272, "setns": 308, "clone3": 435,
    "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427,
    # Additional escape / privilege-escalation primitives
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "process_vm_readv": 310, "process_vm_writev": 311,
    "process_madvise": 440,
    "move_mount": 429, "open_tree": 428, "fsopen": 430,
    "fsconfig": 431, "fsmount": 432, "fspick": 433,
    "mount_setattr": 442,
    "pidfd_send_signal": 424, "pidfd_open": 434, "pidfd_getfd": 438,
    "seccomp": 317, "modify_ldt": 154,
    "iopl": 172, "ioperm": 173,
    "create_module": 174, "query_module": 178, "get_kernel_syms": 177,
    "quotactl": 179, "quotactl_fd": 443,
    "name_to_handle_at": 303, "open_by_handle_at": 304,
    "fanotify_init": 300, "fanotify_mark": 301,
    "lookup_dcookie": 212,
}

# ---- BPF Instruction Builder ----

def bpf_stmt(code, k):
    """Build a BPF statement (no jumps)."""
    # struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };
    return struct.pack("HBBI", code, 0, 0, k)


def bpf_jump(code, k, jt, jf):
    """Build a BPF jump instruction."""
    return struct.pack("HBBI", code, jt, jf, k)


# ---- Predefined Syscall Sets ----

# Minimal set for a typical Python/shell agent
SAFE_SYSCALLS = [
    # File I/O
    "read", "write", "open", "openat", "close", "fstat", "newfstatat", "statx",
    "lstat", "stat", "lseek", "pread64", "pwrite64", "readv", "writev",
    "access", "faccessat", "faccessat2",
    # Memory
    "mmap", "mprotect", "munmap", "brk", "mremap", "madvise",
    # Signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
    # Process basics
    "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
    "getppid", "getpgrp", "getpgid", "getsid",
    "exit", "exit_group",
    # Directories
    "getdents", "getcwd", "chdir", "fchdir",
    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
    "rename", "renameat",
    # File metadata
    "fcntl", "flock", "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "fchownat", "lchown",
    "link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat",
    "umask", "truncate", "ftruncate", "fallocate",
    # Pipes, sockets (for loopback)
    "pipe", "pipe2", "dup", "dup2", "dup3",
    "socket", "connect", "accept", "accept4", "bind", "listen",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "shutdown", "setsockopt", "getsockopt", "getsockname", "getpeername",
    "socketpair",
    # Polling / events
    "select", "pselect6", "poll", "ppoll",
    "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "eventfd", "eventfd2", "signalfd", "signalfd4",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "inotify_init1",
    # Process control (limited)
    "clone", "clone3", "fork", "vfork", "execve", "wait4",
    "kill", "tgkill",
    "set_robust_list", "get_robust_list", "rseq",
    # Time
    "nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres",
    "gettimeofday", "getitimer", "setitimer", "alarm",
    # System info
    "uname", "sysinfo", "getrlimit", "prlimit64", "getrusage", "times",
    # Misc
    "ioctl", "getrandom", "personality",
    "capget", "splice", "tee", "sendfile",
    "fsync", "fdatasync", "sync_file_range",
    "creat", "close_range", "openat2",
    "memfd_create",  # needed by some Python internals
    "setpgid", "setsid",
    # glibc / threading / dynamic linker essentials
    "arch_prctl", "set_tid_address", "futex",
    "sched_getaffinity", "sched_setaffinity",
    "prctl", "mlock", "munlock", "mlock2",
    "getdents64", "fadvise64",
    "epoll_create", "waitid",
    "copy_file_range",
    "sched_getparam", "sched_setparam",
    "sched_getscheduler", "sched_setscheduler",
    "sched_get_priority_max", "sched_get_priority_min",
    "sched_yield",
]

# Dangerous syscalls - these are what seccomp should block.
# Kept deliberately broad: the agent does not need any of these for
# ordinary work (read/write/network/process), and each is a documented
# escape primitive or privilege-escalation vector.
DANGEROUS_SYSCALLS = [
    # Debugging / cross-process memory
    "ptrace", "process_vm_readv", "process_vm_writev", "process_madvise",
    # Filesystem mount manipulation (classic and new-mount-API)
    "mount", "umount2", "pivot_root",
    "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount",
    "fspick", "mount_setattr",
    # Kernel code loading
    "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "create_module", "query_module", "get_kernel_syms",
    # Other powerful kernel interfaces
    "bpf", "perf_event_open", "userfaultfd",
    "reboot", "swapon", "swapoff", "acct",
    "quotactl", "quotactl_fd",
    # Namespace manipulation (prevent further nesting / privileged ns)
    "unshare", "setns",
    # io_uring (complex attack surface, bypass of some seccomp patterns)
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    # pidfd — can send signals across namespaces / steal file descriptors
    "pidfd_send_signal", "pidfd_open", "pidfd_getfd",
    # Kernel keyring — CVE-rich
    "keyctl", "add_key", "request_key",
    # Direct modification of seccomp, LDT, I/O ports
    "seccomp", "modify_ldt", "iopl", "ioperm",
    # File handle bypass of path-based checks
    "name_to_handle_at", "open_by_handle_at",
    # Filesystem event listeners (information leak + DoS)
    "fanotify_init", "fanotify_mark",
    # Audit info leak
    "lookup_dcookie",
]


def build_allowlist_filter(allowed_syscalls: list[str],
                           default_action: int = SECCOMP_RET_ERRNO | 1,
                           log_blocked: bool = False) -> bytes:
    """
    Build a BPF filter program that allows only the specified syscalls.

    Args:
        allowed_syscalls: List of syscall names to allow
        default_action: What to do for non-allowed syscalls
                       SECCOMP_RET_KILL_PROCESS = kill
                       SECCOMP_RET_ERRNO | errno = return error
                       SECCOMP_RET_LOG = log but allow (debug mode)
        log_blocked: If True, use SECCOMP_RET_LOG instead of default_action
                    (useful for discovering which syscalls your app needs)

    Returns:
        Bytes containing the BPF program
    """
    if log_blocked:
        default_action = SECCOMP_RET_LOG

    instructions = []

    # 1. Load architecture (offset 4 in seccomp_data)
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH))

    # 2. Check architecture is x86_64
    #    If not x86_64, kill (to prevent ABI confusion attacks)
    instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # 3. Load syscall number (offset 0 in seccomp_data)
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR))

    # 4. For each allowed syscall, add a JEQ check
    #    Jump to ALLOW if match, fall through otherwise
    syscall_nums = []
    for name in allowed_syscalls:
        if name in SYSCALL_NUMBERS_X86_64:
            syscall_nums.append(SYSCALL_NUMBERS_X86_64[name])
        else:
            print(f"  Warning: unknown syscall '{name}', skipping", file=sys.stderr)

    # Remove duplicates and sort for cleaner filter
    syscall_nums = sorted(set(syscall_nums))

    # Each allowed syscall: if nr == X, jump to ALLOW (which is at the end)
    # Jump offsets: jt = distance to ALLOW, jf = 0 (next instruction)
    n = len(syscall_nums)
    for i, nr in enumerate(syscall_nums):
        # jt = jump forward to the ALLOW return (n - i instructions away)
        # jf = 0 (continue to next check)
        instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, n - i, 0))

    # 5. Default action (deny): reached if no syscall matched
    instructions.append(bpf_stmt(BPF_RET | BPF_K, default_action))

    # 6. ALLOW return: reached on successful match
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    return b"".join(instructions)


def build_denylist_filter(denied_syscalls: list[str],
                          default_action: int = SECCOMP_RET_ERRNO | 1,
                          log_blocked: bool = False) -> bytes:
    """
    Build a BPF program that blocks the named syscalls and allows
    everything else. Useful for Node.js / JIT-heavy agents where an
    allowlist is too restrictive.
    """
    if log_blocked:
        default_action = SECCOMP_RET_LOG

    # Warn if any names in the denylist aren't known — otherwise they
    # silently become no-ops and a blocked operation looks safe when
    # it actually isn't.
    for name in denied_syscalls:
        if name not in SYSCALL_NUMBERS_X86_64:
            print(f"  WARNING: seccomp denylist references unknown "
                  f"syscall '{name}' — it will NOT be blocked.",
                  file=sys.stderr)

    instructions = []

    # 1. Arch check (kill on mismatch to prevent ABI confusion)
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH))
    instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K,
                                 AUDIT_ARCH_X86_64, 1, 0))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # 2. Load syscall number, then kill if the x32 ABI bit is set.
    # Without this, an attacker can invoke syscalls via the x32 ABI
    # (nr | 0x40000000) and bypass every JEQ below, which compare
    # against the plain nr. BPF_JSET tests (A & K) != 0; the accumulator
    # is not modified, so the nr is still in A for the JEQ chain.
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR))
    X32_SYSCALL_BIT = 0x40000000
    BPF_JSET = 0x40
    instructions.append(bpf_jump(BPF_JMP | BPF_JSET | BPF_K,
                                 X32_SYSCALL_BIT, 0, 1))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # 3. For each denied syscall: if nr == X, jump to DENY.
    # DENY is placed at the end; ALLOW falls through right after the JEQs.
    syscall_nums = sorted(set(
        SYSCALL_NUMBERS_X86_64[name]
        for name in denied_syscalls
        if name in SYSCALL_NUMBERS_X86_64
    ))

    n = len(syscall_nums)
    # Layout after this loop:
    #   [JEQs...]    (n instructions)
    #   [RET ALLOW]  <-- fall-through target
    #   [RET DENY]   <-- jump target for each JEQ
    # JEQ jumps need: jt = (n - i - 1) + 1  (skip remaining JEQs + ALLOW)
    for i, nr in enumerate(syscall_nums):
        jt = (n - i - 1) + 1
        instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0))

    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, default_action))

    return b"".join(instructions)


def apply_seccomp_filter(allowed_syscalls: list[str] = None,
                         mode: str = "strict",
                         log_only: bool = False,
                         denied_syscalls: list[str] = None) -> bool:
    """
    Apply a seccomp BPF filter to the current process.

    Args:
        allowed_syscalls: List of syscall names to allow. If None, uses SAFE_SYSCALLS.
        mode: "strict" = KILL on violation, "permissive" = EPERM, "log" = log only
        log_only: If True, overrides mode to just log (for debugging)

    Returns:
        True if successfully applied, False otherwise.
    """
    use_denylist = denied_syscalls is not None
    if allowed_syscalls is None and not use_denylist:
        allowed_syscalls = SAFE_SYSCALLS

    # Determine default action for blocked syscalls
    if log_only or mode == "log":
        default_action = SECCOMP_RET_LOG
        mode_desc = "LOG (audit only, no blocking)"
    elif mode == "permissive":
        default_action = SECCOMP_RET_ERRNO | 1  # EPERM
        mode_desc = "PERMISSIVE (return EPERM)"
    else:  # strict
        default_action = SECCOMP_RET_KILL_PROCESS
        mode_desc = "STRICT (kill on violation)"

    # Build the BPF program
    if use_denylist:
        print(f"  Seccomp mode: {mode_desc} (denylist)", file=sys.stderr)
        print(f"  Denied syscalls: {len(denied_syscalls)}", file=sys.stderr)
        prog_bytes = build_denylist_filter(
            denied_syscalls, default_action, log_only
        )
    else:
        print(f"  Seccomp mode: {mode_desc}", file=sys.stderr)
        print(f"  Allowed syscalls: {len(allowed_syscalls)}", file=sys.stderr)
        prog_bytes = build_allowlist_filter(
            allowed_syscalls, default_action, log_only
        )
    n_instructions = len(prog_bytes) // 8  # each instruction is 8 bytes

    # struct sock_fprog { unsigned short len; struct sock_filter *filter; };
    # On x86_64: len=2 bytes + 6 bytes padding + pointer=8 bytes = 16 bytes
    # But actually it's: unsigned short (2) + padding (6) + pointer (8)
    # Using ctypes for correct struct layout:

    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort),
                     ("jt", ctypes.c_ubyte),
                     ("jf", ctypes.c_ubyte),
                     ("k", ctypes.c_uint)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort),
                     ("filter", ctypes.POINTER(SockFilter))]

    # Create filter array
    FilterArray = SockFilter * n_instructions
    filters = FilterArray()
    for i in range(n_instructions):
        offset = i * 8
        code, jt, jf, k = struct.unpack("HBBI", prog_bytes[offset:offset+8])
        filters[i].code = code
        filters[i].jt = jt
        filters[i].jf = jf
        filters[i].k = k

    prog = SockFprog()
    prog.len = n_instructions
    prog.filter = ctypes.cast(filters, ctypes.POINTER(SockFilter))

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    # Step 1: Set NO_NEW_PRIVS (required before seccomp filter)
    ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret != 0:
        errno = ctypes.get_errno()
        print(f"  Failed to set NO_NEW_PRIVS: errno={errno}", file=sys.stderr)
        return False

    # Step 2: Apply the seccomp filter
    ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    if ret != 0:
        errno = ctypes.get_errno()
        print(f"  Failed to apply seccomp filter: errno={errno}", file=sys.stderr)
        return False

    print(f"  Seccomp filter applied ({n_instructions} BPF instructions)",
          file=sys.stderr)
    return True


def get_seccomp_status() -> dict:
    """Check current seccomp status from /proc/self/status."""
    status = {"mode": "unknown", "filters": 0}
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    mode_num = int(line.split(":")[1].strip())
                    status["mode"] = {0: "disabled", 1: "strict", 2: "filter"}.get(mode_num, f"unknown({mode_num})")
                elif line.startswith("Seccomp_filters:"):
                    status["filters"] = int(line.split(":")[1].strip())
    except Exception:
        pass
    return status


# ---- CLI for testing ----

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Apply seccomp filter (pure ctypes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["strict", "permissive", "log"],
                        default="permissive",
                        help="Enforcement mode")
    parser.add_argument("--test", action="store_true",
                        help="Apply filter and run basic tests")
    parser.add_argument("--deny", action="store_true",
                        help="Use denylist (block DANGEROUS_SYSCALLS) "
                             "instead of allowlist. Recommended for "
                             "Node.js/JIT agents.")
    parser.add_argument("--exec", dest="exec_mode", action="store_true",
                        help="Apply filter then execvp() the remaining "
                             "argv (everything after --).")
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="Command to exec after applying the filter "
                             "(requires --exec).")
    args = parser.parse_args()

    if args.exec_mode:
        denied = DANGEROUS_SYSCALLS if args.deny else None
        ok = apply_seccomp_filter(mode=args.mode, denied_syscalls=denied)
        if not ok:
            print("Failed to apply seccomp filter; aborting exec.",
                  file=sys.stderr)
            sys.exit(1)

        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("--exec requires a command after --", file=sys.stderr)
            sys.exit(2)

        try:
            os.execvp(cmd[0], cmd)
        except OSError as exc:
            print(f"execvp({cmd[0]!r}) failed: {exc}", file=sys.stderr)
            sys.exit(127)

    print("=== Seccomp Helper (Pure Python/ctypes) ===")
    print(f"Before: {get_seccomp_status()}")

    denied = DANGEROUS_SYSCALLS if args.deny else None
    ok = apply_seccomp_filter(mode=args.mode, denied_syscalls=denied)
    print(f"Applied: {ok}")
    print(f"After:  {get_seccomp_status()}")

    if args.test and ok:
        print("\n--- Quick tests after seccomp ---")

        # Should work
        print(f"  getpid() = {os.getpid()}")
        print(f"  getcwd() = {os.getcwd()}")

        # Should fail (ptrace is blocked)
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.ptrace(0, 0, 0, 0)
            errno = ctypes.get_errno()
            print(f"  ptrace: ret={ret}, errno={errno}")
        except Exception as e:
            print(f"  ptrace: {e}")

        # Should fail (mount is blocked)
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.mount(b"none", b"/mnt", b"tmpfs", 0, None)
            errno = ctypes.get_errno()
            print(f"  mount: ret={ret}, errno={errno}")
        except Exception as e:
            print(f"  mount: {e}")

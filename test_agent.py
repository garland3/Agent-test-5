#!/usr/bin/env python3
"""
Test Agent - Probes all security boundaries and reports results.

This agent attempts various operations to test whether the sandbox
is correctly restricting access. Each test reports PASS (blocked)
or FAIL (allowed when it shouldn't be) depending on the expected
security level.

Usage:
    python3 test_agent.py [--level N]

The --level flag sets expectations for what SHOULD be blocked.
Level 0 = no sandbox, everything should succeed.
Level 5 = full sandwich, most dangerous ops should be blocked.
"""

import argparse
import json
import os
import platform
import signal
import socket
import struct
import sys
import tempfile
import time


# ---- Result tracking ----

class TestResults:
    def __init__(self):
        self.results = []

    def record(self, category: str, test_name: str, allowed: bool, detail: str = ""):
        self.results.append({
            "category": category,
            "test": test_name,
            "allowed": allowed,
            "detail": detail,
        })
        status = "ALLOWED" if allowed else "BLOCKED"
        icon = "o" if allowed else "x"
        print(f"  [{icon}] {test_name}: {status}" + (f" ({detail})" if detail else ""))

    def summary(self):
        print("\n" + "=" * 65)
        print("SANDBOX TEST RESULTS SUMMARY")
        print("=" * 65)
        cats = {}
        for r in self.results:
            cats.setdefault(r["category"], []).append(r)
        for cat, tests in cats.items():
            allowed_count = sum(1 for t in tests if t["allowed"])
            blocked_count = sum(1 for t in tests if not t["allowed"])
            print(f"\n  {cat}:")
            print(f"    Allowed: {allowed_count}  |  Blocked: {blocked_count}")
            for t in tests:
                icon = "o" if t["allowed"] else "x"
                print(f"      [{icon}] {t['test']}")
        print("\n" + "=" * 65)
        return self.results

    def to_json(self):
        return json.dumps(self.results, indent=2)


# ---- Filesystem Tests ----

def test_filesystem(results: TestResults):
    print("\n--- Filesystem Tests ---")

    # Read system files (should be allowed with RO access)
    for path in ["/etc/hostname", "/etc/os-release", "/usr/bin/python3"]:
        try:
            with open(path, "rb") as f:
                f.read(64)
            results.record("filesystem", f"Read {path}", True)
        except Exception as e:
            results.record("filesystem", f"Read {path}", False, str(e))

    # Read sensitive files (should be blocked by Landlock)
    for path in ["/etc/shadow", "/root/.bashrc", "/root/.ssh/id_rsa"]:
        try:
            with open(path, "r") as f:
                f.read(1)
            results.record("filesystem", f"Read SENSITIVE {path}", True, "DANGER: sensitive file readable!")
        except Exception as e:
            results.record("filesystem", f"Read SENSITIVE {path}", False, type(e).__name__)

    # Write to workspace (should be allowed)
    workspace_file = os.path.join(os.getcwd(), "sandbox_test_output.txt")
    try:
        with open(workspace_file, "w") as f:
            f.write(f"Sandbox test at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        results.record("filesystem", "Write to workspace", True)
        os.unlink(workspace_file)
    except Exception as e:
        results.record("filesystem", "Write to workspace", False, str(e))

    # Write outside workspace (should be blocked by Landlock)
    for path in ["/tmp/sandbox_escape_test", "/var/tmp/escape_test"]:
        try:
            with open(path, "w") as f:
                f.write("escape attempt\n")
            results.record("filesystem", f"Write OUTSIDE {path}", True, "DANGER: wrote outside workspace!")
            os.unlink(path)
        except Exception as e:
            results.record("filesystem", f"Write OUTSIDE {path}", False, type(e).__name__)

    # Create directory outside workspace
    try:
        os.makedirs("/tmp/sandbox_escape_dir/test", exist_ok=True)
        results.record("filesystem", "Mkdir outside workspace", True, "DANGER")
        os.rmdir("/tmp/sandbox_escape_dir/test")
        os.rmdir("/tmp/sandbox_escape_dir")
    except Exception as e:
        results.record("filesystem", "Mkdir outside workspace", False, type(e).__name__)

    # Symlink escape attempt
    try:
        link_path = os.path.join(os.getcwd(), "escape_link")
        os.symlink("/etc/shadow", link_path)
        with open(link_path, "r") as f:
            f.read(1)
        results.record("filesystem", "Symlink escape to /etc/shadow", True, "DANGER: symlink escape worked!")
        os.unlink(link_path)
    except Exception as e:
        results.record("filesystem", "Symlink escape to /etc/shadow", False, type(e).__name__)


# ---- Network Tests ----

def test_network(results: TestResults):
    print("\n--- Network Tests ---")

    # Loopback connectivity
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(2)
        c.connect(("127.0.0.1", port))
        c.close()
        s.close()
        results.record("network", "Loopback (127.0.0.1) TCP", True)
    except Exception as e:
        results.record("network", "Loopback (127.0.0.1) TCP", False, str(e))

    # UDP loopback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.sendto(b"ping", ("127.0.0.1", port))
        data, _ = s.recvfrom(64)
        s.close()
        results.record("network", "Loopback (127.0.0.1) UDP", True)
    except Exception as e:
        results.record("network", "Loopback (127.0.0.1) UDP", False, str(e))

    # External network (should be blocked in netns)
    external_targets = [
        ("8.8.8.8", 53, "Google DNS"),
        ("1.1.1.1", 443, "Cloudflare"),
    ]
    for ip, port, name in external_targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, port))
            s.close()
            results.record("network", f"External TCP to {name} ({ip}:{port})", True, "DANGER: internet accessible!")
        except Exception as e:
            results.record("network", f"External TCP to {name} ({ip}:{port})", False, type(e).__name__)

    # DNS resolution (should fail without internet)
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2)
        addr = socket.getaddrinfo("example.com", 80, socket.AF_INET)
        socket.setdefaulttimeout(old_timeout)
        results.record("network", "DNS resolution (example.com)", True, "internet reachable")
    except Exception as e:
        socket.setdefaulttimeout(old_timeout)
        results.record("network", "DNS resolution (example.com)", False, type(e).__name__)

    # Raw socket (should be blocked)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        results.record("network", "Raw ICMP socket", True, "DANGER: raw sockets allowed!")
    except Exception as e:
        results.record("network", "Raw ICMP socket", False, type(e).__name__)

    # List network interfaces
    try:
        import subprocess
        # Try to find ip command
        ip_cmd = None
        for candidate in ["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"]:
            if os.path.exists(candidate):
                ip_cmd = candidate
                break
        if ip_cmd:
            out = subprocess.check_output([ip_cmd, "link", "show"], timeout=5,
                                          text=True, stderr=subprocess.DEVNULL)
            ifaces = [line.split(":")[1].strip().split("@")[0]
                      for line in out.strip().split("\n")
                      if ": " in line and not line.startswith(" ")]
            results.record("network", "Network interfaces visible", True, f"ifaces={ifaces}")
        else:
            # Fallback: read /proc/net/dev
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()[2:]  # skip header
                ifaces = [l.split(":")[0].strip() for l in lines]
            results.record("network", "Network interfaces visible", True, f"ifaces={ifaces}")
    except Exception as e:
        results.record("network", "Network interfaces visible", False, str(e))


# ---- Process / Syscall Tests ----

def test_syscalls(results: TestResults):
    print("\n--- Syscall / Privilege Tests ---")

    # Get current IDs
    print(f"  [i] UID={os.getuid()} GID={os.getgid()} EUID={os.geteuid()} PID={os.getpid()}")

    # ptrace (should be blocked by seccomp or permissions)
    # Use PTRACE_PEEKDATA on our own PID — harmless probe
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # PTRACE_PEEKDATA = 2, peek at our own process
        # This checks if ptrace syscall is available without TRACEME side effects
        ctypes.set_errno(0)
        ret = libc.ptrace(2, os.getpid(), 0, 0)  # PTRACE_PEEKDATA
        errno = ctypes.get_errno()
        if errno != 0:
            results.record("syscall", "ptrace", False, f"errno={errno}")
        else:
            results.record("syscall", "ptrace", True, "ptrace available")
    except Exception as e:
        results.record("syscall", "ptrace", False, str(e))

    # mount (should be blocked)
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # Try to mount tmpfs on a temp directory (less destructive than /mnt)
        test_mount = "/tmp/_sandbox_mount_test"
        os.makedirs(test_mount, exist_ok=True)
        ret = libc.mount(b"none", test_mount.encode(), b"tmpfs", 0, None)
        errno = ctypes.get_errno()
        if ret == -1:
            results.record("syscall", "mount(tmpfs)", False, f"errno={errno}")
        else:
            results.record("syscall", "mount(tmpfs)", True, "DANGER: mount succeeded!")
            # Clean up: unmount
            libc.umount2(test_mount.encode(), 0)
        try:
            os.rmdir(test_mount)
        except OSError:
            pass
    except Exception as e:
        results.record("syscall", "mount(tmpfs)", False, str(e))

    # setuid (should fail for non-root)
    try:
        os.setuid(0)
        results.record("syscall", "setuid(0)", True, "DANGER: became root!")
    except Exception as e:
        results.record("syscall", "setuid(0)", False, type(e).__name__)

    # fork test (just test fork works, don't bomb)
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c", "import os; print(os.getpid())"],
            timeout=5, capture_output=True, text=True
        )
        if result.returncode == 0:
            results.record("syscall", "fork+exec", True, f"child_pid={result.stdout.strip()}")
        else:
            results.record("syscall", "fork+exec", False, result.stderr.strip())
    except Exception as e:
        results.record("syscall", "fork+exec", False, str(e))

    # Access /proc/self for info leaks
    try:
        with open("/proc/self/status", "r") as f:
            lines = f.readlines()
        seccomp_line = [l for l in lines if l.startswith("Seccomp:")]
        ns_line = [l for l in lines if l.startswith("NSpid:")]
        detail = "; ".join(l.strip() for l in seccomp_line + ns_line)
        results.record("syscall", "Read /proc/self/status", True, detail)
    except Exception as e:
        results.record("syscall", "Read /proc/self/status", False, str(e))

    # Try to read other process info
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        results.record("syscall", f"List /proc PIDs", True, f"visible_pids={len(pids)}")
    except Exception as e:
        results.record("syscall", f"List /proc PIDs", False, str(e))

    # Signal another process (should fail in PID ns or as different user)
    try:
        # Try to signal PID 1 (init)
        os.kill(1, 0)  # signal 0 = check if we can signal
        results.record("syscall", "Signal PID 1 (init)", True, "can signal init")
    except ProcessLookupError:
        results.record("syscall", "Signal PID 1 (init)", False, "PID 1 not found (PID namespace)")
    except PermissionError:
        results.record("syscall", "Signal PID 1 (init)", False, "Permission denied")
    except Exception as e:
        results.record("syscall", "Signal PID 1 (init)", False, str(e))


# ---- Environment & Info Tests ----

def test_environment(results: TestResults):
    print("\n--- Environment Tests ---")

    # Basic info (always collected)
    print(f"  [i] Python: {platform.python_version()}")
    print(f"  [i] Platform: {platform.platform()}")
    print(f"  [i] CWD: {os.getcwd()}")
    print(f"  [i] Hostname: {socket.gethostname()}")

    # Check if we can see host environment
    sensitive_env = ["HOME", "USER", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"]
    for var in sensitive_env:
        val = os.environ.get(var)
        if val:
            # Don't print actual secret values
            display = val[:8] + "..." if len(val) > 8 else val
            results.record("environment", f"Env ${var}", True, f"value={display}")
        else:
            results.record("environment", f"Env ${var}", False, "not set")

    # Check hostname (inside ns it may differ)
    try:
        hostname = socket.gethostname()
        results.record("environment", "Hostname accessible", True, hostname)
    except Exception as e:
        results.record("environment", "Hostname accessible", False, str(e))

    # /proc/self/cgroup (check if in cgroup)
    try:
        with open("/proc/self/cgroup", "r") as f:
            cgroup = f.read().strip()
        results.record("environment", "Cgroup info", True, cgroup[:80])
    except Exception as e:
        results.record("environment", "Cgroup info", False, str(e))


# ---- Main ----

def main():
    parser = argparse.ArgumentParser(description="AI Agent Sandbox Test")
    parser.add_argument("--level", type=int, default=-1,
                        help="Expected sandbox level (0-5), for reporting")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--seccomp", action="store_true",
                        help="Apply seccomp filter before running tests")
    parser.add_argument("--seccomp-mode", choices=["strict", "permissive", "log"],
                        default="permissive",
                        help="Seccomp enforcement mode (default: permissive)")
    args = parser.parse_args()

    print("=" * 65)
    print("  AI AGENT SANDBOX PROBE")
    print(f"  Level: {args.level if args.level >= 0 else 'unknown'}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Apply seccomp if requested (must happen after Python init but before tests)
    if args.seccomp:
        try:
            # Find seccomp_helper.py in parent dir or same dir
            script_dir = os.path.dirname(os.path.abspath(__file__))
            for search_dir in [script_dir, os.path.dirname(script_dir), os.getcwd()]:
                helper_path = os.path.join(search_dir, "seccomp_helper.py")
                if os.path.exists(helper_path):
                    sys.path.insert(0, search_dir)
                    break
            from seccomp_helper import apply_seccomp_filter, get_seccomp_status, SAFE_SYSCALLS
            print(f"\nApplying seccomp filter ({args.seccomp_mode} mode)...")
            print(f"  Before: {get_seccomp_status()}")
            ok = apply_seccomp_filter(allowed_syscalls=SAFE_SYSCALLS, mode=args.seccomp_mode)
            print(f"  After:  {get_seccomp_status()}")
            if ok:
                print("  Seccomp active!\n")
            else:
                print("  WARNING: Seccomp could not be applied.\n")
        except ImportError:
            print("  WARNING: seccomp_helper.py not found. Skipping seccomp.\n")
        except Exception as e:
            print(f"  WARNING: Seccomp setup failed: {e}\n")

    results = TestResults()

    test_filesystem(results)
    test_network(results)
    test_syscalls(results)
    test_environment(results)

    summary = results.summary()

    if args.json:
        # Write JSON to file for comparison
        json_path = os.path.join(os.getcwd(), f"results_level_{args.level}.json")
        try:
            with open(json_path, "w") as f:
                f.write(results.to_json())
            print(f"\nJSON results written to: {json_path}")
        except Exception:
            # If we can't write (Landlock), print to stdout
            print("\n--- JSON Results ---")
            print(results.to_json())

    return 0


if __name__ == "__main__":
    sys.exit(main())

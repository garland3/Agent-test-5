#!/usr/bin/env python3
"""
Bubblewrap sandbox test agent.

Tests the same categories as test_agent.py but adds HTTP-level tests
for domain whitelist filtering via proxy. Designed to run inside bwrap.

Usage:
    python3 test_bwrap_agent.py [--level NAME] [--json] [--seccomp]
"""

import argparse
import json
import os
import platform
import socket
import struct
import sys
import tempfile
import time
import urllib.request
import urllib.error


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
        print("BUBBLEWRAP SANDBOX TEST RESULTS")
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

    # Read system files
    for path in ["/etc/hostname", "/etc/os-release", "/usr/bin/python3"]:
        try:
            with open(path, "rb") as f:
                f.read(64)
            results.record("filesystem", f"Read {path}", True)
        except Exception as e:
            results.record("filesystem", f"Read {path}", False, type(e).__name__)

    # Read sensitive files (should be blocked by bwrap — not bind-mounted)
    for path in ["/etc/shadow", "/root/.bashrc", "/home"]:
        try:
            if os.path.isdir(path):
                os.listdir(path)
            else:
                with open(path, "r") as f:
                    f.read(1)
            results.record("filesystem", f"Access {path}", True, "visible inside sandbox!")
        except Exception as e:
            results.record("filesystem", f"Access {path}", False, type(e).__name__)

    # Write to workspace (should be allowed)
    workspace_file = os.path.join(os.getcwd(), "bwrap_test_output.txt")
    try:
        with open(workspace_file, "w") as f:
            f.write(f"Bubblewrap test at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        results.record("filesystem", "Write to workspace", True)
        os.unlink(workspace_file)
    except Exception as e:
        results.record("filesystem", "Write to workspace", False, str(e))

    # Write outside workspace (should be blocked)
    for path in ["/tmp/bwrap_escape_test", "/var/tmp/escape_test"]:
        try:
            with open(path, "w") as f:
                f.write("escape attempt\n")
            results.record("filesystem", f"Write OUTSIDE {path}", True, "DANGER!")
            os.unlink(path)
        except Exception as e:
            results.record("filesystem", f"Write OUTSIDE {path}", False, type(e).__name__)


# ---- Network Tests ----

def test_network(results: TestResults):
    print("\n--- Network Tests ---")

    # Loopback
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
        results.record("network", "Loopback TCP", True)
    except Exception as e:
        results.record("network", "Loopback TCP", False, str(e))

    # External network (raw socket, bypasses proxy)
    for ip, port, name in [("8.8.8.8", 53, "Google DNS"), ("1.1.1.1", 443, "Cloudflare")]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.close()
            results.record("network", f"Direct TCP to {name} ({ip})", True, "internet reachable")
        except Exception as e:
            results.record("network", f"Direct TCP to {name} ({ip})", False, type(e).__name__)

    # DNS resolution
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo("example.com", 80, socket.AF_INET)
        results.record("network", "DNS resolution", True)
    except Exception as e:
        results.record("network", "DNS resolution", False, type(e).__name__)
    finally:
        socket.setdefaulttimeout(None)

    # Raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        results.record("network", "Raw ICMP socket", True, "DANGER!")
    except Exception as e:
        results.record("network", "Raw ICMP socket", False, type(e).__name__)


# ---- HTTP Domain Tests (proxy filtering) ----

def test_http_domains(results: TestResults):
    print("\n--- HTTP Domain Whitelist Tests ---")

    proxy = os.environ.get("https_proxy") or os.environ.get("http_proxy")
    if not proxy:
        print("  (no proxy configured, skipping domain tests)")
        return

    print(f"  Using proxy: {proxy}")

    # Domains to test — mix of likely-allowed and likely-blocked
    test_urls = [
        ("https://pypi.org/simple/", "pypi.org", "Package index"),
        ("https://github.com/", "github.com", "Code hosting"),
        ("https://api.github.com/", "api.github.com", "GitHub API"),
        ("https://example.com/", "example.com", "Generic test"),
        ("https://evil-exfiltration.com/", "evil-exfiltration.com", "Exfil attempt"),
        ("https://www.google.com/", "google.com", "Search engine"),
        ("https://stackoverflow.com/", "stackoverflow.com", "Q&A site"),
    ]

    for url, domain, desc in test_urls:
        try:
            req = urllib.request.Request(url, method="HEAD")
            # urllib automatically uses http_proxy/https_proxy env vars
            resp = urllib.request.urlopen(req, timeout=5)
            results.record("http_domains", f"HTTP {domain} ({desc})", True,
                           f"status={resp.status}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                results.record("http_domains", f"HTTP {domain} ({desc})", False,
                               "proxy denied (403)")
            else:
                results.record("http_domains", f"HTTP {domain} ({desc})", True,
                               f"status={e.code}")
        except urllib.error.URLError as e:
            reason = str(e.reason) if hasattr(e, 'reason') else str(e)
            # Proxy rejection shows up as URLError with 403 or tunnel failure
            if "403" in reason or "Forbidden" in reason or "Tunnel" in reason:
                results.record("http_domains", f"HTTP {domain} ({desc})", False,
                               "proxy denied")
            else:
                results.record("http_domains", f"HTTP {domain} ({desc})", False,
                               reason[:80])
        except Exception as e:
            results.record("http_domains", f"HTTP {domain} ({desc})", False,
                           str(e)[:80])


# ---- Syscall / Process Tests ----

def test_syscalls(results: TestResults):
    print("\n--- Syscall / Process Tests ---")

    print(f"  [i] UID={os.getuid()} GID={os.getgid()} PID={os.getpid()}")

    # ptrace
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ctypes.set_errno(0)
        libc.ptrace(2, os.getpid(), 0, 0)
        errno = ctypes.get_errno()
        if errno != 0:
            results.record("syscall", "ptrace", False, f"errno={errno}")
        else:
            results.record("syscall", "ptrace", True)
    except Exception as e:
        results.record("syscall", "ptrace", False, str(e))

    # mount
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret = libc.mount(b"none", b"/mnt", b"tmpfs", 0, None)
        errno = ctypes.get_errno()
        if ret == -1:
            results.record("syscall", "mount(tmpfs)", False, f"errno={errno}")
        else:
            results.record("syscall", "mount(tmpfs)", True, "DANGER!")
            libc.umount2(b"/mnt", 0)
    except Exception as e:
        results.record("syscall", "mount(tmpfs)", False, str(e))

    # PID visibility
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        results.record("syscall", f"Visible PIDs", True, f"count={len(pids)}")
    except Exception as e:
        results.record("syscall", f"Visible PIDs", False, str(e))

    # Signal PID 1
    try:
        os.kill(1, 0)
        results.record("syscall", "Signal PID 1", True, "can signal init")
    except ProcessLookupError:
        results.record("syscall", "Signal PID 1", False, "PID 1 not found (PID ns)")
    except PermissionError:
        results.record("syscall", "Signal PID 1", False, "Permission denied")
    except Exception as e:
        results.record("syscall", "Signal PID 1", False, str(e))

    # /proc/self seccomp status
    try:
        with open("/proc/self/status", "r") as f:
            lines = f.readlines()
        seccomp_line = [l.strip() for l in lines if l.startswith("Seccomp:")]
        detail = seccomp_line[0] if seccomp_line else "no seccomp info"
        results.record("syscall", "Read /proc/self/status", True, detail)
    except Exception as e:
        results.record("syscall", "Read /proc/self/status", False, str(e))


# ---- Environment Tests ----

def test_environment(results: TestResults):
    print("\n--- Environment Tests ---")

    print(f"  [i] Python: {platform.python_version()}")
    print(f"  [i] CWD: {os.getcwd()}")
    try:
        print(f"  [i] Hostname: {socket.gethostname()}")
    except Exception:
        print(f"  [i] Hostname: (unavailable)")

    sensitive_env = ["HOME", "USER", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"]
    for var in sensitive_env:
        val = os.environ.get(var)
        if val:
            display = val[:8] + "..." if len(val) > 8 else val
            results.record("environment", f"Env ${var}", True, f"value={display}")
        else:
            results.record("environment", f"Env ${var}", False, "not set")


# ---- Main ----

def main():
    parser = argparse.ArgumentParser(description="Bubblewrap sandbox test agent")
    parser.add_argument("--level", type=str, default="bwrap",
                        help="Test level name (for reporting)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--seccomp", action="store_true",
                        help="Apply seccomp filter before running tests")
    parser.add_argument("--seccomp-mode", choices=["strict", "permissive", "log"],
                        default="permissive")
    args = parser.parse_args()

    print("=" * 65)
    print("  BUBBLEWRAP SANDBOX PROBE")
    print(f"  Level: {args.level}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Proxy: {os.environ.get('https_proxy', 'none')}")
    print("=" * 65)

    # Apply seccomp if requested
    if args.seccomp:
        try:
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
        except Exception as e:
            print(f"  WARNING: Seccomp setup failed: {e}\n")

    results = TestResults()

    test_filesystem(results)
    test_network(results)
    test_http_domains(results)
    test_syscalls(results)
    test_environment(results)

    summary = results.summary()

    if args.json:
        json_path = os.path.join(os.getcwd(), f"results_{args.level}.json")
        try:
            with open(json_path, "w") as f:
                f.write(results.to_json())
            print(f"\nJSON results written to: {json_path}")
        except Exception:
            print("\n--- JSON Results ---")
            print(results.to_json())

    return 0


if __name__ == "__main__":
    sys.exit(main())

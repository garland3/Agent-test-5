#!/usr/bin/env python3
"""
Tutorial 2: Network Namespace Isolation
=========================================

Network namespaces give a process its OWN isolated network stack:
  - Separate interfaces (only lo by default)
  - Separate routing table
  - Separate firewall rules
  - Separate /proc/net

This is how you prevent an AI agent from:
  - Exfiltrating data to the internet
  - Accessing internal services
  - Scanning the network
  - Phoning home to a C2 server

Prerequisites:
  - Linux (any modern kernel)
  - unshare command (util-linux package)
  - User namespaces enabled (for unprivileged use)
    RHEL 9: sudo sysctl -w user.max_user_namespaces=16384

Run this tutorial:
  python3 tutorials/02_network_namespaces.py
"""

import os
import sys
import subprocess
import socket
import time


# ================================================================
# EXERCISE 1: Understanding your current network
# ================================================================

def exercise_1():
    """
    Before isolating the network, let's see what the current
    (unsandboxed) network looks like.
    """
    print("=" * 60)
    print("EXERCISE 1: Your Current Network (Unsandboxed)")
    print("=" * 60)

    print("\n  --- Network Interfaces ---")
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
        for line in lines[2:]:  # skip headers
            iface = line.split(":")[0].strip()
            # Parse RX/TX bytes
            parts = line.split(":")[1].split()
            rx_bytes = int(parts[0])
            tx_bytes = int(parts[8])
            print(f"    {iface:10s}  RX: {rx_bytes:>12,} bytes  TX: {tx_bytes:>12,} bytes")
    except Exception as e:
        print(f"    Could not read /proc/net/dev: {e}")

    print("\n  --- DNS Resolution ---")
    for host in ["localhost", "example.com"]:
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2)
            addrs = socket.getaddrinfo(host, 80, socket.AF_INET)
            socket.setdefaulttimeout(old_timeout)
            ip = addrs[0][4][0]
            print(f"    {host:20s} -> {ip}")
        except Exception as e:
            print(f"    {host:20s} -> FAILED ({type(e).__name__})")

    print("\n  --- Socket Test ---")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        print(f"    Loopback TCP bind: OK (port {port})")
        s.close()
    except Exception as e:
        print(f"    Loopback TCP bind: FAILED ({e})")

    print(f"""
    WHAT YOU SEE:
    - Multiple network interfaces (lo, eth0, etc.)
    - DNS resolution works (at least for localhost)
    - You can bind sockets on loopback

    In an UNSANDBOXED process, the agent has full network access.
    It could send your code to the internet, scan the local network,
    or connect to any service it wants.
    """)

    input("Press Enter to continue to Exercise 2...")


# ================================================================
# EXERCISE 2: Creating a network namespace
# ================================================================

def exercise_2():
    """
    A network namespace isolates the entire network stack.
    When you create a new netns:
      - Only the 'lo' (loopback) interface exists
      - lo is DOWN by default (no network at all!)
      - No routes, no DNS, no firewall rules
      - The process can't see the host's network

    We'll use 'unshare' to create a namespace unprivileged.
    """
    print("=" * 60)
    print("EXERCISE 2: Creating a Network Namespace")
    print("=" * 60)

    # Check if unshare works
    try:
        subprocess.run(
            ["unshare", "--user", "--map-root-user", "--net", "--",
             "true"],
            check=True, capture_output=True, timeout=5
        )
        print("  unshare with user+net namespaces: AVAILABLE\n")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  unshare not available: {e}")
        print("  On RHEL 9: sudo sysctl -w user.max_user_namespaces=16384")
        print("  Then: sudo dnf install util-linux")
        return

    print("  Running 'ip link show' INSIDE a new network namespace:\n")

    # Run inside a new network namespace
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         "sh", "-c", """
            echo "    Interfaces before bringing up lo:"
            cat /proc/net/dev 2>/dev/null | tail -n +3 | while read line; do
                iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
                echo "      $iface"
            done

            echo ""
            echo "    Bringing up loopback..."
            ip link set lo up 2>/dev/null || echo "    (ip not available, trying alternatives)"

            echo ""
            echo "    Interfaces after bringing up lo:"
            cat /proc/net/dev 2>/dev/null | tail -n +3 | while read line; do
                iface=$(echo "$line" | cut -d: -f1 | tr -d ' ')
                echo "      $iface"
            done
         """],
        capture_output=True, text=True, timeout=10
    )
    print(result.stdout)

    print("""
    WHAT HAPPENED:
    Inside the new network namespace:
    - Only 'lo' (loopback) exists
    - No eth0, no docker0, no wlan0 - NOTHING else
    - Even lo starts DOWN until we bring it up

    The process inside this namespace has NO way to reach
    the internet or any other network interface on the host.
    """)

    input("Press Enter to continue to Exercise 3...")


# ================================================================
# EXERCISE 3: Network isolation in action
# ================================================================

def exercise_3():
    """
    Let's run a Python script inside a network namespace
    and see how network operations fail.
    """
    print("=" * 60)
    print("EXERCISE 3: Network Isolation in Action")
    print("=" * 60)

    # This Python code runs INSIDE the network namespace
    test_code = '''
import socket
import os

print("  Inside network namespace:")
print(f"    PID: {os.getpid()}")

# Test 1: Read /proc/net/dev to see interfaces
print("\\n  [Interfaces]")
try:
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]
    for line in lines:
        iface = line.split(":")[0].strip()
        print(f"    - {iface}")
    if not lines:
        print("    (none)")
except Exception as e:
    print(f"    Error: {e}")

# Test 2: Loopback
print("\\n  [Loopback Tests]")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.settimeout(2)
    c.connect(("127.0.0.1", port))
    c.send(b"Hello from sandbox!")

    conn, addr = s.accept()
    data = conn.recv(100)
    print(f"    TCP loopback: OK (received: {data.decode()})")
    conn.close()
    c.close()
    s.close()
except Exception as e:
    print(f"    TCP loopback: FAILED ({e})")
    print(f"    (Expected if lo is not brought up)")

# Test 3: External network
print("\\n  [External Network Tests]")
targets = [
    ("8.8.8.8", 53, "Google DNS"),
    ("1.1.1.1", 443, "Cloudflare"),
]
for ip, port, name in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        print(f"    {name} ({ip}:{port}): CONNECTED  <-- sandbox broken!")
    except Exception as e:
        print(f"    {name} ({ip}:{port}): BLOCKED ({type(e).__name__})")

# Test 4: DNS
print("\\n  [DNS Tests]")
for host in ["google.com", "example.com"]:
    try:
        socket.setdefaulttimeout(1)
        addrs = socket.getaddrinfo(host, 80, socket.AF_INET)
        print(f"    Resolve {host}: {addrs[0][4][0]}  <-- sandbox broken!")
    except Exception as e:
        print(f"    Resolve {host}: BLOCKED ({type(e).__name__})")
'''

    # Run with loopback UP
    print("  --- With loopback UP ---\n")
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         "sh", "-c", f"ip link set lo up 2>/dev/null; {sys.executable} -c '{test_code}'"],
        capture_output=True, text=True, timeout=15
    )
    print(result.stdout)

    # Run with loopback DOWN (maximum isolation)
    print("\n  --- With loopback DOWN (maximum network isolation) ---\n")
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         sys.executable, "-c", test_code],
        capture_output=True, text=True, timeout=15
    )
    print(result.stdout)

    print("""
    KEY OBSERVATIONS:
    - With lo UP: loopback works, external network blocked
    - With lo DOWN: ALL networking blocked, even loopback
    - DNS resolution fails (no route to DNS servers)
    - Cannot connect to any external IP

    FOR AI AGENTS:
    - "lo UP" is usually the right choice: lets the agent run
      local servers (e.g., for testing) but blocks internet
    - "lo DOWN" is maximum paranoia: no network at all
    """)

    input("Press Enter to continue to Exercise 4...")


# ================================================================
# EXERCISE 4: How it works under the hood
# ================================================================

def exercise_4():
    """
    Under the hood, network namespaces use the clone/unshare
    syscalls with the CLONE_NEWNET flag.

    Two approaches:
    1. unshare command (what we've been using)
    2. Python ctypes calling unshare() directly

    Let's look at both and understand the mechanics.
    """
    print("=" * 60)
    print("EXERCISE 4: How It Works Under the Hood")
    print("=" * 60)

    print("""
    APPROACH 1: unshare command (recommended for scripts)
    ─────────────────────────────────────────────────────
    unshare --user --map-root-user --net -- <command>

    Flags:
      --user           Create a new USER namespace (needed for unprivileged)
      --map-root-user  Map current user to root inside (UID 0 in namespace)
      --net            Create a new NETWORK namespace
      --               Separator before the command to run

    The command runs inside the new namespace. When it exits,
    the namespace is destroyed (no cleanup needed).

    APPROACH 2: Python ctypes (more control)
    ─────────────────────────────────────────
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    CLONE_NEWNET  = 0x40000000
    CLONE_NEWUSER = 0x10000000
    libc.unshare(CLONE_NEWNET | CLONE_NEWUSER)

    This modifies the CURRENT process. After this call,
    the process is in a new network namespace.
    """)

    print("  Let's compare what /proc/self/ns/net looks like:\n")

    # Show current namespace
    try:
        ns_link = os.readlink("/proc/self/ns/net")
        print(f"    Current process net namespace: {ns_link}")
    except Exception as e:
        print(f"    Cannot read namespace: {e}")

    # Show namespace inside unshare
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--",
         sys.executable, "-c",
         "import os; print(f'    Inside unshare net namespace: {os.readlink(\"/proc/self/ns/net\")}')"],
        capture_output=True, text=True, timeout=5
    )
    print(result.stdout.rstrip())

    print(f"""
    Notice: the namespace ID (inode number) is DIFFERENT.
    Each network namespace has a unique identifier.

    The kernel maintains separate data structures for each
    namespace: its own set of interfaces, routes, iptables
    rules, socket tracking, etc.

    LIFECYCLE:
    1. unshare() creates the namespace
    2. Process runs inside it
    3. When last process in the namespace exits, it's destroyed
    4. No manual cleanup needed (unlike 'ip netns add' which persists)

    UNPRIVILEGED USE:
    Creating a network namespace normally requires CAP_NET_ADMIN.
    But if you FIRST create a user namespace (--user), you get
    all capabilities INSIDE that user namespace, including
    CAP_NET_ADMIN. This is how it works without sudo.

    RHEL 9 NOTE:
    RHEL 9 disables user namespaces by default (security hardening).
    You must run: sudo sysctl -w user.max_user_namespaces=16384
    """)


# ================================================================
# EXERCISE 5: Hands-on exploration
# ================================================================

def exercise_5():
    """
    Try these yourself in a terminal to build intuition.
    """
    print("=" * 60)
    print("EXERCISE 5: Hands-On Exploration")
    print("=" * 60)

    print("""
    Try these commands in your terminal:

    1. BASIC ISOLATION:
       unshare --user --map-root-user --net -- bash
       # You're now in an isolated network namespace!
       # Try: curl google.com (should fail)
       # Try: ping 8.8.8.8 (should fail)
       # Try: cat /proc/net/dev (only lo)
       # Type 'exit' to leave

    2. SEE THE DIFFERENCE:
       # Terminal 1 (host):
       cat /proc/net/dev

       # Terminal 2 (namespace):
       unshare --user --map-root-user --net -- cat /proc/net/dev
       # Notice: only 'lo' in the namespace

    3. LOOPBACK SERVER INSIDE NAMESPACE:
       unshare --user --map-root-user --net -- bash -c '
           ip link set lo up
           python3 -m http.server 8080 &
           sleep 1
           curl http://127.0.0.1:8080/
           kill %1
       '
       # This works! The server and client are both inside
       # the namespace and can talk via loopback.

    4. CHECK NAMESPACE IDS:
       readlink /proc/self/ns/net
       unshare --user --map-root-user --net -- readlink /proc/self/ns/net
       # Different inode numbers = different namespaces

    5. COMBINE WITH PID NAMESPACE:
       unshare --user --map-root-user --net --pid --fork -- bash -c '
           echo "PID inside: $$"
           ps aux 2>/dev/null || echo "(ps not available)"
       '
       # The process sees itself as PID 1!

    QUESTIONS TO EXPLORE:
    - What happens if you try to create a socket with AF_INET
      when lo is down? (Hint: ENETUNREACH)
    - Can a process in one namespace communicate with another
      namespace? (Hint: veth pairs, but not covered here)
    - What does /proc/net/tcp show inside vs outside?
    """)


# ================================================================
# Main
# ================================================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║  Tutorial 2: Network Namespace Isolation            ║
    ║  Preventing AI Agent Network Access                 ║
    ╚══════════════════════════════════════════════════════╝

    This tutorial has 5 exercises:
      1. Your current network (baseline)
      2. Creating a network namespace
      3. Network isolation in action
      4. How it works under the hood
      5. Hands-on exploration (try it yourself)
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
    print("Tutorial 2 complete!")
    print()
    print("Next: tutorials/03_seccomp_bpf.py")
    print("=" * 60)


if __name__ == "__main__":
    main()

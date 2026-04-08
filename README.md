# AI Agent Kernel Security Sandbox Demo

Demonstrates three Linux kernel features for containing AI agents, exercised
at progressively stronger isolation levels:

| Layer | Mechanism | What it restricts |
|-------|-----------|-------------------|
| **Landlock** | Linux Security Module (LSM) | Filesystem access (read/write/execute paths) |
| **netns** | Network Namespaces | Network stack (interfaces, routes, sockets) |
| **seccomp** | Syscall filtering (BPF) | Which kernel syscalls the process can invoke |

These three layers form a "kernel sandwich" that significantly reduces the blast
radius if an AI agent goes rogue (prompt injection, tool misuse, data exfiltration).

## Demo Levels

| Level | Isolation | What's restricted |
|-------|-----------|-------------------|
| **0** | None (baseline) | Nothing - shows what an unrestricted process can do |
| **1** | Landlock only | Filesystem access (can't read/write outside allowed paths) |
| **2** | netns only | Network (only loopback, no internet) |
| **3** | seccomp only | Syscalls (blocks ptrace, mount, bpf, kexec, etc.) |
| **4** | Landlock + netns | Filesystem + network combined |
| **5** | Full sandwich | All three + user/PID/mount namespaces |

## Quick Start

```bash
# 1. Setup (detects Ubuntu or RHEL, installs prerequisites)
chmod +x setup.sh run_all.sh demos/*.sh
./setup.sh

# 2. Run all levels and see comparison
./run_all.sh

# 3. Or run individual levels
./demos/level_0.sh    # Baseline
./demos/level_5.sh    # Full sandwich

# 4. Run only levels that don't need namespaces
./run_all.sh --quick  # Runs levels 0, 1, 3 only
```

## Distro Support

### Ubuntu (20.04+)
- User namespaces: enabled by default
- Landlock: available in 22.04+ (kernel 5.15+)
- seccomp: always available
- No special setup needed

### RHEL 9 / CentOS 9 / Rocky 9 / Alma 9
- User namespaces: **disabled by default** (security hardening)
  ```bash
  # Enable (one-time, requires root):
  sudo sysctl -w user.max_user_namespaces=16384
  echo "user.max_user_namespaces = 16384" | sudo tee /etc/sysctl.d/99-userns.conf
  sudo sysctl --system
  ```
- Landlock: available in kernel 5.14.0-162+ (check `CONFIG_SECURITY_LANDLOCK`)
- seccomp: always available

## File Structure

```
.
├── setup.sh              # Distro detection + prerequisite installer
├── run_all.sh            # Master runner - all levels + comparison report
├── sandbox_config.yaml   # YAML config defining allowed paths, network, etc.
├── test_agent.py         # Test agent that probes all security boundaries
├── seccomp_helper.py     # Pure-Python seccomp via ctypes (no pip package needed)
├── demos/
│   ├── level_0.sh        # No sandbox (baseline)
│   ├── level_1.sh        # Landlock only
│   ├── level_2.sh        # netns only
│   ├── level_3.sh        # seccomp only
│   ├── level_4.sh        # Landlock + netns
│   └── level_5.sh        # Full sandwich
├── tutorials/            # Step-by-step tutorials (work through these!)
│   ├── 01_landlock_basics.py       # Landlock filesystem sandboxing
│   ├── 02_network_namespaces.py    # Network namespace isolation
│   ├── 03_seccomp_bpf.py           # Building seccomp BPF filters
│   ├── 04_combining_layers.py      # Layering defenses together
│   └── 05_sandbox_your_agent.py    # Adapt for your own agent
└── workspace/            # Agent working directory (sandboxed writes go here)
```

## Tutorials

Work through these in order to understand how each layer works:

```bash
python3 tutorials/01_landlock_basics.py       # Filesystem restrictions
python3 tutorials/02_network_namespaces.py    # Network isolation
python3 tutorials/03_seccomp_bpf.py           # Syscall filtering
python3 tutorials/04_combining_layers.py      # Putting it all together
python3 tutorials/05_sandbox_your_agent.py    # Adapt for your agent
```

Each tutorial is interactive with hands-on exercises that run sandboxed
code in subprocesses (so your tutorial process stays unrestricted).

## How It Works

### Test Agent (`test_agent.py`)

The test agent attempts operations in four categories:

1. **Filesystem**: Read system files, read sensitive files (/etc/shadow), write
   to workspace, write outside workspace, symlink escape attempts
2. **Network**: Loopback TCP/UDP, external connections (8.8.8.8), DNS resolution,
   raw sockets, interface enumeration
3. **Syscalls**: ptrace, mount, setuid, fork, exec, /proc access, PID visibility,
   signaling PID 1
4. **Environment**: Sensitive env vars, hostname, cgroup info

Each test reports whether the operation was ALLOWED or BLOCKED. The comparison
report shows these side-by-side across all levels.

### Seccomp Helper (`seccomp_helper.py`)

Pure Python implementation using `ctypes` + `prctl` + BPF. No `pip install seccomp`
needed (that package is old and hard to build). Supports:

- **strict** mode: KILL the process on violation
- **permissive** mode: return EPERM (recommended for demos)
- **log** mode: allow but log to audit (for discovering needed syscalls)

### Sandbox Config (`sandbox_config.yaml`)

```yaml
ro_paths:          # Read-only filesystem access
  - /usr
  - /lib
  - /lib64
  - /bin
  - /etc

rw_paths:          # Read-write access (workspace)
  - ./workspace
  - /tmp/agent-sandbox

network:
  mode: loopback_only    # Only lo interface

seccomp:
  extra_deny:      # Additional syscalls to block
    - ptrace
    - mount
    - bpf
```

## Key Concepts

### Defense in Depth
No single mechanism is sufficient. Landlock doesn't block network access.
Namespaces don't restrict syscalls. Seccomp doesn't know about file paths.
Together, they cover each other's gaps.

### Unprivileged Operation
All three mechanisms can be applied by an unprivileged process to itself:
- **Landlock**: `prctl(PR_SET_NO_NEW_PRIVS)` + landlock syscalls
- **seccomp**: `prctl(PR_SET_SECCOMP)` with BPF filter
- **Namespaces**: `unshare --user` (requires `user.max_user_namespaces > 0`)

### Inheritance
Restrictions are inherited by child processes. Once applied, they cannot be
loosened. This means an agent spawning subprocesses (compilers, test runners,
etc.) stays sandboxed.

### Limitations
- These run on the same host kernel. A kernel zero-day could bypass everything.
- For maximum isolation with untrusted agents, consider: gVisor, Kata Containers,
  or Firecracker microVMs on top.
- Landlock granularity is per-directory, not per-file (in current ABI versions).
- The `landlock` pip package doesn't expose fine-grained read-only vs read-write
  (it allows full access). Use the raw syscalls for stricter control.

## Troubleshooting

| Error | Fix |
|-------|-----|
| `unshare: cannot open /proc/self/uid_map: Permission denied` | `sudo sysctl -w user.max_user_namespaces=16384` |
| `Landlock not available` | Kernel too old or `CONFIG_SECURITY_LANDLOCK` not set |
| `ModuleNotFoundError: landlock` | `pip install landlock pyyaml` |
| Agent crashes with signal 31 (SIGSYS) | Seccomp killed it - switch to `permissive` mode or add missing syscalls |
| `ip: command not found` | `sudo apt install iproute2` or `sudo dnf install iproute` |

# AI Agent Kernel Security Sandbox Demo

**See [`cline_sandbox/`](cline_sandbox/README.md) for the full FastAPI
wrapper** that combines every layer below and exposes a dashboard, SSE
streams, and pause/stop/kill controls for running
[Cline](https://github.com/cline/cline) (or any agent) in dangerous (`-y`)
mode safely. Launch with `bash run_cline_sandbox.sh` or
`uv run python -m cline_sandbox`.

---

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

### Bubblewrap Demos

| Demo | Isolation | What it shows |
|------|-----------|---------------|
| **bwrap_basic** | Filesystem + PID + network ns | Selective bind mounts, no user namespace needed |
| **bwrap_seccomp** | Above + seccomp | Defense-in-depth: syscall filtering on top |
| **bwrap_network** | Filesystem + PID + domain whitelist | HTTP proxy filters allowed domains |

Bubblewrap (`bwrap`) is a lightweight sandboxing tool — near-zero startup, no daemon,
no container images. It uses kernel namespaces under the hood but doesn't require
the AppArmor `unprivileged_userns` workaround because it's typically installed setuid
or has the right capabilities. Ideal for sandboxing per-tool-call agent invocations.

## Quick Start

### Using uv (recommended)

```bash
# 1. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Install dependencies
uv sync

# 3. Run the test agent
uv run python test_agent.py

# 4. Run all demo levels
chmod +x run_all.sh demos/*.sh
./run_all.sh

# 5. Or run individual levels
./demos/level_0.sh    # Baseline
./demos/level_5.sh    # Full sandwich

# 6. Bubblewrap demos (no user namespace workaround needed)
bash demos/bwrap_basic.sh     # Filesystem + PID + network isolation
bash demos/bwrap_seccomp.sh   # Above + seccomp syscall filtering
bash demos/bwrap_network.sh   # Selective domain whitelist via proxy
```

### Using setup.sh

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
- Landlock: available in 22.04+ (kernel 5.15+)
- seccomp: always available
- **Ubuntu 24.04+**: AppArmor restricts unprivileged user namespaces by default.
  Levels 2, 4, and 5 (which use `unshare --user`) will fail unless you disable this:
  ```bash
  # Temporary (resets on reboot):
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

  # Persistent:
  echo "kernel.apparmor_restrict_unprivileged_userns = 0" | sudo tee /etc/sysctl.d/99-userns.conf
  sudo sysctl --system
  ```
  This restores the pre-24.04 default and is safe for development machines.
  Tools like Podman rootless, Flatpak, and bubblewrap require the same setting.
  On hardened production servers, prefer running the namespace demos with `sudo` instead.
- Ubuntu 20.04–23.10: user namespaces enabled by default, no extra setup needed

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
├── pyproject.toml        # Project config + dependencies (uv/pip)
├── uv.lock               # Locked dependency versions
├── setup.sh              # Distro detection + prerequisite installer
├── run_all.sh            # Master runner - all levels + comparison report
├── sandbox_config.yaml   # YAML config defining allowed paths, network, etc.
├── test_agent.py         # Test agent that probes all security boundaries
├── test_bwrap_agent.py   # Bubblewrap test agent (adds HTTP domain tests)
├── proxy_filter.py       # Python filtering HTTP proxy (domain whitelist)
├── seccomp_helper.py     # Pure-Python seccomp via ctypes (no pip package needed)
├── demos/
│   ├── level_0.sh        # No sandbox (baseline)
│   ├── level_1.sh        # Landlock only
│   ├── level_2.sh        # netns only
│   ├── level_3.sh        # seccomp only
│   ├── level_4.sh        # Landlock + netns
│   ├── level_5.sh        # Full sandwich
│   ├── bwrap_basic.sh    # Bubblewrap filesystem sandbox
│   ├── bwrap_seccomp.sh  # Bubblewrap + seccomp
│   └── bwrap_network.sh  # Bubblewrap + domain whitelist proxy
├── proxy_setup/          # LLM API proxy for sandboxed agents
│   ├── README.md         # Two-terminal setup guide
│   ├── llm_proxy.py      # Reverse proxy for LLM API calls
│   ├── example_agent.py  # Demo agent using the proxy
│   ├── run_proxy.sh      # Terminal 1: start proxy
│   └── run_agent.sh      # Terminal 2: run agent in bwrap
└── workspace/            # Agent working directory (sandboxed writes go here)
```

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

### Bubblewrap Demos

[Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) is the low-level
sandboxing primitive that Flatpak is built on. It provides:

- **Near-zero startup** (~0ms vs 500ms–2s for containers)
- **No daemon** — just a single binary
- **Granular bind mounts** — expose exactly what the agent needs
- **No container images** — works directly with host filesystem

The three bwrap demos show progressively stronger isolation:

1. **bwrap_basic** — Selective filesystem (`--ro-bind`, `--bind`), isolated PID
   namespace (`--unshare-pid`), isolated network (`--unshare-net`), clean
   environment (`--clearenv`). The agent sees only what you bind-mount.

2. **bwrap_seccomp** — Adds seccomp syscall filtering on top. Even if the agent
   escapes the filesystem sandbox, dangerous syscalls (ptrace, mount, bpf) are
   blocked.

3. **bwrap_network** — Selective domain access via filtering proxy. The agent gets
   network access, but HTTP/HTTPS traffic is forced through a proxy that only
   allows whitelisted domains (e.g., pypi.org, github.com). Architecture:
   ```
   agent (in bwrap) → proxy (127.0.0.1:8888) → internet (whitelisted only)
   ```

### Filtering Proxy (`proxy_filter.py`)

A simple Python HTTP/HTTPS proxy that enforces a domain whitelist. Supports
CONNECT tunneling (for HTTPS) and plain HTTP forwarding. No external
dependencies — uses only stdlib (`http.server`, `socket`, `select`).

```bash
# Standalone usage
python3 proxy_filter.py --port 8888 --allow pypi.org --allow github.com
```

For stronger enforcement where the agent can't bypass the proxy, combine with
`--unshare-net` + a veth pair routing only to the proxy address.

### LLM API Proxy (`proxy_setup/`)

For agents that need to call an LLM API (Anthropic, OpenAI, etc.), the
`proxy_setup/` directory has a complete two-terminal setup:

1. **Terminal 1**: Run `llm_proxy.py` — reverse proxy that forwards to the
   real LLM API over HTTPS, logs all requests (including token usage)
2. **Terminal 2**: Run the agent in bwrap with `ANTHROPIC_BASE_URL=http://localhost:9090`

The agent uses plain HTTP to reach the proxy on loopback (no TLS issues).
The proxy handles the real HTTPS connection. See [`proxy_setup/README.md`](proxy_setup/README.md)
for the full guide.

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

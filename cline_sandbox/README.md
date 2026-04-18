# cline_sandbox

A single-invocation FastAPI wrapper that runs [Cline](https://github.com/cline/cline)
(or any other CLI agent) in "dangerous" (`-y`, yolo) mode *safely*, by
wrapping every instance in a four-layer kernel sandwich:

| Layer | Mechanism | What it restricts |
|-------|-----------|-------------------|
| **Filesystem** | `bwrap --ro-bind` / `--bind` | Only `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc` (read-only) and the per-session workspace (read-write). No `$HOME`, no `/root`, no `/var`. |
| **Process** | `bwrap --unshare-pid --unshare-uts --unshare-ipc` | Hides host processes; the agent sees a fresh PID namespace. |
| **Network** | `bwrap --unshare-net` (optional) + filtering LLM proxy | The agent's outbound traffic is funnelled through a reverse proxy that only forwards to the configured LLM upstream. |
| **Syscalls** | seccomp-BPF denylist | Blocks `ptrace`, `mount`, `bpf`, `kexec*`, `init_module`, `unshare`, `setns`, `io_uring_*`, `userfaultfd`, and other escape / privilege-raising syscalls. |

The wrapper itself (FastAPI + supervisor) runs **outside** the sandbox
and is the only component that can see the LLM API key or signal the
agent. The agent child inherits all restrictions and cannot loosen
them — `PR_SET_NO_NEW_PRIVS` + seccomp-mode-2 filter are set before
`execve()`.

## Quick start

```bash
# 1. Install deps (FastAPI, uvicorn, pydantic are new)
uv sync

# 2. Export an API key for the upstream LLM
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Launch everything in one shot — API server + LLM proxy
uv run python -m cline_sandbox
# → API listening on http://127.0.0.1:8080
# → proxy listening on http://127.0.0.1:9090 (Anthropic upstream)

# 4. Open the dashboard
xdg-open http://127.0.0.1:8080/
```

From the dashboard you can create a session, see its log stream, pause /
resume / stop / kill it, and send additional messages into its stdin.

The same workflow is available over the HTTP API — see the auto-generated
docs at `http://127.0.0.1:8080/docs`.

## HTTP API surface

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/healthz` | Liveness + preflight (missing binaries). |
| `GET`  | `/config` | Read effective runtime configuration. |
| `POST` | `/sessions` | Create a new sandboxed session. |
| `GET`  | `/sessions` | List sessions. |
| `GET`  | `/sessions/{id}` | Session detail + sandbox argv. |
| `POST` | `/sessions/{id}/message` | Write text to the agent's stdin. |
| `POST` | `/sessions/{id}/pause` | `SIGSTOP` the agent process group. |
| `POST` | `/sessions/{id}/resume` | `SIGCONT`. |
| `POST` | `/sessions/{id}/stop` | `SIGTERM` + 10 s grace → escalate to SIGKILL. |
| `POST` | `/sessions/{id}/kill` | `SIGKILL` immediately. |
| `GET`  | `/sessions/{id}/events` | Historical JSONL event log. |
| `GET`  | `/sessions/{id}/stream` | Server-Sent Events: replays history, then tails live. |

All events (stdin, stdout, stderr, state transitions, signals, timeouts)
are persisted as line-delimited JSON under
`{state_dir}/{id}/events.jsonl`.

## Architecture

```
            ┌──────────────────────────────────────────┐
            │  uvicorn + FastAPI (cline_sandbox.app)   │
            │     state: SessionManager                │
            │     routes: /sessions, /stream, …        │
            └───────────────────┬──────────────────────┘
                                │ asyncio.subprocess
                                ▼
      ┌─────────────────────────────────────────────────┐
      │ bwrap   (fs, pid, uts, ipc ns — optional netns) │
      │  └── python3 seccomp_helper.py --deny --exec -- │
      │       └── cline -y "<task>"   (the agent)       │
      └──────────────┬──────────────────────────────────┘
                     │ http_proxy=…:9090
                     ▼
            ┌────────────────────────────┐
            │ llm_proxy.py (port 9090)   │ ← injects API key
            │ forwards → api.anthropic…  │
            └────────────────────────────┘
```

### Why a proxy

The agent never sees the real API key and cannot exfiltrate to an
arbitrary domain. Add a domain allowlist to `llm_proxy.py` to restrict
further, or run with `CLINE_SANDBOX_UNSHARE_NET=1` and expose the proxy
over a unix socket for the strongest isolation.

### Session states

```
pending → starting → running ⇄ paused
                          │
                          ▼
                     stopping → completed
                                  failed
                                  killed
                     error (never spawned)
```

* `completed` — exit 0
* `failed` — exit > 0 or SIGTERM after grace expired
* `killed` — exit < 0 (signalled) or user issued `/kill`
* `error` — sandbox couldn't be constructed (missing bwrap, bad config)

## Configuration

Everything has an env-var override (`CLINE_SANDBOX_*`) so you can drop
a `.env` next to the server or export inline.

| Variable | Default | Meaning |
|----------|---------|---------|
| `CLINE_SANDBOX_HOST` | `127.0.0.1` | API bind address. |
| `CLINE_SANDBOX_PORT` | `8080` | API port. |
| `CLINE_SANDBOX_STATE_DIR` | `workspace/sessions` | Per-session scratch root. |
| `CLINE_SANDBOX_AGENT_COMMAND` | `cline -y` | Command to execute inside the sandbox. `{task}` substitutes the task text; otherwise the task is appended as the last arg. |
| `CLINE_SANDBOX_ENABLE_SECCOMP` | `true` | Apply the BPF denylist. |
| `CLINE_SANDBOX_UNSHARE_NET` | `false` | Put the agent in a fresh netns. Requires the proxy to be reachable via a bind-mounted socket (future work). |
| `CLINE_SANDBOX_LLM_PROXY_URL` | `http://127.0.0.1:9090` | What the agent talks to. Injected as `http_proxy`, `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`. |
| `CLINE_SANDBOX_LLM_UPSTREAM` | `https://api.anthropic.com` | Where the proxy forwards. |
| `CLINE_SANDBOX_LLM_API_KEY_ENV` | `ANTHROPIC_API_KEY` | Which env var holds the upstream API key. |
| `CLINE_SANDBOX_START_LLM_PROXY` | `true` | Launch the proxy alongside the API. |
| `CLINE_SANDBOX_MAX_SESSIONS` | `32` | Refuse new sessions once this many are alive. |
| `CLINE_SANDBOX_EXTRA_RO_BINDS` | *(empty)* | Comma-separated extra `--ro-bind` paths (operator-specified; always allowed). |
| `CLINE_SANDBOX_EXTRA_RW_BINDS` | *(empty)* | Comma-separated extra `--bind` paths (operator-specified; always allowed). |
| `CLINE_SANDBOX_ALLOWED_EXTRA_BINDS` | *(empty)* | Prefix allowlist for **API-supplied** extra binds. Empty means API callers cannot add binds — only operator-specified ones via `EXTRA_*_BINDS` above. |
| `CLINE_SANDBOX_AUTH_TOKEN` | *(unset)* | If set, required as `X-Auth-Token:` or `Authorization: Bearer …` on every request. |
| `CLINE_SANDBOX_CORS_ALLOW_ORIGIN` | *(unset)* | Comma-separated CORS origins for the dashboard. |

## Running a non-cline agent

The wrapper isn't hard-wired to cline. Override the command per session:

```bash
curl -sS -X POST http://127.0.0.1:8080/sessions \
  -H "Content-Type: application/json" \
  -d '{
        "task": "Refactor foo.py",
        "agent_command": "aider --yes --message {task}"
      }'
```

`{task}` is replaced inline; if absent, the task text is appended as
the trailing positional argument (what cline expects).

## Tests

```bash
uv run pytest cline_sandbox/tests -v
```

Integration tests that exercise the real sandbox are skipped when
`bwrap` isn't installed.

## Security notes / limitations

* **Kernel shared**. A kernel 0-day can bypass any of these layers. For
  fully untrusted code, layer this inside a VM (Firecracker, Kata,
  gVisor).
* **Seccomp mode**. Denied syscalls **kill** the agent
  (`SECCOMP_RET_KILL_PROCESS`) — an attacker can't probe for what's
  blocked and retry with a different primitive. The denylist covers
  ~50 syscalls including the classic escape primitives (`ptrace`,
  `mount`, `bpf`, `kexec*`, `init_module`, `unshare`, `setns`,
  `io_uring_*`) **and** modern ones (`keyctl`, `add_key`,
  `process_vm_readv`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`,
  `pidfd_send_signal`, `pidfd_getfd`, `seccomp` itself, `modify_ldt`,
  `iopl`, `name_to_handle_at`, `fanotify_init`). The x32 ABI is killed
  outright so denial can't be bypassed by flipping the high bit.
* **Network isolation**. By default we keep `--share-net` so the proxy
  on `127.0.0.1` is reachable. This means the agent can technically
  connect to **any** host-reachable address (including other loopback
  services — the control-plane API on 8080, any local database, SSH,
  …). The `http_proxy`/`ANTHROPIC_BASE_URL` env vars are a *convention*,
  not an enforcement. The launcher emits a loud warning when this
  default is in use. For tighter isolation, set
  `CLINE_SANDBOX_UNSHARE_NET=1` and bridge the LLM proxy into the agent's
  new netns (bind-mount a unix socket or set up a veth pair).
* **Auth**. The API is unauthenticated by default — set
  `CLINE_SANDBOX_AUTH_TOKEN` before exposing it off-localhost. The token
  is compared in constant time and accepted via `X-Auth-Token:`,
  `Authorization: Bearer …`, or (SSE only) `?token=` since browsers
  can't set custom headers on `EventSource`.
* **CORS**. Leave `CLINE_SANDBOX_CORS_ALLOW_ORIGIN` unset in production.
  Pairing it with `allow_credentials=True` and a hostile origin would
  let a third-party page drive the API on an authenticated user's
  behalf.
* **API-supplied binds**. `extra_ro_binds`/`extra_rw_binds` on
  `POST /sessions` are rejected unless a prefix allowlist is configured
  via `CLINE_SANDBOX_ALLOWED_EXTRA_BINDS`. Without this, an
  authenticated caller could bind `/` read-write and defeat the
  filesystem isolation.
* **User namespace**. `bwrap --unshare-user-try` is set, so the agent's
  view of uid/gid is virtualised. On kernels where unprivileged
  user-ns is disabled (hardened RHEL), the flag silently no-ops and the
  agent falls back to the host user-ns. A nested `clone(CLONE_NEWUSER)`
  inside that case is a residual concern — enable user namespaces on
  such hosts (`sysctl user.max_user_namespaces=16384`).
* **No resource limits yet**. Add `--setrlimit`, `--cap-drop`, or cgroup
  budgets for memory/CPU pressure protection. `max_sessions` is the
  only current ceiling.

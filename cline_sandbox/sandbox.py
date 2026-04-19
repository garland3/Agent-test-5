"""Build the bubblewrap command line for a sandboxed agent session.

The sandbox combines three kernel features:

* **Filesystem** — selective `--ro-bind` / `--bind` so the agent only sees
  system binaries and its own per-session workspace. `$HOME`, `/root`,
  `/var`, and the host `/tmp` are never exposed.
* **Process namespace** — `--unshare-pid` hides host processes.
* **Network** — either `--unshare-net` (loopback only, LLM proxy reached
  via a bind-mounted unix socket … future work) or `--share-net` plus an
  `http_proxy` env pointing at the filtering LLM proxy. In both cases the
  agent's outbound network is constrained to a single, audited endpoint.

Seccomp layering is applied by `wrap_with_seccomp` — it prepends the
bwrap argv with an invocation of `seccomp_helper.py --exec` so that the
BPF filter is installed before `execve` of the agent.

The builder is deliberately side-effect free: it validates paths and
returns an argv list. Starting the process is the session manager's job.
"""

from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

# Repo layout — resolved once at import time so we can locate
# seccomp_helper.py regardless of the caller's cwd.
_PKG_DIR = Path(__file__).resolve().parent
_REPO_DIR = _PKG_DIR.parent
_SECCOMP_HELPER = _REPO_DIR / "seccomp_helper.py"


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot be constructed (missing binaries,
    invalid paths, etc.)."""


@dataclass
class SandboxPlan:
    """Result of `SandboxBuilder.build` — the full argv plus metadata
    useful for logging and dashboards."""

    argv: List[str]
    workspace: Path
    env: Dict[str, str]
    description: Dict[str, object] = field(default_factory=dict)


class SandboxBuilder:
    """Compose a bwrap invocation from per-session inputs."""

    def __init__(
        self,
        *,
        ro_binds: Sequence[str],
        rw_binds: Sequence[str] = (),
        unshare_net: bool = False,
        enable_seccomp: bool = True,
        bwrap_binary: str = "bwrap",
        python_binary: Optional[str] = None,
    ) -> None:
        self.ro_binds = [str(p) for p in ro_binds]
        self.rw_binds = [str(p) for p in rw_binds]
        self.unshare_net = unshare_net
        self.enable_seccomp = enable_seccomp
        self.bwrap_binary = bwrap_binary
        # The python used inside the sandbox must live under a path
        # that is ro-bind-mounted. /usr/bin/python3 is always bound via
        # ro_binds; `sys.executable` is typically the wrapper's venv
        # python, which is *not* bound inside the sandbox.
        self.python_binary = python_binary or "/usr/bin/python3"

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def build(
        self,
        *,
        workspace: Path,
        agent_argv: Sequence[str],
        extra_env: Optional[Dict[str, str]] = None,
        proxy_url: Optional[str] = None,
    ) -> SandboxPlan:
        """Produce a full bwrap+seccomp argv.

        The caller is responsible for creating any files inside the
        workspace *before* invoking the agent (e.g. a ``task.md`` for
        cline to pick up).
        """
        if shutil.which(self.bwrap_binary) is None:
            raise SandboxError(
                f"bwrap binary '{self.bwrap_binary}' not found on PATH. "
                "Install bubblewrap: `sudo apt install bubblewrap` or "
                "`sudo dnf install bubblewrap`."
            )
        if not agent_argv:
            raise SandboxError("agent_argv must not be empty")

        workspace = Path(workspace).resolve()
        workspace.mkdir(parents=True, exist_ok=True)

        env = self._base_env(proxy_url=proxy_url)
        if extra_env:
            env.update(extra_env)

        bwrap_args = self._bwrap_core_args(env=env, workspace=workspace)

        # Seccomp layering: if requested, prepend seccomp_helper.py --exec.
        # That module installs the BPF filter then exec()s the agent, so
        # the filter is inherited across the exec boundary.
        if self.enable_seccomp:
            if not _SECCOMP_HELPER.exists():
                raise SandboxError(
                    f"seccomp helper not found at {_SECCOMP_HELPER}"
                )
            # `strict` makes DANGEROUS_SYSCALLS kill the process rather
            # than return EPERM. Permissive mode lets an attacker probe
            # for blocked ops and pivot; KILL is the secure default.
            inner_cmd: List[str] = [
                self.python_binary,
                "/project/seccomp_helper.py",
                "--mode",
                "strict",
                "--deny",
                "--exec",
                "--",
                *agent_argv,
            ]
        else:
            inner_cmd = list(agent_argv)

        argv = [self.bwrap_binary, *bwrap_args, "--", *inner_cmd]

        return SandboxPlan(
            argv=argv,
            workspace=workspace,
            env=env,
            description={
                "ro_binds": list(self.ro_binds),
                "rw_binds": list(self.rw_binds),
                "unshare_net": self.unshare_net,
                "seccomp": self.enable_seccomp,
                "agent_argv": list(agent_argv),
                "proxy_url": proxy_url,
            },
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _base_env(self, *, proxy_url: Optional[str]) -> Dict[str, str]:
        env: Dict[str, str] = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/workspace",
            "PYTHONUNBUFFERED": "1",
            "CLINE_SANDBOX": "1",
            "CLINE_YOLO": "1",
        }
        if proxy_url:
            env.update(
                {
                    "http_proxy": proxy_url,
                    "https_proxy": proxy_url,
                    "HTTP_PROXY": proxy_url,
                    "HTTPS_PROXY": proxy_url,
                    "ANTHROPIC_BASE_URL": proxy_url,
                    "OPENAI_BASE_URL": proxy_url,
                }
            )
        return env

    def _bwrap_core_args(
        self, *, env: Dict[str, str], workspace: Path
    ) -> List[str]:
        args: List[str] = ["--clearenv", "--die-with-parent", "--new-session"]

        for k, v in env.items():
            args += ["--setenv", k, v]

        # Read-only system paths
        for p in self.ro_binds:
            if p == "/lib64":
                # Some distros (e.g. Debian multiarch) lack /lib64;
                # treat that bind as best-effort.
                args += ["--ro-bind-try", p, p]
            else:
                args += ["--ro-bind", p, p]

        # Project source is read-only inside the sandbox — the agent sees
        # helpers (seccomp_helper.py) but cannot modify them.
        args += ["--ro-bind", str(_REPO_DIR), "/project"]

        # Per-session read-write workspace.
        args += ["--bind", str(workspace), "/workspace"]

        # Additional rw binds (power-user escape hatch).
        for p in self.rw_binds:
            resolved = str(Path(p).resolve())
            args += ["--bind", resolved, resolved]

        # Minimal /proc, /dev, and a fresh tmpfs for /tmp.
        args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]

        if self.unshare_net:
            args += ["--unshare-net"]
        # --unshare-user-try mitigates clone3(CLONE_NEWUSER) escapes:
        # once the agent is already in an unprivileged user-ns, a child
        # that nests another user-ns cannot gain capabilities it
        # didn't have. `-try` silently no-ops on kernels where user
        # namespaces are disabled (e.g. hardened RHEL defaults).
        args += [
            "--unshare-pid", "--unshare-uts", "--unshare-ipc",
            "--unshare-user-try", "--unshare-cgroup-try",
        ]

        args += ["--chdir", "/workspace"]
        return args

    # ------------------------------------------------------------------
    # debugging
    # ------------------------------------------------------------------
    @staticmethod
    def render(argv: Sequence[str]) -> str:
        """Render argv as a copy-pasteable shell string."""
        return " ".join(shlex.quote(str(a)) for a in argv)


def ensure_binaries_available(*, need_seccomp: bool = True) -> List[str]:
    """Return a list of missing binaries for preflight error messages.

    Empty list = all clear.
    """
    missing: List[str] = []
    if shutil.which("bwrap") is None:
        missing.append("bwrap (bubblewrap)")
    if need_seccomp and not _SECCOMP_HELPER.exists():
        missing.append(f"seccomp_helper.py at {_SECCOMP_HELPER}")
    return missing

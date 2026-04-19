"""Configuration for the cline_sandbox wrapper.

All runtime knobs live here and can be overridden via environment variables
(prefix `CLINE_SANDBOX_`) or constructor args. Defaults are conservative.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def _env(name: str, default: str) -> str:
    return os.environ.get(f"CLINE_SANDBOX_{name}", default)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(f"CLINE_SANDBOX_{name}")
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(f"CLINE_SANDBOX_{name}")
    return int(raw) if raw else default


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(f"CLINE_SANDBOX_{name}")
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


DEFAULT_RO_BINDS = [
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
]


@dataclass
class Settings:
    """Runtime configuration for the sandbox wrapper."""

    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8080))

    state_dir: Path = field(
        default_factory=lambda: Path(_env("STATE_DIR", "workspace/sessions")).resolve()
    )

    agent_command: str = field(
        default_factory=lambda: _env("AGENT_COMMAND", "cline -y")
    )

    extra_ro_binds: List[str] = field(
        default_factory=lambda: _env_list("EXTRA_RO_BINDS", [])
    )
    extra_rw_binds: List[str] = field(
        default_factory=lambda: _env_list("EXTRA_RW_BINDS", [])
    )
    # Path prefixes under which API callers may request additional
    # bind mounts. Empty list = API callers cannot add binds (default).
    allowed_extra_binds: List[str] = field(
        default_factory=lambda: _env_list("ALLOWED_EXTRA_BINDS", [])
    )

    enable_seccomp: bool = field(
        default_factory=lambda: _env_bool("ENABLE_SECCOMP", True)
    )
    unshare_net: bool = field(
        default_factory=lambda: _env_bool("UNSHARE_NET", False)
    )

    llm_proxy_url: str = field(
        default_factory=lambda: _env("LLM_PROXY_URL", "http://127.0.0.1:9090")
    )
    llm_upstream: str = field(
        default_factory=lambda: _env("LLM_UPSTREAM", "https://api.anthropic.com")
    )
    llm_api_key_env: str = field(
        default_factory=lambda: _env("LLM_API_KEY_ENV", "ANTHROPIC_API_KEY")
    )
    start_llm_proxy: bool = field(
        default_factory=lambda: _env_bool("START_LLM_PROXY", True)
    )

    max_sessions: int = field(
        default_factory=lambda: _env_int("MAX_SESSIONS", 32)
    )
    default_timeout_seconds: int = field(
        default_factory=lambda: _env_int("DEFAULT_TIMEOUT", 0)
    )

    auth_token: Optional[str] = field(
        default_factory=lambda: os.environ.get("CLINE_SANDBOX_AUTH_TOKEN") or None
    )

    cors_allow_origin: str = field(
        default_factory=lambda: _env("CORS_ALLOW_ORIGIN", "")
    )

    def ensure_state_dir(self) -> Path:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        return self.state_dir

    def parsed_agent_command(self) -> List[str]:
        return shlex.split(self.agent_command)

    def ro_binds(self) -> List[str]:
        seen: List[str] = []
        for p in DEFAULT_RO_BINDS + list(self.extra_ro_binds):
            if p and p not in seen:
                seen.append(p)
        return seen

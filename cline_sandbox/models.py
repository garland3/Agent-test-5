"""Pydantic models for the HTTP API.

Kept minimal — the manager is the source of truth, these models are
serialization schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CreateSessionRequest(BaseModel):
    task: str = Field(..., description="Initial task prompt sent to the agent.")
    agent_command: Optional[str] = Field(
        default=None,
        description="Override the configured agent command "
                    "(e.g. 'cline -y' or 'aider --yes').",
    )
    extra_ro_binds: List[str] = Field(
        default_factory=list,
        description="Additional read-only paths to bind-mount into the sandbox.",
    )
    extra_rw_binds: List[str] = Field(
        default_factory=list,
        description="Additional read-write paths (use with care).",
    )
    timeout_seconds: Optional[int] = Field(
        default=None,
        description="Kill the session after this many seconds (0 / null = no timeout).",
    )
    env: Dict[str, str] = Field(
        default_factory=dict,
        description="Extra environment variables injected into the sandbox.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata stored with the session.",
    )


class SessionSummary(BaseModel):
    id: str
    state: str
    created_at: float
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    task: str
    agent_command: str
    workspace: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SessionDetail(SessionSummary):
    sandbox: Dict[str, Any] = Field(default_factory=dict)
    event_count: int = 0
    last_event_time: Optional[float] = None


class MessageRequest(BaseModel):
    content: str = Field(..., description="Text to send to the agent on stdin.")
    append_newline: bool = Field(
        default=True,
        description="Append '\\n' so the agent sees a complete line.",
    )


class SimpleResponse(BaseModel):
    ok: bool = True
    detail: Optional[str] = None


class Event(BaseModel):
    session_id: str
    time: float
    kind: str
    data: Dict[str, Any] = Field(default_factory=dict)

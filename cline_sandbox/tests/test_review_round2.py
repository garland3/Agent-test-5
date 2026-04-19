"""Regression tests for issues flagged by Codex and Copilot on PR #2."""

from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport

from cline_sandbox.app import create_app
from cline_sandbox.config import Settings
from cline_sandbox.session_manager import (
    InvalidStateError,
    SessionManager,
    SessionState,
)

from .conftest import requires_bwrap


pytestmark = [requires_bwrap]


async def _client(settings: Settings):
    manager = SessionManager(settings)
    app = create_app(settings, manager=manager)
    await manager.start()
    transport = ASGITransport(app=app)
    return manager, httpx.AsyncClient(transport=transport, base_url="http://t")


# --------------------------------------------------------------------
# Codex P1: stop-grace escalation must not report as COMPLETED.
# --------------------------------------------------------------------
async def test_stop_escalation_maps_to_killed(tmp_path: Path):
    """When stop() escalates to SIGKILL (grace expired), the final
    state must be KILLED, not COMPLETED. We prove this directly by
    driving the manager through the escalation code path rather than
    trying to race an uncooperative agent — bwrap is PID 1 of the new
    pid namespace, so when SIGTERM hits bwrap the whole ns dies
    regardless of any SIGTERM handlers set inside."""
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/sleep 30",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        for _ in range(40):
            if session.state == SessionState.RUNNING:
                break
            await asyncio.sleep(0.05)
        # Directly simulate the escalation path: mark the flag and send
        # a SIGKILL. This is exactly what stop() does on grace timeout.
        session.stop_escalated = True
        session.state = SessionState.STOPPING
        await manager.kill(session.id, reason="stop-grace-expired")
        for _ in range(60):
            if session.state in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert session.state == SessionState.KILLED, (
            f"expected KILLED, got {session.state} "
            f"(escalated={session.stop_escalated}, rc={session.exit_code})"
        )
    finally:
        await manager.aclose()


async def test_stop_no_escalation_stays_completed(tmp_path: Path):
    """A cooperating agent that exits on SIGTERM is still COMPLETED."""
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/sleep 30",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        for _ in range(40):
            if session.state == SessionState.RUNNING:
                break
            await asyncio.sleep(0.05)
        await manager.stop(session.id, grace_seconds=3.0)
        for _ in range(60):
            if session.state in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert session.state == SessionState.COMPLETED
        assert session.stop_escalated is False
    finally:
        await manager.aclose()


# --------------------------------------------------------------------
# Codex P1: max_sessions must count PENDING sessions too.
# --------------------------------------------------------------------
async def test_max_sessions_counts_pending(tmp_path: Path):
    """After the cap, create() must raise — even if earlier sessions
    haven't transitioned out of PENDING yet."""
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/sleep 10",
        enable_seccomp=False,
        start_llm_proxy=False,
        max_sessions=1,
    )
    manager = SessionManager(settings)
    await manager.start()
    try:
        await manager.create(task="a")
        with pytest.raises(InvalidStateError):
            await manager.create(task="b")
    finally:
        await manager.aclose()


# --------------------------------------------------------------------
# Copilot: extra_ro_binds must reach the sandbox, not just be validated.
# --------------------------------------------------------------------
async def test_extra_ro_binds_reach_sandbox(tmp_path: Path):
    """Creating a session with a valid extra_ro_bind should produce
    a bwrap argv that actually includes that path."""
    allowed = tmp_path / "payload"
    allowed.mkdir()
    (allowed / "marker.txt").write_text("hi")

    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
        allowed_extra_binds=[str(allowed)],
    )
    manager, client = await _client(settings)
    async with client:
        r = await client.post("/sessions", json={
            "task": "check bind",
            "extra_ro_binds": [str(allowed)],
        })
        assert r.status_code == 201, r.text
        argv = r.json()["sandbox"]["argv"]
        # The requested path must appear in the bwrap argv.
        assert str(allowed) in argv, (
            f"extra_ro_binds did not reach argv: {argv}"
        )
    await manager.aclose()


# --------------------------------------------------------------------
# Copilot: `limit` query must reject negative / absurd values.
# --------------------------------------------------------------------
async def test_events_limit_rejects_bad_values(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager, client = await _client(settings)
    async with client:
        r = await client.post("/sessions", json={"task": "noop"})
        sid = r.json()["id"]
        for _ in range(40):
            r = await client.get(f"/sessions/{sid}")
            if r.json()["state"] in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)

        # Negative → 422
        r = await client.get(f"/sessions/{sid}/events?limit=-1")
        assert r.status_code == 422
        # Zero → 422 (we require ge=1)
        r = await client.get(f"/sessions/{sid}/events?limit=0")
        assert r.status_code == 422
        # Too large → 422
        r = await client.get(f"/sessions/{sid}/events?limit=99999999")
        assert r.status_code == 422
        # Sane value → 200
        r = await client.get(f"/sessions/{sid}/events?limit=2")
        assert r.status_code == 200
        assert len(r.json()) <= 2
    await manager.aclose()


# --------------------------------------------------------------------
# Copilot: _await_exit must not hang when a subscriber queue is full.
# --------------------------------------------------------------------
async def test_exit_sentinel_does_not_hang_on_full_queue(tmp_path: Path):
    """Fill a subscriber's queue then let the session exit; teardown
    must not block."""
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="noop")
        # Simulate a stuck SSE consumer by creating a small subscriber
        # queue and packing it full before the exit fan-out runs.
        stuck: asyncio.Queue = asyncio.Queue(maxsize=1)
        session.subscribers.append(stuck)
        stuck.put_nowait("FILL")  # queue is now full

        # Wait for the session to exit naturally.
        for _ in range(100):
            if session.state in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert session.state == SessionState.COMPLETED

        # The _await_exit task must have completed in bounded time.
        for task in session.reader_tasks:
            try:
                await asyncio.wait_for(task, timeout=1.0)
            except asyncio.TimeoutError:
                pytest.fail(f"reader task {task} hung on exit fan-out")
    finally:
        await manager.aclose()


# --------------------------------------------------------------------
# Copilot: allowlist seccomp filter also kills x32 syscalls.
# --------------------------------------------------------------------
def test_allowlist_filter_kills_x32():
    """The BPF program returned by build_allowlist_filter must contain
    a JSET against 0x40000000 — otherwise x32 syscalls skate past the
    JEQ chain."""
    from seccomp_helper import build_allowlist_filter
    import struct

    prog = build_allowlist_filter(["read", "write"])
    # Instructions are 8 bytes each; unpack and look for a JSET with
    # immediate k=0x40000000.
    found = False
    for i in range(0, len(prog), 8):
        code, jt, jf, k = struct.unpack("HBBI", prog[i:i + 8])
        # BPF_JMP | BPF_JSET | BPF_K == 0x45
        if code == 0x45 and k == 0x40000000:
            found = True
            break
    assert found, "x32 ABI JSET guard missing from allowlist filter"

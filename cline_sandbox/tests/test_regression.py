"""Regression tests for issues identified during the security /
code review. Each test is named after the finding it guards against.
"""

from __future__ import annotations

import asyncio
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
# extra_*_binds restriction (review: HIGH "attacker-controlled host mounts")
# --------------------------------------------------------------------
async def test_extra_rw_binds_rejected_without_allowlist(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager, client = await _client(settings)
    async with client:
        r = await client.post("/sessions", json={
            "task": "evil",
            "extra_rw_binds": ["/root"],
        })
        assert r.status_code == 429  # InvalidStateError → 429
        assert "not configured" in r.text.lower() or "safety" in r.text.lower()
    await manager.aclose()


async def test_extra_rw_binds_prefix_allowlist(tmp_path: Path):
    allowed = tmp_path / "shared"
    allowed.mkdir()
    bad = tmp_path / "secret"
    bad.mkdir()

    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
        allowed_extra_binds=[str(allowed)],
    )
    manager, client = await _client(settings)
    async with client:
        # Path not under allowlist → 429
        r = await client.post("/sessions", json={
            "task": "evil",
            "extra_rw_binds": [str(bad)],
        })
        assert r.status_code == 429

        # Path under allowlist → accepted (201)
        r = await client.post("/sessions", json={
            "task": "ok",
            "extra_rw_binds": [str(allowed)],
        })
        assert r.status_code == 201
    await manager.aclose()


# --------------------------------------------------------------------
# session_id path validation (review: MEDIUM "session_id not validated")
# --------------------------------------------------------------------
async def test_bad_session_id_returns_404(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager, client = await _client(settings)
    async with client:
        # Wrong length, non-hex, mixed case (we enforce lowercase hex).
        for bad in ["nope", "z" * 32, "0" * 31, "A" * 32, "1" * 33]:
            r = await client.get(f"/sessions/{bad}")
            assert r.status_code in (404, 422), (bad, r.status_code)
    await manager.aclose()


# --------------------------------------------------------------------
# SSE ?token= query support (review: MEDIUM "auth header vs query mismatch")
# --------------------------------------------------------------------
async def test_sse_accepts_query_token(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
        auth_token="sekret",
    )
    manager, client = await _client(settings)
    async with client:
        r = await client.post(
            "/sessions",
            json={"task": "noop"},
            headers={"X-Auth-Token": "sekret"},
        )
        sid = r.json()["id"]

        # Without any auth → 401
        r = await client.get(f"/sessions/{sid}/stream")
        assert r.status_code == 401

        # With ?token= → 200
        r = await client.get(
            f"/sessions/{sid}/stream?token=sekret",
        )
        assert r.status_code == 200

        # With wrong token → 401
        r = await client.get(f"/sessions/{sid}/stream?token=wrong")
        assert r.status_code == 401
    await manager.aclose()


# --------------------------------------------------------------------
# max_sessions enforcement (review: MUST-FIX "create() race")
# --------------------------------------------------------------------
async def test_max_sessions_rejects_429(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/sleep 10",
        enable_seccomp=False,
        start_llm_proxy=False,
        max_sessions=2,
    )
    manager, client = await _client(settings)
    async with client:
        s1 = await client.post("/sessions", json={"task": "a"})
        s2 = await client.post("/sessions", json={"task": "b"})
        s3 = await client.post("/sessions", json={"task": "c"})
        assert s1.status_code == 201
        assert s2.status_code == 201
        assert s3.status_code == 429

        # Kill one → a new slot opens up
        await client.post(f"/sessions/{s1.json()['id']}/kill")
        # Brief pause for reaper
        for _ in range(40):
            r = await client.get(f"/sessions/{s1.json()['id']}")
            if r.json()["state"] in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)

        s4 = await client.post("/sessions", json={"task": "d"})
        assert s4.status_code == 201
    await manager.aclose()


# --------------------------------------------------------------------
# historical_events(limit=N) slicing (review: NIT)
# --------------------------------------------------------------------
async def test_historical_events_limit(tmp_path: Path):
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

        r = await client.get(f"/sessions/{sid}/events")
        total = len(r.json())
        assert total >= 3  # created, spawning, started, exited at minimum

        r = await client.get(f"/sessions/{sid}/events?limit=1")
        assert len(r.json()) == 1
    await manager.aclose()


# --------------------------------------------------------------------
# stop() → SIGTERM should produce COMPLETED, not FAILED
# (review: SHOULD-FIX "stop state mapping")
# --------------------------------------------------------------------
async def test_stop_maps_to_completed(tmp_path: Path):
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
        # Wait for it to actually be running
        for _ in range(40):
            if session.state == SessionState.RUNNING:
                break
            await asyncio.sleep(0.05)
        await manager.stop(session.id, grace_seconds=3.0)
        # After stop the state should be COMPLETED, not FAILED,
        # even though the process's rc is negative (-SIGTERM).
        for _ in range(40):
            if session.state in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert session.state == SessionState.COMPLETED, (
            f"expected COMPLETED, got {session.state} rc={session.exit_code}"
        )
    finally:
        await manager.aclose()


# --------------------------------------------------------------------
# Reader tasks are cleaned up on aclose (review: MUST-FIX)
# --------------------------------------------------------------------
async def test_aclose_drains_reader_tasks(tmp_path: Path):
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/sleep 30",
        enable_seccomp=False,
        start_llm_proxy=False,
    )
    manager = SessionManager(settings)
    await manager.start()
    session = await manager.create(task="sleep")
    # Let it start
    for _ in range(40):
        if session.state == SessionState.RUNNING:
            break
        await asyncio.sleep(0.05)

    await manager.aclose()
    # All reader tasks should be done.
    for task in session.reader_tasks:
        assert task.done(), f"task {task} still pending after aclose"


# --------------------------------------------------------------------
# killpg TOCTOU: signalling a reaped session is a no-op, not a crash
# --------------------------------------------------------------------
async def test_kill_after_exit_is_noop(tmp_path: Path):
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
        # Wait for natural exit
        for _ in range(100):
            if session.state in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)
        assert session.state == SessionState.COMPLETED

        # Killing a session that has already been reaped must not raise.
        await manager.kill(session.id)  # no-op, returncode is set
    finally:
        await manager.aclose()

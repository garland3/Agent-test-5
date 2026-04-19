"""Integration tests for SessionManager. These require bwrap."""

from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path

import pytest

from cline_sandbox.session_manager import (
    InvalidStateError,
    SessionManager,
    SessionState,
)

from .conftest import requires_bwrap


pytestmark = [requires_bwrap]


async def _wait_for_state(
    manager: SessionManager, session_id: str, *, predicate, timeout: float = 10.0
) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        s = manager.get(session_id)
        if predicate(s):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(
        f"timeout waiting for session {session_id} "
        f"(current state: {manager.get(session_id).state})"
    )


async def _wait_for_event(
    manager: SessionManager, session_id: str, kind: str, *, timeout: float = 10.0
) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        events = manager.historical_events(session_id)
        if any(e["kind"] == kind for e in events):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"never saw event '{kind}' for session {session_id}")


async def test_session_lifecycle_echo(settings, echo_script: Path):
    """Spawn the echo 'agent', send a message, read it back, then quit."""
    # Use the system python3 so the interpreter is visible inside bwrap
    # (the venv python isn't bind-mounted).
    settings.agent_command = f"/usr/bin/python3 {shlex.quote(str(echo_script))}"
    settings.extra_ro_binds = [str(echo_script.parent)]

    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="hello")
        await _wait_for_event(manager, session.id, "started")

        # Give the fake agent a moment to print READY.
        await _wait_for_event(manager, session.id, "stdout")

        await manager.send_message(session.id, "world")
        # The fake agent prints 'ECHO: world'.
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: any(
                e["kind"] == "stdout" and "ECHO: world" in e["data"].get("text", "")
                for e in manager.historical_events(session.id)
            ),
        )

        await manager.send_message(session.id, "QUIT")
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
        )
        assert manager.get(session.id).state == SessionState.COMPLETED
        assert manager.get(session.id).exit_code == 0
    finally:
        await manager.aclose()


async def test_kill_terminates_process(settings):
    settings.agent_command = "/bin/sleep 60"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        await _wait_for_event(manager, session.id, "started")

        await manager.kill(session.id)
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
        )
        assert manager.get(session.id).state in (
            SessionState.KILLED, SessionState.FAILED
        )
    finally:
        await manager.aclose()


async def test_stop_sends_sigterm(settings):
    # /bin/sleep exits 0 on SIGTERM without writing — STOP should therefore
    # end in `completed` (0) or `failed` (non-zero) depending on shell.
    settings.agent_command = "/bin/sleep 60"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        await _wait_for_event(manager, session.id, "started")
        await manager.stop(session.id, grace_seconds=5.0)
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
        )
        assert manager.get(session.id).state in SessionState.TERMINAL
    finally:
        await manager.aclose()


async def test_pause_resume(settings):
    settings.agent_command = "/bin/sleep 30"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        await _wait_for_event(manager, session.id, "started")

        await manager.pause(session.id)
        assert manager.get(session.id).state == SessionState.PAUSED

        await manager.resume(session.id)
        assert manager.get(session.id).state == SessionState.RUNNING

        await manager.kill(session.id)
    finally:
        await manager.aclose()


async def test_invalid_state_raises(settings):
    settings.agent_command = "/bin/sleep 30"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="sleep")
        await _wait_for_event(manager, session.id, "started")

        # cannot resume when running
        with pytest.raises(InvalidStateError):
            await manager.resume(session.id)

        await manager.kill(session.id)
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
        )

        # cannot send input to terminated session
        with pytest.raises(InvalidStateError):
            await manager.send_message(session.id, "late")
    finally:
        await manager.aclose()


async def test_events_persisted_to_jsonl(settings):
    settings.agent_command = "/bin/true"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="noop")
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
            timeout=15.0,
        )
        assert session.events_path.exists()
        lines = session.events_path.read_text().splitlines()
        kinds = [line for line in lines if line.strip()]
        assert any('"kind": "created"' in line for line in kinds)
        assert any('"kind": "exited"' in line for line in kinds)
    finally:
        await manager.aclose()


async def test_historical_events_api(settings):
    settings.agent_command = "/bin/true"
    manager = SessionManager(settings)
    await manager.start()
    try:
        session = await manager.create(task="noop")
        await _wait_for_state(
            manager, session.id,
            predicate=lambda s: s.state in SessionState.TERMINAL,
        )
        events = manager.historical_events(session.id)
        kinds = [e["kind"] for e in events]
        assert "created" in kinds
        assert "exited" in kinds
    finally:
        await manager.aclose()

"""HTTP-level smoke tests via httpx.AsyncClient + ASGI transport."""

from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport

from cline_sandbox.app import create_app
from cline_sandbox.session_manager import SessionManager, SessionState

from .conftest import requires_bwrap


pytestmark = [requires_bwrap]


async def _mk_client(settings):
    manager = SessionManager(settings)
    app = create_app(settings, manager=manager)
    transport = ASGITransport(app=app)
    return manager, app, httpx.AsyncClient(
        transport=transport, base_url="http://test"
    )


async def test_healthz(settings):
    manager, app, client = await _mk_client(settings)
    async with client:
        # Trigger startup
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as _:
            pass
        r = await client.get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ok", "degraded")


async def test_config_endpoint(settings):
    manager, app, client = await _mk_client(settings)
    async with client:
        r = await client.get("/config")
        assert r.status_code == 200
        data = r.json()
        assert data["agent_command"] == settings.agent_command
        assert data["enable_seccomp"] is False


async def test_session_crud_flow(settings):
    settings.agent_command = "/bin/true"
    manager, app, client = await _mk_client(settings)
    # Start the manager explicitly — ASGITransport does not fire lifespan by default.
    await manager.start()
    async with client:
        # Create
        r = await client.post("/sessions", json={"task": "just exit"})
        assert r.status_code == 201, r.text
        session_id = r.json()["id"]

        # Wait until terminal
        for _ in range(100):
            r = await client.get(f"/sessions/{session_id}")
            if r.json()["state"] in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)

        # List
        r = await client.get("/sessions")
        ids = [s["id"] for s in r.json()]
        assert session_id in ids

        # Events
        r = await client.get(f"/sessions/{session_id}/events")
        kinds = [e["kind"] for e in r.json()]
        assert "created" in kinds
        assert "exited" in kinds

    await manager.aclose()


async def test_message_endpoint_for_terminated_session(settings, echo_script: Path):
    settings.agent_command = f"/usr/bin/python3 {shlex.quote(str(echo_script))}"
    settings.extra_ro_binds = [str(echo_script.parent)]
    manager, app, client = await _mk_client(settings)
    await manager.start()
    async with client:
        r = await client.post("/sessions", json={"task": "echo"})
        session_id = r.json()["id"]

        # Wait for it to be running
        for _ in range(100):
            r = await client.get(f"/sessions/{session_id}")
            if r.json()["state"] == SessionState.RUNNING:
                break
            await asyncio.sleep(0.05)

        r = await client.post(
            f"/sessions/{session_id}/message",
            json={"content": "QUIT"},
        )
        assert r.status_code == 200

        # Wait for exit
        for _ in range(200):
            r = await client.get(f"/sessions/{session_id}")
            if r.json()["state"] in SessionState.TERMINAL:
                break
            await asyncio.sleep(0.05)

        # Sending again should 409
        r = await client.post(
            f"/sessions/{session_id}/message",
            json={"content": "too late"},
        )
        assert r.status_code == 409

    await manager.aclose()


async def test_auth_token(tmp_path: Path):
    from cline_sandbox.config import Settings
    settings = Settings(
        state_dir=tmp_path / "sessions",
        agent_command="/bin/true",
        enable_seccomp=False,
        start_llm_proxy=False,
        auth_token="secret",
    )
    manager, app, client = await _mk_client(settings)
    await manager.start()
    async with client:
        r = await client.get("/sessions")
        assert r.status_code == 401
        r = await client.get("/sessions", headers={"X-Auth-Token": "secret"})
        assert r.status_code == 200
        r = await client.get(
            "/sessions",
            headers={"Authorization": "Bearer secret"},
        )
        assert r.status_code == 200
    await manager.aclose()

"""FastAPI surface for the sandbox wrapper.

All endpoints operate on a single `SessionManager` stored on
`app.state.manager`. Construction is split into ``create_app`` so tests
can inject a manager with stub settings.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

import re

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .models import (
    CreateSessionRequest,
    Event,
    MessageRequest,
    SessionDetail,
    SessionSummary,
    SimpleResponse,
)
from .sandbox import SandboxError, ensure_binaries_available
from .session_manager import (
    InvalidStateError,
    SessionManager,
    SessionNotFoundError,
    SessionState,
)

log = logging.getLogger("cline_sandbox.app")

# Session IDs are 32-char hex UUIDs (see uuid4().hex in the manager).
# Pinning the path parameter to this shape closes a small class of
# log-injection / ambiguous-path bugs before anything downstream has to
# think about them.
SESSION_ID_PATTERN = r"^[0-9a-f]{32}$"
SESSION_ID_REGEX = re.compile(SESSION_ID_PATTERN)


def _validate_session_id(session_id: str) -> str:
    if not SESSION_ID_REGEX.match(session_id):
        raise HTTPException(status_code=404, detail="session not found")
    return session_id


def create_app(
    settings: Optional[Settings] = None,
    *,
    manager: Optional[SessionManager] = None,
) -> FastAPI:
    settings = settings or Settings()
    manager = manager or SessionManager(settings)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        missing = ensure_binaries_available(
            need_seccomp=settings.enable_seccomp
        )
        if missing:
            log.warning(
                "Preflight: missing required components: %s. Session "
                "creation will fail until they are installed.",
                ", ".join(missing),
            )
        await manager.start()
        try:
            yield
        finally:
            await manager.aclose()

    app = FastAPI(
        title="cline_sandbox",
        version="0.1.0",
        description=(
            "FastAPI wrapper that launches Cline (or any agent) inside a "
            "bubblewrap + seccomp + namespace sandbox. The wrapper itself "
            "runs *outside* the sandbox and provides session control, "
            "message streaming, pause/stop/kill, and per-session logs."
        ),
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.manager = manager

    if settings.cors_allow_origin:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[
                o.strip()
                for o in settings.cors_allow_origin.split(",")
                if o.strip()
            ],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ------------------------------------------------------------------
    # auth dependency (optional shared-secret via header)
    # ------------------------------------------------------------------
    def _check_token(supplied: str) -> bool:
        import hmac
        token = settings.auth_token or ""
        return bool(token) and hmac.compare_digest(supplied, token)

    async def auth_check(request: Request) -> None:
        token = settings.auth_token
        if not token:
            return
        header = request.headers.get("X-Auth-Token") or request.headers.get(
            "Authorization", ""
        )
        if header.startswith("Bearer "):
            header = header[len("Bearer "):]
        if not _check_token(header):
            raise HTTPException(status_code=401, detail="invalid auth token")

    async def auth_check_or_query(request: Request) -> None:
        """Same as auth_check but also accepts ?token=… on the URL.

        Browsers cannot set custom headers on `EventSource`, so the SSE
        endpoint needs this escape hatch. It's scoped to that one route.
        """
        token = settings.auth_token
        if not token:
            return
        header = request.headers.get("X-Auth-Token") or request.headers.get(
            "Authorization", ""
        )
        if header.startswith("Bearer "):
            header = header[len("Bearer "):]
        query_token = request.query_params.get("token", "")
        if not (_check_token(header) or _check_token(query_token)):
            raise HTTPException(status_code=401, detail="invalid auth token")

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------
    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        missing = ensure_binaries_available(
            need_seccomp=settings.enable_seccomp
        )
        return {
            "status": "ok" if not missing else "degraded",
            "missing": missing,
            "active_sessions": sum(
                1 for s in manager.list()
                if s.state in SessionState.ACTIVE
            ),
            "total_sessions": len(manager.list()),
        }

    @app.get("/config")
    async def config() -> Dict[str, Any]:
        return {
            "agent_command": settings.agent_command,
            "enable_seccomp": settings.enable_seccomp,
            "unshare_net": settings.unshare_net,
            "ro_binds": settings.ro_binds(),
            "llm_proxy_url": settings.llm_proxy_url,
            "max_sessions": settings.max_sessions,
            "state_dir": str(settings.state_dir),
        }

    @app.post(
        "/sessions",
        response_model=SessionDetail,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(auth_check)],
    )
    async def create_session(req: CreateSessionRequest) -> SessionDetail:
        try:
            session = await manager.create(
                task=req.task,
                agent_command=req.agent_command,
                extra_ro_binds=req.extra_ro_binds,
                extra_rw_binds=req.extra_rw_binds,
                timeout_seconds=req.timeout_seconds,
                env=req.env,
                metadata=req.metadata,
            )
        except SandboxError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        except InvalidStateError as exc:
            raise HTTPException(status_code=429, detail=str(exc))
        return SessionDetail(**session.detail())

    @app.get(
        "/sessions",
        response_model=List[SessionSummary],
        dependencies=[Depends(auth_check)],
    )
    async def list_sessions() -> List[SessionSummary]:
        return [SessionSummary(**s.summary()) for s in manager.list()]

    @app.get(
        "/sessions/{session_id}",
        response_model=SessionDetail,
        dependencies=[Depends(auth_check)],
    )
    async def get_session(
        session_id: str = PathParam(..., pattern=SESSION_ID_PATTERN),
    ) -> SessionDetail:
        try:
            return SessionDetail(**manager.get(session_id).detail())
        except SessionNotFoundError:
            raise HTTPException(status_code=404, detail="session not found")

    @app.post(
        "/sessions/{session_id}/message",
        response_model=SimpleResponse,
        dependencies=[Depends(auth_check)],
    )
    async def send_message(
        req: MessageRequest,
        session_id: str = PathParam(..., pattern=SESSION_ID_PATTERN),
    ) -> SimpleResponse:
        try:
            await manager.send_message(
                session_id, req.content, append_newline=req.append_newline
            )
        except SessionNotFoundError:
            raise HTTPException(status_code=404, detail="session not found")
        except InvalidStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return SimpleResponse()

    def _control_endpoint(action: str):
        async def _inner(
            session_id: str = PathParam(..., pattern=SESSION_ID_PATTERN),
        ) -> SimpleResponse:
            fn = {
                "pause": manager.pause,
                "resume": manager.resume,
                "stop": manager.stop,
                "kill": manager.kill,
            }[action]
            try:
                await fn(session_id)
            except SessionNotFoundError:
                raise HTTPException(status_code=404, detail="session not found")
            except InvalidStateError as exc:
                raise HTTPException(status_code=409, detail=str(exc))
            return SimpleResponse(detail=f"{action} issued")

        return _inner

    for act in ("pause", "resume", "stop", "kill"):
        app.add_api_route(
            f"/sessions/{{session_id}}/{act}",
            _control_endpoint(act),
            methods=["POST"],
            response_model=SimpleResponse,
            dependencies=[Depends(auth_check)],
            name=f"{act}_session",
        )

    @app.get(
        "/sessions/{session_id}/events",
        response_model=List[Event],
        dependencies=[Depends(auth_check)],
    )
    async def get_events(
        session_id: str = PathParam(..., pattern=SESSION_ID_PATTERN),
        limit: Optional[int] = Query(
            None, ge=1, le=10000,
            description="Most recent N events (null = all).",
        ),
    ) -> List[Event]:
        try:
            events = manager.historical_events(session_id, limit=limit)
        except SessionNotFoundError:
            raise HTTPException(status_code=404, detail="session not found")
        return [Event(**e) for e in events]

    @app.get(
        "/sessions/{session_id}/stream",
        dependencies=[Depends(auth_check_or_query)],
    )
    async def stream(
        request: Request,
        session_id: str = PathParam(..., pattern=SESSION_ID_PATTERN),
    ) -> StreamingResponse:
        try:
            manager.get(session_id)
        except SessionNotFoundError:
            raise HTTPException(status_code=404, detail="session not found")

        async def event_source() -> AsyncIterator[bytes]:
            # Replay history first so late subscribers don't miss context.
            for event in manager.historical_events(session_id):
                yield _sse(event)
            async for event in manager.stream_events(session_id):
                if await request.is_disconnected():
                    return
                yield _sse(event)
            yield b"event: end\ndata: {}\n\n"

        return StreamingResponse(
            event_source(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ------------------------------------------------------------------
    # dashboard (static)
    # ------------------------------------------------------------------
    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.is_dir():
        app.mount(
            "/ui",
            StaticFiles(directory=str(static_dir), html=True),
            name="ui",
        )

        @app.get("/", include_in_schema=False)
        async def _root_redirect() -> Response:
            index = static_dir / "index.html"
            if index.exists():
                return FileResponse(str(index))
            return Response(
                "cline_sandbox is running. See /docs for the API.",
                media_type="text/plain",
            )

    return app


def _sse(event: Dict[str, Any]) -> bytes:
    """Format a dict as an SSE event with kind as the event name."""
    kind = event.get("kind", "message")
    payload = json.dumps(event, ensure_ascii=False)
    return f"event: {kind}\ndata: {payload}\n\n".encode("utf-8")

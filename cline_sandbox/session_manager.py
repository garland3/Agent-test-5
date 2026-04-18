"""Session lifecycle: spawn, observe, and control sandboxed agents.

One `Session` corresponds to one invocation of the agent (cline) inside
its own per-session workspace. The manager owns all sessions in memory
and mirrors their events to disk as JSON Lines so the state survives
restarts (for post-hoc inspection, not for resuming).

States::

    pending      -> session accepted, not yet spawned
    starting     -> bwrap process is being created
    running      -> child process alive, accepting stdin
    paused       -> child received SIGSTOP (still alive)
    stopping     -> SIGTERM sent, waiting for graceful exit
    completed    -> child exited with code 0
    failed       -> child exited with non-zero code
    killed       -> manager (or user) sent SIGKILL
    error        -> couldn't spawn at all (missing binary, bad config)

The manager is async-first but cooperates with synchronous callers via
the public API.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from .config import Settings
from .sandbox import SandboxBuilder, SandboxPlan, SandboxError


class SessionState:
    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"
    ERROR = "error"

    TERMINAL = frozenset({COMPLETED, FAILED, KILLED, ERROR})
    ALIVE = frozenset({STARTING, RUNNING, PAUSED, STOPPING})
    # "Active" from the admission-control perspective — includes PENDING
    # so concurrent create() calls can't bypass max_sessions during the
    # window between registry insert and _spawn() flipping state.
    ACTIVE = frozenset({PENDING, STARTING, RUNNING, PAUSED, STOPPING})


class SessionNotFoundError(KeyError):
    pass


class InvalidStateError(RuntimeError):
    pass


@dataclass
class Session:
    id: str
    task: str
    agent_command: str
    workspace: Path
    events_path: Path
    state: str = SessionState.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    sandbox: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_count: int = 0
    last_event_time: Optional[float] = None

    # Runtime-only fields — excluded from serialization.
    process: Optional[asyncio.subprocess.Process] = field(
        default=None, repr=False
    )
    subscribers: List[asyncio.Queue] = field(default_factory=list, repr=False)
    reader_tasks: List[asyncio.Task] = field(default_factory=list, repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    timeout_task: Optional[asyncio.Task] = field(default=None, repr=False)
    # Set when stop() escalates to SIGKILL (grace expired). Needed so
    # _await_exit can distinguish a graceful-stop completion from a
    # forced kill — both pass through state=STOPPING but only the
    # second should map to KILLED.
    stop_escalated: bool = False

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "pid": self.pid,
            "task": self.task,
            "agent_command": self.agent_command,
            "workspace": str(self.workspace),
            "metadata": self.metadata,
        }

    def detail(self) -> Dict[str, Any]:
        d = self.summary()
        d.update(
            sandbox=self.sandbox,
            event_count=self.event_count,
            last_event_time=self.last_event_time,
        )
        return d


class SessionManager:
    """Owns the live registry of sessions.

    Call ``start()`` before use and ``aclose()`` on shutdown. The manager
    is re-entrant — multiple callers may hold a session at the same
    time; mutations are serialized through each session's lock.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._sessions: Dict[str, Session] = {}
        self._registry_lock = asyncio.Lock()
        self._started = False

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.settings.ensure_state_dir()
        self._started = True

    async def aclose(self) -> None:
        """Terminate every live session and drain their helper tasks.
        Safe to call on shutdown."""
        async with self._registry_lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            if s.state in SessionState.ALIVE:
                try:
                    await self.kill(s.id, reason="manager-shutdown")
                except Exception:
                    pass
        # Ensure the child has actually been reaped and the reader
        # tasks have drained — otherwise uvicorn exits while asyncio
        # still has pending tasks and prints "Task was destroyed but
        # it is pending!" warnings.
        for s in sessions:
            if s.process is not None and s.process.returncode is None:
                try:
                    await asyncio.wait_for(s.process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try:
                        s.process.kill()
                    except ProcessLookupError:
                        pass
            for task in list(s.reader_tasks):
                if not task.done():
                    task.cancel()
            if s.timeout_task and not s.timeout_task.done():
                s.timeout_task.cancel()
            all_tasks = [t for t in s.reader_tasks if t is not None]
            if s.timeout_task is not None:
                all_tasks.append(s.timeout_task)
            if all_tasks:
                await asyncio.gather(*all_tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # session creation
    # ------------------------------------------------------------------
    async def create(
        self,
        *,
        task: str,
        agent_command: Optional[str] = None,
        extra_ro_binds: Sequence[str] = (),
        extra_rw_binds: Sequence[str] = (),
        timeout_seconds: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Session:
        # Validate extra binds against the configured allowlist before
        # doing anything with them. We do this outside the registry lock
        # so it's cheap.
        self._validate_extra_binds(extra_ro_binds, extra_rw_binds)

        async with self._registry_lock:
            active = sum(
                1 for s in self._sessions.values()
                if s.state in SessionState.ACTIVE
            )
            if active >= self.settings.max_sessions:
                raise InvalidStateError(
                    f"Too many active sessions ({active}). "
                    f"Max is {self.settings.max_sessions}."
                )

            session_id = uuid.uuid4().hex
            state_dir = self.settings.ensure_state_dir()
            workspace = state_dir / session_id / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            events_path = state_dir / session_id / "events.jsonl"

            resolved_agent = agent_command or self.settings.agent_command

            session = Session(
                id=session_id,
                task=task,
                agent_command=resolved_agent,
                workspace=workspace,
                events_path=events_path,
                metadata=dict(metadata or {}),
            )
            # Register with state=PENDING inside the same lock so a
            # concurrent create() sees us in the ALIVE count and the
            # max_sessions check cannot be double-passed.
            self._sessions[session_id] = session

        # Write the task text to the workspace so cline can pick it up
        # (cline reads ./task.md or takes it as a CLI arg).
        (session.workspace / "task.md").write_text(task, encoding="utf-8")

        await self._record_event(session, "created", {
            "task_preview": task[:200],
            "agent_command": resolved_agent,
            "metadata": session.metadata,
        })

        # Build the sandbox command and launch the process.
        builder = SandboxBuilder(
            ro_binds=(
                list(self.settings.ro_binds()) + list(extra_ro_binds)
            ),
            rw_binds=list(self.settings.extra_rw_binds) + list(extra_rw_binds),
            unshare_net=self.settings.unshare_net,
            enable_seccomp=self.settings.enable_seccomp,
        )

        agent_argv = self._resolve_agent_argv(resolved_agent, task)
        extra_env = dict(env or {})

        try:
            plan = builder.build(
                workspace=session.workspace,
                agent_argv=agent_argv,
                extra_env=extra_env,
                proxy_url=self.settings.llm_proxy_url,
            )
        except SandboxError as exc:
            session.state = SessionState.ERROR
            session.ended_at = time.time()
            await self._record_event(session, "error", {"message": str(exc)})
            raise

        session.sandbox = {
            "argv": plan.argv,
            "rendered": SandboxBuilder.render(plan.argv),
            **plan.description,
        }

        await self._spawn(session, plan)

        if timeout_seconds and timeout_seconds > 0:
            session.timeout_task = asyncio.create_task(
                self._enforce_timeout(session, timeout_seconds)
            )

        return session

    def _validate_extra_binds(
        self,
        extra_ro_binds: Sequence[str],
        extra_rw_binds: Sequence[str],
    ) -> None:
        """Reject bind mounts that fall outside the operator-configured
        allowlist. Without this check, an authenticated caller of
        POST /sessions could bind `/` or `/root` read-write into the
        sandbox and defeat the filesystem isolation entirely."""
        allowed = [Path(p).resolve() for p in self.settings.allowed_extra_binds]
        if not extra_ro_binds and not extra_rw_binds:
            return
        if not allowed:
            raise InvalidStateError(
                "extra_ro_binds / extra_rw_binds supplied, but the "
                "operator has not configured CLINE_SANDBOX_ALLOWED_EXTRA_BINDS; "
                "refusing for safety."
            )
        for p in list(extra_ro_binds) + list(extra_rw_binds):
            resolved = Path(p).resolve()
            if not any(
                resolved == base or base in resolved.parents
                for base in allowed
            ):
                raise InvalidStateError(
                    f"path {p!r} is not under any allowed prefix "
                    f"({', '.join(str(a) for a in allowed)})"
                )

    @staticmethod
    def _resolve_agent_argv(agent_command: str, task: str) -> List[str]:
        """Split the command and append the task as the final argument.

        Supports the ``{task}`` placeholder inside agent_command for cases
        where the task should be embedded mid-command.
        """
        import shlex

        parts = shlex.split(agent_command)
        substituted = [p.replace("{task}", task) for p in parts]
        if any("{task}" in p for p in parts):
            return substituted
        return substituted + [task]

    # ------------------------------------------------------------------
    # process plumbing
    # ------------------------------------------------------------------
    async def _spawn(self, session: Session, plan: SandboxPlan) -> None:
        session.state = SessionState.STARTING
        session.started_at = time.time()
        await self._record_event(session, "spawning", {
            "argv": plan.argv,
        })

        # Give bwrap a tightly controlled environment. bwrap itself uses
        # --clearenv to wipe the env before execve()'ing the agent, but
        # anything in this env can still influence the *host* binaries
        # bwrap and seccomp_helper.py invoke (e.g. LD_PRELOAD, PYTHONPATH
        # could hijack the pre-seccomp Python).
        bwrap_env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TZ": os.environ.get("TZ", ""),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                *plan.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Put the child in its own process group so signals can
                # target the whole tree without risking the parent.
                start_new_session=True,
                env=bwrap_env,
            )
        except FileNotFoundError as exc:
            session.state = SessionState.ERROR
            session.ended_at = time.time()
            await self._record_event(session, "error", {
                "message": f"failed to spawn: {exc}",
            })
            raise

        session.process = process
        session.pid = process.pid
        session.state = SessionState.RUNNING
        await self._record_event(session, "started", {"pid": process.pid})

        session.reader_tasks = [
            asyncio.create_task(self._pump(session, process.stdout, "stdout")),
            asyncio.create_task(self._pump(session, process.stderr, "stderr")),
            asyncio.create_task(self._await_exit(session)),
        ]

    async def _pump(
        self,
        session: Session,
        stream: Optional[asyncio.StreamReader],
        channel: str,
    ) -> None:
        if stream is None:
            return
        while True:
            try:
                line = await stream.readline()
            except Exception as exc:  # noqa: BLE001
                await self._record_event(session, "stream-error", {
                    "channel": channel, "message": str(exc),
                })
                return
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip("\n")
            await self._record_event(session, channel, {"text": text})

    async def _await_exit(self, session: Session) -> None:
        process = session.process
        assert process is not None
        rc = await process.wait()
        # Acquire the session lock to ensure no concurrent signal is
        # dispatched between the reap (rc is now set) and the state
        # transition. _signal_pgroup reads proc.returncode under this
        # same lock.
        async with session.lock:
            session.exit_code = rc
            session.ended_at = time.time()
            prev = session.state
            # Pick the appropriate terminal state. When the stop/kill
            # path signals the child, the child typically exits with a
            # negative rc (`-SIGTERM`, `-SIGKILL`). In that case the
            # state the operator asked for is authoritative, not the
            # raw rc.
            if prev == SessionState.STOPPING:
                # A STOPPING session that escalated to SIGKILL is a
                # forced kill, not a clean completion — the agent
                # ignored SIGTERM and the grace timer blew past.
                final = (
                    SessionState.KILLED if session.stop_escalated
                    else SessionState.COMPLETED
                )
            elif rc == 0:
                final = SessionState.COMPLETED
            elif rc < 0:
                final = SessionState.KILLED
            else:
                final = SessionState.FAILED
            session.state = final
        await self._record_event(session, "exited", {
            "exit_code": rc, "final_state": final, "previous_state": prev,
        })
        # Drain reader tasks so they don't linger as pending on shutdown.
        for task in list(session.reader_tasks):
            if task is not asyncio.current_task() and not task.done():
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    task.cancel()
        # Fan-out a sentinel so SSE consumers cleanly terminate.
        # We must not `await` on put here: we drop events on QueueFull
        # elsewhere, so a slow subscriber's queue can already be full —
        # a blocking put would hang _await_exit and leak the task. Drain
        # one slot if needed and drop the sentinel on definitive failure.
        for q in list(session.subscribers):
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
        if session.timeout_task and not session.timeout_task.done():
            session.timeout_task.cancel()

    async def _enforce_timeout(
        self, session: Session, timeout_seconds: int
    ) -> None:
        try:
            await asyncio.sleep(timeout_seconds)
        except asyncio.CancelledError:
            return
        if session.state in SessionState.ALIVE:
            await self._record_event(session, "timeout", {
                "after_seconds": timeout_seconds,
            })
            try:
                await self.kill(session.id, reason="timeout")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # events / streaming
    # ------------------------------------------------------------------
    async def _record_event(
        self, session: Session, kind: str, data: Dict[str, Any]
    ) -> None:
        event = {
            "session_id": session.id,
            "time": time.time(),
            "kind": kind,
            "data": data,
        }
        session.event_count += 1
        session.last_event_time = event["time"]

        # Persist off the event loop — a busy agent can emit thousands
        # of stdout lines per second and synchronous file I/O on the
        # reactor would stall every SSE subscriber.
        line = json.dumps(event, ensure_ascii=False) + "\n"

        def _append() -> None:
            try:
                session.events_path.parent.mkdir(parents=True, exist_ok=True)
                with session.events_path.open("a", encoding="utf-8") as f:
                    f.write(line)
            except OSError:
                # Disk full / permission issues shouldn't kill the
                # session; swallow.
                pass

        await asyncio.to_thread(_append)

        # Fan out to SSE subscribers.
        for q in list(session.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow consumer: drop the event rather than stall the
                # producer. Backpressure is not worth a deadlock here.
                pass

    async def subscribe(self, session_id: str) -> asyncio.Queue:
        session = self.get(session_id)
        q: asyncio.Queue = asyncio.Queue(maxsize=1024)
        session.subscribers.append(q)
        if session.state in SessionState.TERMINAL:
            # Terminal sessions: put the sentinel so the consumer
            # immediately gets EOF after reading history separately.
            await q.put(None)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        try:
            session = self._sessions.get(session_id)
            if session and queue in session.subscribers:
                session.subscribers.remove(queue)
        except Exception:
            pass

    async def stream_events(
        self, session_id: str
    ) -> AsyncIterator[Dict[str, Any]]:
        q = await self.subscribe(session_id)
        try:
            while True:
                event = await q.get()
                if event is None:
                    return
                yield event
        finally:
            self.unsubscribe(session_id, q)

    def historical_events(
        self, session_id: str, *, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        session = self.get(session_id)
        events: List[Dict[str, Any]] = []
        if not session.events_path.exists():
            return events
        with session.events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if limit is not None:
            events = events[-limit:]
        return events

    # ------------------------------------------------------------------
    # control
    # ------------------------------------------------------------------
    def get(self, session_id: str) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(session_id)
        return session

    def list(self) -> List[Session]:
        return list(self._sessions.values())

    async def send_message(
        self, session_id: str, content: str, *, append_newline: bool = True
    ) -> None:
        session = self.get(session_id)
        async with session.lock:
            if session.state not in (SessionState.RUNNING, SessionState.PAUSED):
                raise InvalidStateError(
                    f"Session is {session.state}; cannot accept input."
                )
            if session.process is None or session.process.stdin is None:
                raise InvalidStateError("session has no stdin pipe")
            if session.process.returncode is not None:
                raise InvalidStateError(
                    f"session already exited (rc={session.process.returncode})"
                )
            payload = content + ("\n" if append_newline else "")
            try:
                session.process.stdin.write(payload.encode("utf-8"))
                await session.process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError, AttributeError) as exc:
                raise InvalidStateError(
                    f"stdin closed: {exc}"
                ) from exc
        await self._record_event(session, "input", {
            "content": content,
            "append_newline": append_newline,
        })

    async def _signal_pgroup(
        self, session: Session, sig: signal.Signals
    ) -> None:
        """Signal the session's process group, guarding against the
        reaper race: if the child has already exited, `os.getpgid()`
        would return another process' pgid (or ESRCH), potentially
        signalling an unrelated host process.

        Callers must hold session.lock.
        """
        proc = session.process
        if proc is None:
            return
        # If returncode is set, the child has been reaped — do not
        # signal anything that might have taken its pid.
        if proc.returncode is not None:
            return
        pid = proc.pid
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            return
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise InvalidStateError(f"permission denied signalling {pid}: {exc}")

    async def pause(self, session_id: str) -> None:
        session = self.get(session_id)
        async with session.lock:
            if session.state != SessionState.RUNNING:
                raise InvalidStateError(
                    f"cannot pause from state {session.state}"
                )
            await self._signal_pgroup(session, signal.SIGSTOP)
            session.state = SessionState.PAUSED
        await self._record_event(session, "paused", {})

    async def resume(self, session_id: str) -> None:
        session = self.get(session_id)
        async with session.lock:
            if session.state != SessionState.PAUSED:
                raise InvalidStateError(
                    f"cannot resume from state {session.state}"
                )
            await self._signal_pgroup(session, signal.SIGCONT)
            session.state = SessionState.RUNNING
        await self._record_event(session, "resumed", {})

    async def stop(
        self, session_id: str, *, grace_seconds: float = 10.0
    ) -> None:
        """Graceful shutdown: SIGTERM + wait; escalate to SIGKILL if needed."""
        session = self.get(session_id)
        async with session.lock:
            if session.state in SessionState.TERMINAL:
                return
            if session.state == SessionState.PAUSED:
                # Resume before terminating; otherwise SIGTERM queues and
                # the process never sees it.
                await self._signal_pgroup(session, signal.SIGCONT)
            await self._signal_pgroup(session, signal.SIGTERM)
            session.state = SessionState.STOPPING
        await self._record_event(session, "stopping", {
            "grace_seconds": grace_seconds,
        })
        try:
            assert session.process is not None
            await asyncio.wait_for(session.process.wait(), timeout=grace_seconds)
        except asyncio.TimeoutError:
            session.stop_escalated = True
            await self.kill(session_id, reason="stop-grace-expired")

    async def kill(self, session_id: str, *, reason: str = "requested") -> None:
        session = self.get(session_id)
        async with session.lock:
            if session.state in SessionState.TERMINAL:
                return
            if session.state == SessionState.PAUSED:
                await self._signal_pgroup(session, signal.SIGCONT)
            await self._signal_pgroup(session, signal.SIGKILL)
        await self._record_event(session, "killed", {"reason": reason})
        # Wait briefly for the reaper to run so callers can rely on
        # the session being in a terminal state after this returns.
        if session.process is not None:
            try:
                await asyncio.wait_for(session.process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

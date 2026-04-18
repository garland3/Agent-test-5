"""`python -m cline_sandbox` — single-command launcher.

Supervises two processes:

1. The LLM API proxy (`proxy_setup/llm_proxy.py`) — unless
   ``--no-proxy`` is passed or ``CLINE_SANDBOX_START_LLM_PROXY=0``.
2. The FastAPI server (uvicorn) hosting the sandbox control plane.

Both share this parent's signal handlers; Ctrl+C / SIGTERM brings down
the full tree. Proxy logs are prefixed ``[proxy]`` so they are easy to
distinguish from the API logs.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from .config import Settings

log = logging.getLogger("cline_sandbox.launcher")


REPO_DIR = Path(__file__).resolve().parent.parent
PROXY_SCRIPT = REPO_DIR / "proxy_setup" / "llm_proxy.py"


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m cline_sandbox",
        description="Launch the sandbox API (+ LLM proxy) in one shot.",
    )
    p.add_argument("--host", default=None,
                   help="API bind address (default from settings)")
    p.add_argument("--port", type=int, default=None,
                   help="API listen port (default from settings)")
    p.add_argument("--no-proxy", action="store_true",
                   help="Skip launching the LLM proxy (bring your own).")
    p.add_argument("--proxy-port", type=int, default=None,
                   help="Port the LLM proxy should listen on.")
    p.add_argument("--proxy-upstream", default=None,
                   help="Upstream API URL for the LLM proxy "
                        "(default: from CLINE_SANDBOX_LLM_UPSTREAM).")
    p.add_argument("--reload", action="store_true",
                   help="Enable uvicorn auto-reload (dev only).")
    p.add_argument("--log-level", default="info",
                   help="uvicorn log level (default: info)")
    return p.parse_args(argv)


def _proxy_port(settings: Settings, override: Optional[int]) -> int:
    if override is not None:
        return override
    try:
        from urllib.parse import urlparse
        return urlparse(settings.llm_proxy_url).port or 9090
    except Exception:
        return 9090


async def _stream_output(
    stream: Optional[asyncio.StreamReader], prefix: str
) -> None:
    if stream is None:
        return
    while True:
        line = await stream.readline()
        if not line:
            return
        sys.stdout.buffer.write(prefix.encode() + line)
        sys.stdout.buffer.flush()


async def _run(args: argparse.Namespace) -> int:
    settings = Settings()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="[%(asctime)s %(levelname)s %(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Loud warnings for the two configurations that weaken the sandbox
    # the most — we'd rather the operator notice them in the console
    # than hunt through docs.
    if not settings.enable_seccomp:
        log.warning(
            "*** SECCOMP IS DISABLED — DANGEROUS_SYSCALLS (ptrace, mount, "
            "bpf, kexec_load, …) will be reachable from inside the sandbox. "
            "Set CLINE_SANDBOX_ENABLE_SECCOMP=1 to re-enable.")
    if not settings.unshare_net:
        log.warning(
            "*** NETWORK ISOLATION IS OFF (share-net). The agent can reach "
            "any host-reachable address, including 127.0.0.1 services. "
            "The LLM proxy URL is only a convention via http_proxy env. "
            "Set CLINE_SANDBOX_UNSHARE_NET=1 for a fresh netns; you will "
            "need to bridge the proxy into that ns separately.")

    start_proxy = settings.start_llm_proxy and not args.no_proxy
    proxy_proc: Optional[asyncio.subprocess.Process] = None
    proxy_tail_task: Optional[asyncio.Task] = None

    if start_proxy:
        if not PROXY_SCRIPT.exists():
            log.warning(
                "llm_proxy.py not found at %s; continuing without proxy.",
                PROXY_SCRIPT,
            )
            start_proxy = False
        else:
            port = _proxy_port(settings, args.proxy_port)
            upstream = args.proxy_upstream or settings.llm_upstream
            api_key = os.environ.get(settings.llm_api_key_env, "")
            cmd = [
                sys.executable, str(PROXY_SCRIPT),
                "--upstream", upstream,
                "--port", str(port),
                "--bind", "127.0.0.1",
            ]
            if api_key:
                cmd += ["--api-key", api_key]
            log.info("starting LLM proxy on port %d (upstream=%s, key=%s)",
                     port, upstream, "yes" if api_key else "passthrough")
            proxy_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            proxy_tail_task = asyncio.create_task(
                _stream_output(proxy_proc.stdout, "[proxy] ")
            )

    # Import uvicorn late so the proxy can boot first.
    import uvicorn  # noqa: WPS433 - intentional

    from .app import create_app

    app = create_app(settings)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level=args.log_level,
        reload=args.reload,
        lifespan="on",
    )
    server = uvicorn.Server(config)

    # Wire SIGTERM/SIGINT to bring the whole process group down cleanly.
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _on_signal(*_):
        log.info("shutdown signal received")
        server.should_exit = True
        stop_event.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _on_signal)
        except NotImplementedError:
            signal.signal(s, lambda *_: _on_signal())

    log.info("API listening on http://%s:%d", settings.host, settings.port)
    try:
        await server.serve()
    finally:
        if proxy_proc and proxy_proc.returncode is None:
            log.info("stopping LLM proxy (pid %d)", proxy_proc.pid)
            try:
                proxy_proc.terminate()
                await asyncio.wait_for(proxy_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proxy_proc.kill()
                await proxy_proc.wait()
        if proxy_tail_task is not None and not proxy_tail_task.done():
            proxy_tail_task.cancel()
            try:
                await proxy_tail_task
            except (asyncio.CancelledError, Exception):
                pass

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

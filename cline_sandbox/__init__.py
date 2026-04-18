"""cline_sandbox - FastAPI wrapper that runs Cline (or any agent) in a
tight bubblewrap + seccomp + netns + landlock sandbox with dangerous
(`-y`) mode enabled safely.

Public entry points:
    cline_sandbox.app.create_app()       - build the FastAPI application
    cline_sandbox.SessionManager         - sandboxed agent lifecycle
    cline_sandbox.SandboxBuilder         - bwrap/seccomp command builder
"""

from .config import Settings
from .session_manager import SessionManager, SessionState
from .sandbox import SandboxBuilder

__all__ = ["Settings", "SessionManager", "SessionState", "SandboxBuilder"]

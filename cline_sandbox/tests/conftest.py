"""Shared test fixtures.

The tests never invoke a real LLM. They use small shell / python scripts
as stand-in 'agents' so sandbox + lifecycle behaviour can be verified
without needing cline installed.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from cline_sandbox.config import Settings


REPO_DIR = Path(__file__).resolve().parent.parent.parent


def _bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


requires_bwrap = pytest.mark.skipif(
    not _bwrap_available(), reason="bwrap not installed"
)


@pytest.fixture
def tmp_state_dir(tmp_path: Path) -> Path:
    (tmp_path / "sessions").mkdir()
    return tmp_path / "sessions"


@pytest.fixture
def settings(tmp_state_dir: Path) -> Settings:
    """Settings suitable for tests: no seccomp, no real agent command.

    Seccomp is disabled because our test 'agent' is often /bin/cat or a
    small Python script running under bwrap; the extra BPF layer isn't
    what we're validating.
    """
    s = Settings(
        state_dir=tmp_state_dir,
        agent_command="/bin/cat",
        enable_seccomp=False,
        unshare_net=False,
        start_llm_proxy=False,
    )
    return s


@pytest.fixture
def echo_script(tmp_path: Path) -> Path:
    """Tiny stand-in 'agent' that echoes what it reads on stdin and
    exits on EOF. Doubles for cline in the session-lifecycle tests."""
    script = tmp_path / "fake_agent.py"
    script.write_text(
        "import sys, time\n"
        "print('READY', flush=True)\n"
        "for line in sys.stdin:\n"
        "    line = line.rstrip()\n"
        "    if line == 'QUIT':\n"
        "        print('BYE', flush=True)\n"
        "        break\n"
        "    print(f'ECHO: {line}', flush=True)\n"
        "sys.exit(0)\n"
    )
    script.chmod(0o755)
    return script

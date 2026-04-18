"""Unit tests for SandboxBuilder — these do not execute bwrap."""

from __future__ import annotations

from pathlib import Path

import pytest

from cline_sandbox.sandbox import SandboxBuilder, SandboxError


def test_build_basic(tmp_path: Path):
    b = SandboxBuilder(
        ro_binds=["/usr", "/lib"],
        enable_seccomp=False,
    )
    plan = b.build(
        workspace=tmp_path / "ws",
        agent_argv=["/bin/true"],
        proxy_url="http://127.0.0.1:9090",
    )

    assert plan.argv[0].endswith("bwrap")
    # Standard hardening flags
    for flag in ("--clearenv", "--die-with-parent", "--new-session",
                 "--unshare-pid", "--unshare-uts", "--unshare-ipc",
                 "--proc", "--dev", "--tmpfs"):
        assert flag in plan.argv, f"missing flag {flag}"

    # Read-only binds are present
    assert "--ro-bind" in plan.argv
    assert "/usr" in plan.argv
    assert "/lib" in plan.argv

    # Workspace bound read-write at /workspace
    idx = plan.argv.index("--bind")
    assert plan.argv[idx + 2] == "/workspace"
    assert str(plan.workspace) == plan.argv[idx + 1]

    # Agent argv comes after `--`
    assert "--" in plan.argv
    assert plan.argv[-1] == "/bin/true"

    # Proxy env propagated
    assert plan.env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9090"
    assert plan.env["OPENAI_BASE_URL"] == "http://127.0.0.1:9090"


def test_build_with_seccomp(tmp_path: Path):
    b = SandboxBuilder(ro_binds=["/usr"], enable_seccomp=True)
    plan = b.build(
        workspace=tmp_path / "ws",
        agent_argv=["/bin/echo", "hi"],
    )
    # Seccomp helper should appear between `--` and the agent argv
    dash = plan.argv.index("--")
    inner = plan.argv[dash + 1:]
    assert "/project/seccomp_helper.py" in inner
    assert "--deny" in inner
    # `strict` means blocked syscalls KILL (not EPERM).
    assert "strict" in inner
    assert inner[-2:] == ["/bin/echo", "hi"]


def test_build_rejects_empty_argv(tmp_path: Path):
    b = SandboxBuilder(ro_binds=["/usr"], enable_seccomp=False)
    with pytest.raises(SandboxError):
        b.build(workspace=tmp_path / "ws", agent_argv=[])


def test_unshare_net_adds_flag(tmp_path: Path):
    b = SandboxBuilder(ro_binds=["/usr"], enable_seccomp=False, unshare_net=True)
    plan = b.build(workspace=tmp_path / "ws", agent_argv=["/bin/true"])
    assert "--unshare-net" in plan.argv


def test_unshare_net_default_false(tmp_path: Path):
    b = SandboxBuilder(ro_binds=["/usr"], enable_seccomp=False)
    plan = b.build(workspace=tmp_path / "ws", agent_argv=["/bin/true"])
    assert "--unshare-net" not in plan.argv


def test_render_is_copy_pasteable(tmp_path: Path):
    import shlex

    b = SandboxBuilder(ro_binds=["/usr"], enable_seccomp=False)
    plan = b.build(workspace=tmp_path / "ws", agent_argv=["/bin/sh",
                                                          "-c",
                                                          "echo hi world"])
    rendered = SandboxBuilder.render(plan.argv)
    # Re-splitting should give back the original argv.
    assert shlex.split(rendered) == plan.argv

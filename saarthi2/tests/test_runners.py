"""Execution runners: local / docker / ssh command wrapping."""

from __future__ import annotations

import shlex

import pytest

from saarthi2.runners import wrap_command


def test_local_default_no_shell() -> None:
    assert wrap_command("nmap -sV x", {}) == ("nmap -sV x", False)


def test_local_shell_opt_in() -> None:
    assert wrap_command("a | b", {"shell": True}) == ("a | b", True)


def test_docker_wraps_and_quotes() -> None:
    cmd, shell = wrap_command(
        "subfinder -d x", {"runner": "docker", "image": "proj/subfinder"}
    )
    assert shell is True
    assert "docker run --rm" in cmd
    assert "proj/subfinder" in cmd
    assert shlex.quote("subfinder -d x") in cmd


def test_ssh_pools_by_default() -> None:
    cmd, shell = wrap_command("id", {"runner": "ssh", "ssh_host": "user@host"})
    assert shell is True
    # pooling (ControlMaster/Path/Persist) is on by default
    assert "-o ControlMaster=auto" in cmd
    assert "-o ControlPath=" in cmd and "cm-%C" in cmd
    assert "-o ControlPersist=60s" in cmd
    assert " user@host " in cmd
    assert cmd.endswith(shlex.quote("id"))


def test_ssh_pool_can_be_disabled() -> None:
    cmd, _ = wrap_command(
        "id", {"runner": "ssh", "ssh_host": "user@host", "ssh_pool": False}
    )
    assert cmd.startswith("ssh user@host ")
    assert "ControlMaster" not in cmd


def test_ssh_pool_custom_persist_and_dir() -> None:
    cmd, _ = wrap_command(
        "id",
        {
            "runner": "ssh",
            "ssh_host": "h",
            "ssh_persist": "10m",
            "ssh_control_dir": "/tmp/cm",
        },
    )
    assert "-o ControlPersist=10m" in cmd
    assert "-o ControlPath=/tmp/cm/cm-%C" in cmd


def test_prepare_runner_creates_ssh_control_dir(tmp_path) -> None:
    from saarthi2.runners import prepare_runner

    control = tmp_path / "cm"
    prepare_runner({"runner": "ssh", "ssh_host": "h", "ssh_control_dir": str(control)})
    assert control.is_dir()
    # non-ssh and pool-disabled are no-ops
    prepare_runner({"runner": "local"})
    prepare_runner({"runner": "ssh", "ssh_host": "h", "ssh_pool": False,
                    "ssh_control_dir": str(tmp_path / "nope")})
    assert not (tmp_path / "nope").exists()


def test_ssh_requires_host() -> None:
    with pytest.raises(ValueError, match="ssh_host"):
        wrap_command("id", {"runner": "ssh"})


def test_unknown_runner_rejected() -> None:
    with pytest.raises(ValueError, match="unknown runner"):
        wrap_command("x", {"runner": "cloud"})

"""Execution runners — where a tool step's command actually runs.

``local`` runs on the host. ``docker`` wraps the command in an ephemeral
container. ``ssh`` runs it on a remote host, **reusing a pooled connection** by
default (OpenSSH ControlMaster/ControlPersist) so many steps against the same
host share one authenticated TCP session instead of re-handshaking per command.
Each returns ``(command, shell)`` for the engine's ``run_command``; docker/ssh
use a shell because they embed a quoted inner command.

``prepare_runner`` performs any side effects (creating the SSH control-socket
directory) that must happen before the wrapped command runs; the tool step calls
it first. ``wrap_command`` itself stays pure so it is trivially testable.
"""

from __future__ import annotations

import shlex
from pathlib import Path

RUNNERS = ("local", "docker", "ssh")

# Default location for SSH ControlMaster sockets and how long an idle master
# lingers so subsequent steps reuse it.
DEFAULT_SSH_CONTROL_DIR = "~/.saarthi2/ssh"
DEFAULT_SSH_PERSIST = "60s"


def _ssh_control_dir(params: dict) -> Path:
    return Path(str(params.get("ssh_control_dir") or DEFAULT_SSH_CONTROL_DIR)).expanduser()


def _ssh_pool_enabled(params: dict) -> bool:
    return bool(params.get("ssh_pool", True))


def prepare_runner(params: dict) -> None:
    """Side effects needed before a runner's command executes.

    For pooled SSH, OpenSSH will not create the control-socket directory itself,
    so ensure it exists. No-op for local/docker (and for non-pooled SSH).
    """

    if str(params.get("runner", "local")).lower() == "ssh" and _ssh_pool_enabled(params):
        _ssh_control_dir(params).mkdir(parents=True, exist_ok=True)


def wrap_command(cmd: str, params: dict) -> tuple[str, bool]:
    """Transform a command for the requested runner.

    params keys: ``runner`` (local|docker|ssh), ``shell`` (local only),
    ``image``/``docker_args`` (docker), ``ssh_host``/``ssh_args`` (ssh),
    ``ssh_pool`` (default true), ``ssh_persist`` (default 60s),
    ``ssh_control_dir`` (default ~/.saarthi2/ssh).
    """

    runner = str(params.get("runner", "local")).lower()

    if runner == "local":
        return cmd, bool(params.get("shell", False))

    if runner == "docker":
        image = str(params.get("image", "alpine:latest"))
        parts = ["docker", "run", "--rm"]
        parts += [str(a) for a in params.get("docker_args", []) or []]
        parts += [image, "sh", "-c", shlex.quote(cmd)]
        return " ".join(parts), True

    if runner == "ssh":
        host = str(params.get("ssh_host", "")).strip()
        if not host:
            raise ValueError("ssh runner requires 'ssh_host'")
        parts = ["ssh"]
        if _ssh_pool_enabled(params):
            # %C is an OpenSSH token: a hash of (host, port, user, ...), so each
            # distinct connection gets its own reused master socket.
            control_path = _ssh_control_dir(params) / "cm-%C"
            persist = str(params.get("ssh_persist", DEFAULT_SSH_PERSIST))
            parts += [
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={control_path}",
                "-o", f"ControlPersist={persist}",
            ]
        parts += [str(a) for a in params.get("ssh_args", []) or []]
        parts += [host, shlex.quote(cmd)]
        return " ".join(parts), True

    raise ValueError(f"unknown runner {runner!r}; expected one of {RUNNERS}")

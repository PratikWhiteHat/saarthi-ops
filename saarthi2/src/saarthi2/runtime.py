"""Composition root: real implementations of the injected collaborators."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
from collections.abc import Callable
from typing import Any

from saarthi2.config import Settings
from saarthi2.engine.runner import StepDeps
from saarthi2.policy import PermissiveGate
from saarthi2.tools import default_tool_registry

# Terminal control sequences many tools emit (colors, cursor moves). We strip them
# so stored/displayed output is clean text and so the LLM isn't fed escape noise.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _expand_user_tokens(args: list[str]) -> list[str]:
    """Expand a leading ``~`` in each token, mirroring how a shell would.

    Commands run with ``shell=False`` are not processed by a shell, so ``~`` in a
    path argument (e.g. ``-o ~/.saarthi2/out``) would otherwise be passed to the
    tool literally. ``expanduser`` only touches a leading ``~`` and leaves other
    tokens unchanged.
    """

    return [os.path.expanduser(token) if token.startswith("~") else token for token in args]


def _which_all(name: str, path: str | None = None) -> list[str]:
    """Every executable named ``name`` on PATH, in order, de-duplicated by realpath."""

    dirs = (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep)
    seen: set[str] = set()
    found: list[str] = []
    for directory in dirs:
        if not directory:
            continue
        candidate = os.path.join(directory, name)
        real = os.path.realpath(candidate)
        if real in seen:
            continue
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            seen.add(real)
            found.append(candidate)
    return found


def _is_python_script(path: str) -> bool:
    """Whether a file is a Python wrapper script (not a real compiled binary).

    Covers both a ``#!...python`` shebang and pip's ``#!/bin/sh`` ``exec``-wrapper
    (used when the interpreter path contains spaces or is too long for a shebang) —
    both mention ``python`` in their header. Compiled binaries do not start with
    ``#!`` at all.
    """

    try:
        with open(path, "rb") as handle:
            head = handle.read(512)
    except OSError:
        return False
    return head.startswith(b"#!") and b"python" in head.lower()


def resolve_tool_binary(name: str, *, path: str | None = None) -> str:
    """Resolve an executable, preferring the real compiled tool over a Python shadow.

    Security tools are system-installed compiled binaries (e.g. ``~/go/bin/httpx``),
    but a Python package can ship a console script of the same name — the ``httpx``
    library shadows ProjectDiscovery ``httpx`` and often sits earlier on PATH (a
    venv or the framework Python). When several candidates share a name we pick the
    first that is NOT a ``#!...python`` wrapper script, so the recon tool wins.
    A tool that only exists as a Python script (e.g. pip-installed ``semgrep``)
    still resolves. An explicit path is returned unchanged.
    """

    if os.sep in name:
        return name
    candidates = _which_all(name, path=path)
    if not candidates:
        return name
    real = [c for c in candidates if not _is_python_script(c)]
    return (real or candidates)[0]


async def run_command(
    cmd: str, *, timeout: int = 300, shell: bool = False
) -> tuple[int, str, str]:
    """Run a command, returning ``(exit_code, stdout, stderr)``.

    ``shell=False`` (default) splits with ``shlex`` and runs without a shell.
    """

    if shell:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    else:
        args = _expand_user_tokens(shlex.split(cmd))
        if not args:
            return (-1, "", "empty command")
        # Run the system tool, not a shadowing venv console-script of the same name.
        args[0] = resolve_tool_binary(args[0])
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return (-1, "", f"command timed out after {timeout}s")
    return (
        proc.returncode if proc.returncode is not None else -1,
        strip_ansi(out.decode("utf-8", "replace")),
        strip_ansi(err.decode("utf-8", "replace")),
    )


async def http_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    body: Any = None,
    timeout: int = 30,
) -> Any:
    """Perform one HTTP request and return the httpx response."""

    import httpx

    async with httpx.AsyncClient(
        follow_redirects=True, verify=False, timeout=timeout
    ) as client:
        return await client.request(
            method, url, headers=headers or None, content=body
        )


def build_deps(
    settings: Settings,
    *,
    store: Any = None,
    on_event: Callable[[str], None] | None = None,
    use_ai: bool = True,
) -> StepDeps:
    """Wire the real StepDeps (subprocess, httpx, Ollama agent, permissive gate)."""

    agent = None
    if use_ai:
        from saarthi2.ai import Agent, OllamaChat

        chat = OllamaChat(settings.ollama_host, settings.ollama_model)
        agent = Agent(chat.chat, default_tool_registry())

    from saarthi2.notify import Notifier
    from saarthi2.rag import SkillLibrary

    return StepDeps(
        run_command=run_command,
        http_request=http_request,
        agent=agent,
        gate=PermissiveGate(store=store),
        store=store,
        notifier=Notifier.from_settings(settings, http_request),
        skills=SkillLibrary.from_dir(settings.skills_dir),
        on_event=on_event,
    )

"""Composition root: real implementations of the injected collaborators."""

from __future__ import annotations

import asyncio
import shlex
from collections.abc import Callable
from typing import Any

from saarthi2.config import Settings
from saarthi2.engine.runner import StepDeps
from saarthi2.policy import PermissiveGate
from saarthi2.tools import default_tool_registry


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
        args = shlex.split(cmd)
        if not args:
            return (-1, "", "empty command")
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
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
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

    return StepDeps(
        run_command=run_command,
        http_request=http_request,
        agent=agent,
        gate=PermissiveGate(store=store),
        store=store,
        on_event=on_event,
    )

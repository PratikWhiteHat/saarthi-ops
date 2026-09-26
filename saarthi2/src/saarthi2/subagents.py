"""ACP sub-agent orchestration — delegate a prompt to an external agent CLI.

Osmedeus can hand a task to Claude Code / Codex / Gemini / OpenCode. Here the
``subagent`` step shells out to the chosen agent's CLI in non-interactive mode.
Requires that agent's CLI to be installed and authenticated.
"""

from __future__ import annotations

import shlex

# agent name -> non-interactive command prefix (binary + flags); the prompt is
# appended as a single quoted argument.
SUBAGENT_COMMANDS: dict[str, str] = {
    "claude": "claude -p",
    "codex": "codex exec",
    "gemini": "gemini -p",
    "opencode": "opencode run",
}


def render_subagent_command(
    agent: str, prompt: str, extra_args: list | None = None
) -> str:
    prefix = SUBAGENT_COMMANDS.get(agent)
    if prefix is None:
        raise ValueError(
            f"unknown sub-agent {agent!r}; known: {sorted(SUBAGENT_COMMANDS)}"
        )
    parts = [prefix]
    if extra_args:
        parts += [str(token) for token in extra_args]
    parts.append(shlex.quote(prompt))
    return " ".join(parts)


def subagent_catalog() -> list[dict]:
    return [{"name": name, "command": cmd} for name, cmd in SUBAGENT_COMMANDS.items()]

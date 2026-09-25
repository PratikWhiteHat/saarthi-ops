"""Tool registry the agentic ``llm`` step can call (Ollama tool-calling).

Each tool is a thin, JSON-schema-described wrapper over the engine's injected
collaborators (``run_command``/``http_request``), so the AI runs tools through
the exact same path — and the same policy gate — as declarative steps.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

MAX_TOOL_OUTPUT = 6_000


@dataclass(frozen=True)
class AITool:
    """One callable tool exposed to the model."""

    name: str
    description: str
    parameters: dict
    run: Callable[[dict, Any, Any], Awaitable[str]]

    def schema(self) -> dict:
        """Ollama/OpenAI-style function schema."""

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


async def _run_command_tool(args: dict, ctx: Any, deps: Any) -> str:
    cmd = str(args.get("cmd", "")).strip()
    if not cmd:
        return "error: 'cmd' is required"
    timeout = int(args.get("timeout", 120))
    if deps.gate is not None:
        deps.gate.check("command", {"cmd": cmd, "source": "ai"})
    exit_code, stdout, stderr = await deps.run_command(cmd, timeout=timeout, shell=False)
    body = stdout or stderr
    return f"exit_code={exit_code}\n{body[:MAX_TOOL_OUTPUT]}"


async def _http_get_tool(args: dict, ctx: Any, deps: Any) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        return "error: 'url' is required"
    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "source": "ai"})
    resp = await deps.http_request("GET", url, timeout=int(args.get("timeout", 20)))
    status = getattr(resp, "status_code", "?")
    text = getattr(resp, "text", "")[:MAX_TOOL_OUTPUT]
    return f"status={status}\n{text}"


def default_tool_registry() -> dict[str, AITool]:
    """Build the default AI tool registry."""

    return {
        "run_command": AITool(
            name="run_command",
            description=(
                "Run a shell/CLI security tool (e.g. subfinder, httpx, nuclei) "
                "and return its output. Use for recon and scanning."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cmd": {"type": "string", "description": "The full command to run."},
                    "timeout": {"type": "integer", "description": "Seconds (default 120)."},
                },
                "required": ["cmd"],
            },
            run=_run_command_tool,
        ),
        "http_get": AITool(
            name="http_get",
            description="Fetch a URL over HTTP GET and return status + body.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Absolute http(s) URL."},
                },
                "required": ["url"],
            },
            run=_http_get_tool,
        ),
    }

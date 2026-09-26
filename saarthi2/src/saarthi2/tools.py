"""Tool registry the agentic ``llm`` step can call (Ollama tool-calling).

Each tool is a thin, JSON-schema-described wrapper over the engine's injected
collaborators (``run_command``/``http_request``), so the AI runs tools through
the exact same path — and the same policy gate — as declarative steps.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from saarthi2.engine.context import apex_domain, host_of

MAX_TOOL_OUTPUT = 6_000

# Non-destructive detection/recon adapters the AGENT may run autonomously via
# ``run_scan``. Deliberately excludes brute-forcers (ffuf/gobuster/feroxbuster/
# massdns) that can DoS a small host, and sqlmap (data exfil via --dump) — those
# stay operator-driven in declarative steps only.
AI_SCAN_ALLOWLIST = frozenset(
    {
        "subfinder", "assetfinder", "amass", "findomain", "chaos",
        "dnsx", "httpx", "httprobe", "tlsx", "asnmap", "cdncheck",
        "katana", "gau", "waybackurls", "hakrawler", "unfurl",
        "naabu", "nuclei", "dalfox", "whatweb", "wafw00f", "subzy", "subjack",
    }
)

# Defense-in-depth: refuse a rendered command containing any of these, even for
# an allowlisted adapter (e.g. an injected flag).
_DESTRUCTIVE_TOKENS = ("--dump", "rm -rf", "mkfs", "dd if=", ":(){", " shutdown", " reboot")


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


async def _run_scan_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Run ONE allowlisted, non-destructive adapter against an in-scope target.

    This is the bounded alternative to raw ``run_command`` for autonomous hunts:
    the agent may only pick a tool from :data:`AI_SCAN_ALLOWLIST`, the target is
    scope-locked to the run's apex domain (defends against prompt injection via
    untrusted tool output), and destructive tokens are refused.
    """

    from saarthi2.adapters import render_adapter_command

    tool = str(args.get("tool", "")).strip()
    target = str(args.get("target", "")).strip()
    if tool not in AI_SCAN_ALLOWLIST:
        return (
            f"error: tool {tool!r} is not allowed for autonomous scanning. "
            f"Allowed: {', '.join(sorted(AI_SCAN_ALLOWLIST))}"
        )
    if not target:
        return "error: 'target' is required"

    # Scope lock: the requested host must be the run target's apex or a subdomain.
    run_target = getattr(ctx, "target", None) if ctx is not None else None
    if run_target:
        run_apex = apex_domain(run_target)
        req_host = host_of(target)
        if run_apex and not (req_host == run_apex or req_host.endswith("." + run_apex)):
            return f"error: {req_host!r} is out of scope (authorized apex: {run_apex})"

    params: dict[str, Any] = {"target": target, "input": target}
    extra = args.get("args")
    if isinstance(extra, list):
        params["args"] = [str(a) for a in extra]
    try:
        cmd = render_adapter_command(tool, params)
    except ValueError as exc:
        return f"error: {exc}"

    lowered = cmd.lower()
    for token in _DESTRUCTIVE_TOKENS:
        if token in lowered:
            return f"error: blocked destructive token {token.strip()!r}"

    if deps.gate is not None:
        deps.gate.check("command", {"cmd": cmd, "source": "ai", "target": target})
    timeout = int(args.get("timeout", 180))
    exit_code, stdout, stderr = await deps.run_command(cmd, timeout=timeout, shell=False)
    body = stdout or stderr
    return f"$ {cmd}\nexit_code={exit_code}\n{body[:MAX_TOOL_OUTPUT]}"


async def _search_skills_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Retrieve the most relevant bug-hunting playbook sections for a query."""

    library = getattr(deps, "skills", None)
    if library is None or library.is_empty:
        return "no skill library loaded (run `saarthi2 skills fetch`)"
    query = str(args.get("query", "")).strip()
    if not query:
        return "error: 'query' is required"
    context = library.context_for(query, k=int(args.get("k", 3)))
    return context or f"no skills matched {query!r}"


def default_tool_registry() -> dict[str, AITool]:
    """Build the default AI tool registry."""

    return {
        "search_skills": AITool(
            name="search_skills",
            description=(
                "Look up the relevant bug-hunting playbook(s) (methodology, payloads, "
                "bypasses, validation) for a vuln class or target signal. Call this "
                "FIRST when planning how to hunt something."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Vuln class or topic."},
                    "k": {"type": "integer", "description": "How many sections (default 3)."},
                },
                "required": ["query"],
            },
            run=_search_skills_tool,
        ),
        "run_scan": AITool(
            name="run_scan",
            description=(
                "Run ONE non-destructive recon/scan tool against an in-scope target "
                "and return its output. Prefer this over run_command for hunting. "
                "Allowed tools: " + ", ".join(sorted(AI_SCAN_ALLOWLIST)) + ". The "
                "target must be the authorized domain or one of its subdomains."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Adapter name (see allowed list)."},
                    "target": {"type": "string", "description": "Host/URL to scan (in scope)."},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional extra flags for the tool.",
                    },
                },
                "required": ["tool", "target"],
            },
            run=_run_scan_tool,
        ),
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

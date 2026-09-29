"""Tool registry the agentic ``llm`` step can call (Ollama tool-calling).

Each tool is a thin, JSON-schema-described wrapper over the engine's injected
collaborators (``run_command``/``http_request``), so the AI runs tools through
the exact same path — and the same policy gate — as declarative steps.
"""

from __future__ import annotations

import os
import re
import tempfile
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
    # The model mostly runs curl with pipes/grep and shell quoting (e.g.
    # `curl -s URL | grep '...'`). Those need a real shell — with shell=False the
    # command is shlex-split and pipes/quotes break ("No closing quotation"). Run in
    # a shell so the agent's curl works, but refuse obviously destructive commands.
    lowered = cmd.lower()
    for token in _DESTRUCTIVE_TOKENS:
        if token in lowered:
            return f"error: blocked destructive token {token.strip()!r}"
    timeout = int(args.get("timeout", 120))
    if deps.gate is not None:
        deps.gate.check("command", {"cmd": cmd, "source": "ai"})
    exit_code, stdout, stderr = await deps.run_command(cmd, timeout=timeout, shell=True)
    body = stdout or stderr
    return f"$ {cmd}\nexit_code={exit_code}\n{body[:MAX_TOOL_OUTPUT]}"


def _http_error(url: str, exc: Exception) -> str:
    """Turn a request exception into instructive feedback for the model.

    A DNS/connection failure means the host or path was invented — tell the model
    plainly so it stops retrying fabricated URLs and goes back to real endpoints.
    """

    from saarthi2.engine.context import host_of

    text = str(exc).lower()
    if "missing an 'http" in text or "relative url" in text or "no host" in text:
        return (
            f"error: {url!r} is not an absolute URL. Pass the FULL URL including the "
            f"scheme and host, e.g. https://<host>{url if url.startswith('/') else '/'+url}."
        )
    if any(s in text for s in ("nodename", "servname", "name or service", "resolve", "getaddrinfo", "connecterror", "connection refused", "failed to establish")):
        host = host_of(url) or url
        return (
            f"error: could not connect to {host!r} — this host/endpoint does not "
            f"exist or is unreachable. Do NOT retry it or invent similar URLs; only "
            f"test hosts and paths you actually found in a real response."
        )
    return f"error: request to {url} failed: {exc}"


async def _http_get_tool(args: dict, ctx: Any, deps: Any) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        return "error: 'url' is required"
    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "source": "ai"})
    try:
        resp = await deps.http_request("GET", url, timeout=int(args.get("timeout", 20)))
    except Exception as exc:  # DNS/connection failures etc.
        return _http_error(url, exc)
    status = getattr(resp, "status_code", "?")
    text = getattr(resp, "text", "")[:MAX_TOOL_OUTPUT]
    return f"status={status}\n{text}"


# Response headers worth surfacing to the model (auth, CORS, tech, redirects, cookies).
_SHOW_HEADERS = frozenset(
    {
        "server", "location", "set-cookie", "content-type", "x-powered-by",
        "www-authenticate", "access-control-allow-origin",
        "access-control-allow-credentials", "x-frame-options", "content-security-policy",
    }
)


async def _http_request_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Send an arbitrary HTTP request — the agent's reliable testing primitive.

    Structured (method/headers/body) so the model doesn't hand-craft error-prone
    curl strings. Returns the status, the security-relevant response headers, and the
    body — enough to judge a finding (reflected input, other users' data, redirects,
    CORS, auth differences).
    """

    url = str(args.get("url", "")).strip()
    if not url:
        return "error: 'url' is required"
    method = (str(args.get("method", "GET")).strip() or "GET").upper()
    headers = args.get("headers") if isinstance(args.get("headers"), dict) else None
    if headers:
        headers = {str(k): str(v) for k, v in headers.items()}
    body = args.get("body")
    if body is not None:
        body = str(body)
    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "method": method, "source": "ai"})
    try:
        resp = await deps.http_request(
            method, url, headers=headers, body=body, timeout=int(args.get("timeout", 20))
        )
    except Exception as exc:  # DNS/connection failures etc.
        return _http_error(url, exc)
    status = getattr(resp, "status_code", "?")
    resp_headers = dict(getattr(resp, "headers", {}) or {})
    shown = "\n".join(
        f"{k}: {v}" for k, v in resp_headers.items() if k.lower() in _SHOW_HEADERS
    )
    text = getattr(resp, "text", "")[:MAX_TOOL_OUTPUT]
    return f"{method} {url}\nstatus={status}\n{shown}\n\n{text}"


async def _run_scan_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Run ONE allowlisted, non-destructive adapter against an in-scope target.

    This is the bounded alternative to raw ``run_command`` for autonomous hunts:
    the agent may only pick a tool from :data:`AI_SCAN_ALLOWLIST`, the target is
    scope-locked to the run's apex domain (defends against prompt injection via
    untrusted tool output), and destructive tokens are refused.
    """

    from saarthi2.adapters import TOOL_ADAPTERS, render_adapter_command

    tool = str(args.get("tool", "")).strip()
    if tool not in AI_SCAN_ALLOWLIST:
        return (
            f"error: tool {tool!r} is not allowed for autonomous scanning. "
            f"Allowed: {', '.join(sorted(AI_SCAN_ALLOWLIST))}"
        )

    # Accept one host (``target``) or many (``targets``) — the latter lets the agent
    # chain, e.g. feed a whole subfinder result into httpx. A bare ``target`` may
    # itself be a whitespace/comma/newline-separated list.
    targets: list[str] = []
    raw_list = args.get("targets")
    if isinstance(raw_list, list):
        targets.extend(str(t).strip() for t in raw_list if str(t).strip())
    single = str(args.get("target", "")).strip()
    if single and not targets:
        targets = [part for part in re.split(r"[\s,]+", single) if part]
    if not targets:
        return "error: 'target' is required (or pass a 'targets' list of hosts)"

    # Scope lock: EVERY requested host must be the run target's apex or a subdomain.
    # (No run target — e.g. the operator-driven LLM Playground — means no lock.)
    run_target = getattr(ctx, "target", None) if ctx is not None else None
    if run_target:
        run_apex = apex_domain(run_target)
        if run_apex:
            for candidate in targets:
                req_host = host_of(candidate)
                if not (req_host == run_apex or req_host.endswith("." + run_apex)):
                    return (
                        f"error: {req_host!r} is out of scope "
                        f"(authorized apex: {run_apex})"
                    )

    adapter = TOOL_ADAPTERS.get(tool)
    template = adapter.template if adapter is not None else ""
    params: dict[str, Any] = {"target": targets[0], "input": targets[0]}
    extra = args.get("args")
    if isinstance(extra, list):
        params["args"] = [str(a) for a in extra]

    # Tools whose template reads a host LIST from a file (``{input}`` -> e.g.
    # ``httpx -l``, ``dnsx -l``, ``tlsx -l``) must be given a real file. Passing a
    # bare hostname there produces the classic ``httpx -l example.com`` ->
    # "No input provided: no files found" failure. Write the targets to a temp file.
    tmp_path: str | None = None
    if "{input}" in template:
        fd, tmp_path = tempfile.mkstemp(prefix="saarthi2_scan_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(targets) + "\n")
        params["input"] = tmp_path

    try:
        try:
            cmd = render_adapter_command(tool, params)
        except ValueError as exc:
            return f"error: {exc}"

        lowered = cmd.lower()
        for token in _DESTRUCTIVE_TOKENS:
            if token in lowered:
                return f"error: blocked destructive token {token.strip()!r}"

        if deps.gate is not None:
            deps.gate.check(
                "command", {"cmd": cmd, "source": "ai", "target": targets[0]}
            )
        timeout = int(args.get("timeout", 180))
        exit_code, stdout, stderr = await deps.run_command(
            cmd, timeout=timeout, shell=False
        )
        body = stdout or stderr
        shown = ", ".join(targets[:8]) + (" …" if len(targets) > 8 else "")
        return (
            f"$ {cmd}\n# targets ({len(targets)}): {shown}\n"
            f"exit_code={exit_code}\n{body[:MAX_TOOL_OUTPUT]}"
        )
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


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


# --- headless-browser tools (Playwright) --------------------------------------
# Session is persisted to files so it survives across separate tool calls: a
# Playwright storage_state (for browser_open) and a Netscape cookie jar (for curl).
_BROWSER_STATE = os.path.join(tempfile.gettempdir(), "saarthi2_browser_state.json")
_BROWSER_COOKIE_JAR = os.path.join(tempfile.gettempdir(), "saarthi2_cookies.txt")
_PW_MISSING = (
    "error: browser tool unavailable — Playwright is not installed in the server env. "
    "Install: uv pip install --python <server-python> playwright && "
    "<server-python> -m playwright install chromium"
)


def _write_netscape_jar(cookies: list[dict], path: str) -> None:
    """Persist Playwright cookies as a Netscape jar so curl (-b) can reuse the session."""

    lines = ["# Netscape HTTP Cookie File"]
    for cookie in cookies:
        domain = str(cookie.get("domain", ""))
        expires = cookie.get("expires", 0) or 0
        try:
            expires = str(int(expires)) if float(expires) > 0 else "0"
        except (TypeError, ValueError):
            expires = "0"
        lines.append(
            "\t".join(
                [
                    domain,
                    "TRUE" if domain.startswith(".") else "FALSE",
                    str(cookie.get("path", "/")),
                    "TRUE" if cookie.get("secure") else "FALSE",
                    expires,
                    str(cookie.get("name", "")),
                    str(cookie.get("value", "")),
                ]
            )
        )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


async def _browser_login_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Log in with a real headless browser — handles JS + CSRF tokens automatically."""

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return _PW_MISSING
    url = str(args.get("url", "")).strip()
    username = str(args.get("username", ""))
    password = str(args.get("password", ""))
    if not url or not username:
        return "error: 'url', 'username' and 'password' are required"
    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "source": "ai", "action": "browser_login"})
    user_sel = args.get("username_selector") or (
        "input[name='username'], input[name='user'], input[name='email'], "
        "input[type='email'], input[type='text']"
    )
    pass_sel = args.get("password_selector") or "input[name='password'], input[type='password']"
    submit_sel = args.get("submit_selector") or (
        "input[type='submit'], button[type='submit'], input[name='Login'], "
        "button:has-text('Log in'), button:has-text('Login'), button:has-text('Sign in')"
    )
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.fill(user_sel, username, timeout=8000)
            await page.fill(pass_sel, password, timeout=8000)
            try:
                await page.click(submit_sel, timeout=5000)
            except Exception:
                await page.keyboard.press("Enter")
            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            final_url = page.url
            title = await page.title()
            content = await page.content()
            cookies = await context.cookies()
            await context.storage_state(path=_BROWSER_STATE)
            _write_netscape_jar(cookies, _BROWSER_COOKIE_JAR)
            await browser.close()
    except Exception as exc:
        return f"error: browser login failed: {exc}"
    names = ", ".join(sorted({str(c.get("name", "")) for c in cookies}))
    return (
        f"browser login submitted. final_url={final_url}\ntitle={title}\n"
        f"cookies ({len(cookies)}): {names}\n"
        f"session saved — reuse with browser_open, or with curl: -b {_BROWSER_COOKIE_JAR}\n\n"
        f"{content[:MAX_TOOL_OUTPUT]}"
    )


async def _browser_open_tool(args: dict, ctx: Any, deps: Any) -> str:
    """Open a URL in the headless browser, reusing the logged-in session."""

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return _PW_MISSING
    url = str(args.get("url", "")).strip()
    if not url:
        return "error: 'url' is required"
    if deps.gate is not None:
        deps.gate.check("http", {"url": url, "source": "ai", "action": "browser_open"})
    state = _BROWSER_STATE if os.path.exists(_BROWSER_STATE) else None
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True, storage_state=state)
            page = await context.new_page()
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            status = resp.status if resp else "?"
            title = await page.title()
            text = await page.inner_text("body")
            await context.storage_state(path=_BROWSER_STATE)
            await browser.close()
    except Exception as exc:
        return f"error: browser open failed: {exc}"
    return f"{url}\nstatus={status}\ntitle={title}\n\n{text[:MAX_TOOL_OUTPUT]}"


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
                "Run ONE non-destructive recon/scan tool against in-scope target(s) "
                "and return its output. Prefer this over run_command for hunting. "
                "Allowed tools: " + ", ".join(sorted(AI_SCAN_ALLOWLIST)) + ". Targets "
                "must be the authorized domain or its subdomains. To PROBE MANY HOSTS "
                "AT ONCE (e.g. feed subdomains from a subfinder result into httpx, "
                "dnsx, or tlsx), pass them in 'targets' — they are written to a file "
                "the tool reads. Use 'target' for a single host (nuclei, whatweb, "
                "katana, naabu)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Adapter name (see allowed list)."},
                    "target": {"type": "string", "description": "A single host/URL to scan (in scope)."},
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Multiple in-scope hosts to scan together — e.g. the "
                            "subdomains discovered by subfinder. Best for httpx/dnsx/tlsx."
                        ),
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional extra flags for the tool.",
                    },
                },
                "required": ["tool"],
            },
            run=_run_scan_tool,
        ),
        "run_command": AITool(
            name="run_command",
            description=(
                "Run a command in a REAL shell — your main testing tool. Pipes, "
                "quoting, and redirects work, so use curl for HTTP tests: keep a "
                "cookie jar for authenticated flows (curl -c cj.txt -b cj.txt), POST "
                "creds/payloads with -d, add -H headers, and -i to see status+headers. "
                "Example: curl -s -i -c cj.txt -b cj.txt -d "
                "'username=admin&password=password&Login=Login' https://host/login.php"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cmd": {"type": "string", "description": "The full shell command (curl …, pipes ok)."},
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
        "http_request": AITool(
            name="http_request",
            description=(
                "Send an HTTP request with any method, headers, cookies, and body — "
                "your MAIN testing tool. Prefer this over run_command/curl to probe "
                "endpoints: tamper params/ids, POST injection payloads, add auth or "
                "Host/Origin headers, change the method. Returns status + key response "
                "headers + body so you can judge the result."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "method": {"type": "string", "description": "GET, POST, PUT, DELETE, PATCH, OPTIONS…"},
                    "url": {"type": "string", "description": "Absolute http(s) URL (in scope)."},
                    "headers": {
                        "type": "object",
                        "description": "Request headers, e.g. {\"Cookie\":\"session=…\",\"Content-Type\":\"application/json\"}.",
                    },
                    "body": {"type": "string", "description": "Request body for POST/PUT/PATCH."},
                },
                "required": ["url"],
            },
            run=_http_request_tool,
        ),
        "browser_login": AITool(
            name="browser_login",
            description=(
                "Log in with a REAL headless browser (Chromium). Use this when a login "
                "needs JavaScript or a hidden CSRF/anti-forgery token (e.g. DVWA) — the "
                "browser submits the form correctly and keeps the session. Give url + "
                "username + password (optional CSS selectors if auto-detect misses the "
                "fields). It saves the session for browser_open AND a cookie jar for curl."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Login page URL."},
                    "username": {"type": "string", "description": "Username to submit."},
                    "password": {"type": "string", "description": "Password to submit."},
                    "username_selector": {"type": "string", "description": "Optional CSS selector for the username field."},
                    "password_selector": {"type": "string", "description": "Optional CSS selector for the password field."},
                    "submit_selector": {"type": "string", "description": "Optional CSS selector for the submit button."},
                },
                "required": ["url", "username", "password"],
            },
            run=_browser_login_tool,
        ),
        "browser_open": AITool(
            name="browser_open",
            description=(
                "Open a URL in the headless browser, REUSING the logged-in session from "
                "browser_login. Use it to browse and test authenticated pages; returns "
                "the rendered page text."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Absolute URL to open in the logged-in session."},
                },
                "required": ["url"],
            },
            run=_browser_open_tool,
        ),
    }

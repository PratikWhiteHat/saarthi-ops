"""The bounded run_scan agent tool and the ai-hunt workflow."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from saarthi2.engine.context import apex_domain, host_of
from saarthi2.engine.loader import load_workflow
from saarthi2.tools import AI_SCAN_ALLOWLIST, default_tool_registry


class _FakeGate:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def check(self, kind: str, details: dict) -> None:
        self.calls.append((kind, details))


def _deps(capture: list[str]):
    async def run_command(cmd, *, timeout=300, shell=False):
        capture.append(cmd)
        return (0, "scan-output", "")

    return SimpleNamespace(gate=_FakeGate(), run_command=run_command)


def _run_scan(args, target="ex.com"):
    tool = default_tool_registry()["run_scan"]
    capture: list[str] = []
    deps = _deps(capture)
    ctx = SimpleNamespace(target=target)
    out = asyncio.run(tool.run(args, ctx, deps))
    return out, capture, deps


def test_helpers() -> None:
    assert host_of("https://a.b.ex.com/x?y=1") == "a.b.ex.com"
    assert apex_domain("https://a.b.ex.com/x") == "ex.com"
    assert apex_domain("sub.target.co.in") == "target.co.in"


def test_run_scan_registered_and_allowlist() -> None:
    assert "run_scan" in default_tool_registry()
    assert {"nuclei", "httpx", "tlsx"} <= AI_SCAN_ALLOWLIST
    # brute-forcers / data-exfil tools are NOT autonomously runnable
    assert "sqlmap" not in AI_SCAN_ALLOWLIST
    assert "ffuf" not in AI_SCAN_ALLOWLIST


def test_run_scan_allowed_tool_in_scope() -> None:
    out, capture, deps = _run_scan({"tool": "nuclei", "target": "app.ex.com"})
    assert capture == ["nuclei -u app.ex.com -silent -jsonl"]
    assert "scan-output" in out
    assert deps.gate.calls and deps.gate.calls[0][0] == "command"


def test_run_scan_rejects_disallowed_tool() -> None:
    out, capture, _ = _run_scan({"tool": "sqlmap", "target": "ex.com"})
    assert "not allowed" in out
    assert capture == []  # never executed


def test_run_scan_scope_lock() -> None:
    out, capture, _ = _run_scan({"tool": "nuclei", "target": "evil.com"}, target="ex.com")
    assert "out of scope" in out
    assert capture == []
    # a subdomain of the authorized apex is allowed. httpx reads a host LIST from a
    # file (-l), so the command points at a temp file and the host shows in output.
    ok, cap2, _ = _run_scan({"tool": "httpx", "target": "https://a.ex.com"}, target="https://ex.com/p")
    assert cap2 and cap2[0].startswith("httpx -l ") and "a.ex.com" in ok
    assert "out of scope" not in ok


def test_run_scan_httpx_uses_file_for_target() -> None:
    # Regression: `httpx -l <host>` treats the host as a filename and fails. The
    # tool must write host(s) to a real file so `-l` works and the apex is probed.
    out, capture, _ = _run_scan({"tool": "httpx", "target": "app.ex.com"})
    assert capture and capture[0].startswith("httpx -l ")
    assert " app.ex.com " not in capture[0]  # host is in the file, not the flag
    assert "# targets (1): app.ex.com" in out


def test_run_scan_multiple_targets_written_to_file() -> None:
    # The agent can feed a whole subfinder result into httpx via `targets`.
    subs = ["a.ex.com", "b.ex.com", "c.ex.com"]
    out, capture, _ = _run_scan({"tool": "httpx", "targets": subs})
    assert capture and capture[0].startswith("httpx -l ")
    assert "# targets (3): a.ex.com, b.ex.com, c.ex.com" in out


def test_run_scan_single_host_tool_uses_target_flag() -> None:
    # A per-host tool (nuclei) still renders `-u <host>`, no temp file involved.
    out, capture, _ = _run_scan({"tool": "nuclei", "target": "app.ex.com"})
    assert capture == ["nuclei -u app.ex.com -silent -jsonl"]


def test_run_scan_blocks_destructive_args() -> None:
    out, capture, _ = _run_scan({"tool": "nuclei", "target": "ex.com", "args": ["--dump"]})
    assert "destructive token" in out
    assert capture == []


def test_run_scan_requires_target() -> None:
    out, _, _ = _run_scan({"tool": "nuclei"})
    assert "'target' is required" in out


def test_http_request_tool_sends_method_headers_body() -> None:
    captured: dict = {}

    async def http_request(method, url, *, headers=None, body=None, timeout=20):
        captured.update(method=method, url=url, headers=headers, body=body)
        return SimpleNamespace(
            status_code=200,
            headers={"Server": "nginx", "Set-Cookie": "x=1", "X-Ignored": "z"},
            text="hello world",
        )

    deps = SimpleNamespace(gate=None, http_request=http_request)
    tool = default_tool_registry()["http_request"]
    out = asyncio.run(
        tool.run(
            {"method": "post", "url": "http://t/api", "headers": {"Cookie": "s=1"}, "body": "a=b"},
            None,
            deps,
        )
    )
    assert captured == {"method": "POST", "url": "http://t/api", "headers": {"Cookie": "s=1"}, "body": "a=b"}
    assert "status=200" in out and "Server: nginx" in out and "hello world" in out
    assert "X-Ignored" not in out  # only security-relevant headers surfaced


def test_ai_hunt_workflow_validates() -> None:
    path = Path(__file__).resolve().parent.parent / "src/saarthi2/workflows/ai-hunt.yaml"
    wf = load_workflow(path)
    assert wf.name == "ai-hunt"
    hunt = next(s for s in wf.steps if s.id == "hunt")
    assert hunt.uses == "llm"
    assert hunt.with_["tools"] == ["search_skills", "run_scan", "http_get"]

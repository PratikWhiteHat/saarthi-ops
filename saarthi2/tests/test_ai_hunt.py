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
    # a subdomain of the authorized apex is allowed
    ok, cap2, _ = _run_scan({"tool": "httpx", "target": "https://a.ex.com"}, target="https://ex.com/p")
    assert cap2 and "a.ex.com" in cap2[0]


def test_run_scan_blocks_destructive_args() -> None:
    out, capture, _ = _run_scan({"tool": "nuclei", "target": "ex.com", "args": ["--dump"]})
    assert "destructive token" in out
    assert capture == []


def test_run_scan_requires_target() -> None:
    out, _, _ = _run_scan({"tool": "nuclei"})
    assert "'target' is required" in out


def test_ai_hunt_workflow_validates() -> None:
    path = Path(__file__).resolve().parent.parent / "src/saarthi2/workflows/ai-hunt.yaml"
    wf = load_workflow(path)
    assert wf.name == "ai-hunt"
    hunt = next(s for s in wf.steps if s.id == "hunt")
    assert hunt.uses == "llm"
    assert hunt.with_["tools"] == ["search_skills", "run_scan", "http_get"]

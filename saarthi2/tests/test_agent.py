"""The agentic loop calls tools, feeds results back, and bounds iterations."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from saarthi2.ai.agent import Agent
from saarthi2.tools import AITool


def _tool(calls: list) -> dict[str, AITool]:
    async def run(args, ctx, deps):
        calls.append(args)
        return "TOOL_OK"

    return {
        "run_command": AITool(
            name="run_command",
            description="run a command",
            parameters={"type": "object", "properties": {"cmd": {"type": "string"}}},
            run=run,
        )
    }


def test_agent_calls_tool_then_finalizes() -> None:
    calls: list = []
    script = [
        {"content": "", "tool_calls": [{"name": "run_command", "arguments": {"cmd": "id"}}]},
        {"content": "final answer", "tool_calls": []},
    ]
    step = {"n": 0}

    async def fake_chat(messages, *, tools=None, num_predict=800):
        response = script[step["n"]]
        step["n"] += 1
        return response

    agent = Agent(fake_chat, _tool(calls))
    result = asyncio.run(
        agent.run(
            "do it",
            tool_names=["run_command"],
            max_iterations=5,
            deps=SimpleNamespace(gate=None),
        )
    )

    assert result.answer == "final answer"
    assert result.iterations == 2
    assert calls == [{"cmd": "id"}]
    assert result.tool_calls == [{"name": "run_command", "arguments": {"cmd": "id"}}]
    assert result.stopped_reason == "final answer"


def test_agent_respects_max_iterations() -> None:
    calls: list = []

    async def always_tool(messages, *, tools=None, num_predict=800):
        if tools is None:  # the final wrap-up call
            return {"content": "wrapup", "tool_calls": []}
        return {"content": "", "tool_calls": [{"name": "run_command", "arguments": {"cmd": "x"}}]}

    agent = Agent(always_tool, _tool(calls))
    result = asyncio.run(
        agent.run(
            "go",
            tool_names=["run_command"],
            max_iterations=2,
            deps=SimpleNamespace(gate=None),
        )
    )

    assert result.stopped_reason == "max_iterations"
    assert result.answer == "wrapup"
    assert result.iterations == 2
    assert len(calls) == 2  # one tool call per iteration


def test_agent_handles_unknown_tool_gracefully() -> None:
    script = [
        {"content": "", "tool_calls": [{"name": "nope", "arguments": {}}]},
        {"content": "recovered", "tool_calls": []},
    ]
    step = {"n": 0}

    async def fake_chat(messages, *, tools=None, num_predict=800):
        response = script[step["n"]]
        step["n"] += 1
        return response

    agent = Agent(fake_chat, _tool([]))
    result = asyncio.run(
        agent.run("go", tool_names=["run_command"], deps=SimpleNamespace(gate=None))
    )
    assert result.answer == "recovered"

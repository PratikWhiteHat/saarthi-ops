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


def test_agent_recovers_tool_call_emitted_as_text() -> None:
    # The model prints the tool call as JSON text instead of a structured call;
    # the agent must recover it, run the tool, and keep going (not stop early).
    calls: list = []
    script = [
        {"content": '```json\n{"name": "run_command", "arguments": {"cmd": "id"}}\n```', "tool_calls": []},
        {"content": "done hunting", "tool_calls": []},
    ]
    step = {"n": 0}

    async def fake_chat(messages, *, tools=None, num_predict=800):
        response = script[step["n"]]
        step["n"] += 1
        return response

    agent = Agent(fake_chat, _tool(calls))
    result = asyncio.run(
        agent.run("go", tool_names=["run_command"], deps=SimpleNamespace(gate=None))
    )
    assert calls == [{"cmd": "id"}]  # the text-emitted call actually executed
    assert result.answer == "done hunting"
    assert result.tool_calls == [{"name": "run_command", "arguments": {"cmd": "id"}}]


def test_recover_tool_calls_various_text_formats() -> None:
    from saarthi2.ai.agent import _tool_calls_from_text

    names = {"http_get", "http_request", "run_command"}
    # flat array (the real failure): fields as siblings, no "arguments" wrapper
    c1 = _tool_calls_from_text('```json\n[{"name":"http_request","url":"https://x/","method":"HEAD"}]\n```', names)
    assert c1 == [{"name": "http_request", "arguments": {"url": "https://x/", "method": "HEAD"}}]
    # function-wrapper
    assert _tool_calls_from_text('{"function":{"name":"http_get","arguments":{"url":"https://y/"}}}', names) \
        == [{"name": "http_get", "arguments": {"url": "https://y/"}}]
    # tool_calls wrapper
    assert _tool_calls_from_text('{"tool_calls":[{"name":"run_command","arguments":{"cmd":"id"}}]}', names) \
        == [{"name": "run_command", "arguments": {"cmd": "id"}}]
    # unknown name is NOT misread as a call
    assert _tool_calls_from_text('{"name":"admin","role":"x"}', names) == []


def test_agent_nudges_model_that_narrates_instead_of_calling() -> None:
    # Model describes running the tool (names it) but makes no call; after the nudge
    # it emits a real call. The agent should recover and run it rather than stop.
    calls: list = []
    script = [
        {"content": "I will now Call `run_command` with `id` against the host.", "tool_calls": []},
        {"content": "", "tool_calls": [{"name": "run_command", "arguments": {"cmd": "id"}}]},
        {"content": "hunt complete", "tool_calls": []},
    ]
    step = {"n": 0}

    async def fake_chat(messages, *, tools=None, num_predict=800):
        response = script[step["n"]]
        step["n"] += 1
        return response

    events: list = []
    agent = Agent(fake_chat, _tool(calls))
    result = asyncio.run(
        agent.run(
            "go",
            tool_names=["run_command"],
            max_iterations=5,
            deps=SimpleNamespace(gate=None),
            on_event=events.append,
        )
    )
    assert calls == [{"cmd": "id"}]  # nudge made it actually execute
    assert result.answer == "hunt complete"
    assert any(e.get("type") == "note" for e in events)  # a nudge note was emitted


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

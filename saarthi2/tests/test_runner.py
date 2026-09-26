"""The runner sequences steps, expands loops, honours when, and threads output."""

from __future__ import annotations

import asyncio

from saarthi2.ai.agent import AgentResult
from saarthi2.engine.loader import load_workflow_from_str
from saarthi2.engine.models import StepStatus
from saarthi2.engine.runner import StepDeps, WorkflowRunner

_WF = """
name: t
vars: {target: ex.com}
steps:
  - id: a
    uses: tool
    with: {cmd: "echo {{ target }}"}
    register: enum
  - id: probe
    uses: tool
    when: "{{ steps.a.output }}"
    loop: "{{ steps.a.output }}"
    with: {cmd: "probe {{ item }}"}
  - id: skipme
    uses: tool
    when: "false"
    with: {cmd: "should-not-run"}
  - id: triage
    uses: llm
    with: {prompt: "triage {{ steps.probe.output }}"}
"""


class _FakeAgent:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def run(self, prompt, *, tool_names=None, max_iterations=6, ctx=None, deps=None):
        self.prompts.append(prompt)
        return AgentResult(answer="TRIAGE", iterations=1)


def _deps():
    calls: list[str] = []

    async def fake_run_command(cmd, *, timeout=300, shell=False):
        calls.append(cmd)
        if cmd.startswith("echo"):
            return (0, "h1\nh2", "")
        return (0, f"ran:{cmd}", "")

    async def fake_http(*args, **kwargs):  # unused here
        raise AssertionError("http not expected")

    agent = _FakeAgent()
    deps = StepDeps(
        run_command=fake_run_command,
        http_request=fake_http,
        agent=agent,
        gate=None,
        store=None,
    )
    return deps, calls, agent


def test_runner_full_flow() -> None:
    wf = load_workflow_from_str(_WF)
    deps, calls, agent = _deps()
    result = asyncio.run(WorkflowRunner(deps).run(wf, target="ex.com"))

    assert result.status is StepStatus.COMPLETED
    # echo ran, loop expanded over 2 lines, skipme skipped
    assert calls == ["echo ex.com", "probe h1", "probe h2"]

    by_id = {s.step_id: s for s in result.steps}
    assert by_id["a"].output == "h1\nh2"
    assert by_id["probe"].status is StepStatus.COMPLETED
    assert by_id["probe"].data["item_count"] == 2
    assert by_id["probe"].output == "ran:probe h1\nran:probe h2"
    assert by_id["skipme"].status is StepStatus.SKIPPED
    # llm step got the probe output threaded into its prompt
    assert "ran:probe h1" in agent.prompts[0]
    assert by_id["triage"].output == "TRIAGE"


def test_runner_stops_on_failure() -> None:
    wf = load_workflow_from_str(
        """
name: f
steps:
  - id: boom
    uses: tool
    with: {cmd: "fail"}
  - id: after
    uses: tool
    with: {cmd: "echo later"}
"""
    )

    async def failing(cmd, *, timeout=300, shell=False):
        return (1, "", "nope")

    async def fake_http(*a, **k):
        raise AssertionError

    deps = StepDeps(run_command=failing, http_request=fake_http)
    result = asyncio.run(WorkflowRunner(deps).run(wf))
    assert result.status is StepStatus.FAILED
    # the second step never ran (stopped on failure)
    assert [s.step_id for s in result.steps] == ["boom"]


_PAR = """
name: par
steps:
  - id: fan
    uses: parallel
    with:
      steps:
        - {id: one, uses: tool, with: {cmd: "probe A"}}
        - {id: two, uses: tool, with: {cmd: "probe B"}}
"""


def test_parallel_runs_all_branches() -> None:
    wf = load_workflow_from_str(_PAR)
    deps, calls, _ = _deps()
    result = asyncio.run(WorkflowRunner(deps).run(wf))
    assert result.status is StepStatus.COMPLETED
    fan = result.steps[0]
    assert fan.data["branches"] == 2
    assert set(calls) == {"probe A", "probe B"}
    # both branch outputs registered for downstream steps
    assert "one" in [s.step_id for s in fan.iterations]


_FN = """
name: fn
vars: {out: "PLACEHOLDER"}
steps:
  - id: w
    uses: function
    with: {func: write, content: "hello world", output: "{{ vars.out }}"}
  - id: r
    uses: function
    with: {func: read, input: "{{ vars.out }}"}
"""


def test_function_step_end_to_end(tmp_path) -> None:
    wf = load_workflow_from_str(_FN)
    deps, _, _ = _deps()
    out = tmp_path / "f.txt"
    result = asyncio.run(
        WorkflowRunner(deps).run(wf, extra_vars={"out": str(out)})
    )
    assert result.status is StepStatus.COMPLETED
    by_id = {s.step_id: s for s in result.steps}
    assert by_id["r"].output == "hello world"
    assert out.read_text() == "hello world"


def test_notify_step() -> None:
    sent: list[tuple[str, list | None]] = []

    class _FakeNotifier:
        async def send(self, message, *, channels=None):
            sent.append((message, channels))
            return {"slack": True}

    wf = load_workflow_from_str(
        'name: n\nsteps:\n  - {id: a, uses: notify, with: {message: "done {{ target }}"}}\n'
    )
    deps, _, _ = _deps()
    deps.notifier = _FakeNotifier()
    result = asyncio.run(WorkflowRunner(deps).run(wf, target="ex.com"))
    assert result.status is StepStatus.COMPLETED
    assert sent == [("done ex.com", None)]


def test_subagent_step_builds_command() -> None:
    wf = load_workflow_from_str(
        'name: s\nsteps:\n'
        '  - {id: a, uses: subagent, with: {agent: claude, prompt: "find bugs"}}\n'
    )
    deps, calls, _ = _deps()
    result = asyncio.run(WorkflowRunner(deps).run(wf))
    assert result.status is StepStatus.COMPLETED
    assert calls == ["claude -p 'find bugs'"]


def test_continue_on_error_keeps_going() -> None:
    wf = load_workflow_from_str(
        """
name: c
steps:
  - id: boom
    uses: tool
    continue_on_error: true
    with: {cmd: "fail"}
  - id: after
    uses: tool
    with: {cmd: "ok"}
"""
    )

    async def runner(cmd, *, timeout=300, shell=False):
        return (1, "", "e") if cmd == "fail" else (0, "done", "")

    async def fake_http(*a, **k):
        raise AssertionError

    deps = StepDeps(run_command=runner, http_request=fake_http)
    result = asyncio.run(WorkflowRunner(deps).run(wf))
    assert [s.step_id for s in result.steps] == ["boom", "after"]
    assert result.status is StepStatus.COMPLETED

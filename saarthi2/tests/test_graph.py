"""Workflow -> Mermaid visualization."""

from __future__ import annotations

from saarthi2.engine import load_workflow_from_str, to_mermaid

_WF = """
name: t
steps:
  - {id: a, uses: tool, with: {cmd: "x"}}
  - {id: b, uses: tool, loop: "{{ steps.a.output }}", with: {cmd: "y {{ item }}"}}
  - {id: c, uses: llm, with: {prompt: "p"}}
"""


def test_mermaid_has_nodes_edges_and_ai_class() -> None:
    mermaid = to_mermaid(load_workflow_from_str(_WF))
    assert mermaid.startswith("flowchart TD")
    for node in ("n_a", "n_b", "n_c"):
        assert node in mermaid
    # sequential edges follow declaration order
    assert "n_a --> n_b" in mermaid
    assert "n_b --> n_c" in mermaid
    # loop + llm annotations
    assert "loop" in mermaid
    assert "class n_c ai;" in mermaid


def test_mermaid_node_ids_are_safe() -> None:
    mermaid = to_mermaid(
        load_workflow_from_str(
            "name: t\nsteps:\n  - {id: 'my-step.1', uses: tool, with: {cmd: x}}\n"
        )
    )
    assert "n_my_step_1" in mermaid

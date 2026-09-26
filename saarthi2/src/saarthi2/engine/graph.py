"""Render a workflow as a Mermaid flowchart for visualization."""

from __future__ import annotations

import re

from saarthi2.engine.models import Workflow

_ICON = {"tool": "⚙", "http": "🌐", "llm": "🤖"}


def _node_id(step_id: str) -> str:
    """A mermaid-safe node identifier."""

    return "n_" + re.sub(r"\W", "_", step_id)


def _label(step_id: str, uses: str, *, loop: bool, when: bool) -> str:
    icon = _ICON.get(uses, "•")
    parts = [f"{icon} {step_id}", uses]
    if loop:
        parts.append("loop")
    if when:
        parts.append("when")
    text = "<br/>".join(parts)
    # Escape the quotes mermaid label delimiters can't contain.
    return text.replace('"', "'")


def to_mermaid(workflow: Workflow) -> str:
    """Build a top-down Mermaid flowchart of the workflow's steps.

    v1 steps run sequentially, so edges follow declaration order; loop and
    conditional steps are annotated on the node.
    """

    lines = ["flowchart TD"]
    previous: str | None = None
    for step in workflow.steps:
        node = _node_id(step.id)
        label = _label(
            step.id, step.uses, loop=step.loop is not None, when=step.when is not None
        )
        lines.append(f'  {node}["{label}"]')
        if step.uses == "llm":
            lines.append(f"  class {node} ai;")
        if previous is not None:
            lines.append(f"  {previous} --> {node}")
        previous = node
    lines.append("  classDef ai fill:#3b1d5e,stroke:#a06bd6,color:#fff;")
    return "\n".join(lines)

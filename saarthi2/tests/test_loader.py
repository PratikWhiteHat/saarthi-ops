"""The loader parses and validates declarative workflows."""

from __future__ import annotations

from pathlib import Path

import pytest

from saarthi2.engine.loader import (
    WorkflowError,
    list_workflows,
    load_workflow,
    load_workflow_from_str,
)

_WORKFLOWS = Path(__file__).resolve().parent.parent / "src" / "saarthi2" / "workflows"


def test_loads_sample_recon_workflow() -> None:
    wf = load_workflow(_WORKFLOWS / "recon.yaml")
    assert wf.name == "recon"
    ids = [s.id for s in wf.steps]
    assert ids == ["subs", "probe", "triage"]
    assert {s.uses for s in wf.steps} == {"tool", "llm"}
    # 'with' alias populates with_
    assert wf.steps[0].with_["cmd"].startswith("subfinder")


def test_list_workflows_finds_yaml() -> None:
    names = [p.stem for p in list_workflows(_WORKFLOWS)]
    assert "recon" in names
    assert "general" in names


def test_general_workflow_uses_new_step_types() -> None:
    wf = load_workflow(_WORKFLOWS / "general.yaml")
    uses = {s.uses for s in wf.steps}
    assert {"function", "parallel", "llm"} <= uses


def test_duplicate_step_id_rejected() -> None:
    text = """
name: dup
steps:
  - id: a
    uses: tool
    with: {cmd: "x"}
  - id: a
    uses: tool
    with: {cmd: "y"}
"""
    with pytest.raises(WorkflowError, match="Duplicate step id"):
        load_workflow_from_str(text)


def test_unknown_step_type_rejected() -> None:
    text = """
name: bad
steps:
  - id: a
    uses: teleport
    with: {}
"""
    with pytest.raises(WorkflowError, match="unknown type"):
        load_workflow_from_str(text)


def test_empty_workflow_rejected() -> None:
    with pytest.raises(WorkflowError):
        load_workflow_from_str("name: empty\nsteps: []\n")


def test_non_mapping_rejected() -> None:
    with pytest.raises(WorkflowError):
        load_workflow_from_str("- just\n- a\n- list\n")

"""Load and validate declarative YAML workflows."""

from __future__ import annotations

from pathlib import Path

import yaml

from saarthi2.engine.models import Workflow


class WorkflowError(ValueError):
    """Raised when a workflow file is missing, malformed, or invalid."""


def load_workflow_from_str(text: str) -> Workflow:
    """Parse and validate a workflow from a YAML string."""

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WorkflowError(f"Invalid YAML: {exc}") from exc

    if not isinstance(payload, dict):
        raise WorkflowError("A workflow must be a YAML mapping at the top level.")

    try:
        workflow = Workflow.model_validate(payload)
    except Exception as exc:  # pydantic ValidationError and friends
        raise WorkflowError(f"Invalid workflow: {exc}") from exc

    _validate(workflow)
    return workflow


def load_workflow(path: str | Path) -> Workflow:
    """Load a workflow from a file path."""

    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise WorkflowError(f"Workflow file not found: {file_path}")
    return load_workflow_from_str(file_path.read_text(encoding="utf-8"))


def _validate(workflow: Workflow) -> None:
    if not workflow.steps:
        raise WorkflowError("A workflow must define at least one step.")

    seen: set[str] = set()
    from saarthi2.steps import STEP_TYPES  # local import avoids an import cycle

    for step in workflow.steps:
        if step.id in seen:
            raise WorkflowError(f"Duplicate step id: {step.id!r}")
        seen.add(step.id)
        if step.uses not in STEP_TYPES:
            raise WorkflowError(
                f"Step {step.id!r} uses unknown type {step.uses!r}. "
                f"Known types: {sorted(STEP_TYPES)}."
            )


def list_workflows(directory: str | Path) -> list[Path]:
    """List workflow YAML files in a directory (sorted)."""

    root = Path(directory).expanduser()
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob("*.y*ml") if p.is_file())

"""Pydantic models for workflows, steps, and results."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StepStatus(StrEnum):
    """Lifecycle status of a step or run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Step(BaseModel):
    """One declarative workflow step.

    ``uses`` selects the step type (``tool``/``http``/``llm``). ``with`` carries
    the type-specific parameters (strings support ``{{ }}`` interpolation).
    ``loop`` expands the step once per item of a list/step-output (each bound to
    ``item``). ``when`` skips the step when the rendered expression is falsy.
    ``register`` stores the result under ``steps.<register>`` for later steps.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str = ""
    uses: str
    with_: dict = Field(default_factory=dict, alias="with")
    loop: str | None = None
    when: str | None = None
    # ``register:`` in YAML; aliased to avoid shadowing a pydantic attribute.
    register_: str | None = Field(default=None, alias="register")
    continue_on_error: bool = False

    @property
    def register(self) -> str | None:
        return self.register_


class Workflow(BaseModel):
    """A declarative pipeline of steps plus default variables."""

    name: str
    description: str = ""
    vars: dict = Field(default_factory=dict)
    steps: list[Step]


class StepResult(BaseModel):
    """Outcome of running one step (or one loop iteration)."""

    step_id: str
    status: StepStatus
    output: str = ""
    data: dict = Field(default_factory=dict)
    exit_code: int | None = None
    error: str | None = None
    duration_ms: int = 0
    evidence_path: str | None = None
    iterations: list[StepResult] = Field(default_factory=list)


class RunResult(BaseModel):
    """The full outcome of a workflow run."""

    run_id: str
    workflow: str
    target: str | None = None
    workspace: str | None = None
    status: StepStatus = StepStatus.PENDING
    steps: list[StepResult] = Field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.status is StepStatus.FAILED

"""Saarthi 2.0 command-line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from saarthi2.config import Settings, get_settings
from saarthi2.engine import (
    RunResult,
    WorkflowRunner,
    list_workflows,
    load_workflow,
)
from saarthi2.engine.loader import WorkflowError
from saarthi2.runtime import build_deps
from saarthi2.state import Store

app = typer.Typer(
    help="Saarthi 2.0 — a local-first, AI-native security workflow engine.",
    no_args_is_help=True,
)
workflow_app = typer.Typer(help="Inspect and validate workflows.", no_args_is_help=True)
app.add_typer(workflow_app, name="workflow")
console = Console()


def _resolve_workflow(name: str, settings: Settings) -> Path:
    candidate = Path(name).expanduser()
    if candidate.is_file():
        return candidate
    for suffix in (".yaml", ".yml"):
        path = settings.workflows_dir / f"{name}{suffix}"
        if path.is_file():
            return path
    raise WorkflowError(
        f"Workflow {name!r} not found (looked for a file and in "
        f"{settings.workflows_dir})."
    )


def _parse_vars(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise typer.BadParameter(f"--var must be key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        out[key.strip()] = value
    return out


def _print_summary(result: RunResult) -> None:
    table = Table(title=f"Run {result.run_id} · {result.workflow}")
    table.add_column("Step")
    table.add_column("Status")
    table.add_column("ms", justify="right")
    table.add_column("Detail")
    for step in result.steps:
        detail = step.error or (f"exit={step.exit_code}" if step.exit_code is not None else "")
        if step.data.get("item_count") is not None:
            detail = f"{step.data['item_count']} item(s)"
        table.add_row(step.step_id, step.status.value, str(step.duration_ms), detail[:60])
    console.print(table)
    console.print(f"[bold]Overall:[/bold] {result.status.value}")


@app.command()
def run(
    workflow: Annotated[str, typer.Argument(help="Workflow name or path to a YAML file.")],
    target: Annotated[
        str | None, typer.Option("--target", "-t", help="Target passed as {{ target }}.")
    ] = None,
    var: Annotated[
        list[str] | None,
        typer.Option("--var", help="Extra vars as key=value (repeatable)."),
    ] = None,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Disable the AI agent (llm steps will fail).")
    ] = False,
) -> None:
    """Run a workflow end to end against a target."""

    settings = get_settings()
    try:
        wf_path = _resolve_workflow(workflow, settings)
        wf = load_workflow(wf_path)
    except WorkflowError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc

    extra = _parse_vars(var or [])
    store = Store(settings.db_path, settings.evidence_dir, settings.audit_path)
    deps = build_deps(
        settings,
        store=store,
        on_event=lambda message: console.print(message, markup=False, highlight=False),
        use_ai=not no_ai,
    )
    runner = WorkflowRunner(deps)

    shown_target = target or wf.vars.get("target", "-")
    console.print(f"[bold]Workflow:[/bold] {wf.name} · target={shown_target}")
    result = asyncio.run(runner.run(wf, target=target, extra_vars=extra))
    store.close()
    _print_summary(result)
    raise typer.Exit(code=1 if result.failed else 0)


@workflow_app.command("list")
def workflow_list() -> None:
    """List available workflows."""

    settings = get_settings()
    found = list_workflows(settings.workflows_dir)
    if not found:
        console.print(f"No workflows in {settings.workflows_dir}")
        return
    for path in found:
        console.print(f"{path.stem}\t[dim]{path}[/dim]")


@workflow_app.command("lint")
def workflow_lint(
    workflow: Annotated[str, typer.Argument(help="Workflow name or path.")],
) -> None:
    """Validate a workflow without running it."""

    settings = get_settings()
    try:
        wf = load_workflow(_resolve_workflow(workflow, settings))
    except WorkflowError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[bold green]OK[/bold green] {wf.name}: {len(wf.steps)} step(s)")


if __name__ == "__main__":
    app()

"""Saarthi 2.0 command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
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
from saarthi2.state import open_store

app = typer.Typer(
    help="Saarthi 2.0 — a local-first, AI-native security workflow engine.",
    no_args_is_help=True,
)
workflow_app = typer.Typer(help="Inspect and validate workflows.", no_args_is_help=True)
app.add_typer(workflow_app, name="workflow")
function_app = typer.Typer(help="List and run built-in functions.", no_args_is_help=True)
app.add_typer(function_app, name="function")
db_app = typer.Typer(help="Query the local run database.", no_args_is_help=True)
app.add_typer(db_app, name="db")
snapshot_app = typer.Typer(help="Export/import run snapshots.", no_args_is_help=True)
app.add_typer(snapshot_app, name="snapshot")
storage_app = typer.Typer(help="Cloud object-storage upload (needs the CLI).", no_args_is_help=True)
app.add_typer(storage_app, name="storage")
plugins_app = typer.Typer(help="Discover extension plugins.", no_args_is_help=True)
app.add_typer(plugins_app, name="plugins")
skills_app = typer.Typer(help="Bug-hunting skill library (RAG).", no_args_is_help=True)
app.add_typer(skills_app, name="skills")
console = Console()


@app.callback()
def _bootstrap() -> None:
    """Load extension plugins (functions/adapters/steps) before any command runs."""

    from saarthi2.plugins import load_plugins

    load_plugins(get_settings())


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
    store = open_store(settings)
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


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Bind port.")] = 8777,
    reload: Annotated[
        bool,
        typer.Option("--reload", help="Auto-restart on source changes (dev)."),
    ] = False,
) -> None:
    """Launch the Web UI + REST API (dashboard, workflow visualization, runs)."""

    import uvicorn

    settings = get_settings()
    console.print(
        f"[bold]Saarthi 2.0[/bold] web UI → [bold cyan]http://{host}:{port}[/bold cyan]"
    )
    console.print(f"Workflows: {settings.workflows_dir}")
    if reload:
        # Import-string + factory so the reloader can respawn workers on edits.
        uvicorn.run(
            "saarthi2.server:app_factory",
            factory=True,
            host=host,
            port=port,
            reload=True,
            log_level="info",
        )
    else:
        from saarthi2.server import create_app

        uvicorn.run(create_app(settings), host=host, port=port, log_level="info")


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


cloud_app = typer.Typer(help="Cloud provisioning (needs the provider CLI).", no_args_is_help=True)
app.add_typer(cloud_app, name="cloud")


@app.command()
def enqueue(
    workflow: Annotated[str, typer.Argument(help="Workflow name or path.")],
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    var: Annotated[list[str] | None, typer.Option("--var")] = None,
) -> None:
    """Push a job onto the distributed queue (needs SAARTHI2_REDIS_URL to share)."""

    from saarthi2.distributed import Job, get_queue

    settings = get_settings()
    if not settings.redis_url:
        console.print(
            "[yellow]Note:[/yellow] no SAARTHI2_REDIS_URL set — the in-memory queue "
            "does not persist across processes; workers on other hosts won't see it."
        )
    queue = get_queue(settings.redis_url)
    job = Job(workflow=workflow, target=target, vars=_parse_vars(var or []))
    queue.push(job)
    console.print(f"[green]Enqueued[/green] {job.id} · {workflow} · queue size={queue.size()}")


@app.command()
def worker(
    once: Annotated[bool, typer.Option("--once", help="Drain the queue then exit.")] = False,
) -> None:
    """Run a worker that pops jobs from the queue and executes them."""

    from saarthi2.distributed import get_queue, run_worker

    settings = get_settings()
    queue = get_queue(settings.redis_url)
    console.print(
        f"[bold]Worker[/bold] started · redis={'yes' if settings.redis_url else 'memory'}"
    )
    count = asyncio.run(
        run_worker(
            queue,
            settings,
            once=once,
            on_event=lambda m: console.print(m, markup=False, highlight=False),
        )
    )
    console.print(f"Processed {count} job(s).")


@app.command()
def schedule(
    workflow: Annotated[str, typer.Argument(help="Workflow name or path.")],
    every: Annotated[int, typer.Option("--every", help="Interval seconds.")] = 3600,
    cron: Annotated[
        str | None, typer.Option("--cron", help='5-field cron expr, e.g. "0 */6 * * *".')
    ] = None,
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    times: Annotated[int | None, typer.Option("--times", help="Stop after N runs.")] = None,
) -> None:
    """Run a workflow repeatedly on an interval or a cron expression."""

    from saarthi2.distributed import Job
    from saarthi2.scheduler import run_cron_schedule, run_schedule

    settings = get_settings()
    job = Job(workflow=workflow, target=target)
    emit = lambda m: console.print(m, markup=False, highlight=False)  # noqa: E731
    if cron:
        console.print(f"[bold]Scheduling[/bold] {workflow} on cron {cron!r} (times={times or '∞'})")
        try:
            count = asyncio.run(
                run_cron_schedule(job, settings, expr=cron, times=times, on_event=emit)
            )
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    else:
        console.print(f"[bold]Scheduling[/bold] {workflow} every {every}s (times={times or '∞'})")
        count = asyncio.run(
            run_schedule(job, settings, every=every, times=times, on_event=emit)
        )
    console.print(f"Fired {count} time(s).")


@cloud_app.command("providers")
def cloud_providers() -> None:
    """List supported cloud providers."""

    from saarthi2.cloud import cloud_catalog

    for p in cloud_catalog():
        console.print(f"{p['name']:14} cli={p['cli']:12} requires: {p['requires']}")


@cloud_app.command("provision")
def cloud_provision(
    provider: Annotated[str, typer.Option("--provider")],
    name: Annotated[str, typer.Option("--name")],
    size: Annotated[str, typer.Option("--size")] = "",
    image: Annotated[str, typer.Option("--image")] = "",
    region: Annotated[str, typer.Option("--region")] = "",
    execute: Annotated[bool, typer.Option("--execute", help="Actually run the CLI.")] = False,
) -> None:
    """Print (or run with --execute) the provider CLI command to provision a box."""

    from saarthi2.cloud import render_provision_command

    try:
        cmd = render_provision_command(
            provider,
            {"name": name, "size": size, "image": image, "region": region},
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(cmd, markup=False, highlight=False)
    if execute:
        from saarthi2.runtime import run_command

        code, out, err = asyncio.run(run_command(cmd, shell=True, timeout=600))
        console.print((out or err), markup=False, highlight=False)
        raise typer.Exit(code=0 if code == 0 else 1)


@app.command()
def health() -> None:
    """Check which tool adapters' binaries are installed on PATH."""

    from saarthi2.adapters import adapter_catalog
    from saarthi2.runtime import resolve_tool_binary

    table = Table(title="Tool availability")
    table.add_column("Tool")
    table.add_column("Binary")
    table.add_column("Category")
    table.add_column("Installed")
    present = 0
    for entry in adapter_catalog():
        # resolve the same way runs do (system tool wins over a venv shadow)
        found = os.sep in resolve_tool_binary(entry["binary"])
        present += found
        table.add_row(
            entry["name"],
            entry["binary"],
            entry["category"],
            "[green]yes[/green]" if found else "[red]no[/red]",
        )
    console.print(table)
    total = len(adapter_catalog())
    console.print(f"[bold]{present}/{total}[/bold] tools installed.")


@function_app.command("list")
def function_list() -> None:
    """List built-in workflow functions."""

    from saarthi2.functions import function_catalog

    table = Table(title="Built-in functions")
    table.add_column("Name")
    table.add_column("Description")
    for entry in function_catalog():
        table.add_row(entry["name"], entry["description"])
    console.print(table)


@function_app.command("run")
def function_run(
    name: Annotated[str, typer.Argument(help="Function name (see `function list`).")],
    arg: Annotated[
        list[str] | None,
        typer.Option("--arg", help="Function arg as key=value (repeatable)."),
    ] = None,
) -> None:
    """Run a single built-in function with the given args and print its output."""

    from saarthi2.engine.context import RunContext
    from saarthi2.functions import FUNCTION_REGISTRY

    fn = FUNCTION_REGISTRY.get(name)
    if fn is None:
        console.print(f"[red]Unknown function {name!r}.[/red] Try `saarthi2 function list`.")
        raise typer.Exit(code=1)
    args = _parse_vars(arg or [])
    ctx = RunContext(run_id="function-cli", target=None, vars={})
    result = fn(dict(args), ctx)
    console.print(str(result.get("output", "")), markup=False, highlight=False)


@app.command()
def config() -> None:
    """Show the resolved runtime configuration (secrets redacted)."""

    settings = get_settings()

    def _redact(value: str) -> str:
        return "***set***" if value else "-"

    table = Table(title="Saarthi 2.0 configuration")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("ollama_host", settings.ollama_host)
    table.add_row("ollama_model", settings.ollama_model)
    table.add_row("work_dir", str(settings.work_dir))
    table.add_row("workflows_dir", str(settings.workflows_dir))
    table.add_row("redis_url", _redact(settings.redis_url))
    table.add_row("api_key", _redact(settings.api_key))
    table.add_row("slack_webhook", _redact(settings.slack_webhook))
    table.add_row("discord_webhook", _redact(settings.discord_webhook))
    table.add_row("telegram_token", _redact(settings.telegram_token))
    console.print(table)


@db_app.command("runs")
def db_runs(
    limit: Annotated[int, typer.Option("--limit", help="Max rows.")] = 50,
) -> None:
    """List recent runs."""

    settings = get_settings()
    store = open_store(settings)
    try:
        rows = store.list_runs(limit=limit)
    finally:
        store.close()
    if not rows:
        console.print("No runs recorded yet.")
        return
    cols = ("run_id", "workflow", "target", "status", "created_at")
    table = Table(title="Runs")
    for col in cols:
        table.add_column(col)
    for row in rows:
        table.add_row(*(str(row.get(c, "")) for c in cols))
    console.print(table)


@db_app.command("findings")
def db_findings(
    run_id: Annotated[str | None, typer.Option("--run-id", help="Filter by run.")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 100,
) -> None:
    """List recorded findings."""

    settings = get_settings()
    store = open_store(settings)
    try:
        rows = store.list_findings(run_id=run_id, limit=limit)
    finally:
        store.close()
    if not rows:
        console.print("No findings recorded yet.")
        return
    cols = ("severity", "tool", "rule_id", "message", "location")
    table = Table(title="Findings")
    for col in cols:
        table.add_column(col)
    for row in rows:
        table.add_row(*(str(row.get(c, ""))[:60] for c in cols))
    console.print(table)


@db_app.command("workspaces")
def db_workspaces() -> None:
    """List workspaces (grouped runs) with counts and last activity."""

    settings = get_settings()
    store = open_store(settings)
    try:
        rows = store.list_workspaces()
    finally:
        store.close()
    if not rows:
        console.print("No workspaces yet.")
        return
    table = Table(title="Workspaces")
    for col in ("workspace", "runs", "last_run"):
        table.add_column(col)
    for row in rows:
        table.add_row(
            str(row.get("workspace") or "-"),
            str(row.get("runs")),
            str(row.get("last_run")),
        )
    console.print(table)


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target passed as {{ target }}.")],
    workflow: Annotated[
        str, typer.Option("--workflow", "-w", help="Flow to run.")
    ] = "full",
    no_ai: Annotated[bool, typer.Option("--no-ai")] = False,
) -> None:
    """Convenience: run a flow (default 'full') against a target."""

    run(workflow=workflow, target=target, var=[], no_ai=no_ai)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="Run id to report on.")],
    fmt: Annotated[
        str, typer.Option("--format", help="markdown or json.")
    ] = "markdown",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to a file instead of stdout.")
    ] = None,
) -> None:
    """Render a Markdown/JSON report for a completed run."""

    from saarthi2.report import render_json, render_markdown

    settings = get_settings()
    store = open_store(settings)
    try:
        run_row = store.get_run(run_id)
        steps = store.list_steps(run_id)
        findings_rows = store.list_findings(run_id=run_id)
    finally:
        store.close()
    if run_row is None:
        console.print(f"[red]Run {run_id!r} not found.[/red]")
        raise typer.Exit(code=1)
    renderer = render_json if fmt == "json" else render_markdown
    content = renderer(run_row, steps, findings_rows)
    if output:
        output.expanduser().write_text(content, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output}")
    else:
        console.print(content, markup=False, highlight=False)


@snapshot_app.command("export")
def snapshot_export(
    run_id: Annotated[str, typer.Argument(help="Run id to snapshot.")],
    output_dir: Annotated[
        Path, typer.Option("--output", "-o", help="Directory to write the snapshot into.")
    ],
) -> None:
    """Export a run (JSON summary + Markdown report + evidence manifest) to a folder."""

    from saarthi2.report import render_json, render_markdown

    settings = get_settings()
    store = open_store(settings)
    try:
        run_row = store.get_run(run_id)
        steps = store.list_steps(run_id)
        findings_rows = store.list_findings(run_id=run_id)
    finally:
        store.close()
    if run_row is None:
        console.print(f"[red]Run {run_id!r} not found.[/red]")
        raise typer.Exit(code=1)

    out = output_dir.expanduser()
    out.mkdir(parents=True, exist_ok=True)
    (out / "snapshot.json").write_text(
        render_json(run_row, steps, findings_rows), encoding="utf-8"
    )
    (out / "report.md").write_text(
        render_markdown(run_row, steps, findings_rows), encoding="utf-8"
    )
    evidence = [s.get("evidence_path") for s in steps if s.get("evidence_path")]
    (out / "evidence_manifest.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )
    console.print(f"[green]Snapshot written[/green] → {out} ({len(evidence)} evidence file(s))")


@snapshot_app.command("import")
def snapshot_import(
    path: Annotated[Path, typer.Argument(help="snapshot.json file or a snapshot directory.")],
    run_id: Annotated[
        str | None, typer.Option("--run-id", help="Import under a new run id.")
    ] = None,
) -> None:
    """Import a snapshot.json into the local database (run + steps + findings)."""

    target = path.expanduser()
    if target.is_dir():
        target = target / "snapshot.json"
    if not target.is_file():
        console.print(f"[red]Snapshot file not found:[/red] {target}")
        raise typer.Exit(code=1)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid snapshot JSON:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    settings = get_settings()
    store = open_store(settings)
    try:
        imported = store.import_snapshot(payload, new_run_id=run_id)
    finally:
        store.close()
    console.print(f"[green]Imported[/green] run {imported}")


@storage_app.command("providers")
def storage_providers() -> None:
    """List cloud object-storage providers."""

    from saarthi2.storage import storage_catalog

    for p in storage_catalog():
        console.print(f"{p['name']:6} cli={p['cli']:8} requires: {p['requires']}")


@storage_app.command("upload")
def storage_upload(
    src: Annotated[str, typer.Argument(help="Local file to upload.")],
    provider: Annotated[str, typer.Option("--provider", help="s3|s3c|gcs|azure.")],
    bucket: Annotated[str, typer.Option("--bucket", help="Bucket/container name.")],
    dest: Annotated[str, typer.Option("--dest", help="Remote object name.")] = "",
    endpoint: Annotated[str, typer.Option("--endpoint", help="For s3c (S3-compatible).")] = "",
    account: Annotated[str, typer.Option("--account", help="For azure.")] = "",
    execute: Annotated[bool, typer.Option("--execute", help="Actually run the CLI.")] = False,
) -> None:
    """Print (or run with --execute) the provider CLI command to upload a file."""

    from saarthi2.storage import render_upload_command

    params = {"src": src, "bucket": bucket, "endpoint": endpoint, "account": account}
    if dest:
        params["dest"] = dest
    try:
        cmd = render_upload_command(provider, params)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(cmd, markup=False, highlight=False)
    if execute:
        from saarthi2.runtime import run_command

        code, out, err = asyncio.run(run_command(cmd, shell=True, timeout=600))
        console.print((out or err), markup=False, highlight=False)
        raise typer.Exit(code=0 if code == 0 else 1)


@app.command()
def watch(
    workflow: Annotated[str, typer.Argument(help="Workflow name or path.")],
    path: Annotated[str, typer.Option("--path", help="File or directory to watch.")],
    target: Annotated[str | None, typer.Option("--target", "-t")] = None,
    interval: Annotated[float, typer.Option("--interval", help="Poll seconds.")] = 5.0,
    fires: Annotated[int | None, typer.Option("--fires", help="Stop after N fires.")] = None,
) -> None:
    """Fire a workflow whenever a watched file/directory changes (mtime poll)."""

    from saarthi2.distributed import Job
    from saarthi2.triggers import run_watch

    settings = get_settings()
    job = Job(workflow=workflow, target=target)
    console.print(f"[bold]Watching[/bold] {path} → {workflow} (every {interval}s)")
    count = asyncio.run(
        run_watch(
            job, settings, path=path, poll_interval=interval, max_fires=fires,
            on_event=lambda m: console.print(m, markup=False, highlight=False),
        )
    )
    console.print(f"Fired {count} time(s).")


@app.command()
def install(
    tool: Annotated[
        list[str] | None,
        typer.Argument(help="Tool names to install (default: all missing)."),
    ] = None,
    execute: Annotated[
        bool, typer.Option("--execute", help="Actually run the curated install commands.")
    ] = False,
) -> None:
    """Show (or run with --execute) install commands for missing tool adapters.

    Only commands from the built-in adapter catalog are ever run — a curated
    allowlist, never arbitrary input.
    """

    from saarthi2.adapters import TOOL_ADAPTERS, adapter_catalog
    from saarthi2.runtime import resolve_tool_binary

    wanted = set(tool or [])
    missing = [
        a for a in adapter_catalog()
        if (not wanted or a["name"] in wanted) and os.sep not in resolve_tool_binary(a["binary"])
    ]
    if not missing:
        console.print("[green]Nothing to install[/green] — all requested tools are present.")
        return
    for entry in missing:
        hint = TOOL_ADAPTERS[entry["name"]].install or "(no curated installer; install manually)"
        console.print(f"[bold]{entry['name']}[/bold]: {hint}")

    if not execute:
        console.print("\n[dim]Re-run with --execute to run the curated commands above.[/dim]")
        return
    if not typer.confirm(f"Run {sum(1 for e in missing if TOOL_ADAPTERS[e['name']].install)} "
                         "curated install command(s)?"):
        raise typer.Exit(code=0)
    from saarthi2.runtime import run_command

    for entry in missing:
        cmd = TOOL_ADAPTERS[entry["name"]].install
        if not cmd:
            continue
        console.print(f"[cyan]$ {cmd}[/cyan]", highlight=False)
        code, out, err = asyncio.run(run_command(cmd, shell=True, timeout=600))
        console.print((out or err)[:2000], markup=False, highlight=False)
        console.print(f"exit={code}")


@app.command()
def usage() -> None:
    """Print common usage examples."""

    examples = [
        ("Run a workflow", "saarthi2 run recon -t example.com"),
        ("Quick scan (full flow)", "saarthi2 scan example.com"),
        ("Lint a workflow", "saarthi2 workflow lint full"),
        ("List built-in functions", "saarthi2 function list"),
        ("Run one function", "saarthi2 function run apex_domain --arg text=a.b.co.uk"),
        ("Check installed tools", "saarthi2 health"),
        ("Install missing tools", "saarthi2 install --execute"),
        ("List recent runs", "saarthi2 db runs"),
        ("Report on a run", "saarthi2 report run-abc123 --format markdown"),
        ("Snapshot a run", "saarthi2 snapshot run-abc123 -o ./snap"),
        ("Serve the web UI + API", "saarthi2 serve -p 8777"),
        ("Enqueue a distributed job", "saarthi2 enqueue full -t example.com"),
        ("Run a worker", "saarthi2 worker"),
        ("Schedule every hour", "saarthi2 schedule recon --every 3600 -t example.com"),
    ]
    table = Table(title="Saarthi 2.0 — usage examples")
    table.add_column("Task")
    table.add_column("Command")
    for label, cmd in examples:
        table.add_row(label, cmd)
    console.print(table)


_SKILLS_URL = "https://github.com/elementalsouls/Claude-BugHunter/archive/refs/heads/main.tar.gz"


@skills_app.command("fetch")
def skills_fetch() -> None:
    """Download the bug-hunting skill corpus into the skills dir (for RAG)."""

    import io
    import tarfile
    import urllib.request

    settings = get_settings()
    dest = settings.skills_dir
    console.print(f"Downloading skills → {dest} …")
    try:
        with urllib.request.urlopen(_SKILLS_URL, timeout=180) as resp:  # noqa: S310 (known URL)
            raw = resp.read()
    except Exception as exc:  # network/URL error
        console.print(f"[red]download failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = member.name.split("/")
            if len(parts) < 3 or parts[1] != "skills" or not member.isfile():
                continue
            rel = "/".join(parts[2:])
            target = dest / rel
            if not str(target.resolve()).startswith(str(dest.resolve())):
                continue  # path-traversal guard
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is not None:
                target.write_bytes(extracted.read())
                count += 1
    console.print(f"[green]Fetched[/green] {count} file(s) into {dest}")


@skills_app.command("list")
def skills_list() -> None:
    """List the loaded skills."""

    from saarthi2.rag import SkillLibrary

    settings = get_settings()
    lib = SkillLibrary.from_dir(settings.skills_dir)
    if lib.is_empty:
        console.print(f"No skills in {settings.skills_dir}. Run `saarthi2 skills fetch`.")
        return
    table = Table(title=f"Skills ({len(lib.catalog())})")
    for col in ("name", "sections", "description"):
        table.add_column(col)
    for entry in lib.catalog():
        table.add_row(entry["name"], str(entry["sections"]), entry["description"][:70])
    console.print(table)


@skills_app.command("search")
def skills_search(
    query: Annotated[str, typer.Argument(help="What to look up, e.g. 'idor api'.")],
    k: Annotated[int, typer.Option("--k", help="Number of results.")] = 5,
) -> None:
    """Search the skill library and print the top matching sections."""

    from saarthi2.rag import SkillLibrary

    settings = get_settings()
    lib = SkillLibrary.from_dir(settings.skills_dir)
    hits = lib.search(query, k=k)
    if not hits:
        console.print("No matches (is the skill library fetched?).")
        return
    table = Table(title=f"Skill search: {query}")
    for col in ("skill", "heading", "preview"):
        table.add_column(col)
    for h in hits:
        table.add_row(h["skill"], h["heading"], h["preview"])
    console.print(table)


@plugins_app.command("list")
def plugins_list() -> None:
    """List discovered extension plugins and what each contributes."""

    from saarthi2.plugins import discover

    settings = get_settings()
    bundle = discover(plugins_dir=settings.plugins_dir)
    if not bundle.details:
        console.print(
            f"No plugins found. Drop a *.py module (SAARTHI2_FUNCTIONS/ADAPTERS/STEPS) "
            f"into {settings.plugins_dir} or install a 'saarthi2.plugins' entry point."
        )
        return
    table = Table(title="Plugins")
    for col in ("name", "source", "functions", "adapters", "steps"):
        table.add_column(col)
    for entry in bundle.details:
        table.add_row(
            entry["name"],
            entry["source"],
            str(entry["functions"]),
            str(entry["adapters"]),
            str(entry["steps"]),
        )
    console.print(table)


if __name__ == "__main__":
    app()

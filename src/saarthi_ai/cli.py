from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from saarthi_ai.assessments.planner import build_assessment_plan
from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.assessments.scope import (
    ScopeValidationError,
    validate_assessment,
)
from saarthi_ai.config import get_settings
from saarthi_ai.execution.http_collector import HttpCollectionError
from saarthi_ai.execution.http_models import HttpMetadataCollectionRequest
from saarthi_ai.llm import (
    OllamaUnavailableError,
    SaarthiOllamaClient,
)
from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    ExecutionNotFoundError,
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.dns_workflow import (
    run_tracked_dns_collection,
)
from saarthi_ai.persistence.http_workflow import (
    run_tracked_http_collection,
)
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.projects import (
    ProjectAlreadyExistsError,
    ProjectCreate,
    ProjectError,
    ProjectNotFoundError,
    ProjectRepository,
)
from saarthi_ai.persistence.subdomain_workflow import (
    run_tracked_subdomain_collection,
)
from saarthi_ai.recon.dns_collector import DnsCollectionError
from saarthi_ai.recon.subdomain_collector import SubdomainCollectionError
from saarthi_ai.schemas import Message

app = typer.Typer(
    no_args_is_help=True,
    help="Saarthi OPS — local-first authorized VAPT assistant.",
)

project_app = typer.Typer(
    no_args_is_help=True,
    help="Manage pentest projects.",
)

execution_app = typer.Typer(
    no_args_is_help=True,
    help="Inspect assessment executions.",
)

evidence_app = typer.Typer(
    no_args_is_help=True,
    help="Inspect collected assessment evidence.",
)

recon_app = typer.Typer(
    no_args_is_help=True,
    help="Run authorized reconnaissance workflows.",
)

app.add_typer(project_app, name="project")
app.add_typer(execution_app, name="execution")
app.add_typer(evidence_app, name="evidence")
app.add_typer(recon_app, name="recon")

console = Console()


def get_database() -> SaarthiDatabase:
    """Return an initialized local execution database."""

    database = SaarthiDatabase(DEFAULT_DATABASE_PATH)
    database.initialize()
    return database


def get_project_repository() -> ProjectRepository:
    """Return an initialized local project repository."""

    repository = ProjectRepository(DEFAULT_DATABASE_PATH)
    repository.initialize()
    return repository


def print_execution_table(executions: list[object]) -> None:
    """Render execution records as a terminal table."""

    table = Table(title="Saarthi Executions")
    table.add_column("Execution ID")
    table.add_column("Assessment")
    table.add_column("State")
    table.add_column("Targets")
    table.add_column("Created")

    for execution in executions:
        table.add_row(
            execution.execution_id,
            execution.assessment_name,
            execution.state.value,
            ", ".join(execution.targets),
            execution.created_at.isoformat(timespec="seconds"),
        )

    console.print(table)


@app.command()
def doctor() -> None:
    """Check the local Ollama service and configured model."""

    async def run() -> None:
        client = SaarthiOllamaClient(get_settings())

        try:
            health_status = await client.health()
        except OllamaUnavailableError as exc:
            console.print(f"[bold red]Failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

        console.print("[bold green]Ollama is reachable.[/bold green]")
        console.print(health_status)

        if not health_status["model_available"]:
            console.print(
                "[yellow]Configured model is missing. Run:[/yellow] "
                f"ollama pull "
                f"{health_status['configured_model']}"
            )
            raise typer.Exit(code=1)

    asyncio.run(run())


@app.command()
def chat(
    think: Annotated[
        bool,
        typer.Option(
            help="Enable model thinking output.",
        ),
    ] = False,
) -> None:
    """Start a local terminal chat with Saarthi."""

    async def run() -> None:
        client = SaarthiOllamaClient(get_settings())
        history: list[Message] = []

        console.print("[bold]Saarthi local chat[/bold] — type /exit to quit.")

        while True:
            user_input = console.input("\n[bold cyan]You>[/bold cyan] ").strip()

            if user_input.lower() in {"/exit", "/quit"}:
                break

            if not user_input:
                continue

            history.append(
                Message(
                    role="user",
                    content=user_input,
                )
            )

            try:
                content, thinking = await client.chat(
                    history,
                    think=think,
                )
            except OllamaUnavailableError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                continue

            if think and thinking:
                console.print("\n[dim]Model thinking received (not stored in chat history).[/dim]")

            console.print("\n[bold green]Saarthi>[/bold green]")
            console.print(Markdown(content))

            history.append(
                Message(
                    role="assistant",
                    content=content,
                )
            )

    asyncio.run(run())


@project_app.command("create")
def project_create(
    name: Annotated[
        str,
        typer.Argument(
            help="Project name.",
        ),
    ],
    description: Annotated[
        str | None,
        typer.Option(
            "--description",
            "-d",
            help="Optional project description.",
        ),
    ] = None,
    owner: Annotated[
        str | None,
        typer.Option(
            "--owner",
            help="Optional project owner.",
        ),
    ] = None,
) -> None:
    """Create a persistent pentest project."""

    repository = get_project_repository()

    try:
        project = repository.create_project(
            ProjectCreate(
                name=name,
                description=description,
                owner=owner,
            )
        )
    except ProjectAlreadyExistsError as exc:
        console.print(f"[bold red]Failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print("[bold green]Project created.[/bold green]")
    console.print(f"Name: {project.name}")
    console.print(f"Slug: {project.slug}")
    console.print(f"ID: {project.project_id}")


@project_app.command("list")
def project_list(
    limit: Annotated[
        int,
        typer.Option(
            min=1,
            max=1_000,
            help="Maximum projects to display.",
        ),
    ] = 100,
) -> None:
    """List local pentest projects."""

    repository = get_project_repository()
    projects = repository.list_projects(limit=limit)

    table = Table(title="Saarthi Projects")
    table.add_column("Slug")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Created")

    for project in projects:
        table.add_row(
            project.slug,
            project.name,
            project.owner or "-",
            project.created_at.isoformat(timespec="seconds"),
        )

    console.print(table)


@project_app.command("show")
def project_show(
    project: Annotated[
        str,
        typer.Argument(
            help="Project slug or project ID.",
        ),
    ],
) -> None:
    """Show one project and its executions."""

    repository = get_project_repository()

    try:
        record = repository.get_project(project)
        executions = repository.list_project_executions(project)
    except ProjectNotFoundError as exc:
        console.print(f"[bold red]Failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]{record.name}[/bold]")
    console.print(f"Slug: {record.slug}")
    console.print(f"ID: {record.project_id}")
    console.print(f"Owner: {record.owner or '-'}")
    console.print(f"Description: {record.description or '-'}")
    console.print(f"Executions: {len(executions)}")

    if executions:
        print_execution_table(executions)


@app.command()
def assess(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Authorized Web or API URL.",
        ),
    ],
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            "-p",
            help="Existing project slug or project ID.",
        ),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            help="Assessment name.",
        ),
    ] = None,
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirm written authorization.",
        ),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            "--active",
            help="Allow active testing.",
        ),
    ] = False,
    intrusive: Annotated[
        bool,
        typer.Option(
            "--intrusive",
            help="Allow intrusive testing.",
        ),
    ] = False,
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            min=1,
            max=100,
            help="Maximum requests per second.",
        ),
    ] = 2,
) -> None:
    """Create a scoped Web assessment and execution plan."""

    if not authorized:
        console.print(
            "[bold red]Authorization required.[/bold red] "
            "Use --authorized only when written permission exists."
        )
        raise typer.Exit(code=1)

    if intrusive and not active:
        console.print(
            "[bold red]Invalid testing level.[/bold red] --intrusive also requires --active."
        )
        raise typer.Exit(code=1)

    repository = get_project_repository()
    project_record = None

    if project is not None:
        try:
            project_record = repository.get_project(project)
        except ProjectNotFoundError as exc:
            console.print(f"[bold red]Failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    assessment_name = name or (
        f"{project_record.name} Web Assessment" if project_record else "Authorized Web Assessment"
    )

    request = AssessmentRequest(
        name=assessment_name,
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value=url,
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=active,
        allow_intrusive_testing=intrusive,
        rate_limit_per_second=rate_limit,
    )

    try:
        validated = validate_assessment(request)
        plan = build_assessment_plan(
            request,
            validated,
        )
    except ScopeValidationError as exc:
        console.print(f"[bold red]Scope validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    database = get_database()

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name=plan.assessment_name,
            plan_version=plan.plan_version,
            asset_types=[asset_type.value for asset_type in plan.asset_types],
            targets=[target.normalized_value for target in validated.targets],
            authorization_confirmed=True,
            active_testing_allowed=active,
            intrusive_testing_allowed=intrusive,
            metadata={
                "project_id": (project_record.project_id if project_record else None),
                "project_slug": (project_record.slug if project_record else None),
                "rate_limit_per_second": rate_limit,
                "plan_step_count": len(plan.steps),
            },
        )
    )

    execution = database.transition_execution(
        execution.execution_id,
        ExecutionState.VALIDATED,
        actor="cli",
        reason="CLI assessment scope validation passed.",
    )

    execution = database.transition_execution(
        execution.execution_id,
        ExecutionState.PLANNED,
        actor="cli",
        reason="Structured Web assessment plan generated.",
    )

    table = Table(title="Assessment Plan")
    table.add_column("Step")
    table.add_column("Level")
    table.add_column("Status")
    table.add_column("Title")

    for step in plan.steps:
        status_text = "[green]enabled[/green]" if step.enabled else "[yellow]blocked[/yellow]"

        table.add_row(
            step.id,
            step.execution_level.value,
            status_text,
            step.title,
        )

    console.print("[bold green]Assessment created.[/bold green]")
    console.print(f"Execution ID: {execution.execution_id}")
    console.print(f"State: {execution.state.value}")
    console.print(f"Target: {url}")

    if project_record:
        console.print(f"Project: {project_record.slug}")

    console.print(table)


@execution_app.command("list")
def execution_list(
    state: Annotated[
        ExecutionState | None,
        typer.Option(
            "--state",
            help="Filter by execution state.",
        ),
    ] = None,
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            "-p",
            help="Filter by project slug or ID.",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option(
            min=1,
            max=1_000,
            help="Maximum executions to display.",
        ),
    ] = 100,
) -> None:
    """List persistent assessment executions."""

    database = get_database()

    if project is None:
        executions = database.list_executions(
            state=state,
            limit=limit,
        )
    else:
        repository = get_project_repository()

        try:
            executions = repository.list_project_executions(project)
        except ProjectError as exc:
            console.print(f"[bold red]Failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

        if state is not None:
            executions = [execution for execution in executions if execution.state is state]

        executions = executions[:limit]

    print_execution_table(executions)


@execution_app.command("show")
def execution_show(
    execution_id: Annotated[
        str,
        typer.Argument(
            help="Execution identifier.",
        ),
    ],
) -> None:
    """Show one execution and its audit history."""

    database = get_database()

    try:
        execution = database.get_execution(execution_id)
        events = database.list_audit_events(execution_id)
    except ExecutionNotFoundError as exc:
        console.print(f"[bold red]Failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]{execution.assessment_name}[/bold]")
    console.print(f"Execution ID: {execution.execution_id}")
    console.print(f"State: {execution.state.value}")
    console.print(f"Targets: {', '.join(execution.targets)}")
    console.print(f"Active allowed: {execution.active_testing_allowed}")
    console.print(f"Intrusive allowed: {execution.intrusive_testing_allowed}")

    table = Table(title="Audit History")
    table.add_column("Time")
    table.add_column("Actor")
    table.add_column("Event")
    table.add_column("Message")

    for event in events:
        table.add_row(
            event.created_at.isoformat(timespec="seconds"),
            event.actor,
            event.event_type.value,
            event.message,
        )

    console.print(table)


@evidence_app.command("list")
def evidence_list(
    execution_id: Annotated[
        str,
        typer.Argument(
            help="Execution identifier.",
        ),
    ],
    evidence_type: Annotated[
        EvidenceType | None,
        typer.Option(
            "--type",
            help="Filter by evidence type.",
        ),
    ] = None,
) -> None:
    """List evidence registered for an execution."""

    database = get_database()

    try:
        evidence_items = database.list_evidence(
            execution_id,
            evidence_type=evidence_type,
        )
    except ExecutionNotFoundError as exc:
        console.print(f"[bold red]Failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title=f"Evidence — {execution_id}")
    table.add_column("Evidence ID")
    table.add_column("Type")
    table.add_column("Step")
    table.add_column("Tool")
    table.add_column("Path")

    for evidence in evidence_items:
        table.add_row(
            evidence.evidence_id,
            evidence.evidence_type.value,
            evidence.step_id or "-",
            evidence.tool_name or "-",
            evidence.path,
        )

    console.print(table)


@execution_app.command("run-http")
def execution_run_http(
    execution_id: Annotated[
        str,
        typer.Argument(
            help="Planned execution identifier.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=("Confirm approval to send the controlled HTTP metadata request."),
        ),
    ] = False,
) -> None:
    """Run tracked HTTP metadata collection for an execution."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    try:
        execution = database.get_execution(execution_id)
    except ExecutionNotFoundError as exc:
        console.print(f"[bold red]Failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if len(execution.targets) != 1:
        console.print(
            "[bold red]Unsupported execution.[/bold red] "
            "The initial HTTP workflow requires exactly one target."
        )
        raise typer.Exit(code=1)

    if len(execution.asset_types) != 1:
        console.print(
            "[bold red]Unsupported execution.[/bold red] "
            "The initial HTTP workflow requires one asset type."
        )
        raise typer.Exit(code=1)

    try:
        asset_type = AssetType(execution.asset_types[0])
    except ValueError as exc:
        console.print(f"[bold red]Unsupported asset type:[/bold red] {execution.asset_types[0]}")
        raise typer.Exit(code=1) from exc

    if asset_type not in {AssetType.WEB, AssetType.API}:
        console.print(
            "[bold red]Unsupported asset type.[/bold red] "
            "HTTP collection currently supports Web and API targets."
        )
        raise typer.Exit(code=1)

    target = execution.targets[0]

    raw_rate_limit = execution.metadata.get(
        "rate_limit_per_second",
        2,
    )

    try:
        rate_limit = int(raw_rate_limit)
    except (TypeError, ValueError):
        rate_limit = 2

    rate_limit = max(1, min(rate_limit, 100))

    assessment = AssessmentRequest(
        name=execution.assessment_name,
        targets=[
            AssessmentTarget(
                asset_type=asset_type,
                value=target,
            )
        ],
        authorization_confirmed=(execution.authorization_confirmed),
        allow_active_testing=(execution.active_testing_allowed),
        allow_intrusive_testing=(execution.intrusive_testing_allowed),
        rate_limit_per_second=rate_limit,
    )

    request = HttpMetadataCollectionRequest(
        assessment=assessment,
        target=target,
    )

    async def run() -> None:
        console.print("[bold cyan]Starting controlled HTTP collection...[/bold cyan]")
        console.print(f"Execution: {execution_id}")
        console.print(f"Target: {target}")

        try:
            result = await run_tracked_http_collection(
                database,
                execution_id,
                request,
                actor="cli-http-collector",
            )
        except (
            HttpCollectionError,
            InvalidStateTransitionError,
        ) as exc:
            console.print(f"[bold red]Collection failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

        console.print("\n[bold green]HTTP collection completed.[/bold green]")
        console.print(f"Execution state: {result.execution.state.value}")
        console.print(f"HTTP status: {result.collection.status_code}")
        console.print(f"Final URL: {result.collection.final_url}")
        console.print(f"Captured bytes: {result.collection.body_bytes_captured}")
        console.print(f"Body truncated: {result.collection.body_truncated}")
        console.print(f"Evidence ID: {result.evidence.evidence_id}")
        console.print(f"Evidence path: {result.evidence.path}")

    asyncio.run(run())


@recon_app.command("dns")
def recon_dns(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Planned execution identifier.",
        ),
    ],
    domain: Annotated[
        str,
        typer.Option(
            "--domain",
            help="Authorized domain included in the execution scope.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm approval to perform controlled DNS queries.",
        ),
    ] = False,
) -> None:
    """Collect scoped DNS records and register JSON evidence."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    console.print("[bold]Starting controlled DNS collection...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Domain: {domain}")

    try:
        result = run_tracked_dns_collection(
            database,
            execution_id,
            domain,
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        DnsCollectionError,
    ) as exc:
        console.print(f"[bold red]DNS collection failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    total_records = sum(len(items) for items in result.collection.records.values())

    console.print()
    console.print("[bold green]DNS collection completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Domain: {result.collection.domain}")
    console.print(f"Nameserver: {result.collection.nameserver or '-'}")
    console.print(f"Records captured: {total_records}")

    for record_type, records in result.collection.records.items():
        console.print(f"{record_type}: {len(records)}")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")


@recon_app.command("subdomains")
def recon_subdomains(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Planned execution identifier.",
        ),
    ],
    domain: Annotated[
        str,
        typer.Option(
            "--domain",
            help="Authorized parent domain included in execution scope.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm approval to perform passive subdomain discovery.",
        ),
    ] = False,
) -> None:
    """Collect passive subdomain candidates and register JSON evidence."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    console.print("[bold]Starting passive subdomain collection...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Domain: {domain}")

    try:
        result = run_tracked_subdomain_collection(
            database,
            execution_id,
            domain,
            actor="cli-subdomain-collector",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        SubdomainCollectionError,
    ) as exc:
        console.print(f"[bold red]Subdomain collection failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]Subdomain collection completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Domain: {result.collection.domain}")
    console.print(f"Source: {result.collection.source}")
    console.print(f"Candidates discovered: {len(result.collection.candidates)}")
    console.print(f"Raw CT entries: {result.collection.raw_entry_count}")
    console.print(f"Rejected names: {len(result.collection.rejected_names)}")

    for candidate in result.collection.candidates[:20]:
        wildcard_marker = " (wildcard certificate)" if candidate.wildcard_source else ""
        console.print(f"- {candidate.hostname}{wildcard_marker}")

    if len(result.collection.candidates) > 20:
        remaining = len(result.collection.candidates) - 20
        console.print(f"... and {remaining} more")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from saarthi_ai.analysis import (
    AnalysisError,
    analyze_run,
    gather_run_digest,
)
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
from saarthi_ai.attack_hypothesis import (
    AttackHypothesisGenerationRequest,
)
from saarthi_ai.automation.auto_validation import (
    AutoValidationError,
    run_automatic_validation,
)
from saarthi_ai.automation.chain_config import (
    ChainConfigError,
    build_auto_validation_config_from_chain,
)
from saarthi_ai.blind_validation.models import (
    BlindValidationRequest,
    CallbackProtocol,
)
from saarthi_ai.checks.models import DirectCheckRequest
from saarthi_ai.config import get_settings
from saarthi_ai.confirmation.models import ConfirmationCandidate
from saarthi_ai.controlled_validation.executor import (
    MAX_REQUEST_BODY_BYTES,
    ControlledValidationExecutionRequest,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.controlled_validation.validator_registry import (
    list_phase6_validators,
    summarize_phase6_validator_modules,
)
from saarthi_ai.execution.http_collector import HttpCollectionError
from saarthi_ai.execution.http_models import HttpMetadataCollectionRequest
from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiExecutionRequest,
    build_nuclei_invocation_preview,
)
from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapMethod,
    SqlmapPostContentType,
    SqlmapPreviewRequest,
)
from saarthi_ai.execution.tool_runner import (
    ToolOutputEvent,
    ToolRunnerError,
    run_tool,
)
from saarthi_ai.llm import (
    OllamaUnavailableError,
    SaarthiOllamaClient,
)
from saarthi_ai.orchestration.models import OrchestrationStatus
from saarthi_ai.persistence.attack_hypothesis_workflow import (
    AttackHypothesisWorkflowError,
    create_tracked_attack_hypotheses,
)
from saarthi_ai.persistence.blind_validation_workflow import (
    BlindValidationWorkflowError,
    run_tracked_blind_validation,
)
from saarthi_ai.persistence.confirmation_workflow import (
    ConfirmationWorkflowError,
    run_confirmation_workflow,
)
from saarthi_ai.persistence.controlled_validation_observation_workflow import (
    ControlledValidationObservationWorkflowError,
    run_tracked_controlled_validation_observation,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    ControlledValidationWorkflowError,
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.crawl_workflow import (
    run_tracked_crawl,
)
from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    ExecutionNotFoundError,
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.direct_check_workflow import (
    DirectCheckWorkflowError,
    run_tracked_direct_check,
)
from saarthi_ai.persistence.dns_workflow import (
    run_tracked_dns_collection,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    run_tracked_http_intelligence,
)
from saarthi_ai.persistence.http_workflow import (
    run_tracked_http_collection,
)
from saarthi_ai.persistence.hypothesis_routing_workflow import (
    HypothesisRoutingRequest,
    HypothesisRoutingWorkflowError,
    route_hypothesis_to_controlled_validation,
)
from saarthi_ai.persistence.javascript_workflow import (
    run_tracked_javascript_intelligence,
)
from saarthi_ai.persistence.models import (
    EvidenceType,
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.nuclei_execution_verification import (
    NucleiExecutionVerificationRequest,
)
from saarthi_ai.persistence.nuclei_execution_workflow import (
    NucleiExecutionWorkflowError,
    run_tracked_nuclei_execution,
)
from saarthi_ai.persistence.nuclei_preparation_workflow import (
    NucleiPreparationWorkflowError,
    create_tracked_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preview_workflow import (
    NucleiPreviewWorkflowError,
    create_tracked_nuclei_preview,
)
from saarthi_ai.persistence.orchestration_workflow import (
    OrchestrationWorkflowError,
    create_orchestration,
    run_assessment_pipeline,
)
from saarthi_ai.persistence.phase6_chain_workflow import (
    run_phase6_safe_chain,
)
from saarthi_ai.persistence.projects import (
    ProjectAlreadyExistsError,
    ProjectCreate,
    ProjectError,
    ProjectNotFoundError,
    ProjectRepository,
)
from saarthi_ai.persistence.sqlmap_handoff_workflow import (
    SqlmapHandoffWorkflowError,
    analyze_imported_sqlmap_result,
    finalize_sqlmap_external_result,
    import_sqlmap_external_result,
)
from saarthi_ai.persistence.sqlmap_preview_workflow import (
    SqlmapPreviewWorkflowError,
    create_tracked_sqlmap_preview,
)
from saarthi_ai.persistence.subdomain_workflow import (
    run_tracked_subdomain_collection,
)
from saarthi_ai.persistence.upload_validation_workflow import (
    UploadValidationKind,
    UploadValidationWorkflowError,
    create_upload_validation_plan,
    import_upload_validation_result,
)
from saarthi_ai.recon.crawl_collector import CrawlCollectionError
from saarthi_ai.recon.dns_collector import DnsCollectionError
from saarthi_ai.recon.http_intelligence_collector import (
    HttpIntelligenceCollectionError,
)
from saarthi_ai.recon.javascript_collector import (
    JavaScriptCollectionError,
)
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

check_app = typer.Typer(
    no_args_is_help=True,
    help="Run authorized policy-controlled vulnerability checks.",
)

blind_app = typer.Typer(
    no_args_is_help=True,
    help="Manage bounded Phase 4B blind-validation correlations.",
)

confirm_app = typer.Typer(
    no_args_is_help=True,
    help="Run deterministic Phase 4D evidence confirmation.",
)

controlled_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Generate hypotheses and manage bounded Phase 6 "
        "controlled-validation workflows."
    ),
)

workflow_app = typer.Typer(
    no_args_is_help=True,
    help="Run authorized multi-phase assessment workflows.",
)

app.add_typer(project_app, name="project")
app.add_typer(execution_app, name="execution")
app.add_typer(evidence_app, name="evidence")
app.add_typer(recon_app, name="recon")
app.add_typer(check_app, name="check")
app.add_typer(blind_app, name="blind")
app.add_typer(confirm_app, name="confirm")
app.add_typer(controlled_app, name="controlled")
app.add_typer(workflow_app, name="workflow")

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


@app.command()
def analyze(
    orchestration: Annotated[
        str | None,
        typer.Option(
            "--orchestration",
            help=(
                "Orchestration id to analyze. Defaults to the most recent run."
            ),
        ),
    ] = None,
) -> None:
    """AI-triage an assessment run's evidence with the local model."""

    database = get_database()

    try:
        digest = gather_run_digest(
            database,
            orchestration_id=orchestration,
        )
    except AnalysisError as exc:
        console.print(f"[bold red]Cannot analyze:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print("[bold]AI analysis of assessment run[/bold]")
    console.print(f"Target       : {digest.target}")
    console.print(f"Orchestration: {digest.orchestration_id}")
    console.print(
        f"Findings     : {len(digest.findings)} | "
        f"phases: {len(digest.phases)} | state: {digest.parent_state}"
    )
    console.print("[dim]Asking the local model to triage the evidence…[/dim]")

    client = SaarthiOllamaClient(get_settings())

    try:
        content = asyncio.run(analyze_run(client, digest))
    except OllamaUnavailableError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(Markdown(content))


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


@recon_app.command("wayback")
def recon_wayback(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Authorized absolute http(s) URL to archive.",
        ),
    ],
    backends: Annotated[
        str,
        typer.Option(
            "--backends",
            help="Comma-separated archive backends: ia,is,ph,ga,ip.",
        ),
    ] = "ia,is",
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "REQUIRED: confirm you authorize PUBLISHING this target to "
                "public web archives (outward-facing, irreversible)."
            ),
        ),
    ] = False,
) -> None:
    """Archive an authorized target to public web archives, with an AI note.

    wayback PUBLISHES the target's pages to third-party archives (Internet
    Archive, archive.today, IPFS, ...). It is opt-in and requires --approved.
    """

    import asyncio
    import hashlib
    import json
    from pathlib import Path

    from saarthi_ai.analysis import comment_on_live_output
    from saarthi_ai.execution.wayback_adapter import (
        WaybackError,
        run_wayback_archive,
    )
    from saarthi_ai.llm.ollama_client import (
        OllamaUnavailableError,
        SaarthiOllamaClient,
    )

    console.print(
        "[bold yellow]WARNING:[/bold yellow] wayback PUBLISHES the target to "
        "public archives (Internet Archive, archive.today, IPFS, ...). This "
        "is outward-facing and effectively irreversible."
    )
    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] Re-run with "
            "--approved to confirm external publishing is authorized."
        )
        raise typer.Exit(code=1)

    selected = tuple(part.strip() for part in backends.split(",") if part.strip())
    console.print(
        f"[bold]Archiving {url} via {', '.join(selected) or '(none)'}...[/bold]"
    )

    def on_output(event) -> None:
        console.print(
            f"[dim][{event.tool_name}:{event.stream}] {event.line}[/dim]"
        )

    try:
        result = run_wayback_archive(
            url,
            backends=selected,
            authorized=True,
            on_output=on_output,
        )
    except WaybackError as exc:
        console.print(f"[bold red]wayback failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]Archive run complete.[/bold green]")
    console.print(f"Exit code: {result.tool_result.exit_code}")
    console.print(f"Archived URLs ({len(result.archived_urls)}):")
    for archived in result.archived_urls:
        console.print(f"  {archived}")

    # Persist JSON evidence, mirroring the other recon tools.
    evidence_dir = Path.cwd() / "evidence" / "wayback"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(
        (url + "|" + ",".join(selected)).encode("utf-8")
    ).hexdigest()[:12]
    evidence_path = evidence_dir / f"wayback-{digest}.json"
    evidence_path.write_text(
        json.dumps(
            {
                "target_url": result.target_url,
                "backends": list(result.backends),
                "archived_urls": list(result.archived_urls),
                "exit_code": result.tool_result.exit_code,
                "timed_out": result.tool_result.timed_out,
                "stdout_sha256": result.tool_result.stdout_sha256,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    console.print(f"Evidence path: {evidence_path}")

    # AI note on the result, using the same local model as the other tools.
    lines = [
        f"[wayback:stdout] {line}"
        for line in (result.tool_result.stdout or "").splitlines()
        if line.strip()
    ][:40]
    if not lines:
        return
    try:
        client = SaarthiOllamaClient(get_settings())
        note = asyncio.run(
            comment_on_live_output(client, "wayback", url, lines)
        )
        console.print()
        console.print(f"[bold]AI:[/bold] {note}")
    except OllamaUnavailableError as exc:
        console.print(f"[dim]AI note unavailable: {exc}[/dim]")
    except Exception as exc:  # defensive: never fail the run on the AI note
        console.print(f"[dim]AI note failed: {exc}[/dim]")


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


@recon_app.command("live-hosts")
def recon_live_hosts(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Planned execution identifier.",
        ),
    ],
    source_evidence: Annotated[
        Path,
        typer.Option(
            "--source-evidence",
            help="Phase 3B subdomain evidence JSON file.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm approval to perform low-risk HTTP probing.",
        ),
    ] = False,
) -> None:
    """Probe scoped Phase 3B hosts and register HTTP intelligence evidence."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    console.print("[bold]Starting controlled live-host intelligence...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Source evidence: {source_evidence}")

    try:
        result = run_tracked_http_intelligence(
            database,
            execution_id,
            source_evidence,
            actor="cli-http-intelligence-collector",
            evidence_root=Path.cwd() / "evidence" / "http-intelligence",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        HttpIntelligenceCollectionError,
    ) as exc:
        console.print(f"[bold red]HTTP intelligence collection failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]HTTP intelligence collection completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Domain: {result.collection.domain}")
    console.print(f"Inputs probed: {result.collection.input_count}")
    console.print(f"Live services: {result.collection.live_service_count}")
    console.print(f"Malformed output lines: {result.collection.malformed_line_count}")
    console.print(f"Rejected inputs: {len(result.collection.rejected_inputs)}")
    console.print(f"Rejected results: {len(result.collection.rejected_results)}")

    for record in result.collection.records[:20]:
        status = record.status_code if record.status_code is not None else "-"
        title = record.title or "-"
        console.print(f"- [{status}] {record.url} — {title}")

    if len(result.collection.records) > 20:
        remaining = len(result.collection.records) - 20
        console.print(f"... and {remaining} more")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")


@recon_app.command("crawl")
def recon_crawl(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Planned execution identifier.",
        ),
    ],
    source_evidence: Annotated[
        Path,
        typer.Option(
            "--source-evidence",
            help="Phase 3C HTTP intelligence evidence JSON file.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm approval to perform controlled low-risk crawling.",
        ),
    ] = False,
) -> None:
    """Crawl scoped Phase 3C services and register URL intelligence evidence."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    console.print("[bold]Starting controlled URL crawling...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Source evidence: {source_evidence}")

    try:
        result = run_tracked_crawl(
            database,
            execution_id,
            source_evidence,
            actor="cli-crawl-collector",
            evidence_root=Path.cwd() / "evidence" / "crawling",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        CrawlCollectionError,
    ) as exc:
        console.print(f"[bold red]Crawl collection failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]URL crawling completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Domain: {result.collection.domain}")
    console.print(f"Input services: {result.collection.input_service_count}")
    console.print(f"Crawled services: {result.collection.crawled_service_count}")
    console.print(f"URLs discovered: {result.collection.discovered_url_count}")
    console.print(f"Forms discovered: {result.collection.form_count}")
    console.print(f"Parameters discovered: {result.collection.parameter_count}")
    console.print(f"JavaScript URLs: {result.collection.javascript_url_count}")
    console.print(f"WebSocket URLs: {result.collection.websocket_url_count}")
    console.print(f"Malformed output lines: {result.collection.malformed_line_count}")
    console.print(f"Rejected inputs: {len(result.collection.rejected_inputs)}")
    console.print(f"Rejected results: {len(result.collection.rejected_results)}")

    for record in result.collection.urls[:20]:
        status = record.status_code if record.status_code is not None else "-"
        console.print(f"- [{status}] {record.method} {record.url}")

    if len(result.collection.urls) > 20:
        remaining = len(result.collection.urls) - 20
        console.print(f"... and {remaining} more")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")


@recon_app.command("javascript-intelligence")
def recon_javascript_intelligence(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Planned execution identifier.",
        ),
    ],
    source_evidence: Annotated[
        Path,
        typer.Option(
            "--source-evidence",
            help="Phase 3D crawl evidence JSON file.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=("Confirm approval to fetch and analyze in-scope JavaScript assets."),
        ),
    ] = False,
) -> None:
    """Analyze scoped JavaScript assets and register intelligence evidence."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution and rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    console.print("[bold]Starting controlled JavaScript intelligence collection...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Source evidence: {source_evidence}")

    try:
        result = run_tracked_javascript_intelligence(
            database,
            execution_id,
            source_evidence,
            actor="cli-javascript-intelligence-collector",
            evidence_root=(Path.cwd() / "evidence" / "javascript-intelligence"),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        JavaScriptCollectionError,
    ) as exc:
        console.print(f"[bold red]JavaScript intelligence collection failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]JavaScript intelligence collection completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Domain: {result.collection.domain}")
    console.print(f"JavaScript inputs: {result.collection.input_javascript_count}")
    console.print(f"JavaScript fetched: {result.collection.fetched_javascript_count}")
    console.print(f"Failed fetches: {result.collection.failed_fetch_count}")
    console.print(f"Endpoints discovered: {result.collection.endpoint_count}")
    console.print(f"Parameters discovered: {result.collection.parameter_count}")
    console.print(f"WebSocket URLs: {result.collection.websocket_count}")
    console.print(f"Source maps: {result.collection.source_map_count}")
    console.print(f"Redacted secret candidates: {result.collection.secret_candidate_count}")
    console.print(f"Rejected inputs: {len(result.collection.rejected_inputs)}")

    displayed_assets = 0

    for asset in result.collection.assets:
        if asset.fetch.status_code is None:
            continue

        console.print(f"- [{asset.fetch.status_code}] {asset.fetch.url}")
        displayed_assets += 1

        if displayed_assets >= 20:
            break

    remaining = result.collection.fetched_javascript_count - displayed_assets

    if remaining > 0:
        console.print(f"... and {remaining} more")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")


@check_app.command("direct")
def check_direct(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized assessment execution identifier.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="In-scope HTTP or HTTPS target URL.",
        ),
    ],
    check_id: Annotated[
        str,
        typer.Option(
            "--check",
            help="Registered Phase 4A direct-check identifier.",
        ),
    ] = "security-headers",
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm approval to execute the selected direct check.",
        ),
    ] = False,
) -> None:
    """Run one authorized, policy-controlled Phase 4A direct check."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the target and selected check, then rerun with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    check_execution_settings = {
        "security-headers": {
            "active_testing": False,
            "requested_method": "GET",
            "requested_requests": 1,
        },
        "cors-configuration": {
            "active_testing": True,
            "requested_method": "GET",
            "requested_requests": 3,
        },
    }

    settings = check_execution_settings.get(
        check_id,
        {
            "active_testing": True,
            "requested_method": "GET",
            "requested_requests": 1,
        },
    )

    request = DirectCheckRequest(
        execution_id=execution_id,
        target_url=target_url,
        check_id=check_id,
        authorized=True,
        active_testing=settings["active_testing"],
        explicitly_approved=True,
        requested_method=settings["requested_method"],
        requested_requests=settings["requested_requests"],
    )

    console.print("[bold]Starting policy-controlled Phase 4A direct check...[/bold]")
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Check: {check_id}")

    try:
        result = run_tracked_direct_check(
            database,
            request,
            actor="cli-direct-check-executor",
            evidence_root=Path.cwd() / "evidence" / "direct-checks",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        DirectCheckWorkflowError,
    ) as exc:
        console.print(f"[bold red]Direct check failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print("[bold green]Direct check completed.[/bold green]")
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Check: {result.check.check_id}")
    console.print(f"Target: {result.check.target_url}")
    console.print(f"Policy decision: {result.check.policy.decision.value}")
    console.print(f"Executed: {result.check.executed}")

    check_result = result.check.result

    if check_result is not None and check_id == "security-headers":
        console.print(f"HTTP status: {check_result.status_code}")
        console.print(
            "Present security headers: "
            f"{len(check_result.present_headers)}"
        )
        console.print(
            "Missing security headers: "
            f"{len(check_result.missing_headers)}"
        )

        for header in check_result.missing_headers:
            console.print(f"- Missing: {header}")

        console.print(
            "Sensitive response headers: "
            f"{len(check_result.sensitive_headers)}"
        )

        for finding in check_result.sensitive_headers:
            reasons = ", ".join(finding.reasons)
            console.print(
                f"- Sensitive: {finding.header_name} = "
                f"{finding.redacted_value} [{reasons}]"
            )

        if check_result.error:
            console.print(f"Checker error: {check_result.error}")

    if check_result is not None and check_id == "cors-configuration":
        console.print(f"CORS probes executed: {len(check_result.probes)}")
        console.print(f"CORS findings: {len(check_result.findings)}")

        for probe in check_result.probes:
            console.print(
                f"- Probe: {probe.probe_name} "
                f"[{probe.request_method}] "
                f"status={probe.status_code} "
                f"allow-origin={probe.allow_origin or '-'} "
                f"credentials={probe.allow_credentials}"
            )

        for finding in check_result.findings:
            console.print(
                f"- [{finding.severity.upper()}] "
                f"{finding.title}: {finding.evidence}"
            )

        if check_result.error:
            console.print(f"Checker error: {check_result.error}")

    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")


@blind_app.command("create")
def blind_create(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized assessment execution identifier.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="In-scope HTTP or HTTPS target URL.",
        ),
    ],
    protocol: Annotated[
        CallbackProtocol,
        typer.Option(
            "--protocol",
            help="Planned callback protocol.",
            case_sensitive=False,
        ),
    ] = CallbackProtocol.HTTPS,
    poll_attempts: Annotated[
        int,
        typer.Option(
            "--poll-attempts",
            min=1,
            help="Bounded number of future correlation checks.",
        ),
    ] = 6,
    poll_interval: Annotated[
        int,
        typer.Option(
            "--poll-interval",
            min=1,
            help="Seconds between future correlation checks.",
        ),
    ] = 10,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm explicit approval for blind validation.",
        ),
    ] = False,
) -> None:
    """Create a Phase 4B correlation record without sending a payload."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the target and callback settings, then rerun with "
            "--approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    request = BlindValidationRequest(
        execution_id=execution_id,
        target_url=target_url,
        authorized=True,
        active_testing=True,
        explicitly_approved=True,
        callback_protocol=protocol,
        requested_poll_attempts=poll_attempts,
        requested_poll_interval_seconds=poll_interval,
    )

    console.print(
        "[bold]Creating bounded Phase 4B correlation record...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Protocol: {protocol.value}")
    console.print(f"Poll attempts: {poll_attempts}")
    console.print(f"Poll interval: {poll_interval} seconds")

    try:
        result = run_tracked_blind_validation(
            database,
            request,
            actor="cli-blind-validation-manager",
            evidence_root=(
                Path.cwd() / "evidence" / "blind-validation"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        BlindValidationWorkflowError,
    ) as exc:
        console.print(
            f"[bold red]Blind validation failed:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(
        "[bold green]Correlation record created.[/bold green]"
    )
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Status: {result.status.value}")
    console.print(f"Token ID: {result.token.token_id}")
    console.print(f"Token SHA-256: {result.token.token_hash}")
    console.print(
        "[bold yellow]One-time raw correlation token:[/bold yellow]"
    )
    console.print(result.token.token_value)
    console.print(
        "[dim]This raw token is shown once and is not persisted.[/dim]"
    )
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")
    console.print(
        "[dim]No payload was sent and no external OAST service "
        "was contacted.[/dim]"
    )


@confirm_app.command("ghauri")
def confirm_ghauri(
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Authorized absolute http(s) URL with the parameter to test.",
        ),
    ],
    parameter: Annotated[
        str,
        typer.Option(
            "--parameter",
            help="Testable parameter name to cross-check for blind SQLi.",
        ),
    ],
    technique: Annotated[
        str,
        typer.Option(
            "--technique",
            help="Blind techniques only: B, T, E, or combinations (e.g. BT).",
        ),
    ] = "BT",
    match_string: Annotated[
        str,
        typer.Option(
            "--string",
            help="Optional true-condition marker string (from a prior run).",
        ),
    ] = "",
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="REQUIRED: confirm authorization for active SQLi testing.",
        ),
    ] = False,
) -> None:
    """Cross-check a blind-SQLi finding with ghauri (non-destructive) + AI note.

    ghauri actively injects payloads, so it requires --approved. Runs blind
    techniques with identity-proof enumeration only — never a data dump.
    """

    import asyncio

    from saarthi_ai.analysis import comment_on_live_output
    from saarthi_ai.execution.ghauri_adapter import (
        GhauriError,
        run_ghauri_crosscheck,
    )
    from saarthi_ai.llm.ollama_client import (
        OllamaUnavailableError,
        SaarthiOllamaClient,
    )

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] ghauri performs "
            "active SQL-injection testing. Re-run with --approved."
        )
        raise typer.Exit(code=1)

    console.print(
        f"[bold]ghauri blind-SQLi cross-check[/bold] on parameter "
        f"'{parameter}' at {url} (technique={technique})..."
    )

    def on_output(event) -> None:
        console.print(
            f"[dim][{event.tool_name}:{event.stream}] {event.line}[/dim]"
        )

    try:
        result = run_ghauri_crosscheck(
            url,
            parameter,
            technique=technique,
            match_string=match_string or None,
            authorized=True,
            on_output=on_output,
        )
    except GhauriError as exc:
        console.print(f"[bold red]ghauri failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print()
    verdict = (
        "[bold green]INJECTABLE[/bold green]"
        if result.injectable
        else "[bold]not confirmed injectable[/bold]"
    )
    console.print(f"ghauri verdict: {verdict}")
    console.print(f"Exit code: {result.tool_result.exit_code}")

    lines = [
        f"[ghauri:stdout] {line}"
        for line in (result.tool_result.stdout or "").splitlines()
        if line.strip()
    ][:40]
    if not lines:
        return
    try:
        client = SaarthiOllamaClient(get_settings())
        note = asyncio.run(
            comment_on_live_output(client, "ghauri", url, lines)
        )
        console.print()
        console.print(f"[bold]AI:[/bold] {note}")
    except OllamaUnavailableError as exc:
        console.print(f"[dim]AI note unavailable: {exc}[/dim]")
    except Exception as exc:  # defensive: never fail on the AI note
        console.print(f"[dim]AI note failed: {exc}[/dim]")


@confirm_app.command("run")
def confirm_run(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized assessment execution identifier.",
        ),
    ],
    candidate_id: Annotated[
        str,
        typer.Option(
            "--candidate-id",
            help="Stable identifier for the candidate finding.",
        ),
    ],
    title: Annotated[
        str,
        typer.Option(
            "--title",
            help="Human-readable candidate finding title.",
        ),
    ],
    candidate_type: Annotated[
        str,
        typer.Option(
            "--candidate-type",
            help="Candidate category used by the confirmation engine.",
        ),
    ],
    expected_token_id: Annotated[
        str | None,
        typer.Option(
            "--expected-token-id",
            help=(
                "Expected Phase 4B token ID for correlated OAST "
                "confirmation."
            ),
        ),
    ] = None,
) -> None:
    """Evaluate one candidate using evidence already stored locally."""

    database = get_database()

    candidate = ConfirmationCandidate(
        candidate_id=candidate_id,
        execution_id=execution_id,
        title=title,
        candidate_type=candidate_type,
        expected_token_id=expected_token_id,
    )

    console.print(
        "[bold]Running deterministic Phase 4D confirmation...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Candidate ID: {candidate_id}")
    console.print(f"Candidate type: {candidate_type}")
    console.print(
        f"Expected token ID: {expected_token_id or '-'}"
    )

    try:
        evidence_records = database.list_evidence(execution_id)

        decision, evidence = run_confirmation_workflow(
            database,
            candidate,
            evidence_records,
            actor="cli-confirmation-engine",
            evidence_root=(
                Path.cwd() / "evidence" / "confirmation-results"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        ConfirmationWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            f"[bold red]Confirmation failed:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(
        "[bold green]Confirmation evaluation completed.[/bold green]"
    )
    console.print(f"Status: {decision.status.value.upper()}")
    console.print(f"Reason: {decision.reason}")

    if decision.supporting_evidence_ids:
        console.print("Supporting evidence:")
        for evidence_id in decision.supporting_evidence_ids:
            console.print(f"- {evidence_id}")
    else:
        console.print("Supporting evidence: none")

    if decision.rejected_evidence_ids:
        console.print("Rejecting evidence:")
        for evidence_id in decision.rejected_evidence_ids:
            console.print(f"- {evidence_id}")

    console.print(f"Confirmation evidence ID: {evidence.evidence_id}")
    console.print(f"Evidence path: {evidence.path}")
    console.print(f"Evidence SHA-256: {evidence.sha256}")
    console.print(
        "[dim]No additional security test or payload was executed.[/dim]"
    )


@controlled_app.command("hypotheses")
def controlled_hypotheses(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized execution containing Phase 1-5 evidence.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="In-scope credential-free HTTP or HTTPS target URL.",
        ),
    ],
    max_hypotheses: Annotated[
        int,
        typer.Option(
            "--max-hypotheses",
            min=1,
            max=50,
            help="Maximum deterministic candidate paths to persist.",
        ),
    ] = 20,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Confirm authorization to analyze existing redacted "
                "evidence metadata and persist Phase 6A hypotheses."
            ),
        ),
    ] = False,
) -> None:
    """Generate Phase 6A hypotheses without executing validation."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution, target, evidence scope, and output "
            "bound, then rerun with --approved."
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Payload generated: false")
        console.print("Subprocess started: false")
        raise typer.Exit(code=1)

    request = AttackHypothesisGenerationRequest(
        execution_id=execution_id,
        target_url=target_url,
        authorized=True,
        max_hypotheses=max_hypotheses,
    )

    console.print(
        "[bold]Generating evidence-driven Phase 6A attack "
        "hypotheses...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Maximum hypotheses: {max_hypotheses}")

    try:
        result = create_tracked_attack_hypotheses(
            get_database(),
            request,
            actor="cli-attack-hypothesis-engine",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "attack-hypothesis-sets"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        AttackHypothesisWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Attack-hypothesis generation failed:"
            f"[/bold red] {exc}"
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Payload generated: false")
        console.print("Subprocess started: false")
        raise typer.Exit(code=1) from exc

    hypothesis_set = result.hypothesis_set

    console.print()
    console.print(
        "[bold green]Phase 6A hypothesis set persisted.[/bold green]"
    )
    console.print(
        f"Hypotheses: {len(hypothesis_set.hypotheses)}"
    )
    console.print(
        "Evidence considered: "
        f"{len(hypothesis_set.considered_evidence_ids)}"
    )
    console.print(
        "Evidence rejected: "
        f"{len(hypothesis_set.rejected_evidence_ids)}"
    )
    console.print(
        f"Truncated: {str(hypothesis_set.truncated).lower()}"
    )

    for hypothesis in hypothesis_set.hypotheses:
        console.print()
        console.print(
            f"[bold]{hypothesis.hypothesis_id}[/bold]"
        )
        console.print(
            f"  Family: {hypothesis.family.value}"
        )
        console.print(f"  Title: {hypothesis.title}")
        console.print(
            "  Confidence: "
            f"{hypothesis.confidence.value} "
            f"({hypothesis.confidence_score})"
        )
        console.print(
            f"  Validation risk: {hypothesis.validation_risk.value}"
        )
        console.print(
            "  Validation method: "
            f"{hypothesis.validation_method.value}"
        )
        console.print(
            "  Supporting evidence: "
            + ", ".join(hypothesis.supporting_evidence_ids)
        )

    console.print()
    console.print("Executed: false")
    console.print("Network activity: false")
    console.print("Payload generated: false")
    console.print("Subprocess started: false")
    console.print(
        "Existing evidence reused: "
        f"{str(result.reused_existing_evidence).lower()}"
    )
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")
    console.print(
        "[dim]Phase 6A generated candidate paths from redacted "
        "evidence metadata only. No validation or security test "
        "was executed.[/dim]"
    )


@controlled_app.command("route-hypothesis")
def controlled_route_hypothesis(
    source_execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Execution containing the persisted Phase 6A evidence.",
        ),
    ],
    hypothesis_evidence_id: Annotated[
        str,
        typer.Option(
            "--evidence",
            help="Phase 6A attack-hypothesis-set evidence identifier.",
        ),
    ],
    hypothesis_id: Annotated[
        str,
        typer.Option(
            "--hypothesis",
            help="Low-risk hypothesis identifier selected for review.",
        ),
    ],
    requests_count: Annotated[
        int,
        typer.Option(
            "--requests",
            min=1,
            max=5,
            help="Maximum request count recorded in the Phase 6B plan.",
        ),
    ] = 1,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Record fresh approval for the integrity-checked "
                "6A to 6B handoff."
            ),
        ),
    ] = False,
) -> None:
    """Route one intact low-risk 6A hypothesis into a 6B plan."""

    if not approved:
        console.print(
            "[bold yellow]Fresh approval required.[/bold yellow] "
            "Review the source evidence, hypothesis, target, and request "
            "bound, then rerun with --approved."
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Payload sent: false")
        console.print("Subprocess started: false")
        raise typer.Exit(code=1)

    request = HypothesisRoutingRequest(
        source_execution_id=source_execution_id,
        hypothesis_evidence_id=hypothesis_evidence_id,
        hypothesis_id=hypothesis_id,
        explicitly_approved=True,
        requested_requests=requests_count,
    )

    console.print(
        "[bold]Routing integrity-checked Phase 6A hypothesis "
        "through the Phase 6B approval gate...[/bold]"
    )
    console.print(f"Source execution: {source_execution_id}")
    console.print(f"Source evidence: {hypothesis_evidence_id}")
    console.print(f"Hypothesis: {hypothesis_id}")
    console.print(f"Requested requests: {requests_count}")

    try:
        result = route_hypothesis_to_controlled_validation(
            get_database(),
            request,
            actor="cli-hypothesis-routing-workflow",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-validation-plans"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        HypothesisRoutingWorkflowError,
        ControlledValidationWorkflowError,
        OSError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Hypothesis routing failed:[/bold red] "
            f"{exc}"
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Payload sent: false")
        console.print("Subprocess started: false")
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(
        "[bold green]Phase 6B linked validation plan persisted."
        "[/bold green]"
    )
    console.print(
        "Validation execution: "
        f"{result.validation_execution.execution_id}"
    )
    console.print(
        "Validation execution state: "
        f"{result.validation_execution.state.value}"
    )
    console.print(f"Action: {result.plan.evidence.metadata['action']}")
    console.print(
        f"Policy decision: {result.plan.policy.decision.value}"
    )
    console.print(f"Risk: {result.plan.policy.risk.value}")
    console.print(
        "Existing validation execution reused: "
        f"{str(result.reused_validation_execution).lower()}"
    )
    console.print(
        f"Plan evidence ID: {result.plan.evidence.evidence_id}"
    )
    console.print(f"Plan evidence path: {result.plan.evidence.path}")
    console.print(
        f"Plan evidence SHA-256: {result.plan.evidence.sha256}"
    )
    console.print("Executed: false")
    console.print("Network activity: false")
    console.print("Payload sent: false")
    console.print("Subprocess started: false")
    console.print(
        "[dim]The source evidence was integrity-checked and a separate "
        "approval-gated execution was planned. No validation request "
        "was sent.[/dim]"
    )


@controlled_app.command("plan")
def controlled_plan(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized assessment execution identifier.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="In-scope HTTP or HTTPS target URL.",
        ),
    ],
    action: Annotated[
        ControlledValidationAction,
        typer.Option(
            "--action",
            help="Supported controlled-validation action.",
            case_sensitive=False,
        ),
    ] = ControlledValidationAction.RESPONSE_DIFFERENTIAL,
    requests_count: Annotated[
        int,
        typer.Option(
            "--requests",
            min=1,
            max=5,
            help="Maximum bounded request count recorded in the plan.",
        ),
    ] = 1,
    intrusive: Annotated[
        bool,
        typer.Option(
            "--intrusive",
            help="Confirm that intrusive testing is permitted.",
        ),
    ] = False,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Confirm explicit approval to persist this validation plan.",
        ),
    ] = False,
) -> None:
    """Persist one bounded Phase 6 plan without executing an action."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the target, action, and request bound, then rerun "
            "with --approved."
        )
        raise typer.Exit(code=1)

    database = get_database()

    request = ControlledValidationRequest(
        execution_id=execution_id,
        target_url=target_url,
        action=action,
        authorized=True,
        active_testing=True,
        intrusive_testing=intrusive,
        explicitly_approved=True,
        reversible=True,
        requested_requests=requests_count,
    )

    console.print(
        "[bold]Preparing bounded Phase 6 controlled-validation plan...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Action: {action.value}")
    console.print(f"Requested requests: {requests_count}")
    console.print(f"Intrusive permission requested: {intrusive}")

    try:
        result = create_tracked_controlled_validation_plan(
            database,
            request,
            actor="cli-controlled-validation-planner",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-validation-plans"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        ControlledValidationWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Controlled-validation planning failed:"
            f"[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print()
    console.print(
        "[bold green]Controlled-validation plan persisted.[/bold green]"
    )
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Policy decision: {result.policy.decision.value}")
    console.print(f"Risk: {result.policy.risk.value}")
    console.print(f"Reason: {result.policy.reason}")
    console.print("Executed: false")
    console.print("Network activity: false")
    console.print("Payload sent: false")
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")
    console.print(
        "[dim]This command persisted a validation plan only. "
        "No request, payload, or subprocess was executed.[/dim]"
    )


@controlled_app.command("nuclei-preview")
def controlled_nuclei_preview(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized assessment execution identifier.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="In-scope credential-free HTTP or HTTPS target URL.",
        ),
    ],
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            min=1,
            max=2,
            help="Previewed Nuclei request rate per second, capped at 2.",
        ),
    ] = 1,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency",
            min=1,
            max=2,
            help="Previewed Nuclei concurrency, capped at 2.",
        ),
    ] = 1,
    timeout_seconds: Annotated[
        int,
        typer.Option(
            "--timeout",
            min=1,
            max=10,
            help="Previewed per-request timeout in seconds, capped at 10.",
        ),
    ] = 10,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Explicitly approve persistence of this non-executed "
                "Nuclei preview."
            ),
        ),
    ] = False,
) -> None:
    """Persist one controlled Nuclei invocation preview without execution."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the execution, target, rate, concurrency, and timeout, "
            "then rerun with --approved."
        )
        console.print(
            "[dim]No Nuclei process or network request was started.[/dim]"
        )
        raise typer.Exit(code=1)

    request = NucleiDryRunRequest(
        target_url=target_url,
        authorized=True,
        active_testing=True,
        approval_granted=True,
        rate_limit_per_second=rate_limit,
        concurrency=concurrency,
        timeout_seconds=timeout_seconds,
        dry_run=True,
    )

    console.print(
        "[bold]Preparing controlled Nuclei dry-run preview...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Rate limit: {rate_limit} request(s)/second")
    console.print(f"Concurrency: {concurrency}")
    console.print(f"Timeout: {timeout_seconds} second(s)")
    console.print("Dry run: true")

    try:
        result = create_tracked_nuclei_preview(
            get_database(),
            execution_id,
            request,
            actor="cli-controlled-nuclei-preview",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-nuclei-previews"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        NucleiPreviewWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Nuclei preview failed:[/bold red] "
            f"{exc}"
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Subprocess started: false")
        raise typer.Exit(code=1) from exc

    preview = result.preview

    console.print()
    console.print(
        "[bold green]Controlled Nuclei preview persisted.[/bold green]"
    )
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Tool: {preview.tool_name}")
    console.print(f"Target: {preview.target_url}")
    console.print("Arguments:")
    console.print("  " + " ".join(preview.arguments))
    console.print(
        f"Rate limit: {preview.rate_limit_per_second} request(s)/second"
    )
    console.print(f"Concurrency: {preview.concurrency}")
    console.print(f"Timeout: {preview.timeout_seconds} second(s)")
    console.print(
        "Allowed tags: " + ", ".join(preview.allowed_tags)
    )
    console.print(
        "Excluded tags: " + ", ".join(preview.excluded_tags)
    )
    console.print("Executed: false")
    console.print("Network activity: false")
    console.print("Subprocess started: false")
    console.print(
        "Existing evidence reused: "
        f"{str(result.reused_existing_evidence).lower()}"
    )
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")
    console.print(
        "[dim]This command persisted a fixed invocation preview only. "
        "Nuclei was not started and no network request was sent.[/dim]"
    )


@controlled_app.command("nuclei-prepare")
def controlled_nuclei_prepare(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Execution containing a matching persisted Nuclei preview.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Exact in-scope URL from the persisted Nuclei preview.",
        ),
    ],
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            min=1,
            max=2,
            help="Approved Nuclei request rate per second, capped at 2.",
        ),
    ] = 1,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency",
            min=1,
            max=2,
            help="Approved Nuclei concurrency, capped at 2.",
        ),
    ] = 1,
    timeout_seconds: Annotated[
        int,
        typer.Option(
            "--timeout",
            min=1,
            max=10,
            help="Approved per-request timeout in seconds, capped at 10.",
        ),
    ] = 10,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Explicitly approve persistence of the bounded, "
                "non-executed Nuclei runner preparation."
            ),
        ),
    ] = False,
) -> None:
    """Persist a bounded Nuclei execution preparation without execution."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the matching preview, target, rate, concurrency, "
            "request timeout, 120-second process bound, and output cap, "
            "then rerun with --approved."
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Subprocess started: false")
        console.print("Runner invoked: false")
        console.print("Executable resolved: false")
        raise typer.Exit(code=1)

    preview = build_nuclei_invocation_preview(
        NucleiDryRunRequest(
            target_url=target_url,
            authorized=True,
            active_testing=True,
            approval_granted=True,
            rate_limit_per_second=rate_limit,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            dry_run=True,
        )
    )

    request = NucleiExecutionRequest(
        preview=preview,
        authorization_confirmed=True,
        active_testing_allowed=True,
        explicitly_approved=True,
    )

    console.print(
        "[bold]Preparing bounded non-executed Nuclei runner binding...[/bold]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {preview.target_url}")
    console.print(
        f"Rate limit: {preview.rate_limit_per_second} request(s)/second"
    )
    console.print(f"Concurrency: {preview.concurrency}")
    console.print(
        f"Request timeout: {preview.timeout_seconds} second(s)"
    )
    console.print("Process timeout bound: 120 second(s)")
    console.print("Output cap per stream: 1000000 byte(s)")

    try:
        result = create_tracked_nuclei_preparation(
            get_database(),
            execution_id,
            request,
            actor="cli-controlled-nuclei-preparation",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-nuclei-preparations"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        NucleiPreparationWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Nuclei preparation failed:[/bold red] "
            f"{exc}"
        )
        console.print("Executed: false")
        console.print("Network activity: false")
        console.print("Subprocess started: false")
        console.print("Runner invoked: false")
        console.print("Executable resolved: false")
        raise typer.Exit(code=1) from exc

    plan = result.plan
    binding = result.binding

    console.print()
    console.print(
        "[bold green]Controlled Nuclei preparation persisted.[/bold green]"
    )
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Tool: {plan.tool_name}")
    console.print(f"Target: {plan.target_url}")
    console.print("Arguments:")
    console.print("  " + " ".join(plan.arguments))
    console.print(
        f"Rate limit: {plan.rate_limit_per_second} request(s)/second"
    )
    console.print(f"Concurrency: {plan.concurrency}")
    console.print(
        f"Request timeout: {plan.request_timeout_seconds} second(s)"
    )
    console.print(
        "Process timeout: "
        f"{binding.profile.timeout_seconds} second(s)"
    )
    console.print(
        "Output cap per stream: "
        f"{binding.profile.max_output_bytes} byte(s)"
    )
    console.print(
        f"Maximum arguments: {binding.profile.max_arguments}"
    )
    console.print("Executed: false")
    console.print("Network activity: false")
    console.print("Subprocess started: false")
    console.print("Runner invoked: false")
    console.print("Executable resolved: false")
    console.print(
        "Existing evidence reused: "
        f"{str(result.reused_existing_evidence).lower()}"
    )
    console.print(
        f"Preview evidence ID: "
        f"{result.preview_evidence.evidence_id}"
    )
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")
    console.print(
        "[dim]This command persisted an immutable runner preparation only. "
        "The runner was not invoked, no executable was resolved, "
        "Nuclei was not started, and no network request was sent.[/dim]"
    )


@controlled_app.command("nuclei-execute")
def controlled_nuclei_execute(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Execution containing the exact persisted Nuclei preparation.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Exact in-scope URL from the persisted Nuclei preparation.",
        ),
    ],
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            min=1,
            max=2,
            help="Approved Nuclei request rate per second, capped at 2.",
        ),
    ] = 1,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency",
            min=1,
            max=2,
            help="Approved Nuclei concurrency, capped at 2.",
        ),
    ] = 1,
    timeout_seconds: Annotated[
        int,
        typer.Option(
            "--timeout",
            min=1,
            max=10,
            help="Approved per-request timeout in seconds, capped at 10.",
        ),
    ] = 10,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Confirm scope, authorization, active testing, and the exact "
                "persisted Nuclei preparation."
            ),
        ),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help=(
                "Confirm awareness that one real Nuclei subprocess and "
                "network activity will occur."
            ),
        ),
    ] = False,
) -> None:
    """Execute one exact persisted Phase 6C Nuclei preparation."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "Review the persisted preparation, scope, target, rate, "
            "concurrency, and timeout, then rerun with --approved."
        )
        console.print("Execution requested: false")
        console.print("Network activity: false")
        console.print("Subprocess started: false")
        console.print("Runner invoked: false")
        raise typer.Exit(code=1)

    if not execute:
        console.print(
            "[bold yellow]Execution confirmation required.[/bold yellow] "
            "This command starts one real Nuclei subprocess and permits "
            "bounded network activity. Rerun with --execute after review."
        )
        console.print("Execution requested: false")
        console.print("Network activity: false")
        console.print("Subprocess started: false")
        console.print("Runner invoked: false")
        raise typer.Exit(code=1)

    preview = build_nuclei_invocation_preview(
        NucleiDryRunRequest(
            target_url=target_url,
            authorized=True,
            active_testing=True,
            approval_granted=True,
            rate_limit_per_second=rate_limit,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            dry_run=True,
        )
    )

    request = NucleiExecutionVerificationRequest(
        target_url=preview.target_url,
        arguments=preview.arguments,
        authorization_confirmed=True,
        active_testing_allowed=True,
        explicitly_approved=True,
    )

    console.print(
        "[bold yellow]Phase 6C controlled execution authorized.[/bold yellow]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {preview.target_url}")
    console.print(
        f"Rate limit: {preview.rate_limit_per_second} request(s)/second"
    )
    console.print(f"Concurrency: {preview.concurrency}")
    console.print(
        f"Request timeout: {preview.timeout_seconds} second(s)"
    )
    console.print("Process timeout bound: 120 second(s)")
    console.print("Automatic retry: false")
    console.print(
        "[bold yellow]One real Nuclei subprocess and bounded network "
        "activity will now occur.[/bold yellow]"
    )

    try:
        result = run_tracked_nuclei_execution(
            get_database(),
            execution_id,
            request,
            runner=run_tool,
            actor="cli-controlled-nuclei-execution",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-nuclei-executions"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        NucleiExecutionWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Controlled Nuclei execution failed:[/bold red] "
            f"{exc}"
        )
        console.print("Execution requested: true")
        console.print("Automatic retry: false")
        console.print(
            "[dim]Inspect the execution audit trail to determine whether "
            "the runner or subprocess started before the safe failure.[/dim]"
        )
        raise typer.Exit(code=1) from exc

    execution_result = result.result

    console.print()
    console.print(
        "[bold green]Phase 6C controlled Nuclei execution completed."
        "[/bold green]"
    )
    console.print(f"Execution state: {result.execution.state.value}")
    console.print(f"Tool: {execution_result.tool_name}")
    console.print(f"Target: {execution_result.target_url}")
    console.print(f"Executable: {execution_result.executable}")
    console.print("Arguments:")
    console.print("  " + " ".join(execution_result.arguments))
    console.print(f"Exit code: {execution_result.exit_code}")
    console.print(
        f"Timed out: {str(execution_result.timed_out).lower()}"
    )
    console.print("Automatic retry: false")
    console.print("Executed: true")
    console.print("Network activity: true")
    console.print("Subprocess started: true")
    console.print("Runner invoked: true")
    console.print(
        "Preparation evidence ID: "
        f"{result.verified_preparation.evidence.evidence_id}"
    )
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print(f"Evidence path: {result.evidence.path}")
    console.print(f"Evidence SHA-256: {result.evidence.sha256}")



@controlled_app.command("sqlmap-preview")
def controlled_sqlmap_preview(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Authorized execution with intrusive testing enabled.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Approved in-scope target; query values are redacted.",
        ),
    ],
    parameter_name: Annotated[
        str,
        typer.Option(
            "--parameter",
            help="Exactly one approved parameter to test later.",
        ),
    ],
    method: Annotated[
        SqlmapMethod,
        typer.Option(
            "--method",
            help="Candidate request method: GET or POST.",
        ),
    ] = SqlmapMethod.GET,
    post_parameters: Annotated[
        str,
        typer.Option(
            "--post-parameters",
            help=(
                "Comma-separated POST parameter names only; values are "
                "never accepted or stored."
            ),
        ),
    ] = "",
    post_content_type: Annotated[
        SqlmapPostContentType | None,
        typer.Option(
            "--content-type",
            help="POST body shape: form-encoded or JSON.",
        ),
    ] = None,
    timeout_seconds: Annotated[
        int,
        typer.Option(
            "--timeout",
            min=1,
            max=10,
            help="Previewed SQLmap request timeout, capped at 10.",
        ),
    ] = 5,
) -> None:
    """Persist a redacted GET/POST SQLmap preview without execution."""

    parameter_names = tuple(
        item.strip()
        for item in post_parameters.split(",")
        if item.strip()
    )
    request = SqlmapPreviewRequest(
        target_url=target_url,
        parameter_name=parameter_name,
        method=method,
        authorized=True,
        active_testing=True,
        intrusive_testing=True,
        approval_granted=True,
        post_parameter_names=parameter_names,
        post_content_type=post_content_type,
        timeout_seconds=timeout_seconds,
        dry_run=True,
    )

    console.print(
        "[bold]6C.1 SQLmap preview activity[/bold]"
    )
    console.print("01 stored permission gate: requested")
    console.print(f"02 execution: {execution_id}")
    console.print(f"03 method: {method.value}")
    console.print(f"04 selected parameter: {parameter_name}")
    console.print("05 request values: not accepted")
    console.print("06 SQLmap process: not started")

    try:
        result = create_tracked_sqlmap_preview(
            get_database(),
            execution_id,
            request,
            actor="cli-controlled-sqlmap-preview",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "controlled-sqlmap-previews"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        SqlmapPreviewWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]SQLmap preview failed:[/bold red] "
            f"{exc}"
        )
        console.print(
            "executed=false network_activity=false "
            "subprocess_started=false"
        )
        raise typer.Exit(code=1) from exc

    preview = result.preview
    console.print("07 permission and scope gates: passed")
    console.print(
        f"08 target (redacted): {preview.target_display_url}"
    )
    console.print(
        "09 body shape: "
        + (
            preview.post_content_type.value
            if preview.post_content_type is not None
            else "none"
        )
    )
    console.print(
        "10 bounded policy: "
        f"level={preview.level} risk={preview.risk} "
        f"threads={preview.threads} retries={preview.retries} "
        f"timeout={preview.timeout_seconds} "
        f"techniques={preview.techniques}"
    )
    console.print(
        "11 redacted arguments: "
        + " ".join(preview.redacted_arguments)
    )
    console.print(
        "12 prohibited capabilities: "
        + ", ".join(preview.prohibited_capabilities)
    )
    console.print("13 evidence persisted: true")
    console.print(
        "14 existing evidence reused: "
        f"{str(result.reused_existing_evidence).lower()}"
    )
    console.print(f"15 evidence ID: {result.evidence.evidence_id}")
    console.print(f"16 evidence path: {result.evidence.path}")
    console.print(f"17 evidence SHA-256: {result.evidence.sha256}")
    console.print("18 request values stored: false")
    console.print("19 executable arguments built: false")
    console.print("20 executed: false")
    console.print("21 network activity: false")
    console.print("22 subprocess started: false")


@controlled_app.command("sqlmap-import")
def controlled_sqlmap_import(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="SQLmap handoff execution awaiting an external result.",
        ),
    ],
    result_path: Annotated[
        Path,
        typer.Option(
            "--result",
            help=(
                "Operator-supplied JSON, JSONL, log, text, or CSV result "
                "file to import locally."
            ),
        ),
    ],
) -> None:
    """Import external SQLmap evidence without launching the tool."""

    console.print("[bold]6C.1 SQLmap external-result import[/bold]")
    console.print(f"01 execution: {execution_id}")
    console.print(f"02 supplied result: {result_path}")
    console.print("03 SQLmap process launched by Saarthi: false")
    console.print("04 network activity by Saarthi: false")

    try:
        result = import_sqlmap_external_result(
            get_database(),
            execution_id,
            result_path,
            actor="cli-sqlmap-external-result-importer",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "sqlmap-external-results"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        SqlmapHandoffWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]SQLmap result import failed:[/bold red] "
            f"{exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print("05 manifest association: verified")
    console.print("06 evidence hashing: completed")
    console.print(
        "07 existing evidence reused: "
        f"{str(result.reused_existing_evidence).lower()}"
    )
    console.print(
        f"08 manifest evidence ID: "
        f"{result.manifest_evidence.evidence_id}"
    )
    console.print(
        f"09 result evidence ID: {result.result_evidence.evidence_id}"
    )
    console.print(
        f"10 result evidence path: {result.result_evidence.path}"
    )
    console.print(
        f"11 result SHA-256: {result.result_evidence.sha256}"
    )
    console.print(
        f"12 final state: {result.execution.state.value}"
    )


@controlled_app.command("sqlmap-analyze")
def controlled_sqlmap_analyze(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Completed SQLmap handoff execution to analyze offline.",
        ),
    ],
) -> None:
    """Backfill sanitized findings from imported SQLmap evidence."""

    console.print("[bold]6C.1 SQLmap offline result analysis[/bold]")
    console.print(f"01 execution: {execution_id}")
    console.print("02 network activity: false")
    console.print("03 SQLmap process launched: false")
    console.print("04 payload extraction: disabled")
    console.print("05 database-content extraction: disabled")

    try:
        result = analyze_imported_sqlmap_result(
            get_database(),
            execution_id,
            actor="cli-sqlmap-offline-result-analyzer",
        )
    except (
        ExecutionNotFoundError,
        SqlmapHandoffWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]SQLmap result analysis failed:[/bold red] "
            f"{exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print("06 evidence hash: verified")
    console.print(
        f"07 result evidence ID: {result.result_evidence.evidence_id}"
    )
    console.print(f"08 findings registered: {result.finding_count}")
    console.print(
        "09 existing findings reused: "
        f"{str(result.reused_existing_findings).lower()}"
    )


@controlled_app.command("sqlmap-finalize")
def controlled_sqlmap_finalize(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="SQLmap handoff execution awaiting an external result.",
        ),
    ],
    result_path: Annotated[
        Path,
        typer.Option(
            "--result",
            help="SQLmap result file or output directory to finalize.",
        ),
    ],
) -> None:
    """Import and analyze an existing SQLmap result in one local step."""

    console.print("[bold]6C.1 SQLmap local result finalizer[/bold]")
    console.print(f"01 execution: {execution_id}")
    console.print(f"02 supplied path: {result_path}")
    console.print("03 SQLmap process launched by Saarthi: false")
    console.print("04 network activity: false")

    try:
        result = finalize_sqlmap_external_result(
            get_database(),
            execution_id,
            result_path,
            actor="cli-sqlmap-external-result-finalizer",
            evidence_root=(
                Path.cwd()
                / "evidence"
                / "sqlmap-external-results"
            ),
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        SqlmapHandoffWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]SQLmap result finalization failed:[/bold red] "
            f"{exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print(f"05 selected result: {result.selected_result_path}")
    console.print("06 manifest association: verified")
    console.print("07 evidence hashing: completed")
    console.print(
        f"08 result evidence ID: "
        f"{result.imported.result_evidence.evidence_id}"
    )
    console.print(
        f"09 findings registered: {result.analyzed.finding_count}"
    )
    console.print(
        f"10 final state: {result.imported.execution.state.value}"
    )


@controlled_app.command("validators")
def controlled_validators(
    module_code: Annotated[
        str | None,
        typer.Option(
            "--module",
            help="Optional official module code, for example 6C.2.",
        ),
    ] = None,
) -> None:
    """Show official Phase 6C validator readiness and safety levels."""

    if module_code is None:
        console.print(
            "[bold cyan]Phase 6C Attack Validator Readiness[/bold cyan]"
        )

        for summary in summarize_phase6_validator_modules():
            console.print(
                f"{summary.module_code} — {summary.module_name}: "
                f"ready={summary.implemented}, "
                f"partial={summary.partial}, "
                f"planned={summary.planned}, "
                "authenticated="
                f"{summary.requires_authenticated_workflow}, "
                f"manual={summary.manual_only}, "
                f"total={summary.total} "
                f"[{summary.display_status}]"
            )

        console.print(
            "[dim]Use --module 6C.N to list every validator in one "
            "family.[/dim]"
        )
        return

    validators = list_phase6_validators(module_code)
    if not validators:
        console.print(
            "[bold red]Unknown validator module.[/bold red] "
            "Use one of 6C.1 through 6C.7."
        )
        raise typer.Exit(code=1)

    console.print(
        "[bold cyan]"
        f"{validators[0].module_code} — "
        f"{validators[0].module_name}"
        "[/bold cyan]"
    )

    for validator in validators:
        authentication = (
            "required"
            if validator.requires_authentication
            else "not required"
        )
        console.print(
            f"- {validator.name}: "
            f"level={validator.level.value}; "
            f"status={validator.status.value}; "
            f"authentication={authentication}; "
            f"action={validator.implementation_action or '—'}"
        )


@controlled_app.command("upload-plan")
def controlled_upload_plan(
    execution_id: Annotated[
        str,
        typer.Option("--execution", help="Created upload-validation execution."),
    ],
    target_url: Annotated[
        str,
        typer.Option("--url", help="Approved in-scope upload endpoint."),
    ],
    kind: Annotated[
        UploadValidationKind,
        typer.Option(
            "--kind",
            help="Manual validation kind: extension bypass or MIME consistency.",
        ),
    ],
    approved: Annotated[
        bool,
        typer.Option("--approved", help="Record explicit operator approval."),
    ] = False,
) -> None:
    """Create a non-executing manual file-upload validation plan."""

    console.print("[bold]6C.6 manual upload validation plan[/bold]")
    console.print(f"01 execution: {execution_id}")
    console.print(f"02 validation kind: {kind.value}")
    console.print("03 file created by Saarthi: false")
    console.print("04 file uploaded by Saarthi: false")
    console.print("05 network activity: false")
    try:
        result = create_upload_validation_plan(
            get_database(),
            execution_id,
            target_url=target_url,
            kind=kind,
            explicitly_approved=approved,
            actor="cli-upload-manual-validation-planner",
            evidence_root=Path.cwd() / "evidence" / "upload-validation-plans",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        UploadValidationWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Upload validation planning failed:[/bold red] "
            f"{exc}"
        )
        raise typer.Exit(code=1) from exc
    console.print(f"06 plan ID: {result.plan_id}")
    console.print(f"07 plan evidence ID: {result.evidence.evidence_id}")
    console.print(f"08 plan SHA-256: {result.evidence.sha256}")
    console.print(f"09 state: {result.execution.state.value}")


@controlled_app.command("upload-result-import")
def controlled_upload_result_import(
    execution_id: Annotated[
        str,
        typer.Option("--execution", help="Planned upload-validation execution."),
    ],
    result_path: Annotated[
        Path,
        typer.Option("--result", help="Structured external result JSON file."),
    ],
) -> None:
    """Import and analyze one manual upload-validation result."""

    console.print("[bold]6C.6 upload external-result import[/bold]")
    console.print(f"01 execution: {execution_id}")
    console.print(f"02 result: {result_path}")
    console.print("03 submitted file content accepted: false")
    console.print("04 network activity: false")
    try:
        result = import_upload_validation_result(
            get_database(),
            execution_id,
            result_path,
            actor="cli-upload-external-result-importer",
            evidence_root=Path.cwd() / "evidence" / "upload-external-results",
        )
    except (
        ExecutionNotFoundError,
        InvalidStateTransitionError,
        UploadValidationWorkflowError,
        ValueError,
    ) as exc:
        console.print(
            "[bold red]Upload result import failed:[/bold red] "
            f"{exc}"
        )
        raise typer.Exit(code=1) from exc
    console.print(f"05 outcome: {result.outcome.value}")
    console.print(f"06 cleanup status: {result.cleanup_status.value}")
    console.print(
        f"07 result evidence ID: {result.result_evidence.evidence_id}"
    )
    console.print(f"08 result SHA-256: {result.result_evidence.sha256}")
    console.print(f"09 state: {result.execution.state.value}")


@controlled_app.command("observe")
def controlled_observe(
    execution_id: Annotated[
        str,
        typer.Option(
            "--execution",
            help="Existing execution with a matching Phase 6B plan.",
        ),
    ],
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Approved in-scope HTTP or HTTPS target URL.",
        ),
    ],
    action: Annotated[
        ControlledValidationAction,
        typer.Option(
            "--action",
            help=(
                "Low-risk executable action: response_differential "
                "input_handling_observation, or "
                "clickjacking_header_validation, or "
                "http_parameter_surface_validation, or "
                "session_cookie_attribute_validation, or "
                "csrf_protection_surface_validation, or "
                "api_data_exposure_surface_validation, or "
                "file_upload_surface_validation, or "
                "injection_surface_validation, or "
                "browser_attack_surface_validation, or "
                "server_parser_surface_validation."
            ),
        ),
    ] = ControlledValidationAction.RESPONSE_DIFFERENTIAL,
    method: Annotated[
        str,
        typer.Option(
            "--method",
            help="Bounded HTTP method: GET, HEAD, or POST.",
        ),
    ] = "GET",
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file",
            help="Operator-supplied POST body file; never stored in evidence.",
        ),
    ] = None,
    content_type: Annotated[
        str | None,
        typer.Option(
            "--content-type",
            help="POST media type, including multipart boundary if used.",
        ),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.1,
            max=10.0,
            help="Request timeout in seconds, capped at 10.",
        ),
    ] = 8.0,
    max_response_bytes: Annotated[
        int,
        typer.Option(
            "--max-response-bytes",
            min=1,
            max=131_072,
            help="Maximum response-body bytes captured for hashing.",
        ),
    ] = 65_536,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help=(
                "Explicitly approve one active bounded HTTP observation."
            ),
        ),
    ] = False,
) -> None:
    """Execute one approved Phase 6C GET, HEAD, or baseline POST."""

    if not approved:
        console.print(
            "[bold yellow]Approval required.[/bold yellow] "
            "This command performs active network activity. Review the "
            "execution, target, action, and method, then rerun with "
            "--approved."
        )
        raise typer.Exit(code=1)

    normalized_method = method.strip().upper()

    if normalized_method not in {"GET", "HEAD", "POST"}:
        console.print(
            "[bold red]Invalid method.[/bold red] "
            "Only GET, HEAD, and POST are allowed."
        )
        raise typer.Exit(code=1)

    if action not in {
        ControlledValidationAction.RESPONSE_DIFFERENTIAL,
        ControlledValidationAction.INPUT_HANDLING_OBSERVATION,
        ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION,
        ControlledValidationAction.HTTP_PARAMETER_SURFACE_VALIDATION,
        ControlledValidationAction.SESSION_COOKIE_ATTRIBUTE_VALIDATION,
        ControlledValidationAction.CSRF_PROTECTION_SURFACE_VALIDATION,
        ControlledValidationAction.API_DATA_EXPOSURE_SURFACE_VALIDATION,
        ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION,
        ControlledValidationAction.INJECTION_SURFACE_VALIDATION,
        ControlledValidationAction.BROWSER_ATTACK_SURFACE_VALIDATION,
        ControlledValidationAction.SERVER_PARSER_SURFACE_VALIDATION,
    }:
        console.print(
            "[bold red]Unsupported executable action.[/bold red] "
            "Only registered low-risk response, input-handling, and "
            "clickjacking, parameter-surface, or session-cookie "
            "CSRF-surface, API exposure-surface, file-upload, and "
            "injection, browser, and server/parser-surface observations "
            "are allowed."
        )
        raise typer.Exit(code=1)

    if (
        action
        in {
            ControlledValidationAction.SESSION_COOKIE_ATTRIBUTE_VALIDATION,
            ControlledValidationAction.CSRF_PROTECTION_SURFACE_VALIDATION,
            ControlledValidationAction.API_DATA_EXPOSURE_SURFACE_VALIDATION,
            ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION,
            ControlledValidationAction.INJECTION_SURFACE_VALIDATION,
            ControlledValidationAction.BROWSER_ATTACK_SURFACE_VALIDATION,
            ControlledValidationAction.SERVER_PARSER_SURFACE_VALIDATION,
        }
        and normalized_method not in {"GET", "POST"}
    ):
        console.print(
            "[bold red]Invalid method.[/bold red] "
            "This validator requires exactly one GET or controlled POST."
        )
        raise typer.Exit(code=1)

    request_body: bytes | None = None
    headers: tuple[tuple[str, str], ...] = ()
    if normalized_method == "POST":
        if body_file is None or content_type is None:
            console.print(
                "[bold red]POST configuration required.[/bold red] "
                "Provide --body-file and --content-type."
            )
            raise typer.Exit(code=1)
        if body_file.is_symlink() or not body_file.is_file():
            console.print(
                "[bold red]Invalid body file.[/bold red] "
                "A regular non-symlink file is required."
            )
            raise typer.Exit(code=1)
        if not 1 <= body_file.stat().st_size <= MAX_REQUEST_BODY_BYTES:
            console.print(
                "[bold red]Invalid body size.[/bold red] "
                f"POST bodies must be between 1 and "
                f"{MAX_REQUEST_BODY_BYTES} bytes."
            )
            raise typer.Exit(code=1)
        request_body = body_file.read_bytes()
        headers = (("Content-Type", content_type),)
    elif body_file is not None or content_type is not None:
        console.print(
            "[bold red]Unexpected body options.[/bold red] "
            "--body-file and --content-type require POST."
        )
        raise typer.Exit(code=1)

    validation = ControlledValidationRequest(
        execution_id=execution_id,
        target_url=target_url,
        action=action,
        authorized=True,
        active_testing=True,
        intrusive_testing=False,
        explicitly_approved=True,
        reversible=True,
        requested_requests=1,
    )

    request = ControlledValidationExecutionRequest(
        validation=validation,
        method=normalized_method,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        follow_redirects=False,
        headers=headers,
        body=request_body,
    )

    database = get_database()

    console.print(
        "[bold yellow]Active network observation approved.[/bold yellow]"
    )
    console.print(f"Execution: {execution_id}")
    console.print(f"Target: {target_url}")
    console.print(f"Action: {action.value}")
    console.print(f"Method: {normalized_method}")
    console.print(f"Request body bytes: {len(request_body or b'')}")
    console.print("Request body stored: false")
    console.print("Request budget: 1")
    console.print("Redirects: disabled")
    console.print(f"Timeout: {timeout_seconds:g} seconds")
    console.print(
        f"Maximum response capture: {max_response_bytes} bytes"
    )

    async def run() -> None:
        try:
            result = await run_tracked_controlled_validation_observation(
                database,
                request,
                actor="cli-controlled-validation-observer",
                evidence_root=(
                    Path.cwd()
                    / "evidence"
                    / "controlled-validation-observations"
                ),
            )
        except (
            ExecutionNotFoundError,
            InvalidStateTransitionError,
            ControlledValidationObservationWorkflowError,
            ValueError,
        ) as exc:
            console.print(
                "[bold red]Controlled-validation observation failed:"
                f"[/bold red] {exc}"
            )
            console.print("[yellow]Automatic retry: disabled.[/yellow]")
            console.print(
                "[dim]If this execution is now in the failed terminal "
                "state, create and approve a new execution before "
                "attempting another observation.[/dim]"
            )
            raise typer.Exit(code=1) from exc

        observation = result.observation

        console.print()
        console.print(
            "[bold green]Controlled-validation observation "
            "completed.[/bold green]"
        )
        console.print(
            f"Execution state: {result.execution.state.value}"
        )
        console.print(
            f"Policy decision: {observation.policy.decision.value}"
        )
        console.print(f"Method: {observation.method}")
        console.print(
            f"Request attempted: "
            f"{str(observation.request_attempted).lower()}"
        )
        console.print(
            f"Response received: "
            f"{str(observation.response_received).lower()}"
        )
        console.print(f"HTTP status: {observation.status_code}")
        console.print(f"Final URL: {observation.final_url or '-'}")
        console.print(
            f"Captured bytes: {observation.body_bytes_captured}"
        )
        console.print(
            f"Body truncated: "
            f"{str(observation.body_truncated).lower()}"
        )
        console.print(
            f"Body SHA-256: {observation.body_sha256 or '-'}"
        )
        console.print(f"Evidence ID: {result.evidence.evidence_id}")
        console.print(f"Evidence path: {result.evidence.path}")
        console.print(
            f"Evidence SHA-256: {result.evidence.sha256}"
        )
        console.print(
            "Existing evidence reused: "
            f"{str(result.reused_existing_evidence).lower()}"
        )

        if (
            analysis := getattr(
                result,
                "validator_analysis",
                None,
            )
        ) is not None:
            console.print()
            if (
                getattr(analysis, "validator_id", None)
                == "6C.6-file-upload-surface-validation"
            ):
                console.print(
                    "[bold cyan]6C.6 File Upload Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    f"Upload forms: {analysis.upload_form_count}"
                )
                console.print(
                    f"File inputs: {analysis.file_input_count}"
                )
                console.print(
                    "POST / multipart upload forms: "
                    f"{analysis.post_upload_form_count} / "
                    f"{analysis.multipart_upload_form_count}"
                )
                console.print(
                    "Restricted / unrestricted accept: "
                    f"{analysis.restricted_accept_input_count} / "
                    f"{analysis.unrestricted_accept_input_count}"
                )
                console.print("Field names discarded: true")
                console.print("Field values discarded: true")
                console.print("Form actions discarded: true")
                console.print("File uploaded: false")
                console.print("Form submitted: false")
                console.print("Request body sent: false")
                console.print("Payload generated: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.1-injection-surface-analysis"
            ):
                console.print(
                    "[bold cyan]6C.1 Injection Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    "Official injection types covered: "
                    f"{len(analysis.injection_types_covered)}"
                )
                console.print(
                    "Observed surfaces: "
                    + (
                        ", ".join(
                            f"{item.injection_type}={item.signal_count}"
                            for item in analysis.observed_surfaces
                        )
                        if analysis.observed_surfaces
                        else "none"
                    )
                )
                console.print(
                    "Query parameters / form inputs: "
                    f"{analysis.query_parameter_count} / "
                    f"{analysis.form_input_count}"
                )
                console.print("Parameter names discarded: true")
                console.print("Parameter values discarded: true")
                console.print("Response body discarded: true")
                console.print("Target unchanged: true")
                console.print("Parameters mutated: false")
                console.print("Request body sent: false")
                console.print("Payload generated: false")
                console.print("Exploit executed: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.2-browser-attack-surface-analysis"
            ):
                console.print(
                    "[bold cyan]6C.2 Browser Attack Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    "Official browser attack types covered: "
                    f"{len(analysis.attack_types_covered)}"
                )
                console.print(
                    "Observed surfaces: "
                    + (
                        ", ".join(
                            f"{item.attack_type}={item.signal_count}"
                            for item in analysis.observed_surfaces
                        )
                        if analysis.observed_surfaces
                        else "none"
                    )
                )
                console.print(
                    "Forms / controls / scripts: "
                    f"{analysis.form_count} / "
                    f"{analysis.form_control_count} / "
                    f"{analysis.script_block_count}"
                )
                console.print(
                    "postMessage handler / origin check: "
                    f"{str(analysis.postmessage_handler_observed).lower()} "
                    f"/ "
                    f"{str(analysis.postmessage_origin_check_observed).lower()}"
                )
                console.print(
                    "WebSocket / auth signal: "
                    f"{str(analysis.websocket_usage_observed).lower()} / "
                    f"{str(analysis.websocket_auth_signal_observed).lower()}"
                )
                console.print(
                    "CORS wildcard / credentials: "
                    f"{str(analysis.cors_wildcard_origin).lower()} / "
                    f"{str(analysis.cors_credentials_allowed).lower()}"
                )
                console.print("Source text discarded: true")
                console.print("Attribute values discarded: true")
                console.print("Browser launched: false")
                console.print("Script executed: false")
                console.print("Payload generated: false")
                console.print("Exploit executed: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.3-server-parser-surface-analysis"
            ):
                console.print(
                    "[bold cyan]6C.3 Server Request & Parser Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    "Official attack types covered: "
                    f"{len(analysis.attack_types_covered)}"
                )
                console.print(
                    "Observed surfaces: "
                    + (
                        ", ".join(
                            f"{item.attack_type}={item.signal_count}"
                            for item in analysis.observed_surfaces
                        )
                        if analysis.observed_surfaces
                        else "none"
                    )
                )
                console.print(
                    "Query / form / URL values: "
                    f"{analysis.query_parameter_count} / "
                    f"{analysis.form_control_count} / "
                    f"{analysis.absolute_url_value_count}"
                )
                console.print(
                    "XML / serialized / archive types: "
                    f"{str(analysis.xml_content_type_observed).lower()} / "
                    f"{str(analysis.serialized_content_type_observed).lower()} "
                    f"/ {str(analysis.archive_content_type_observed).lower()}"
                )
                console.print("Parameter values discarded: true")
                console.print("Response body discarded: true")
                console.print("Parameters mutated: false")
                console.print("Parser payload sent: false")
                console.print("Callback generated: false")
                console.print("Subprocess started: false")
                console.print("Payload generated: false")
                console.print("Exploit executed: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.7-api-data-exposure-surface-validation"
            ):
                console.print(
                    "[bold cyan]6C.7 API Data-Exposure Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    f"JSON nodes inspected: {analysis.nodes_inspected}"
                )
                console.print(
                    "Sensitive categories: "
                    + (
                        ", ".join(
                            f"{name}={count}"
                            for name, count in (
                                analysis.sensitive_category_counts
                            )
                        )
                        if analysis.sensitive_category_counts
                        else "none"
                    )
                )
                console.print("JSON keys discarded: true")
                console.print("JSON values discarded: true")
                console.print("Raw JSON stored: false")
                console.print("Request body sent: false")
                console.print("Authentication used: false")
                console.print("Payload generated: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.2-csrf-protection-surface-validation"
            ):
                console.print(
                    "[bold cyan]6C.2 CSRF Protection Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    f"POST forms: {analysis.post_form_count}"
                )
                console.print(
                    "Forms with token signal: "
                    f"{analysis.forms_with_token_signal}"
                )
                console.print(
                    "Forms without token signal: "
                    f"{analysis.forms_without_token_signal}"
                )
                console.print(
                    "Cross-origin actions: "
                    f"{analysis.cross_origin_action_count}"
                )
                console.print(
                    "Protection sources: "
                    + (
                        ", ".join(analysis.protection_sources)
                        if analysis.protection_sources
                        else "none"
                    )
                )
                console.print("Token values discarded: true")
                console.print("Form submitted: false")
                console.print("Browser launched: false")
                console.print("Request body sent: false")
                console.print("Payload generated: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.4-session-cookie-attribute-validation"
            ):
                console.print(
                    "[bold cyan]6C.4 Session Cookie Attribute "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    f"Cookies observed: {analysis.cookie_count}"
                )
                console.print(
                    "Cookies with issues: "
                    f"{analysis.cookies_with_issues}"
                )
                console.print(
                    "Issue counts: "
                    + (
                        ", ".join(
                            f"{name}={count}"
                            for name, count in analysis.issue_counts
                        )
                        if analysis.issue_counts
                        else "none"
                    )
                )
                console.print("Cookie values discarded: true")
                console.print("Raw Set-Cookie stored: false")
                console.print("Cookie replayed: false")
                console.print("Credential header sent: false")
                console.print("Payload generated: false")
            elif (
                getattr(analysis, "validator_id", None)
                == "6C.3-http-parameter-surface-validation"
            ):
                console.print(
                    "[bold cyan]6C.3 HTTP Parameter Surface "
                    "Validation[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    f"Parameters: {analysis.parameter_count}"
                )
                console.print(
                    "Duplicate names: "
                    + (
                        ", ".join(
                            analysis.duplicate_parameter_names
                        )
                        if analysis.duplicate_parameter_names
                        else "none"
                    )
                )
                console.print(
                    "Variant groups: "
                    + (
                        ", ".join(
                            analysis.variant_parameter_groups
                        )
                        if analysis.variant_parameter_groups
                        else "none"
                    )
                )
                console.print("Target unchanged: true")
                console.print("Parameters mutated: false")
                console.print("Parser attack sent: false")
                console.print("Payload generated: false")
            else:
                console.print(
                    "[bold cyan]6C.2 Clickjacking Header Validation"
                    "[/bold cyan]"
                )
                console.print(
                    "Classification: "
                    f"{analysis.classification.value}"
                )
                console.print(f"Reason: {analysis.reason}")
                console.print(
                    "Protection sources: "
                    + (
                        ", ".join(analysis.protection_sources)
                        if analysis.protection_sources
                        else "none"
                    )
                )
                console.print(
                    "CSP frame-ancestors: "
                    + (
                        " ".join(analysis.csp_frame_ancestors)
                        if analysis.csp_frame_ancestors
                        else "not observed"
                    )
                )
                console.print(
                    "X-Frame-Options: "
                    f"{analysis.x_frame_options or 'not observed'}"
                )
                console.print("Header-only analysis: true")
                console.print("Exploit page generated: false")
                console.print("Browser launched: false")
                console.print("Payload generated: false")

        if result.reused_existing_evidence:
            console.print(
                "[bold cyan]Existing persisted observation reused."
                "[/bold cyan]"
            )
            console.print(
                "[dim]No second network request was sent and no "
                "duplicate observation evidence was created.[/dim]"
            )

        console.print(
            "[dim]No request body, credential header, redirect, "
            "subprocess, batch target, or automatic retry was used.[/dim]"
        )

    asyncio.run(run())


@workflow_app.command("run")
def workflow_run(
    target_url: Annotated[
        str,
        typer.Option(
            "--url",
            help="Authorized in-scope HTTP or HTTPS target URL.",
        ),
    ],
    assessment_name: Annotated[
        str,
        typer.Option(
            "--name",
            help="Assessment name recorded in execution history.",
        ),
    ] = "Full Authorized Assessment",
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirm that testing authorization has been obtained.",
        ),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            "--active",
            help="Allow bounded active testing, including crawling and CORS.",
        ),
    ] = False,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Explicitly approve execution of the full workflow.",
        ),
    ] = False,
    rate_limit: Annotated[
        int,
        typer.Option(
            "--rate-limit",
            min=1,
            max=100,
            help="Maximum approved request rate per second.",
        ),
    ] = 2,
    intrusive: Annotated[
        bool,
        typer.Option(
            "--intrusive",
            help=(
                "Record explicit intrusive-testing permission. Required "
                "for a SQLmap preview; this does not execute SQLmap."
            ),
        ),
    ] = False,
    nuclei_preview_approved: Annotated[
        bool,
        typer.Option(
            "--approve-nuclei-preview",
            help=(
                "Approve the redacted Nuclei preview stage after 4A. "
                "Combine with --execute-nuclei for one bounded run."
            ),
        ),
    ] = False,
    nuclei_execute_approved: Annotated[
        bool,
        typer.Option(
            "--execute-nuclei",
            help=(
                "After an approved preview, execute one bounded Nuclei "
                "run using only exposure, misconfig, and tech templates."
            ),
        ),
    ] = False,
    sqlmap_preview_approved: Annotated[
        bool,
        typer.Option(
            "--approve-sqlmap-preview",
            help=(
                "Approve a redacted SQLmap preview after 4A. Requires "
                "--intrusive and a query parameter; SQLmap is not run."
            ),
        ),
    ] = False,
    auto_validate: Annotated[
        bool,
        typer.Option(
            "--auto-validate",
            help=(
                "After the chain, execute real Nuclei and SQLmap against "
                "the chain target end-to-end (no preview-only stop). "
                "SQLmap runs only when --intrusive is set."
            ),
        ),
    ] = False,
    confirmed_poc: Annotated[
        bool,
        typer.Option(
            "--confirmed-poc",
            help=(
                "With --auto-validate, add read-only SQLmap identity proof "
                "switches. Requires --intrusive. Detection evasion and "
                "OS/SQL/file switches always stay blocked."
            ),
        ),
    ] = False,
    dump_row: Annotated[
        bool,
        typer.Option(
            "--dump-row",
            help=(
                "With --confirmed-poc, permit a bounded single-row "
                "--dump (--start=1 --stop=1) as evidence of reachability."
            ),
        ),
    ] = False,
) -> None:
    """Run Phase 3A-4A, then the permission-gated safe Phase 6C chain."""

    if not authorized:
        console.print(
            "[bold yellow]Authorization confirmation required.[/bold yellow] "
            "Rerun with --authorized only after confirming written scope."
        )
        raise typer.Exit(code=1)

    if not active:
        console.print(
            "[bold yellow]Active-testing approval required.[/bold yellow] "
            "The full workflow includes crawling and bounded CORS probes."
        )
        raise typer.Exit(code=1)

    if not approved:
        console.print(
            "[bold yellow]Explicit execution approval required.[/bold yellow] "
            "Review the target and rerun with --approved."
        )
        raise typer.Exit(code=1)
    if nuclei_execute_approved and not nuclei_preview_approved:
        console.print(
            "[bold yellow]Nuclei preview approval required.[/bold yellow] "
            "Use --approve-nuclei-preview together with "
            "--execute-nuclei."
        )
        raise typer.Exit(code=1)
    if confirmed_poc and not auto_validate:
        console.print(
            "[bold yellow]--confirmed-poc requires --auto-validate.[/bold "
            "yellow] Confirmed-PoC only affects the real SQLmap run."
        )
        raise typer.Exit(code=1)
    if dump_row and not confirmed_poc:
        console.print(
            "[bold yellow]--dump-row requires --confirmed-poc.[/bold yellow]"
        )
        raise typer.Exit(code=1)
    if confirmed_poc and not intrusive:
        console.print(
            "[bold yellow]--confirmed-poc requires --intrusive.[/bold yellow]"
        )
        raise typer.Exit(code=1)
    if auto_validate and not intrusive:
        console.print(
            "[yellow]Note:[/yellow] --auto-validate without --intrusive "
            "runs Nuclei only; SQLmap needs --intrusive."
        )

    database = get_database()

    try:
        context = create_orchestration(
            database,
            assessment_name=assessment_name,
            target_url=target_url,
            active_testing_allowed=True,
            intrusive_testing_allowed=intrusive,
            rate_limit_per_second=rate_limit,
            actor="cli-workflow-orchestrator",
        )

        evidence_root = (
            Path.cwd()
            / "evidence"
            / "orchestrations"
            / context.orchestration_id
        )

        console.print(
            "[bold]Starting authorized assessment workflow...[/bold]"
        )
        console.print(f"Assessment: {assessment_name}")
        console.print(f"Target: {target_url}")
        console.print(f"Orchestration: {context.orchestration_id}")
        console.print(
            f"Parent execution: {context.parent_execution_id}"
        )
        console.print(f"Evidence root: {evidence_root}")

        result = run_assessment_pipeline(
            database,
            context,
            evidence_root=evidence_root,
            explicitly_approved=True,
            actor="cli-workflow-orchestrator",
        )
        phase6_result = asyncio.run(
            run_phase6_safe_chain(
                database,
                result.context,
                evidence_root=evidence_root / "phase6",
                explicitly_approved=True,
                nuclei_preview_approved=nuclei_preview_approved,
                sqlmap_preview_approved=sqlmap_preview_approved,
                nuclei_execute_approved=nuclei_execute_approved,
                actor="cli-phase6-orchestrator",
            )
        )

    except (
        OrchestrationWorkflowError,
        InvalidStateTransitionError,
        DnsCollectionError,
        SubdomainCollectionError,
        HttpIntelligenceCollectionError,
        CrawlCollectionError,
        JavaScriptCollectionError,
        DirectCheckWorkflowError,
        AttackHypothesisWorkflowError,
        NucleiPreviewWorkflowError,
        NucleiPreparationWorkflowError,
        NucleiExecutionWorkflowError,
        SqlmapHandoffWorkflowError,
        ControlledValidationObservationWorkflowError,
        ToolRunnerError,
        ValueError,
    ) as exc:
        console.print(
            f"[bold red]Assessment workflow failed:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    phase_results = [
        result.dns,
        result.subdomains,
        result.http_intelligence,
        result.crawl,
        result.javascript,
        result.security_headers,
        result.cors,
        *phase6_result.phase_results,
    ]

    table = Table(title="Assessment and Phase 6C Workflow Results")
    table.add_column("Phase")
    table.add_column("Outcome")
    table.add_column("Required")
    table.add_column("Execution")
    table.add_column("Evidence")
    table.add_column("Evidence Path")
    table.add_column("Reason")

    for phase in phase_results:
        table.add_row(
            (
                f"{phase.phase.value}:"
                f"{phase.metrics.get('action')}"
                if phase.metrics.get("action")
                else phase.phase.value
            ),
            phase.outcome.value,
            "yes" if phase.required else "no",
            phase.execution_id or "-",
            phase.evidence_id or "-",
            phase.evidence_path or "-",
            phase.reason or phase.error_summary or "-",
        )

    console.print()
    console.print(table)
    console.print()

    overall_status = result.context.status
    if (
        phase6_result.calculated_status
        in {OrchestrationStatus.PARTIAL, OrchestrationStatus.FAILED}
    ):
        overall_status = phase6_result.calculated_status

    if overall_status is OrchestrationStatus.PARTIAL:
        console.print(
            "[bold yellow]Assessment workflow completed "
            "with optional phases skipped or incomplete.[/bold yellow]"
        )
    elif overall_status is OrchestrationStatus.FAILED:
        console.print(
            "[bold red]Phase 6C workflow contains required "
            "failures.[/bold red]"
        )
    else:
        console.print(
            "[bold green]Assessment and safe Phase 6C workflow "
            "completed.[/bold green]"
        )
    console.print(
        f"Parent execution: {result.context.parent_execution_id}"
    )
    console.print(f"Final state: {overall_status.value}")

    if not auto_validate:
        return

    console.print()
    console.print(
        "[bold]Executing chain-derived Nuclei + SQLmap validation...[/bold]"
    )

    try:
        derived = build_auto_validation_config_from_chain(
            database,
            approved=True,
            orchestration_id=context.orchestration_id,
            confirmed_poc=confirmed_poc,
            single_row_dump=dump_row,
            adaptive=True,
            allow_waf_bypass=intrusive,
            evidence_root=evidence_root / "auto-validation",
        )
    except ChainConfigError as exc:
        console.print(
            f"[bold red]Auto-validation could not start:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print(f"Target: {derived.target_url}")
    console.print("Allowed hosts: " + ", ".join(derived.allowed_hosts))
    if derived.sqlmap_parameters:
        console.print(
            "SQLmap parameters: " + ", ".join(derived.sqlmap_parameters)
        )
    else:
        console.print(
            "SQLmap parameters: none "
            "(intrusive testing not authorized; Nuclei-only run)"
        )

    def _emit_output(event: ToolOutputEvent) -> None:
        console.print(
            f"[{event.tool_name}:{event.stream}] {event.line}",
            markup=False,
            highlight=False,
        )

    def _emit_log(message: str) -> None:
        console.print(message, markup=False, highlight=False)

    try:
        validation = run_automatic_validation(
            derived.config,
            on_output=_emit_output,
            on_log=_emit_log,
        )
    except (AutoValidationError, ToolRunnerError) as exc:
        console.print(
            f"[bold red]Auto-validation failed:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print(
        "[bold green]Auto-validation complete.[/bold green] "
        f"Nuclei exit={validation.nuclei.get('exit_code')}, "
        f"SQLmap runs={len(validation.sqlmap)}."
    )
    console.print(f"Evidence: {validation.evidence_path}")

"""Persistent Phase 5 parent/child orchestration foundation."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.checks.models import DirectCheckRequest
from saarthi_ai.orchestration.models import (
    AssessmentPipelineResult,
    DiscoveryPipelineResult,
    InitialReconResult,
    IntelligencePipelineResult,
    OrchestrationContext,
    OrchestrationPhase,
    OrchestrationPhaseOutcome,
    OrchestrationPhaseResult,
    OrchestrationStatus,
    ReconPipelineResult,
)
from saarthi_ai.persistence.crawl_workflow import run_tracked_crawl
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.direct_check_workflow import (
    run_tracked_direct_check,
)
from saarthi_ai.persistence.dns_workflow import (
    run_tracked_dns_collection,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    run_tracked_http_intelligence,
)
from saarthi_ai.persistence.http_workflow import fail_execution_safely
from saarthi_ai.persistence.javascript_workflow import (
    run_tracked_javascript_intelligence,
)
from saarthi_ai.persistence.models import (
    AuditEventType,
    ExecutionCreate,
    ExecutionRecord,
    ExecutionState,
)
from saarthi_ai.persistence.subdomain_workflow import (
    run_tracked_subdomain_collection,
)


class OrchestrationWorkflowError(RuntimeError):
    """Raised when an assessment orchestration cannot be created safely."""


def normalize_target_domain(target_url: str) -> str:
    """Return the normalized hostname from an HTTP or HTTPS URL."""

    parsed = urlparse(target_url.strip())

    if parsed.scheme not in {"http", "https"}:
        raise OrchestrationWorkflowError(
            "Workflow target must use HTTP or HTTPS."
        )

    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        raise OrchestrationWorkflowError(
            "Workflow target must contain a valid hostname."
        )

    return hostname


def count_crawl_javascript_assets(
    evidence_path: Path,
) -> int:
    """Count JavaScript assets in validated Phase 3D evidence."""

    if not evidence_path.is_file():
        raise OrchestrationWorkflowError(
            "Phase 3D crawl evidence file does not exist: "
            f"{evidence_path}"
        )

    try:
        payload = json.loads(
            evidence_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestrationWorkflowError(
            f"Unable to read Phase 3D crawl evidence: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise OrchestrationWorkflowError(
            "Phase 3D crawl evidence must contain a JSON object."
        )

    records = payload.get("urls")

    if not isinstance(records, list):
        raise OrchestrationWorkflowError(
            "Phase 3D crawl evidence does not contain a urls list."
        )

    return sum(
        1
        for record in records
        if isinstance(record, dict)
        and record.get("is_javascript") is True
    )


def create_orchestration(
    database: SaarthiDatabase,
    *,
    assessment_name: str,
    target_url: str,
    active_testing_allowed: bool,
    intrusive_testing_allowed: bool = False,
    rate_limit_per_second: int = 2,
    project_id: str | None = None,
    project_slug: str | None = None,
    actor: str = "saarthi-workflow-orchestrator",
) -> OrchestrationContext:
    """Create and prepare the parent workflow execution."""

    if intrusive_testing_allowed and not active_testing_allowed:
        raise OrchestrationWorkflowError(
            "Intrusive testing requires active testing."
        )

    if rate_limit_per_second < 1 or rate_limit_per_second > 100:
        raise OrchestrationWorkflowError(
            "Rate limit must be between 1 and 100."
        )

    target_domain = normalize_target_domain(target_url)
    orchestration_id = f"orchestration-{uuid4()}"

    parent = database.create_execution(
        ExecutionCreate(
            assessment_name=assessment_name,
            asset_types=["web"],
            targets=[target_url],
            authorization_confirmed=True,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=intrusive_testing_allowed,
            metadata={
                "execution_role": "orchestration_parent",
                "orchestration_id": orchestration_id,
                "project_id": project_id,
                "project_slug": project_slug,
                "target_domain": target_domain,
                "rate_limit_per_second": rate_limit_per_second,
            },
        )
    )

    parent = database.transition_execution(
        parent.execution_id,
        ExecutionState.VALIDATED,
        actor=actor,
        reason="Workflow target and authorization validated.",
    )

    parent = database.transition_execution(
        parent.execution_id,
        ExecutionState.PLANNED,
        actor=actor,
        reason="Phase 5 assessment workflow prepared.",
    )

    return OrchestrationContext(
        orchestration_id=orchestration_id,
        parent_execution_id=parent.execution_id,
        target_url=target_url,
        target_domain=target_domain,
        project_id=project_id,
        project_slug=project_slug,
        status=OrchestrationStatus.CREATED,
    )


def create_phase_execution(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    phase: OrchestrationPhase,
    phase_name: str,
    active_testing_allowed: bool,
    intrusive_testing_allowed: bool = False,
    previous_execution_id: str | None = None,
) -> ExecutionRecord:
    """Create one independently auditable child phase execution."""

    parent = database.get_execution(context.parent_execution_id)

    if active_testing_allowed and not parent.active_testing_allowed:
        raise OrchestrationWorkflowError(
            "Child execution cannot enable active testing when the "
            "parent orchestration does not allow it."
        )

    if intrusive_testing_allowed and not parent.intrusive_testing_allowed:
        raise OrchestrationWorkflowError(
            "Child execution cannot enable intrusive testing when the "
            "parent orchestration does not allow it."
        )

    if intrusive_testing_allowed and not active_testing_allowed:
        raise OrchestrationWorkflowError(
            "Intrusive child execution requires active testing."
        )

    if parent.metadata.get("orchestration_id") != context.orchestration_id:
        raise OrchestrationWorkflowError(
            "Parent execution does not match the orchestration context."
        )

    return database.create_execution(
        ExecutionCreate(
            assessment_name=f"{parent.assessment_name} — {phase.value}",
            plan_version=parent.plan_version,
            asset_types=parent.asset_types,
            targets=parent.targets,
            authorization_confirmed=parent.authorization_confirmed,
            active_testing_allowed=active_testing_allowed,
            intrusive_testing_allowed=intrusive_testing_allowed,
            metadata={
                "execution_role": "orchestration_child",
                "orchestration_id": context.orchestration_id,
                "parent_execution_id": context.parent_execution_id,
                "previous_execution_id": previous_execution_id,
                "phase_code": phase.value,
                "phase_name": phase_name,
                "project_id": context.project_id,
                "project_slug": context.project_slug,
                "target_domain": context.target_domain,
                "rate_limit_per_second": parent.metadata.get(
                    "rate_limit_per_second",
                    2,
                ),
            },
        )
    )


_COMPLETION_PATH: tuple[ExecutionState, ...] = (
    ExecutionState.CREATED,
    ExecutionState.VALIDATED,
    ExecutionState.PLANNED,
    ExecutionState.RUNNING,
    ExecutionState.ANALYZING,
    ExecutionState.COMPLETED,
)

_TERMINAL_STATES = frozenset(
    {
        ExecutionState.COMPLETED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    }
)


def complete_phase_execution(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str,
    reason: str = "Phase completed.",
) -> ExecutionRecord:
    """Walk a phase child from its current state to COMPLETED.

    Phase children are created in CREATED; a tracked step records evidence but
    does not advance state. This drives the canonical
    CREATED->VALIDATED->PLANNED->RUNNING->ANALYZING->COMPLETED path so the phase
    is recognized as done by the orchestration/TUI. Idempotent for terminal
    states.
    """

    execution = database.get_execution(execution_id)
    if execution.state in _TERMINAL_STATES:
        return execution
    try:
        start = _COMPLETION_PATH.index(execution.state)
    except ValueError:
        return execution
    for state in _COMPLETION_PATH[start + 1:]:
        execution = database.transition_execution(
            execution_id,
            state,
            actor=actor,
            reason=reason,
        )
    return execution


def _record_phase_failure(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    phase: OrchestrationPhase,
    child_execution_id: str | None,
    exc: Exception,
    required: bool,
    actor: str,
    metrics: dict[str, int | float | str | bool | None] | None = None,
) -> OrchestrationPhaseResult:
    """Record a phase failure as a FAILED result and continue the workflow.

    Fail-soft: the failing child execution is already marked failed by its
    tracked workflow; here we only log an audit event and return a FAILED
    phase result so the orchestrator jumps to the next phase instead of
    aborting the whole run.
    """

    try:
        database.add_audit_event(
            context.parent_execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                f"[{phase.value}][orchestrator] Phase failed; "
                "continuing to the next phase."
            ),
            details={
                "orchestration_id": context.orchestration_id,
                "phase": phase.value,
                "required": required,
                "outcome": OrchestrationPhaseOutcome.FAILED.value,
                "child_execution_id": child_execution_id,
                "error": str(exc),
                "continued_after_failure": True,
            },
        )
    except Exception:
        # Audit logging must never turn a soft failure into a hard abort.
        pass

    combined_metrics: dict[str, int | float | str | bool | None] = {
        "continued_after_failure": True,
    }
    if metrics:
        combined_metrics.update(metrics)

    return OrchestrationPhaseResult(
        phase=phase,
        outcome=OrchestrationPhaseOutcome.FAILED,
        required=required,
        execution_id=child_execution_id,
        error_summary=str(exc)[:2_000],
        metrics=combined_metrics,
    )


def _skip_dependent_phase(
    phase: OrchestrationPhase,
    *,
    dependency_phase: str,
    required: bool,
) -> OrchestrationPhaseResult:
    """Skip a phase whose upstream dependency produced no evidence."""

    return OrchestrationPhaseResult(
        phase=phase,
        outcome=OrchestrationPhaseOutcome.SKIPPED,
        required=required,
        reason=(
            f"Skipped because upstream {dependency_phase} evidence is "
            "unavailable after an earlier failure."
        ),
    )


def run_initial_recon(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    actor: str = "saarthi-workflow-orchestrator",
) -> InitialReconResult:
    """Run Phase 3A DNS followed by Phase 3B subdomain enumeration."""

    parent = database.get_execution(context.parent_execution_id)

    if parent.state is ExecutionState.PLANNED:
        parent = database.transition_execution(
            parent.execution_id,
            ExecutionState.RUNNING,
            actor=actor,
            reason="Phase 5 automated assessment workflow started.",
        )

    if parent.state is not ExecutionState.RUNNING:
        raise OrchestrationWorkflowError(
            "Parent orchestration must be planned or running."
        )

    running_context = context.model_copy(
        update={"status": OrchestrationStatus.RUNNING}
    )

    dns_child = None
    try:
        dns_child = create_phase_execution(
            database,
            running_context,
            phase=OrchestrationPhase.DNS,
            phase_name="DNS Intelligence",
            active_testing_allowed=False,
        )
        dns_result = run_tracked_dns_collection(
            database,
            dns_child.execution_id,
            running_context.target_domain,
            actor=actor,
            evidence_root=evidence_root / "dns",
        )
        dns_phase = OrchestrationPhaseResult(
            phase=OrchestrationPhase.DNS,
            execution_id=dns_child.execution_id,
            evidence_id=dns_result.evidence.evidence_id,
            evidence_path=dns_result.evidence.path,
        )
    except Exception as exc:
        dns_phase = _record_phase_failure(
            database,
            running_context,
            phase=OrchestrationPhase.DNS,
            child_execution_id=(
                dns_child.execution_id if dns_child else None
            ),
            exc=exc,
            required=True,
            actor=actor,
        )

    subdomain_child = None
    try:
        subdomain_child = create_phase_execution(
            database,
            running_context,
            phase=OrchestrationPhase.SUBDOMAINS,
            phase_name="Subdomain Enumeration",
            active_testing_allowed=False,
            previous_execution_id=(
                dns_child.execution_id if dns_child else None
            ),
        )
        subdomain_result = run_tracked_subdomain_collection(
            database,
            subdomain_child.execution_id,
            running_context.target_domain,
            actor=actor,
            evidence_root=evidence_root / "subdomains",
        )
        subdomain_phase = OrchestrationPhaseResult(
            phase=OrchestrationPhase.SUBDOMAINS,
            execution_id=subdomain_child.execution_id,
            evidence_id=subdomain_result.evidence.evidence_id,
            evidence_path=subdomain_result.evidence.path,
        )
    except Exception as exc:
        subdomain_phase = _record_phase_failure(
            database,
            running_context,
            phase=OrchestrationPhase.SUBDOMAINS,
            child_execution_id=(
                subdomain_child.execution_id if subdomain_child else None
            ),
            exc=exc,
            required=True,
            actor=actor,
        )

    return InitialReconResult(
        context=running_context,
        dns=dns_phase,
        subdomains=subdomain_phase,
    )


def run_recon_pipeline(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    actor: str = "saarthi-workflow-orchestrator",
) -> ReconPipelineResult:
    """Run Phase 3A, 3B, and 3C using linked child executions."""

    initial = run_initial_recon(
        database,
        context,
        evidence_root=evidence_root,
        actor=actor,
    )

    if not initial.subdomains.evidence_path:
        http_phase = _skip_dependent_phase(
            OrchestrationPhase.HTTP_INTELLIGENCE,
            dependency_phase="Phase 3B subdomain",
            required=True,
        )
    else:
        http_child = None
        try:
            http_child = create_phase_execution(
                database,
                initial.context,
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                phase_name="Live Host Intelligence",
                active_testing_allowed=True,
                previous_execution_id=initial.subdomains.execution_id,
            )
            http_result = run_tracked_http_intelligence(
                database,
                http_child.execution_id,
                Path(initial.subdomains.evidence_path),
                actor=actor,
                evidence_root=evidence_root / "http-intelligence",
            )
            http_phase = OrchestrationPhaseResult(
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                execution_id=http_child.execution_id,
                evidence_id=http_result.evidence.evidence_id,
                evidence_path=http_result.evidence.path,
            )
        except Exception as exc:
            http_phase = _record_phase_failure(
                database,
                initial.context,
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                child_execution_id=(
                    http_child.execution_id if http_child else None
                ),
                exc=exc,
                required=True,
                actor=actor,
            )

    return ReconPipelineResult(
        context=initial.context,
        dns=initial.dns,
        subdomains=initial.subdomains,
        http_intelligence=http_phase,
    )


def run_discovery_pipeline(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    actor: str = "saarthi-workflow-orchestrator",
) -> DiscoveryPipelineResult:
    """Run Phase 3A through 3D using linked child executions."""

    recon = run_recon_pipeline(
        database,
        context,
        evidence_root=evidence_root,
        actor=actor,
    )

    if not recon.http_intelligence.evidence_path:
        crawl_phase = _skip_dependent_phase(
            OrchestrationPhase.CRAWL,
            dependency_phase="Phase 3C live-host",
            required=True,
        )
    else:
        crawl_child = None
        try:
            crawl_child = create_phase_execution(
                database,
                recon.context,
                phase=OrchestrationPhase.CRAWL,
                phase_name="Crawling and URL Intelligence",
                active_testing_allowed=True,
                previous_execution_id=(
                    recon.http_intelligence.execution_id
                ),
            )
            crawl_result = run_tracked_crawl(
                database,
                crawl_child.execution_id,
                Path(recon.http_intelligence.evidence_path),
                actor=actor,
                evidence_root=evidence_root / "crawling",
            )
            crawl_phase = OrchestrationPhaseResult(
                phase=OrchestrationPhase.CRAWL,
                execution_id=crawl_child.execution_id,
                evidence_id=crawl_result.evidence.evidence_id,
                evidence_path=crawl_result.evidence.path,
            )
        except Exception as exc:
            crawl_phase = _record_phase_failure(
                database,
                recon.context,
                phase=OrchestrationPhase.CRAWL,
                child_execution_id=(
                    crawl_child.execution_id if crawl_child else None
                ),
                exc=exc,
                required=True,
                actor=actor,
            )

    return DiscoveryPipelineResult(
        context=recon.context,
        dns=recon.dns,
        subdomains=recon.subdomains,
        http_intelligence=recon.http_intelligence,
        crawl=crawl_phase,
    )


def run_intelligence_pipeline(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    actor: str = "saarthi-workflow-orchestrator",
) -> IntelligencePipelineResult:
    """Run Phase 3A through 3E using linked child executions."""

    discovery = run_discovery_pipeline(
        database,
        context,
        evidence_root=evidence_root,
        actor=actor,
    )

    if not discovery.crawl.evidence_path:
        javascript_phase: OrchestrationPhaseResult = _skip_dependent_phase(
            OrchestrationPhase.JAVASCRIPT,
            dependency_phase="Phase 3D crawl",
            required=False,
        )
    else:
        javascript_child = None
        try:
            crawl_evidence_path = Path(discovery.crawl.evidence_path)
            javascript_asset_count = count_crawl_javascript_assets(
                crawl_evidence_path
            )

            if javascript_asset_count == 0:
                javascript_phase = OrchestrationPhaseResult(
                    phase=OrchestrationPhase.JAVASCRIPT,
                    outcome=OrchestrationPhaseOutcome.SKIPPED,
                    required=False,
                    reason=(
                        "Phase 3E skipped because Phase 3D "
                        "discovered no JavaScript assets."
                    ),
                    metrics={"input_javascript_count": 0},
                )
            else:
                javascript_child = create_phase_execution(
                    database,
                    discovery.context,
                    phase=OrchestrationPhase.JAVASCRIPT,
                    phase_name="JavaScript Intelligence",
                    active_testing_allowed=True,
                    previous_execution_id=discovery.crawl.execution_id,
                )
                javascript_result = (
                    run_tracked_javascript_intelligence(
                        database,
                        javascript_child.execution_id,
                        crawl_evidence_path,
                        actor=actor,
                        evidence_root=(
                            evidence_root / "javascript-intelligence"
                        ),
                    )
                )
                javascript_phase = OrchestrationPhaseResult(
                    phase=OrchestrationPhase.JAVASCRIPT,
                    required=False,
                    execution_id=javascript_child.execution_id,
                    evidence_id=(
                        javascript_result.evidence.evidence_id
                    ),
                    evidence_path=javascript_result.evidence.path,
                    metrics={
                        "input_javascript_count": (
                            javascript_asset_count
                        ),
                    },
                )
        except Exception as exc:
            javascript_phase = _record_phase_failure(
                database,
                discovery.context,
                phase=OrchestrationPhase.JAVASCRIPT,
                child_execution_id=(
                    javascript_child.execution_id
                    if javascript_child
                    else None
                ),
                exc=exc,
                required=False,
                actor=actor,
            )

    return IntelligencePipelineResult(
        context=discovery.context,
        dns=discovery.dns,
        subdomains=discovery.subdomains,
        http_intelligence=discovery.http_intelligence,
        crawl=discovery.crawl,
        javascript=javascript_phase,
    )


def run_assessment_pipeline(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    explicitly_approved: bool,
    actor: str = "saarthi-workflow-orchestrator",
) -> AssessmentPipelineResult:
    """Run the authorized Phase 3A through 4A assessment pipeline."""

    parent = database.get_execution(context.parent_execution_id)

    if not explicitly_approved:
        raise OrchestrationWorkflowError(
            "Explicit operator approval is required for the full assessment."
        )

    if not parent.authorization_confirmed:
        raise OrchestrationWorkflowError(
            "Parent orchestration does not have confirmed authorization."
        )

    if not parent.active_testing_allowed:
        raise OrchestrationWorkflowError(
            "The full assessment requires active testing approval."
        )

    intelligence = run_intelligence_pipeline(
        database,
        context,
        evidence_root=evidence_root,
        actor=actor,
    )

    try:
        security_headers_child = None
        try:
            security_headers_child = create_phase_execution(
                database,
                intelligence.context,
                phase=OrchestrationPhase.SECURITY_HEADERS,
                phase_name="Security Headers",
                active_testing_allowed=False,
                previous_execution_id=(
                    intelligence.javascript.execution_id
                    or intelligence.crawl.execution_id
                    or intelligence.http_intelligence.execution_id
                    or intelligence.subdomains.execution_id
                    or intelligence.dns.execution_id
                ),
            )
            security_headers_result = run_tracked_direct_check(
                database,
                DirectCheckRequest(
                    execution_id=security_headers_child.execution_id,
                    target_url=intelligence.context.target_url,
                    check_id="security-headers",
                    authorized=True,
                    active_testing=False,
                    explicitly_approved=True,
                    requested_method="GET",
                    requested_requests=1,
                    metadata={
                        "orchestration_id": (
                            intelligence.context.orchestration_id
                        ),
                        "phase": "4A-security-headers",
                    },
                ),
                actor=actor,
                evidence_root=evidence_root / "security-headers",
            )
            security_headers_phase_result = OrchestrationPhaseResult(
                phase=OrchestrationPhase.SECURITY_HEADERS,
                execution_id=security_headers_child.execution_id,
                evidence_id=(
                    security_headers_result.evidence.evidence_id
                ),
                evidence_path=security_headers_result.evidence.path,
            )
        except Exception as exc:
            security_headers_phase_result = _record_phase_failure(
                database,
                intelligence.context,
                phase=OrchestrationPhase.SECURITY_HEADERS,
                child_execution_id=(
                    security_headers_child.execution_id
                    if security_headers_child
                    else None
                ),
                exc=exc,
                required=True,
                actor=actor,
            )

        cors_child = create_phase_execution(
            database,
            intelligence.context,
            phase=OrchestrationPhase.CORS,
            phase_name="CORS Configuration",
            active_testing_allowed=True,
            previous_execution_id=(
                security_headers_child.execution_id
                if security_headers_child
                else None
            ),
        )

        try:
            cors_result = run_tracked_direct_check(
                database,
                DirectCheckRequest(
                    execution_id=cors_child.execution_id,
                    target_url=intelligence.context.target_url,
                    check_id="cors-configuration",
                    authorized=True,
                    active_testing=True,
                    explicitly_approved=True,
                    requested_method="GET",
                    requested_requests=3,
                    metadata={
                        "orchestration_id": (
                            intelligence.context.orchestration_id
                        ),
                        "phase": "4A-cors",
                    },
                ),
                actor=actor,
                evidence_root=evidence_root / "cors",
            )

            cors_phase_result = OrchestrationPhaseResult(
                phase=OrchestrationPhase.CORS,
                required=False,
                execution_id=cors_child.execution_id,
                evidence_id=cors_result.evidence.evidence_id,
                evidence_path=cors_result.evidence.path,
            )
        except Exception as exc:
            cors_phase_result = OrchestrationPhaseResult(
                phase=OrchestrationPhase.CORS,
                outcome=OrchestrationPhaseOutcome.FAILED,
                required=False,
                execution_id=cors_child.execution_id,
                error_summary=str(exc),
            )

            database.add_audit_event(
                intelligence.context.parent_execution_id,
                event_type=AuditEventType.TOOL_FAILED,
                actor=actor,
                message=(
                    "[5D][orchestrator] Optional CORS phase "
                    "failed; assessment will continue."
                ),
                details={
                    "orchestration_id": (
                        intelligence.context.orchestration_id
                    ),
                    "phase": OrchestrationPhase.CORS.value,
                    "required": False,
                    "outcome": (
                        OrchestrationPhaseOutcome.FAILED.value
                    ),
                    "child_execution_id": cors_child.execution_id,
                    "error": str(exc),
                },
            )

        assessment_result = AssessmentPipelineResult(
            context=intelligence.context,
            dns=intelligence.dns,
            subdomains=intelligence.subdomains,
            http_intelligence=intelligence.http_intelligence,
            crawl=intelligence.crawl,
            javascript=intelligence.javascript,
            security_headers=security_headers_phase_result,
            cors=cors_phase_result,
        )

        final_status = assessment_result.calculated_status

        # Fail-soft: a failed phase never aborts the run. The parent
        # execution completes and the degraded status is surfaced so the
        # workflow jumps ahead to Phase 6 instead of stopping.
        parent = database.get_execution(
            intelligence.context.parent_execution_id
        )

        if parent.state is not ExecutionState.RUNNING:
            raise OrchestrationWorkflowError(
                "Parent orchestration must be running before completion."
            )

        phase_outcomes = [
            {
                "phase": phase.phase.value,
                "outcome": phase.outcome.value,
                "required": phase.required,
                "reason": phase.reason,
                "error_summary": phase.error_summary,
            }
            for phase in assessment_result.phase_results
        ]

        outcome_counts = {
            "completed": sum(
                phase.completed
                for phase in assessment_result.phase_results
            ),
            "skipped": sum(
                phase.skipped
                for phase in assessment_result.phase_results
            ),
            "failed": sum(
                phase.failed
                for phase in assessment_result.phase_results
            ),
            "required": sum(
                phase.required
                for phase in assessment_result.phase_results
            ),
            "optional": sum(
                not phase.required
                for phase in assessment_result.phase_results
            ),
        }

        database.add_audit_event(
            parent.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[5C][orchestrator] Assessment outcome calculated: "
                f"{final_status.value}"
            ),
            details={
                "orchestration_id": (
                    intelligence.context.orchestration_id
                ),
                "orchestration_status": final_status.value,
                "phase_outcomes": phase_outcomes,
                "outcome_counts": outcome_counts,
                "required_phase_failure": any(
                    phase.required and phase.failed
                    for phase in assessment_result.phase_results
                ),
            },
        )

        parent = database.transition_execution(
            parent.execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason=(
                "Automated assessment evidence and orchestration "
                "outcomes are ready for review."
            ),
        )

        completion_reason = (
            "Phase 3A through 4A assessment workflow completed."
            if final_status is OrchestrationStatus.COMPLETED
            else (
                "Phase 3A through 4A assessment workflow completed "
                "with optional phases skipped or incomplete."
            )
        )

        database.transition_execution(
            parent.execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=completion_reason,
        )

        final_context = intelligence.context.model_copy(
            update={"status": final_status}
        )

        return assessment_result.model_copy(
            update={"context": final_context}
        )

    except Exception as exc:
        fail_execution_safely(
            database,
            intelligence.context.parent_execution_id,
            actor=actor,
            reason=f"Phase 4A orchestration failed: {exc}",
        )
        raise

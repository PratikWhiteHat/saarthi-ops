"""Persistent Phase 5 parent/child orchestration foundation."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from saarthi_ai.orchestration.models import (
    DiscoveryPipelineResult,
    InitialReconResult,
    IntelligencePipelineResult,
    OrchestrationContext,
    OrchestrationPhase,
    OrchestrationPhaseResult,
    OrchestrationStatus,
    ReconPipelineResult,
)
from saarthi_ai.persistence.crawl_workflow import run_tracked_crawl
from saarthi_ai.persistence.database import SaarthiDatabase
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

        subdomain_child = create_phase_execution(
            database,
            running_context,
            phase=OrchestrationPhase.SUBDOMAINS,
            phase_name="Subdomain Enumeration",
            active_testing_allowed=False,
            previous_execution_id=dns_child.execution_id,
        )

        subdomain_result = run_tracked_subdomain_collection(
            database,
            subdomain_child.execution_id,
            running_context.target_domain,
            actor=actor,
            evidence_root=evidence_root / "subdomains",
        )

        return InitialReconResult(
            context=running_context,
            dns=OrchestrationPhaseResult(
                phase=OrchestrationPhase.DNS,
                execution_id=dns_child.execution_id,
                evidence_id=dns_result.evidence.evidence_id,
                evidence_path=dns_result.evidence.path,
            ),
            subdomains=OrchestrationPhaseResult(
                phase=OrchestrationPhase.SUBDOMAINS,
                execution_id=subdomain_child.execution_id,
                evidence_id=subdomain_result.evidence.evidence_id,
                evidence_path=subdomain_result.evidence.path,
            ),
        )

    except Exception as exc:
        fail_execution_safely(
            database,
            running_context.parent_execution_id,
            actor=actor,
            reason=f"Initial orchestration failed: {exc}",
        )
        raise


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

        return ReconPipelineResult(
            context=initial.context,
            dns=initial.dns,
            subdomains=initial.subdomains,
            http_intelligence=OrchestrationPhaseResult(
                phase=OrchestrationPhase.HTTP_INTELLIGENCE,
                execution_id=http_child.execution_id,
                evidence_id=http_result.evidence.evidence_id,
                evidence_path=http_result.evidence.path,
            ),
        )

    except Exception as exc:
        fail_execution_safely(
            database,
            initial.context.parent_execution_id,
            actor=actor,
            reason=f"Phase 3C orchestration failed: {exc}",
        )
        raise


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

        return DiscoveryPipelineResult(
            context=recon.context,
            dns=recon.dns,
            subdomains=recon.subdomains,
            http_intelligence=recon.http_intelligence,
            crawl=OrchestrationPhaseResult(
                phase=OrchestrationPhase.CRAWL,
                execution_id=crawl_child.execution_id,
                evidence_id=crawl_result.evidence.evidence_id,
                evidence_path=crawl_result.evidence.path,
            ),
        )

    except Exception as exc:
        fail_execution_safely(
            database,
            recon.context.parent_execution_id,
            actor=actor,
            reason=f"Phase 3D orchestration failed: {exc}",
        )
        raise


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

    try:
        javascript_child = create_phase_execution(
            database,
            discovery.context,
            phase=OrchestrationPhase.JAVASCRIPT,
            phase_name="JavaScript Intelligence",
            active_testing_allowed=True,
            previous_execution_id=discovery.crawl.execution_id,
        )

        javascript_result = run_tracked_javascript_intelligence(
            database,
            javascript_child.execution_id,
            Path(discovery.crawl.evidence_path),
            actor=actor,
            evidence_root=evidence_root / "javascript-intelligence",
        )

        return IntelligencePipelineResult(
            context=discovery.context,
            dns=discovery.dns,
            subdomains=discovery.subdomains,
            http_intelligence=discovery.http_intelligence,
            crawl=discovery.crawl,
            javascript=OrchestrationPhaseResult(
                phase=OrchestrationPhase.JAVASCRIPT,
                execution_id=javascript_child.execution_id,
                evidence_id=javascript_result.evidence.evidence_id,
                evidence_path=javascript_result.evidence.path,
            ),
        )

    except Exception as exc:
        fail_execution_safely(
            database,
            discovery.context.parent_execution_id,
            actor=actor,
            reason=f"Phase 3E orchestration failed: {exc}",
        )
        raise

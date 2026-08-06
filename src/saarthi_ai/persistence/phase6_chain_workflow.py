"""Permission-gated Phase 6C previews and bounded surface validators."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionRequest,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.execution.nuclei_adapter import NucleiDryRunRequest
from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapMethod,
    SqlmapPreviewRequest,
)
from saarthi_ai.orchestration.models import (
    OrchestrationContext,
    OrchestrationPhase,
    OrchestrationPhaseOutcome,
    OrchestrationPhaseResult,
    Phase6ChainResult,
)
from saarthi_ai.persistence.controlled_validation_observation_workflow import (
    run_tracked_controlled_validation_observation,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.nuclei_preview_workflow import (
    create_tracked_nuclei_preview,
)
from saarthi_ai.persistence.orchestration_workflow import (
    create_phase_execution,
)
from saarthi_ai.persistence.sqlmap_preview_workflow import (
    create_tracked_sqlmap_preview,
)

SAFE_VALIDATOR_ACTIONS = (
    ControlledValidationAction.INJECTION_SURFACE_VALIDATION,
    ControlledValidationAction.BROWSER_ATTACK_SURFACE_VALIDATION,
    ControlledValidationAction.SERVER_PARSER_SURFACE_VALIDATION,
    ControlledValidationAction.HTTP_PARAMETER_SURFACE_VALIDATION,
    ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION,
    ControlledValidationAction.SESSION_COOKIE_ATTRIBUTE_VALIDATION,
    ControlledValidationAction.CSRF_PROTECTION_SURFACE_VALIDATION,
    ControlledValidationAction.API_DATA_EXPOSURE_SURFACE_VALIDATION,
    ControlledValidationAction.FILE_UPLOAD_SURFACE_VALIDATION,
)


async def run_phase6_safe_chain(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    explicitly_approved: bool,
    nuclei_preview_approved: bool,
    sqlmap_preview_approved: bool,
    actor: str = "saarthi-phase6-orchestrator",
    transport: httpx.AsyncBaseTransport | None = None,
) -> Phase6ChainResult:
    """Run previews and one-request GET validators after Phase 4A.

    Nuclei and SQLmap are preview-only here. No subprocess is started and
    no scanner payload is sent by this workflow.
    """

    if not explicitly_approved:
        raise ValueError(
            "Explicit approval is required for Phase 6C observations."
        )

    parent = database.get_execution(context.parent_execution_id)
    results: list[OrchestrationPhaseResult] = []
    previous_execution_id: str | None = None

    if nuclei_preview_approved:
        child = create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.NUCLEI_PREVIEW,
            phase_name="Nuclei Non-Executed Preview",
            active_testing_allowed=True,
            previous_execution_id=previous_execution_id,
        )
        preview = create_tracked_nuclei_preview(
            database,
            child.execution_id,
            NucleiDryRunRequest(
                target_url=context.target_url,
                authorized=True,
                active_testing=True,
                approval_granted=True,
                rate_limit_per_second=min(
                    int(parent.metadata.get("rate_limit_per_second", 2)),
                    2,
                ),
                concurrency=1,
                timeout_seconds=10,
                dry_run=True,
            ),
            actor=actor,
            evidence_root=evidence_root / "nuclei-preview",
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.NUCLEI_PREVIEW,
                execution_id=child.execution_id,
                evidence_id=preview.evidence.evidence_id,
                evidence_path=preview.evidence.path,
                metrics={
                    "executed": False,
                    "network_activity": False,
                },
                reason="Approved preview persisted; scanner not executed.",
            )
        )
        previous_execution_id = child.execution_id
    else:
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.NUCLEI_PREVIEW,
                outcome=OrchestrationPhaseOutcome.SKIPPED,
                required=False,
                reason="Nuclei preview permission was not granted.",
            )
        )

    query_names = tuple(
        dict.fromkeys(
            name
            for name, _value in parse_qsl(
                urlsplit(context.target_url).query,
                keep_blank_values=True,
            )
            if name
        )
    )
    if (
        sqlmap_preview_approved
        and parent.intrusive_testing_allowed
        and query_names
    ):
        child = create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.SQLMAP_PREVIEW,
            phase_name="SQLmap Non-Executed Preview",
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            previous_execution_id=previous_execution_id,
        )
        preview = create_tracked_sqlmap_preview(
            database,
            child.execution_id,
            SqlmapPreviewRequest(
                target_url=context.target_url,
                parameter_name=query_names[0],
                method=SqlmapMethod.GET,
                authorized=True,
                active_testing=True,
                intrusive_testing=True,
                approval_granted=True,
                timeout_seconds=5,
                dry_run=True,
            ),
            actor=actor,
            evidence_root=evidence_root / "sqlmap-preview",
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.SQLMAP_PREVIEW,
                execution_id=child.execution_id,
                evidence_id=preview.evidence.evidence_id,
                evidence_path=preview.evidence.path,
                metrics={
                    "executed": False,
                    "network_activity": False,
                    "parameter": query_names[0],
                },
                reason="Approved preview persisted; SQLmap not executed.",
            )
        )
        previous_execution_id = child.execution_id
    else:
        reasons = []
        if not sqlmap_preview_approved:
            reasons.append("permission was not granted")
        if not parent.intrusive_testing_allowed:
            reasons.append("intrusive-testing permission is disabled")
        if not query_names:
            reasons.append("target URL has no query parameter")
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.SQLMAP_PREVIEW,
                outcome=OrchestrationPhaseOutcome.SKIPPED,
                required=False,
                reason="SQLmap preview skipped: " + "; ".join(reasons) + ".",
            )
        )

    for action in SAFE_VALIDATOR_ACTIONS:
        child = create_phase_execution(
            database,
            context,
            phase=OrchestrationPhase.SAFE_VALIDATOR,
            phase_name=action.value,
            active_testing_allowed=True,
            previous_execution_id=previous_execution_id,
        )
        validation = ControlledValidationRequest(
            execution_id=child.execution_id,
            target_url=context.target_url,
            action=action,
            authorized=True,
            active_testing=True,
            explicitly_approved=True,
            reversible=True,
            requested_requests=1,
        )
        create_tracked_controlled_validation_plan(
            database,
            validation,
            actor=actor,
            evidence_root=evidence_root / "plans" / action.value,
        )
        observation = (
            await run_tracked_controlled_validation_observation(
                database,
                ControlledValidationExecutionRequest(
                    validation=validation,
                    method="GET",
                    timeout_seconds=8.0,
                    max_response_bytes=65_536,
                    follow_redirects=False,
                    headers=(),
                    body=None,
                ),
                actor=actor,
                evidence_root=(
                    evidence_root / "observations" / action.value
                ),
                transport=transport,
            )
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.SAFE_VALIDATOR,
                execution_id=child.execution_id,
                evidence_id=observation.evidence.evidence_id,
                evidence_path=observation.evidence.path,
                metrics={
                    "action": action.value,
                    "method": "GET",
                    "request_budget": 1,
                },
            )
        )
        previous_execution_id = child.execution_id

    return Phase6ChainResult(
        context=context,
        phase_results=results,
    )

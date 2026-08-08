"""Permission-gated Phase 6C previews and bounded surface validators."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

from saarthi_ai.attack_hypothesis import (
    AttackHypothesisGenerationRequest,
)
from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionRequest,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
    ControlledValidationRequest,
)
from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiExecutionRequest,
)
from saarthi_ai.execution.sqlmap_adapter import (
    SqlmapMethod,
    SqlmapPreviewRequest,
)
from saarthi_ai.execution.tool_runner import ToolRunResult, run_tool
from saarthi_ai.orchestration.models import (
    OrchestrationContext,
    OrchestrationPhase,
    OrchestrationPhaseOutcome,
    OrchestrationPhaseResult,
    Phase6ChainResult,
)
from saarthi_ai.persistence.attack_hypothesis_workflow import (
    create_tracked_attack_hypotheses,
)
from saarthi_ai.persistence.controlled_validation_observation_workflow import (
    run_tracked_controlled_validation_observation,
)
from saarthi_ai.persistence.controlled_validation_workflow import (
    create_tracked_controlled_validation_plan,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceType,
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
    create_tracked_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preview_workflow import (
    create_tracked_nuclei_preview,
)
from saarthi_ai.persistence.orchestration_workflow import (
    create_phase_execution,
)
from saarthi_ai.persistence.restricted_worker_jobs import (
    approve_worker_job,
    create_worker_job,
)
from saarthi_ai.persistence.sqlmap_handoff_workflow import (
    create_sqlmap_handoff,
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
    nuclei_execute_approved: bool = False,
    actor: str = "saarthi-phase6-orchestrator",
    transport: httpx.AsyncBaseTransport | None = None,
    nuclei_runner: Callable[..., ToolRunResult] | None = None,
    authenticated_sessions_path: Path | str | None = None,
) -> Phase6ChainResult:
    """Run previews and one-request GET validators after Phase 4A.

    SQLmap creates a non-executable asynchronous result handoff. Nuclei
    execution is separately gated and uses the fixed conservative
    template profile when explicitly approved.
    """

    if not explicitly_approved:
        raise ValueError(
            "Explicit approval is required for Phase 6C observations."
        )
    if nuclei_execute_approved and not nuclei_preview_approved:
        raise ValueError(
            "Nuclei execution requires Nuclei preview approval."
        )

    parent = database.get_execution(context.parent_execution_id)
    results: list[OrchestrationPhaseResult] = []
    results.extend(
        (
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.BLIND_VALIDATION,
                outcome=OrchestrationPhaseOutcome.NOT_APPLICABLE,
                required=False,
                reason=(
                    "No approved blind-validation candidate was selected; "
                    "no callback token or request was created."
                ),
                metrics={"gate_evaluated": True},
            ),
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.OAST_MANAGER,
                outcome=OrchestrationPhaseOutcome.NOT_APPLICABLE,
                required=False,
                reason=(
                    "No active OAST correlation exists for this target."
                ),
                metrics={"gate_evaluated": True},
            ),
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.CONFIRMATION,
                outcome=OrchestrationPhaseOutcome.NOT_APPLICABLE,
                required=False,
                reason=(
                    "No confirmation candidate with supporting evidence "
                    "was available."
                ),
                metrics={"gate_evaluated": True},
            ),
        )
    )
    for gate in results:
        database.add_audit_event(
            context.parent_execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                f"[{gate.phase.value}][orchestrator] "
                "Prerequisite gate evaluated: not applicable."
            ),
            details={
                "phase_code": gate.phase.value,
                "outcome": gate.outcome.value,
                "reason": gate.reason,
                "gate_evaluated": True,
                "executed": False,
                "network_activity": False,
            },
        )
    prior_execution_ids = tuple(
        execution.execution_id
        for execution in database.list_executions(limit=1_000)
        if (
            execution.metadata.get("orchestration_id")
            == context.orchestration_id
            and execution.metadata.get("execution_role")
            == "orchestration_child"
            and execution.metadata.get("phase_code")
            in {
                "3A",
                "3B",
                "3C",
                "3D",
                "3E",
                "4A-security-headers",
                "4A-cors",
            }
        )
    )
    previous_execution_id: str | None = (
        prior_execution_ids[0] if prior_execution_ids else None
    )

    hypothesis_child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.ATTACK_HYPOTHESIS,
        phase_name="Attack Hypothesis Engine",
        active_testing_allowed=False,
        previous_execution_id=previous_execution_id,
    )
    try:
        database.transition_execution(
            hypothesis_child.execution_id,
            ExecutionState.VALIDATED,
            actor=actor,
            reason="Phase 6A evidence sources validated.",
        )
        database.transition_execution(
            hypothesis_child.execution_id,
            ExecutionState.PLANNED,
            actor=actor,
            reason="Phase 6A non-executing hypothesis generation planned.",
        )
        database.transition_execution(
            hypothesis_child.execution_id,
            ExecutionState.RUNNING,
            actor=actor,
            reason="Phase 6A evidence analysis started.",
        )
        hypotheses = create_tracked_attack_hypotheses(
            database,
            AttackHypothesisGenerationRequest(
                execution_id=hypothesis_child.execution_id,
                target_url=context.target_url,
                authorized=True,
                max_hypotheses=20,
            ),
            actor=actor,
            evidence_root=evidence_root / "attack-hypotheses",
            source_execution_ids=prior_execution_ids,
        )
        database.transition_execution(
            hypothesis_child.execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason="Phase 6A hypotheses are ready for review.",
        )
        database.transition_execution(
            hypothesis_child.execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=(
                "Phase 6A non-executing hypothesis generation completed."
            ),
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.ATTACK_HYPOTHESIS,
                execution_id=hypothesis_child.execution_id,
                evidence_id=hypotheses.evidence.evidence_id,
                evidence_path=hypotheses.evidence.path,
                metrics={
                    "hypothesis_count": len(
                        hypotheses.hypothesis_set.hypotheses
                    ),
                    "executed": False,
                    "network_activity": False,
                },
            )
        )
    except Exception as exc:
        # Fail-soft: a hypothesis-engine failure never aborts Phase 6.
        database.add_audit_event(
            context.parent_execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6A][orchestrator] Attack-hypothesis engine failed; "
                "continuing with Phase 6."
            ),
            details={
                "phase_code": OrchestrationPhase.ATTACK_HYPOTHESIS.value,
                "outcome": OrchestrationPhaseOutcome.FAILED.value,
                "child_execution_id": hypothesis_child.execution_id,
                "error": str(exc),
                "continued_after_failure": True,
            },
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.ATTACK_HYPOTHESIS,
                outcome=OrchestrationPhaseOutcome.FAILED,
                required=False,
                execution_id=hypothesis_child.execution_id,
                error_summary=str(exc)[:2_000],
                metrics={"continued_after_failure": True},
            )
        )
    previous_execution_id = hypothesis_child.execution_id

    if nuclei_preview_approved:
        child = create_phase_execution(
            database,
            context,
            phase=(
                OrchestrationPhase.NUCLEI
                if nuclei_execute_approved
                else OrchestrationPhase.NUCLEI_PREVIEW
            ),
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
        if nuclei_execute_approved:
            preparation = create_tracked_nuclei_preparation(
                database,
                child.execution_id,
                NucleiExecutionRequest(
                    preview=preview.preview,
                    authorization_confirmed=True,
                    active_testing_allowed=True,
                    explicitly_approved=True,
                ),
                actor=actor,
                evidence_root=evidence_root / "nuclei-preparation",
            )
            try:
                execution = run_tracked_nuclei_execution(
                    database,
                    child.execution_id,
                    NucleiExecutionVerificationRequest(
                        target_url=preparation.plan.target_url,
                        arguments=preparation.plan.arguments,
                        authorization_confirmed=True,
                        active_testing_allowed=True,
                        explicitly_approved=True,
                    ),
                    runner=nuclei_runner or run_tool,
                    actor=actor,
                    evidence_root=evidence_root / "nuclei-execution",
                )
            except NucleiExecutionWorkflowError as exc:
                execution_evidence = database.list_evidence(
                    child.execution_id,
                    evidence_type=(
                        EvidenceType.CONTROLLED_NUCLEI_EXECUTION
                    ),
                )
                latest_evidence = (
                    execution_evidence[-1]
                    if execution_evidence
                    else None
                )
                results.append(
                    OrchestrationPhaseResult(
                        phase=OrchestrationPhase.NUCLEI,
                        outcome=OrchestrationPhaseOutcome.FAILED,
                        required=False,
                        execution_id=child.execution_id,
                        evidence_id=(
                            latest_evidence.evidence_id
                            if latest_evidence is not None
                            else None
                        ),
                        evidence_path=(
                            latest_evidence.path
                            if latest_evidence is not None
                            else None
                        ),
                        metrics={
                            "executed": True,
                            "network_activity": True,
                            "timed_out": bool(
                                latest_evidence is not None
                                and latest_evidence.metadata.get(
                                    "timed_out"
                                )
                            ),
                            "continued_after_failure": True,
                        },
                        reason=(
                            "Optional bounded Nuclei execution failed "
                            "safely; Phase 6C continued."
                        ),
                        error_summary=str(exc),
                    )
                )
            else:
                results.append(
                    OrchestrationPhaseResult(
                        phase=OrchestrationPhase.NUCLEI,
                        execution_id=child.execution_id,
                        evidence_id=execution.evidence.evidence_id,
                        evidence_path=execution.evidence.path,
                        metrics={
                            "executed": True,
                            "network_activity": True,
                            "exit_code": execution.result.exit_code,
                        },
                        reason=(
                            "Approved conservative Nuclei profile "
                            "executed."
                        ),
                    )
                )
        else:
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
                    reason=(
                        "Approved preview persisted; scanner not executed."
                    ),
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
        handoff = create_sqlmap_handoff(
            database,
            preview,
            actor=actor,
            evidence_root=evidence_root / "sqlmap-handoff",
        )
        worker_job = create_worker_job(
            database,
            child.execution_id,
            tool_name="sqlmap",
            adapter_name="unbound",
            target_display=preview.preview.target_display_url,
            purpose=(
                "Track the approved SQLmap external-result handoff. "
                "This job contains no executable command or arguments."
            ),
            timeout_seconds=preview.preview.timeout_seconds,
            rate_limit_per_second=1,
            actor=actor,
        )
        worker_job = approve_worker_job(
            database,
            worker_job.job_id,
            actor=actor,
            reason=(
                "Operator-approved SQLmap preview and external-result "
                "handoff; dispatch remains disabled."
            ),
        )
        results.append(
            OrchestrationPhaseResult(
                phase=OrchestrationPhase.SQLMAP_PREVIEW,
                execution_id=child.execution_id,
                evidence_id=handoff.manifest_evidence.evidence_id,
                evidence_path=handoff.manifest_evidence.path,
                metrics={
                    "executed": False,
                    "network_activity": False,
                    "parameter": query_names[0],
                    "handoff_id": handoff.handoff_id,
                    "result_inbox": handoff.result_inbox,
                    "status": "awaiting_external_result",
                    "worker_job_id": worker_job.job_id,
                    "worker_job_state": worker_job.state.value,
                    "worker_adapter": worker_job.adapter_name,
                    "worker_dispatch_enabled": False,
                    "worker_manifest_sha256": (
                        worker_job.manifest_sha256
                    ),
                },
                reason=(
                    "Approved restricted-worker record and asynchronous "
                    "handoff persisted; SQLmap dispatch remains disabled."
                ),
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
        try:
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
        except Exception as exc:
            # Fail-soft: one validator's failure never aborts the loop.
            database.add_audit_event(
                context.parent_execution_id,
                event_type=AuditEventType.TOOL_FAILED,
                actor=actor,
                message=(
                    f"[6C][orchestrator] Validator {action.value} "
                    "failed; continuing to the next validator."
                ),
                details={
                    "phase_code": OrchestrationPhase.SAFE_VALIDATOR.value,
                    "action": action.value,
                    "outcome": OrchestrationPhaseOutcome.FAILED.value,
                    "child_execution_id": child.execution_id,
                    "error": str(exc),
                    "continued_after_failure": True,
                },
            )
            results.append(
                OrchestrationPhaseResult(
                    phase=OrchestrationPhase.SAFE_VALIDATOR,
                    outcome=OrchestrationPhaseOutcome.FAILED,
                    required=False,
                    execution_id=child.execution_id,
                    error_summary=str(exc)[:2_000],
                    metrics={
                        "action": action.value,
                        "continued_after_failure": True,
                    },
                )
            )
        previous_execution_id = child.execution_id

    # Phase 6D — authenticated workflows. Runs only when an
    # authenticated-sessions config is supplied AND its target matches this
    # assessment's scope; otherwise it records a NOT_APPLICABLE skip.
    results.append(
        await _run_phase6d_authenticated_step(
            database,
            context,
            evidence_root=evidence_root / "authenticated",
            actor=actor,
            previous_execution_id=previous_execution_id,
            sessions_path=authenticated_sessions_path,
        )
    )

    return Phase6ChainResult(
        context=context,
        phase_results=results,
    )


async def _run_phase6d_authenticated_step(
    database: SaarthiDatabase,
    context: OrchestrationContext,
    *,
    evidence_root: Path,
    actor: str,
    previous_execution_id: str | None,
    sessions_path: Path | str | None,
) -> OrchestrationPhaseResult:
    """Run Phase 6D when a scoped authenticated-sessions config is available."""

    import asyncio
    from urllib.parse import urlsplit

    from saarthi_ai.controlled_validation.authenticated.models import (
        AuthWorkflowError,
        load_auth_workflow_config,
    )
    from saarthi_ai.persistence.authenticated_workflow import (
        run_tracked_authenticated_workflow,
    )

    path = (
        Path(sessions_path)
        if sessions_path
        else Path.cwd() / "authenticated-sessions.json"
    )
    if not path.exists():
        return OrchestrationPhaseResult(
            phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
            outcome=OrchestrationPhaseOutcome.NOT_APPLICABLE,
            required=False,
            reason="No authenticated-sessions.json supplied; 6D skipped.",
        )

    try:
        config = load_auth_workflow_config(path)
    except AuthWorkflowError as exc:
        return OrchestrationPhaseResult(
            phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
            outcome=OrchestrationPhaseOutcome.SKIPPED,
            required=False,
            reason=f"6D skipped — invalid sessions config: {exc}"[:500],
        )

    run_host = (urlsplit(context.target_url).hostname or "").lower()
    cfg_host = (urlsplit(config.target_url).hostname or "").lower()
    if run_host != cfg_host:
        return OrchestrationPhaseResult(
            phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
            outcome=OrchestrationPhaseOutcome.NOT_APPLICABLE,
            required=False,
            reason=(
                f"6D skipped — sessions target {cfg_host!r} does not match "
                f"assessment target {run_host!r}."
            ),
        )

    child = create_phase_execution(
        database,
        context,
        phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
        phase_name="authenticated_workflow",
        active_testing_allowed=True,
        previous_execution_id=previous_execution_id,
    )
    try:
        tracked = await asyncio.to_thread(
            run_tracked_authenticated_workflow,
            database,
            child.execution_id,
            config,
            actor=actor,
            evidence_root=evidence_root,
        )
    except Exception as exc:  # fail-soft, like the 6C validators
        database.add_audit_event(
            context.parent_execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message="[6D][orchestrator] Authenticated workflow failed.",
            details={
                "phase_code": "6D",
                "error": str(exc),
                "child_execution_id": child.execution_id,
            },
        )
        return OrchestrationPhaseResult(
            phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
            outcome=OrchestrationPhaseOutcome.FAILED,
            required=False,
            execution_id=child.execution_id,
            error_summary=str(exc)[:2_000],
        )

    return OrchestrationPhaseResult(
        phase=OrchestrationPhase.AUTHENTICATED_WORKFLOW,
        execution_id=child.execution_id,
        evidence_id=(
            tracked.evidence.evidence_id if tracked.evidence else None
        ),
        evidence_path=tracked.evidence_path,
        metrics={
            "findings": len(tracked.result.findings),
            "logins_ok": tracked.result.logins_ok,
        },
    )

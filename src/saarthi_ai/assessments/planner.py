from __future__ import annotations

from collections.abc import Iterable

from saarthi_ai.assessments.planning import (
    AssessmentPlanResponse,
    ExecutionLevel,
    PlanPhase,
    PlanStep,
)
from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentValidationResponse,
    AssetType,
)


class UnsupportedPlannerTargetError(ValueError):
    """Raised when the current planner does not support a target type."""


def build_step(
    *,
    step_id: str,
    phase: PlanPhase,
    title: str,
    description: str,
    execution_level: ExecutionLevel,
    permitted_levels: set[str],
    targets: list[str],
    tool_candidates: Iterable[str] = (),
    evidence_requirements: Iterable[str] = (),
    depends_on: Iterable[str] = (),
) -> PlanStep:
    """Create one plan step and apply execution-level controls."""

    enabled = execution_level.value in permitted_levels
    approval_required = execution_level is not ExecutionLevel.PASSIVE
    blocked_reason: str | None = None

    if not enabled:
        blocked_reason = (
            f"{execution_level.value.capitalize()} testing has not "
            "been approved for this assessment."
        )

    return PlanStep(
        id=step_id,
        phase=phase,
        title=title,
        description=description,
        execution_level=execution_level,
        approval_required=approval_required,
        enabled=enabled,
        blocked_reason=blocked_reason,
        target_values=targets,
        tool_candidates=list(tool_candidates),
        evidence_requirements=list(evidence_requirements),
        depends_on=list(depends_on),
    )


def build_common_steps(
    targets: list[str],
    permitted_levels: set[str],
) -> list[PlanStep]:
    """Create steps required for every Web and API assessment."""

    return [
        build_step(
            step_id="scope-001",
            phase=PlanPhase.SCOPE,
            title="Confirm assessment scope",
            description=(
                "Record authorized targets, exclusions, execution levels, "
                "rate limits, credentials, and assessment constraints."
            ),
            execution_level=ExecutionLevel.PASSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            evidence_requirements=[
                "Authorization confirmation",
                "Normalized target list",
                "Documented exclusions",
            ],
        ),
        build_step(
            step_id="recon-001",
            phase=PlanPhase.RECONNAISSANCE,
            title="Collect initial target metadata",
            description=(
                "Collect HTTP availability, response metadata, TLS details, "
                "redirect behavior, and initial technology indicators."
            ),
            execution_level=ExecutionLevel.PASSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "httpx",
                "tls-inspector",
                "custom-http-client",
            ],
            evidence_requirements=[
                "HTTP status and redirect chain",
                "Response headers",
                "TLS certificate metadata",
            ],
            depends_on=["scope-001"],
        ),
    ]


def build_web_steps(
    targets: list[str],
    permitted_levels: set[str],
) -> list[PlanStep]:
    """Create Web application VAPT plan steps."""

    return [
        build_step(
            step_id="web-attack-surface-001",
            phase=PlanPhase.ATTACK_SURFACE,
            title="Map the web attack surface",
            description=(
                "Discover reachable paths, parameters, forms, scripts, "
                "technologies, and publicly accessible functionality."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "httpx",
                "crawler",
                "ffuf",
                "nuclei",
            ],
            evidence_requirements=[
                "Discovered endpoint inventory",
                "Technology observations",
                "Request and response samples",
            ],
            depends_on=["recon-001"],
        ),
        build_step(
            step_id="web-authentication-001",
            phase=PlanPhase.AUTHENTICATION,
            title="Assess authentication and session controls",
            description=(
                "Review login, logout, password recovery, session creation, "
                "cookie handling, and account-state behavior using approved "
                "test accounts."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "browser-automation",
                "burp-suite",
            ],
            evidence_requirements=[
                "Authentication request sequence",
                "Session cookie attributes",
                "Account-state test results",
            ],
            depends_on=["web-attack-surface-001"],
        ),
        build_step(
            step_id="web-authorization-001",
            phase=PlanPhase.AUTHORIZATION,
            title="Validate authorization boundaries",
            description=(
                "Use approved test identities and controlled resources to "
                "validate object-level, role-level, and function-level "
                "authorization controls."
            ),
            execution_level=ExecutionLevel.INTRUSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "browser-automation",
                "burp-suite",
            ],
            evidence_requirements=[
                "Test identity and role mapping",
                "Baseline authorized request",
                "Controlled unauthorized request",
                "Reproducible response evidence",
            ],
            depends_on=["web-authentication-001"],
        ),
        build_step(
            step_id="web-input-001",
            phase=PlanPhase.INPUT_VALIDATION,
            title="Assess application input handling",
            description=(
                "Review parameters and input points using controlled, "
                "non-destructive test values before attempting any approved "
                "higher-impact validation."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "burp-suite",
                "nuclei",
            ],
            evidence_requirements=[
                "Affected request",
                "Controlled test input",
                "Observed response difference",
                "False-positive analysis",
            ],
            depends_on=["web-attack-surface-001"],
        ),
        build_step(
            step_id="web-configuration-001",
            phase=PlanPhase.CONFIGURATION,
            title="Review web security configuration",
            description=(
                "Assess headers, cookies, caching, TLS behavior, error "
                "handling, exposed files, and unnecessary information "
                "disclosure."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "httpx",
                "nuclei",
                "tls-inspector",
            ],
            evidence_requirements=[
                "Relevant headers",
                "Configuration response evidence",
                "Exposure validation",
            ],
            depends_on=["recon-001"],
        ),
    ]


def build_api_steps(
    targets: list[str],
    permitted_levels: set[str],
) -> list[PlanStep]:
    """Create API VAPT plan steps."""

    return [
        build_step(
            step_id="api-inventory-001",
            phase=PlanPhase.ATTACK_SURFACE,
            title="Build the API endpoint inventory",
            description=(
                "Parse supplied API specifications and observe authorized "
                "traffic to identify endpoints, methods, parameters, schemas, "
                "and authentication requirements."
            ),
            execution_level=ExecutionLevel.PASSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "openapi-parser",
                "postman-parser",
                "custom-http-client",
            ],
            evidence_requirements=[
                "Endpoint and method inventory",
                "Authentication requirement mapping",
                "Request schema inventory",
            ],
            depends_on=["recon-001"],
        ),
        build_step(
            step_id="api-authentication-001",
            phase=PlanPhase.AUTHENTICATION,
            title="Assess API authentication controls",
            description=(
                "Review token issuance, expiration, revocation, session "
                "behavior, and authentication enforcement using approved "
                "test credentials."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "burp-suite",
            ],
            evidence_requirements=[
                "Token lifecycle observations",
                "Authentication request evidence",
                "Unauthorized response evidence",
            ],
            depends_on=["api-inventory-001"],
        ),
        build_step(
            step_id="api-object-authorization-001",
            phase=PlanPhase.AUTHORIZATION,
            title="Validate API object-level authorization",
            description=(
                "Use controlled objects and approved test users to determine "
                "whether the API enforces ownership and tenant boundaries."
            ),
            execution_level=ExecutionLevel.INTRUSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "burp-suite",
            ],
            evidence_requirements=[
                "Object ownership mapping",
                "Authorized baseline request",
                "Cross-user test request",
                "Response comparison",
            ],
            depends_on=["api-authentication-001"],
        ),
        build_step(
            step_id="api-function-authorization-001",
            phase=PlanPhase.AUTHORIZATION,
            title="Validate API function-level authorization",
            description=(
                "Test whether lower-privileged approved accounts can invoke "
                "administrative or restricted API functions."
            ),
            execution_level=ExecutionLevel.INTRUSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "burp-suite",
            ],
            evidence_requirements=[
                "Role mapping",
                "Restricted operation baseline",
                "Lower-privileged test result",
            ],
            depends_on=["api-authentication-001"],
        ),
        build_step(
            step_id="api-input-001",
            phase=PlanPhase.INPUT_VALIDATION,
            title="Assess API input and schema validation",
            description=(
                "Review type enforcement, unexpected fields, mass-assignment "
                "behavior, malformed input handling, and business-rule "
                "validation."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "schema-fuzzer",
            ],
            evidence_requirements=[
                "Baseline API request",
                "Controlled modified request",
                "Response and state comparison",
            ],
            depends_on=["api-inventory-001"],
        ),
        build_step(
            step_id="api-exposure-001",
            phase=PlanPhase.CONFIGURATION,
            title="Review API data exposure and operational controls",
            description=(
                "Assess excessive response fields, verbose errors, rate "
                "limiting, version exposure, caching, and security headers."
            ),
            execution_level=ExecutionLevel.ACTIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            tool_candidates=[
                "custom-http-client",
                "nuclei",
            ],
            evidence_requirements=[
                "Response-field comparison",
                "Error response evidence",
                "Rate-limit observations",
            ],
            depends_on=["api-inventory-001"],
        ),
    ]


def build_final_steps(
    targets: list[str],
    permitted_levels: set[str],
    previous_steps: list[PlanStep],
) -> list[PlanStep]:
    """Create evidence-validation and reporting stages."""

    dependencies = [
        step.id
        for step in previous_steps
        if step.phase not in {PlanPhase.SCOPE, PlanPhase.REPORTING}
    ]

    return [
        build_step(
            step_id="evidence-001",
            phase=PlanPhase.EVIDENCE,
            title="Validate and classify collected evidence",
            description=(
                "Separate observations, hypotheses, rejected false positives, "
                "and confirmed findings. Confirm reproducibility and impact "
                "before assigning vulnerability status."
            ),
            execution_level=ExecutionLevel.PASSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            evidence_requirements=[
                "Reproducible evidence",
                "False-positive analysis",
                "Affected asset mapping",
                "Impact justification",
            ],
            depends_on=dependencies,
        ),
        build_step(
            step_id="reporting-001",
            phase=PlanPhase.REPORTING,
            title="Generate the VAPT report",
            description=(
                "Produce the executive summary, scope, methodology, findings, "
                "supporting evidence, risk ratings, remediation guidance, and "
                "assessment limitations."
            ),
            execution_level=ExecutionLevel.PASSIVE,
            permitted_levels=permitted_levels,
            targets=targets,
            evidence_requirements=[
                "Confirmed finding records",
                "Evidence references",
                "Risk rationale",
                "Remediation recommendations",
            ],
            depends_on=["evidence-001"],
        ),
    ]


def build_assessment_plan(
    request: AssessmentRequest,
    validated: AssessmentValidationResponse,
) -> AssessmentPlanResponse:
    """Build a structured Web and API VAPT plan."""

    supported_types = {AssetType.WEB, AssetType.API}
    target_types = {target.asset_type for target in validated.targets}
    unsupported_types = target_types - supported_types

    if unsupported_types:
        unsupported = ", ".join(sorted(asset_type.value for asset_type in unsupported_types))
        raise UnsupportedPlannerTargetError(
            "The current planner supports only web and API targets. "
            f"Unsupported target types: {unsupported}"
        )

    permitted_levels = set(validated.permitted_execution_levels)
    target_values = [target.normalized_value for target in validated.targets]

    steps = build_common_steps(target_values, permitted_levels)

    web_targets = [
        target.normalized_value
        for target in validated.targets
        if target.asset_type is AssetType.WEB
    ]
    api_targets = [
        target.normalized_value
        for target in validated.targets
        if target.asset_type is AssetType.API
    ]

    if web_targets:
        steps.extend(build_web_steps(web_targets, permitted_levels))

    if api_targets:
        steps.extend(build_api_steps(api_targets, permitted_levels))

    steps.extend(
        build_final_steps(
            target_values,
            permitted_levels,
            steps,
        )
    )

    return AssessmentPlanResponse(
        assessment_name=request.name,
        plan_version="0.1.0",
        asset_types=sorted(
            target_types,
            key=lambda asset_type: asset_type.value,
        ),
        targets=validated.targets,
        permitted_execution_levels=(validated.permitted_execution_levels),
        rate_limit_per_second=validated.rate_limit_per_second,
        steps=steps,
    )

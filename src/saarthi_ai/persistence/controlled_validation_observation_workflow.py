"""Tracked Phase 6C low-risk validation observation workflow."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from saarthi_ai.controlled_validation.clickjacking import (
    ClickjackingClassification,
    ClickjackingValidationResult,
    analyze_clickjacking_protection,
)
from saarthi_ai.controlled_validation.csrf_surface import (
    CsrfSurfaceClassification,
    CsrfSurfaceValidationResult,
)
from saarthi_ai.controlled_validation.executor import (
    ControlledValidationExecutionDecision,
    ControlledValidationExecutionRequest,
    evaluate_controlled_validation_execution,
)
from saarthi_ai.controlled_validation.models import (
    ControlledValidationAction,
)
from saarthi_ai.controlled_validation.observation import (
    ControlledValidationObservationResult,
    execute_bounded_observation,
)
from saarthi_ai.controlled_validation.parameter_surface import (
    ParameterSurfaceClassification,
    ParameterSurfaceValidationResult,
    analyze_parameter_surface,
)
from saarthi_ai.controlled_validation.session_cookie import (
    CookieAttributeObservation,
    SessionCookieClassification,
    SessionCookieValidationResult,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.http_workflow import fail_execution_safely
from saarthi_ai.persistence.models import (
    AuditEventType,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)

DEFAULT_EVIDENCE_ROOT = (
    Path("evidence") / "controlled-validation-observations"
)

ValidatorAnalysis = (
    ClickjackingValidationResult
    | ParameterSurfaceValidationResult
    | SessionCookieValidationResult
    | CsrfSurfaceValidationResult
)


class ControlledValidationObservationWorkflowError(RuntimeError):
    """Raised when a tracked Phase 6C observation cannot complete."""


@dataclass(frozen=True)
class TrackedControlledValidationObservation:
    """Persistent result for one bounded controlled observation."""

    execution: ExecutionRecord
    observation: ControlledValidationObservationResult
    evidence: EvidenceRecord
    validator_analysis: ValidatorAnalysis | None = None
    reused_existing_evidence: bool = False


def _validate_target_scope(
    target_url: str,
    execution: ExecutionRecord,
) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InvalidStateTransitionError(
            "A valid HTTP or HTTPS target URL without credentials is required."
        )

    if not _domain_in_execution_scope(hostname, execution):
        raise InvalidStateTransitionError(
            f"Target '{hostname}' is not associated with this execution."
        )


def _find_matching_plan(
    database: SaarthiDatabase,
    request: ControlledValidationExecutionRequest,
) -> EvidenceRecord | None:
    validation = request.validation

    plans = database.list_evidence(
        validation.execution_id,
        evidence_type=EvidenceType.CONTROLLED_VALIDATION_PLAN,
    )

    for evidence in plans:
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == validation.target_url
            and metadata.get("action") == validation.action.value
            and metadata.get("requested_requests")
            == validation.requested_requests
            and metadata.get("reversible") is validation.reversible
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
        ):
            return evidence

    return None



def _find_matching_observation(
    database: SaarthiDatabase,
    request: ControlledValidationExecutionRequest,
    *,
    plan_evidence: EvidenceRecord,
) -> EvidenceRecord | None:
    """Return an equivalent persisted observation, if one exists."""

    validation = request.validation
    policy = evaluate_controlled_validation_execution(request)

    evidence_items = database.list_evidence(
        validation.execution_id,
        evidence_type=(
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
        ),
    )

    for evidence in evidence_items:
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == validation.target_url
            and metadata.get("action") == validation.action.value
            and metadata.get("method") == policy.method
            and metadata.get("plan_evidence_id")
            == plan_evidence.evidence_id
            and metadata.get("max_response_bytes")
            == policy.max_response_bytes
            and metadata.get("follow_redirects")
            is policy.follow_redirects
            and metadata.get("request_attempted") is True
            and metadata.get("network_activity") is True
        ):
            return evidence

    return None


def _observation_from_evidence(
    request: ControlledValidationExecutionRequest,
    evidence: EvidenceRecord,
) -> ControlledValidationObservationResult:
    """Rebuild a safe observation summary without another request."""

    policy = evaluate_controlled_validation_execution(request)
    metadata = evidence.metadata

    return ControlledValidationObservationResult(
        policy=policy,
        request_attempted=True,
        response_received=True,
        method=str(metadata.get("method") or policy.method),
        target_url=request.validation.target_url,
        final_url=(
            str(metadata["final_url"])
            if metadata.get("final_url") is not None
            else request.validation.target_url
        ),
        status_code=int(metadata.get("status_code") or 0),
        http_version=(
            str(metadata["http_version"])
            if metadata.get("http_version") is not None
            else None
        ),
        content_type=(
            str(metadata["content_type"])
            if metadata.get("content_type") is not None
            else None
        ),
        response_headers=None,
        body_bytes_captured=int(
            metadata.get("body_bytes_captured") or 0
        ),
        body_truncated=bool(metadata.get("body_truncated")),
        body_sha256=(
            str(metadata["body_sha256"])
            if metadata.get("body_sha256") is not None
            else None
        ),
    )


def _validator_analysis_from_evidence(
    evidence: EvidenceRecord,
) -> ValidatorAnalysis | None:
    """Rebuild a persisted bounded validator summary."""

    metadata = evidence.metadata
    validator_id = metadata.get("validator_id")

    if validator_id == "6C.2-clickjacking-header-validation":
        try:
            classification = ClickjackingClassification(
                str(metadata["validator_classification"])
            )
        except (KeyError, ValueError):
            return None

        protection_sources = metadata.get("protection_sources")
        csp_sources = metadata.get("csp_frame_ancestors")

        return ClickjackingValidationResult(
            validator_id=validator_id,
            classification=classification,
            reason=str(metadata.get("validator_reason") or ""),
            protection_sources=tuple(
                item
                for item in protection_sources
                if isinstance(item, str)
            )
            if isinstance(protection_sources, list)
            else (),
            csp_frame_ancestors=tuple(
                item
                for item in csp_sources
                if isinstance(item, str)
            )
            if isinstance(csp_sources, list)
            else (),
            x_frame_options=(
                str(metadata["x_frame_options"])
                if metadata.get("x_frame_options") is not None
                else None
            ),
            response_status_code=int(
                metadata.get("status_code") or 0
            ),
            content_type=(
                str(metadata["content_type"])
                if metadata.get("content_type") is not None
                else None
            ),
        )

    if validator_id == "6C.3-http-parameter-surface-validation":
        try:
            classification = ParameterSurfaceClassification(
                str(metadata["validator_classification"])
            )
        except (KeyError, ValueError):
            return None

        def string_tuple(key: str) -> tuple[str, ...]:
            value = metadata.get(key)
            return (
                tuple(
                    item
                    for item in value
                    if isinstance(item, str)
                )
                if isinstance(value, list)
                else ()
            )

        return ParameterSurfaceValidationResult(
            validator_id=validator_id,
            classification=classification,
            reason=str(metadata.get("validator_reason") or ""),
            parameter_count=int(
                metadata.get("parameter_count") or 0
            ),
            unique_parameter_count=int(
                metadata.get("unique_parameter_count") or 0
            ),
            duplicate_parameter_names=string_tuple(
                "duplicate_parameter_names"
            ),
            variant_parameter_groups=string_tuple(
                "variant_parameter_groups"
            ),
            blank_parameter_name_count=int(
                metadata.get("blank_parameter_name_count") or 0
            ),
            blank_value_parameter_names=string_tuple(
                "blank_value_parameter_names"
            ),
            malformed_percent_encoding=bool(
                metadata.get("malformed_percent_encoding")
            ),
            semicolon_delimiter_observed=bool(
                metadata.get("semicolon_delimiter_observed")
            ),
            analysis_truncated=bool(
                metadata.get("analysis_truncated")
            ),
        )

    if validator_id == "6C.4-session-cookie-attribute-validation":
        try:
            classification = SessionCookieClassification(
                str(metadata["validator_classification"])
            )
        except (KeyError, ValueError):
            return None

        raw_observations = metadata.get("cookie_observations")
        observations: list[CookieAttributeObservation] = []
        if isinstance(raw_observations, list):
            for item in raw_observations:
                if not isinstance(item, dict):
                    continue
                fingerprint = item.get("cookie_name_sha256")
                issues = item.get("issues")
                if (
                    not isinstance(fingerprint, str)
                    or len(fingerprint) != 64
                ):
                    continue
                observations.append(
                    CookieAttributeObservation(
                        cookie_name_sha256=fingerprint,
                        secure=bool(item.get("secure")),
                        http_only=bool(item.get("http_only")),
                        same_site=(
                            str(item["same_site"])
                            if item.get("same_site") is not None
                            else None
                        ),
                        path_is_root=bool(
                            item.get("path_is_root")
                        ),
                        domain_present=bool(
                            item.get("domain_present")
                        ),
                        host_prefix=bool(
                            item.get("host_prefix")
                        ),
                        secure_prefix=bool(
                            item.get("secure_prefix")
                        ),
                        issues=tuple(
                            issue
                            for issue in issues
                            if isinstance(issue, str)
                        )
                        if isinstance(issues, list)
                        else (),
                    )
                )

        raw_issue_counts = metadata.get("issue_counts")
        issue_counts = (
            tuple(
                (str(key), int(value))
                for key, value in raw_issue_counts.items()
                if isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            )
            if isinstance(raw_issue_counts, dict)
            else ()
        )

        return SessionCookieValidationResult(
            validator_id=validator_id,
            classification=classification,
            reason=str(metadata.get("validator_reason") or ""),
            cookie_count=int(metadata.get("cookie_count") or 0),
            cookies_with_issues=int(
                metadata.get("cookies_with_issues") or 0
            ),
            issue_counts=tuple(sorted(issue_counts)),
            cookie_observations=tuple(observations),
            analysis_truncated=bool(
                metadata.get("analysis_truncated")
            ),
            malformed_header_count=int(
                metadata.get("malformed_header_count") or 0
            ),
        )

    if validator_id == "6C.2-csrf-protection-surface-validation":
        try:
            classification = CsrfSurfaceClassification(
                str(metadata["validator_classification"])
            )
        except (KeyError, ValueError):
            return None

        protection_sources = metadata.get("protection_sources")
        return CsrfSurfaceValidationResult(
            validator_id=validator_id,
            classification=classification,
            reason=str(metadata.get("validator_reason") or ""),
            form_count=int(metadata.get("form_count") or 0),
            post_form_count=int(
                metadata.get("post_form_count") or 0
            ),
            forms_with_token_signal=int(
                metadata.get("forms_with_token_signal") or 0
            ),
            forms_without_token_signal=int(
                metadata.get("forms_without_token_signal") or 0
            ),
            cross_origin_action_count=int(
                metadata.get("cross_origin_action_count") or 0
            ),
            cookie_count=int(metadata.get("cookie_count") or 0),
            same_site_protected_cookie_count=int(
                metadata.get(
                    "same_site_protected_cookie_count"
                )
                or 0
            ),
            protection_sources=tuple(
                item
                for item in protection_sources
                if isinstance(item, str)
            )
            if isinstance(protection_sources, list)
            else (),
            body_truncated=bool(metadata.get("body_truncated")),
            analysis_truncated=bool(
                metadata.get("analysis_truncated")
            ),
        )

    return None


def _audit_failure_safely(
    database: SaarthiDatabase,
    execution_id: str,
    *,
    actor: str,
    error: Exception,
    evidence_path: str | None,
    evidence_registered: bool,
    request_attempted: bool,
) -> None:
    """Record a failure without replacing the original exception."""

    orphan_file_removed = False

    if evidence_path is not None and not evidence_registered:
        try:
            Path(evidence_path).unlink(missing_ok=True)
            orphan_file_removed = not Path(evidence_path).exists()
        except OSError:
            orphan_file_removed = False

    try:
        current_state = database.get_execution(execution_id).state
    except RuntimeError:
        current_state = ExecutionState.RUNNING

    try:
        database.add_audit_event(
            execution_id,
            event_type=AuditEventType.TOOL_FAILED,
            actor=actor,
            message=(
                "[6C][controlled-validation] "
                "Bounded HTTP observation failed."
            ),
            details={
                "phase_code": "6C",
                "error_type": type(error).__name__,
                "error": str(error),
                "execution_state": current_state.value,
                "request_attempted": request_attempted,
                "evidence_registered": evidence_registered,
                "orphan_file_removed": orphan_file_removed,
                "retry_allowed": False,
                "requires_new_execution": True,
            },
        )
    except RuntimeError:
        pass

def _serialize_observation(
    request: ControlledValidationExecutionRequest,
    observation: ControlledValidationObservationResult,
    *,
    plan_evidence: EvidenceRecord,
    validator_analysis: ValidatorAnalysis | None = None,
) -> dict[str, object]:
    validation = request.validation

    payload: dict[str, object] = {
        "schema_version": "1.0",
        "phase": "6C",
        "evidence_type": (
            EvidenceType.CONTROLLED_VALIDATION_OBSERVATION.value
        ),
        "collected_at": datetime.now(UTC).isoformat(),
        "plan": {
            "evidence_id": plan_evidence.evidence_id,
            "sha256": plan_evidence.sha256,
        },
        "request": {
            "execution_id": validation.execution_id,
            "target_url": validation.target_url,
            "action": validation.action.value,
            "method": observation.method,
            "requested_requests": validation.requested_requests,
            "explicitly_approved": validation.explicitly_approved,
            "reversible": validation.reversible,
            "timeout_seconds": observation.policy.timeout_seconds,
            "max_response_bytes": (
                observation.policy.max_response_bytes
            ),
            "follow_redirects": observation.policy.follow_redirects,
        },
        "policy": {
            "decision": observation.policy.decision.value,
            "reason": observation.policy.reason,
        },
        "execution": {
            "request_attempted": observation.request_attempted,
            "response_received": observation.response_received,
            "network_activity": observation.request_attempted,
            "subprocess_started": False,
            "payload_sent": False,
        },
        "response": {
            "final_url": observation.final_url,
            "status_code": observation.status_code,
            "http_version": observation.http_version,
            "content_type": observation.content_type,
            "headers": observation.response_headers,
            "body_bytes_captured": observation.body_bytes_captured,
            "body_truncated": observation.body_truncated,
            "body_sha256": observation.body_sha256,
        },
    }

    if validator_analysis is not None:
        serialized_analysis: dict[str, object] = {
            "validator_id": validator_analysis.validator_id,
            "classification": (
                validator_analysis.classification.value
            ),
            "reason": validator_analysis.reason,
            "payload_generated": validator_analysis.payload_generated,
        }

        if isinstance(
            validator_analysis,
            ClickjackingValidationResult,
        ):
            serialized_analysis.update(
                {
                    "protection_sources": list(
                        validator_analysis.protection_sources
                    ),
                    "csp_frame_ancestors": list(
                        validator_analysis.csp_frame_ancestors
                    ),
                    "x_frame_options": (
                        validator_analysis.x_frame_options
                    ),
                    "header_only": validator_analysis.header_only,
                    "exploit_page_generated": (
                        validator_analysis.exploit_page_generated
                    ),
                    "browser_launched": (
                        validator_analysis.browser_launched
                    ),
                }
            )
        elif isinstance(
            validator_analysis,
            ParameterSurfaceValidationResult,
        ):
            serialized_analysis.update(
                {
                    "parameter_count": (
                        validator_analysis.parameter_count
                    ),
                    "unique_parameter_count": (
                        validator_analysis.unique_parameter_count
                    ),
                    "duplicate_parameter_names": list(
                        validator_analysis.duplicate_parameter_names
                    ),
                    "variant_parameter_groups": list(
                        validator_analysis.variant_parameter_groups
                    ),
                    "blank_parameter_name_count": (
                        validator_analysis.blank_parameter_name_count
                    ),
                    "blank_value_parameter_names": list(
                        validator_analysis.blank_value_parameter_names
                    ),
                    "malformed_percent_encoding": (
                        validator_analysis.malformed_percent_encoding
                    ),
                    "semicolon_delimiter_observed": (
                        validator_analysis.semicolon_delimiter_observed
                    ),
                    "analysis_truncated": (
                        validator_analysis.analysis_truncated
                    ),
                    "target_unchanged": (
                        validator_analysis.target_unchanged
                    ),
                    "parameters_mutated": (
                        validator_analysis.parameters_mutated
                    ),
                    "parser_attack_sent": (
                        validator_analysis.parser_attack_sent
                    ),
                }
            )
        elif isinstance(
            validator_analysis,
            SessionCookieValidationResult,
        ):
            serialized_analysis.update(
                {
                    "cookie_count": validator_analysis.cookie_count,
                    "cookies_with_issues": (
                        validator_analysis.cookies_with_issues
                    ),
                    "issue_counts": dict(
                        validator_analysis.issue_counts
                    ),
                    "cookie_observations": [
                        {
                            "cookie_name_sha256": (
                                item.cookie_name_sha256
                            ),
                            "secure": item.secure,
                            "http_only": item.http_only,
                            "same_site": item.same_site,
                            "path_is_root": item.path_is_root,
                            "domain_present": item.domain_present,
                            "host_prefix": item.host_prefix,
                            "secure_prefix": item.secure_prefix,
                            "issues": list(item.issues),
                        }
                        for item in (
                            validator_analysis.cookie_observations
                        )
                    ],
                    "analysis_truncated": (
                        validator_analysis.analysis_truncated
                    ),
                    "malformed_header_count": (
                        validator_analysis.malformed_header_count
                    ),
                    "cookie_values_discarded": (
                        validator_analysis.cookie_values_discarded
                    ),
                    "raw_set_cookie_stored": (
                        validator_analysis.raw_set_cookie_stored
                    ),
                    "cookie_replayed": (
                        validator_analysis.cookie_replayed
                    ),
                    "credential_header_sent": (
                        validator_analysis.credential_header_sent
                    ),
                }
            )
        else:
            serialized_analysis.update(
                {
                    "form_count": validator_analysis.form_count,
                    "post_form_count": (
                        validator_analysis.post_form_count
                    ),
                    "forms_with_token_signal": (
                        validator_analysis.forms_with_token_signal
                    ),
                    "forms_without_token_signal": (
                        validator_analysis.forms_without_token_signal
                    ),
                    "cross_origin_action_count": (
                        validator_analysis.cross_origin_action_count
                    ),
                    "cookie_count": validator_analysis.cookie_count,
                    "same_site_protected_cookie_count": (
                        validator_analysis
                        .same_site_protected_cookie_count
                    ),
                    "protection_sources": list(
                        validator_analysis.protection_sources
                    ),
                    "body_truncated": (
                        validator_analysis.body_truncated
                    ),
                    "analysis_truncated": (
                        validator_analysis.analysis_truncated
                    ),
                    "token_values_discarded": (
                        validator_analysis.token_values_discarded
                    ),
                    "form_submitted": (
                        validator_analysis.form_submitted
                    ),
                    "browser_launched": (
                        validator_analysis.browser_launched
                    ),
                    "request_body_sent": (
                        validator_analysis.request_body_sent
                    ),
                }
            )

        payload["validator_analysis"] = serialized_analysis

    return payload


def _validator_metadata(
    analysis: ValidatorAnalysis | None,
) -> dict[str, object]:
    """Return catalog-safe metadata for one optional validator."""

    if analysis is None:
        return {
            "validator_id": None,
            "validator_classification": None,
            "validator_reason": None,
            "payload_generated": False,
        }

    metadata: dict[str, object] = {
        "validator_id": analysis.validator_id,
        "validator_classification": analysis.classification.value,
        "validator_reason": analysis.reason,
        "payload_generated": analysis.payload_generated,
    }

    if isinstance(analysis, ClickjackingValidationResult):
        metadata.update(
            {
                "protection_sources": list(
                    analysis.protection_sources
                ),
                "csp_frame_ancestors": list(
                    analysis.csp_frame_ancestors
                ),
                "x_frame_options": analysis.x_frame_options,
                "header_only": analysis.header_only,
                "exploit_page_generated": (
                    analysis.exploit_page_generated
                ),
                "browser_launched": analysis.browser_launched,
            }
        )
    elif isinstance(analysis, ParameterSurfaceValidationResult):
        metadata.update(
            {
                "parameter_count": analysis.parameter_count,
                "unique_parameter_count": (
                    analysis.unique_parameter_count
                ),
                "duplicate_parameter_names": list(
                    analysis.duplicate_parameter_names
                ),
                "variant_parameter_groups": list(
                    analysis.variant_parameter_groups
                ),
                "blank_parameter_name_count": (
                    analysis.blank_parameter_name_count
                ),
                "blank_value_parameter_names": list(
                    analysis.blank_value_parameter_names
                ),
                "malformed_percent_encoding": (
                    analysis.malformed_percent_encoding
                ),
                "semicolon_delimiter_observed": (
                    analysis.semicolon_delimiter_observed
                ),
                "analysis_truncated": analysis.analysis_truncated,
                "target_unchanged": analysis.target_unchanged,
                "parameters_mutated": analysis.parameters_mutated,
                "parser_attack_sent": analysis.parser_attack_sent,
            }
        )
    elif isinstance(analysis, SessionCookieValidationResult):
        metadata.update(
            {
                "cookie_count": analysis.cookie_count,
                "cookies_with_issues": analysis.cookies_with_issues,
                "issue_counts": dict(analysis.issue_counts),
                "cookie_observations": [
                    {
                        "cookie_name_sha256": (
                            item.cookie_name_sha256
                        ),
                        "secure": item.secure,
                        "http_only": item.http_only,
                        "same_site": item.same_site,
                        "path_is_root": item.path_is_root,
                        "domain_present": item.domain_present,
                        "host_prefix": item.host_prefix,
                        "secure_prefix": item.secure_prefix,
                        "issues": list(item.issues),
                    }
                    for item in analysis.cookie_observations
                ],
                "analysis_truncated": analysis.analysis_truncated,
                "malformed_header_count": (
                    analysis.malformed_header_count
                ),
                "cookie_values_discarded": (
                    analysis.cookie_values_discarded
                ),
                "raw_set_cookie_stored": (
                    analysis.raw_set_cookie_stored
                ),
                "cookie_replayed": analysis.cookie_replayed,
                "credential_header_sent": (
                    analysis.credential_header_sent
                ),
            }
        )
    else:
        metadata.update(
            {
                "form_count": analysis.form_count,
                "post_form_count": analysis.post_form_count,
                "forms_with_token_signal": (
                    analysis.forms_with_token_signal
                ),
                "forms_without_token_signal": (
                    analysis.forms_without_token_signal
                ),
                "cross_origin_action_count": (
                    analysis.cross_origin_action_count
                ),
                "cookie_count": analysis.cookie_count,
                "same_site_protected_cookie_count": (
                    analysis.same_site_protected_cookie_count
                ),
                "protection_sources": list(
                    analysis.protection_sources
                ),
                "body_truncated": analysis.body_truncated,
                "analysis_truncated": analysis.analysis_truncated,
                "token_values_discarded": (
                    analysis.token_values_discarded
                ),
                "form_submitted": analysis.form_submitted,
                "browser_launched": analysis.browser_launched,
                "request_body_sent": analysis.request_body_sent,
            }
        )

    return metadata


def _write_evidence_atomically(
    payload: dict[str, object],
    *,
    evidence_root: Path | None = None,
) -> tuple[str, str, int]:
    evidence_directory = evidence_root or DEFAULT_EVIDENCE_ROOT
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_id = f"controlled-validation-observation-{uuid4()}"
    evidence_path = evidence_directory / f"{evidence_id}.json"

    serialized = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")

    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=evidence_directory,
            prefix=".controlled-validation-observation-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.replace(temporary_path, evidence_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return (
        str(evidence_path),
        hashlib.sha256(serialized).hexdigest(),
        len(serialized),
    )


async def run_tracked_controlled_validation_observation(
    database: SaarthiDatabase,
    request: ControlledValidationExecutionRequest,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    actor: str = "controlled-validation-observer",
    evidence_root: Path | None = None,
) -> TrackedControlledValidationObservation:
    """Run or safely reuse one preplanned bounded observation."""

    validation = request.validation
    execution = database.get_execution(validation.execution_id)

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if validation.authorized is not True:
        raise InvalidStateTransitionError(
            "Controlled-validation request does not confirm authorization."
        )

    if (
        validation.active_testing
        and not execution.active_testing_allowed
    ):
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    if (
        validation.intrusive_testing
        and not execution.intrusive_testing_allowed
    ):
        raise InvalidStateTransitionError(
            "Execution does not allow intrusive testing."
        )

    _validate_target_scope(validation.target_url, execution)

    policy = evaluate_controlled_validation_execution(request)

    if (
        policy.decision
        is not ControlledValidationExecutionDecision.ALLOW
    ):
        raise ControlledValidationObservationWorkflowError(
            "Controlled-validation observation denied by policy: "
            f"{policy.reason}"
        )

    plan_evidence = _find_matching_plan(database, request)

    if plan_evidence is None:
        raise ControlledValidationObservationWorkflowError(
            "A matching approved Phase 6B controlled-validation plan "
            "is required before observation."
        )

    existing_evidence = _find_matching_observation(
        database,
        request,
        plan_evidence=plan_evidence,
    )

    if existing_evidence is not None:
        if execution.state not in {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
        }:
            raise InvalidStateTransitionError(
                "Existing controlled-validation observation evidence "
                "requires a terminal execution state."
            )

        observation = _observation_from_evidence(
            request,
            existing_evidence,
        )
        validator_analysis = _validator_analysis_from_evidence(
            existing_evidence
        )

        database.add_audit_event(
            validation.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6C][controlled-validation] "
                "Existing bounded observation reused."
            ),
            details={
                "phase_code": "6C",
                "evidence_id": existing_evidence.evidence_id,
                "evidence_sha256": existing_evidence.sha256,
                "plan_evidence_id": plan_evidence.evidence_id,
                "idempotent_reuse": True,
                "network_activity": False,
                "second_request_sent": False,
            },
        )

        return TrackedControlledValidationObservation(
            execution=execution,
            observation=observation,
            evidence=existing_evidence,
            validator_analysis=validator_analysis,
            reused_existing_evidence=True,
        )

    if execution.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Controlled-validation observation requires an execution in "
            f"'planned' state; current state is '{execution.state.value}'."
        )

    evidence_path: str | None = None
    evidence_registered = False
    observation: ControlledValidationObservationResult | None = None
    validator_analysis: ValidatorAnalysis | None = None

    execution = database.transition_execution(
        validation.execution_id,
        ExecutionState.RUNNING,
        actor=actor,
        reason="Approved bounded controlled-validation observation started.",
    )

    try:
        database.add_audit_event(
            validation.execution_id,
            event_type=AuditEventType.TOOL_STARTED,
            actor=actor,
            message=(
                "[6C][controlled-validation] "
                "Bounded HTTP observation started."
            ),
            details={
                "phase_code": "6C",
                "tool": "saarthi-controlled-validation-observer",
                "target_url": validation.target_url,
                "action": validation.action.value,
                "method": policy.method,
                "plan_evidence_id": plan_evidence.evidence_id,
                "requested_requests": validation.requested_requests,
            },
        )

        observation = await execute_bounded_observation(
            request,
            transport=transport,
        )

        if not observation.succeeded:
            raise ControlledValidationObservationWorkflowError(
                observation.error
                or "Controlled-validation observation did not succeed."
            )

        if (
            validation.action
            is ControlledValidationAction.CLICKJACKING_HEADER_VALIDATION
        ):
            validator_analysis = analyze_clickjacking_protection(
                status_code=observation.status_code,
                content_type=observation.content_type,
                headers=observation.response_headers,
            )
        elif (
            validation.action
            is ControlledValidationAction
            .HTTP_PARAMETER_SURFACE_VALIDATION
        ):
            validator_analysis = analyze_parameter_surface(
                validation.target_url
            )
        elif (
            validation.action
            is ControlledValidationAction
            .SESSION_COOKIE_ATTRIBUTE_VALIDATION
        ):
            validator_analysis = (
                observation.session_cookie_analysis
            )
            if validator_analysis is None:
                raise ControlledValidationObservationWorkflowError(
                    "Session-cookie analysis was not produced safely."
                )
        elif (
            validation.action
            is ControlledValidationAction
            .CSRF_PROTECTION_SURFACE_VALIDATION
        ):
            validator_analysis = observation.csrf_surface_analysis
            if validator_analysis is None:
                raise ControlledValidationObservationWorkflowError(
                    "CSRF surface analysis was not produced safely."
                )

        database.add_audit_event(
            validation.execution_id,
            event_type=AuditEventType.TOOL_OUTPUT,
            actor=actor,
            message=(
                "[6C][controlled-validation] "
                f"HTTP {observation.status_code}; "
                f"captured={observation.body_bytes_captured}; "
                f"truncated="
                f"{str(observation.body_truncated).lower()}."
            ),
            details={
                "phase_code": "6C",
                "status_code": observation.status_code,
                "final_url": observation.final_url,
                "http_version": observation.http_version,
                "content_type": observation.content_type,
                "body_bytes_captured": (
                    observation.body_bytes_captured
                ),
                "body_truncated": observation.body_truncated,
                "body_sha256": observation.body_sha256,
                "validator_id": (
                    validator_analysis.validator_id
                    if validator_analysis is not None
                    else None
                ),
                "validator_classification": (
                    validator_analysis.classification.value
                    if validator_analysis is not None
                    else None
                ),
            },
        )

        payload = _serialize_observation(
            request,
            observation,
            plan_evidence=plan_evidence,
            validator_analysis=validator_analysis,
        )
        payload["phase"] = "6C"

        evidence_path, evidence_sha256, evidence_size = (
            _write_evidence_atomically(
                payload,
                evidence_root=evidence_root,
            )
        )

        evidence = database.add_evidence(
            validation.execution_id,
            EvidenceCreate(
                evidence_type=(
                    EvidenceType.CONTROLLED_VALIDATION_OBSERVATION
                ),
                source="saarthi-controlled-validation-observer",
                path=evidence_path,
                sha256=evidence_sha256,
                size_bytes=evidence_size,
                content_type="application/json",
                step_id="controlled-validation-observation-001",
                tool_name="saarthi-controlled-validation-observer",
                metadata={
                    "phase": "6C",
                    "target_url": validation.target_url,
                    "action": validation.action.value,
                    "method": observation.method,
                    "status_code": observation.status_code,
                    "final_url": observation.final_url,
                    "http_version": observation.http_version,
                    "content_type": observation.content_type,
                    "body_bytes_captured": (
                        observation.body_bytes_captured
                    ),
                    "body_truncated": (
                        observation.body_truncated
                    ),
                    "body_sha256": observation.body_sha256,
                    "plan_evidence_id": plan_evidence.evidence_id,
                    "max_response_bytes": (
                        observation.policy.max_response_bytes
                    ),
                    "follow_redirects": (
                        observation.policy.follow_redirects
                    ),
                    "request_attempted": True,
                    "network_activity": True,
                    **_validator_metadata(validator_analysis),
                },
            ),
            actor=actor,
        )
        evidence_registered = True

        database.add_audit_event(
            validation.execution_id,
            event_type=AuditEventType.TOOL_COMPLETED,
            actor=actor,
            message=(
                "[6C][controlled-validation] "
                "Bounded HTTP observation persisted."
            ),
            details={
                "phase_code": "6C",
                "evidence_id": evidence.evidence_id,
                "evidence_sha256": evidence.sha256,
                "plan_evidence_id": plan_evidence.evidence_id,
                "status_code": observation.status_code,
            },
        )

        execution = database.transition_execution(
            validation.execution_id,
            ExecutionState.ANALYZING,
            actor=actor,
            reason=(
                "Controlled-validation observation evidence "
                "is ready for analysis."
            ),
        )

        execution = database.transition_execution(
            validation.execution_id,
            ExecutionState.COMPLETED,
            actor=actor,
            reason=(
                "Phase 6C tracked controlled-validation "
                "observation completed."
            ),
        )

        return TrackedControlledValidationObservation(
            execution=execution,
            observation=observation,
            evidence=evidence,
            validator_analysis=validator_analysis,
        )

    except (
        ControlledValidationObservationWorkflowError,
        InvalidStateTransitionError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        _audit_failure_safely(
            database,
            validation.execution_id,
            actor=actor,
            error=exc,
            evidence_path=evidence_path,
            evidence_registered=evidence_registered,
            request_attempted=(
                observation.request_attempted
                if observation is not None
                else False
            ),
        )

        fail_execution_safely(
            database,
            validation.execution_id,
            actor=actor,
            reason=str(exc),
        )

        if isinstance(
            exc,
            ControlledValidationObservationWorkflowError,
        ):
            raise

        raise ControlledValidationObservationWorkflowError(
            "Controlled-validation observation failed safely."
        ) from exc

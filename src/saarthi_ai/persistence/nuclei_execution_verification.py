"""Non-executing verification for persisted Nuclei preparation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from saarthi_ai.execution.nuclei_adapter import (
    MAX_NUCLEI_OUTPUT_BYTES,
    MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS,
    NucleiExecutionPlan,
    NucleiRunnerBinding,
    build_nuclei_runner_binding,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.http_intelligence_workflow import (
    _domain_in_execution_scope,
)
from saarthi_ai.persistence.models import (
    EvidenceRecord,
    EvidenceType,
    ExecutionRecord,
    ExecutionState,
)


class NucleiExecutionVerificationError(RuntimeError):
    """Raised when persisted Nuclei preparation cannot be verified."""


@dataclass(frozen=True)
class NucleiExecutionVerificationRequest:
    """Fresh operator authorization for preparation verification."""

    target_url: str
    arguments: tuple[str, ...]
    authorization_confirmed: bool
    active_testing_allowed: bool
    explicitly_approved: bool


@dataclass(frozen=True)
class VerifiedNucleiPreparation:
    """Exact persisted Nuclei preparation ready for a later run phase."""

    execution: ExecutionRecord
    evidence: EvidenceRecord
    plan: NucleiExecutionPlan
    binding: NucleiRunnerBinding
    evidence_file_sha256: str
    evidence_file_size_bytes: int


def _validate_execution(
    execution: ExecutionRecord,
    request: NucleiExecutionVerificationRequest,
) -> None:
    """Validate stored permission, fresh approval and execution scope."""

    if not execution.authorization_confirmed:
        raise InvalidStateTransitionError(
            "Execution does not have confirmed authorization."
        )

    if not execution.active_testing_allowed:
        raise InvalidStateTransitionError(
            "Execution does not allow active testing."
        )

    if request.authorization_confirmed is not True:
        raise InvalidStateTransitionError(
            "Nuclei execution verification does not confirm authorization."
        )

    if request.active_testing_allowed is not True:
        raise InvalidStateTransitionError(
            "Nuclei execution verification does not confirm active testing."
        )

    if request.explicitly_approved is not True:
        raise InvalidStateTransitionError(
            "Fresh explicit operator approval is required for Nuclei execution."
        )

    parsed = urlsplit(request.target_url)
    hostname = parsed.hostname

    if hostname is None or not _domain_in_execution_scope(
        hostname,
        execution,
    ):
        raise InvalidStateTransitionError(
            f"Target '{hostname or request.target_url}' is not "
            "associated with this execution."
        )

    if execution.state is not ExecutionState.PLANNED:
        raise InvalidStateTransitionError(
            "Nuclei execution verification requires an execution in "
            f"'planned' state; current state is '{execution.state.value}'."
        )


def _matching_preparation(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiExecutionVerificationRequest,
) -> EvidenceRecord | None:
    """Return the newest exact non-executed preparation record."""

    preparations = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_PREPARATION,
    )

    for evidence in reversed(preparations):
        metadata = evidence.metadata

        if (
            metadata.get("target_url") == request.target_url
            and metadata.get("arguments") == list(request.arguments)
            and metadata.get("process_timeout_seconds")
            == MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS
            and metadata.get("max_output_bytes")
            == MAX_NUCLEI_OUTPUT_BYTES
            and metadata.get("executed") is False
            and metadata.get("network_activity") is False
            and metadata.get("subprocess_started") is False
            and metadata.get("runner_invoked") is False
            and metadata.get("executable_resolved") is False
        ):
            return evidence

    return None


def _verify_evidence_file(
    evidence: EvidenceRecord,
) -> tuple[str, int]:
    """Verify evidence path, size and SHA-256 against its catalog record."""

    path = Path(evidence.path)

    if not path.is_file():
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation evidence file is missing."
        )

    try:
        evidence_bytes = path.read_bytes()
    except OSError as exc:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation evidence could not be read."
        ) from exc

    size_bytes = len(evidence_bytes)
    sha256 = hashlib.sha256(evidence_bytes).hexdigest()

    if evidence.size_bytes is None:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation does not contain a file size."
        )

    if evidence.sha256 is None:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation does not contain a SHA-256."
        )

    if size_bytes != evidence.size_bytes:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation file size does not match its catalog."
        )

    if sha256 != evidence.sha256:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation SHA-256 does not match its catalog."
        )

    return sha256, size_bytes


def verify_persisted_nuclei_preparation(
    database: SaarthiDatabase,
    execution_id: str,
    request: NucleiExecutionVerificationRequest,
) -> VerifiedNucleiPreparation:
    """Verify one exact persisted Nuclei preparation without execution."""

    execution = database.get_execution(execution_id)
    _validate_execution(execution, request)

    evidence = _matching_preparation(
        database,
        execution_id,
        request,
    )

    if evidence is None:
        raise NucleiExecutionVerificationError(
            "A matching persisted Nuclei preparation is required "
            "before controlled execution."
        )

    metadata = evidence.metadata

    request_timeout = metadata.get("request_timeout_seconds")
    rate_limit = metadata.get("rate_limit_per_second")
    concurrency = metadata.get("concurrency")

    if (
        not isinstance(request_timeout, int)
        or isinstance(request_timeout, bool)
        or not isinstance(rate_limit, int)
        or isinstance(rate_limit, bool)
        or not isinstance(concurrency, int)
        or isinstance(concurrency, bool)
    ):
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation contains invalid numeric bounds."
        )

    plan = NucleiExecutionPlan(
        tool_name="nuclei",
        target_url=request.target_url,
        arguments=request.arguments,
        request_timeout_seconds=request_timeout,
        rate_limit_per_second=rate_limit,
        concurrency=concurrency,
        process_timeout_seconds=MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_NUCLEI_OUTPUT_BYTES,
    )

    try:
        binding = build_nuclei_runner_binding(plan)
    except ValueError as exc:
        raise NucleiExecutionVerificationError(
            "Persisted Nuclei preparation does not match "
            "the approved runner contract."
        ) from exc

    evidence_sha256, evidence_size = _verify_evidence_file(
        evidence
    )

    return VerifiedNucleiPreparation(
        execution=execution,
        evidence=evidence,
        plan=plan,
        binding=binding,
        evidence_file_sha256=evidence_sha256,
        evidence_file_size_bytes=evidence_size,
    )

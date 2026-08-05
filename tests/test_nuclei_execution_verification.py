from __future__ import annotations

from pathlib import Path

import pytest

from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiExecutionRequest,
)
from saarthi_ai.persistence.database import (
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)
from saarthi_ai.persistence.nuclei_execution_verification import (
    NucleiExecutionVerificationError,
    NucleiExecutionVerificationRequest,
    verify_persisted_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preparation_workflow import (
    create_tracked_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preview_workflow import (
    create_tracked_nuclei_preview,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "nuclei-execution-verification.db"
    )
    repository.initialize()
    return repository


def create_preparation(
    database: SaarthiDatabase,
    tmp_path: Path,
    *,
    authorized: bool = True,
    active_testing_allowed: bool = True,
):
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Controlled Nuclei Execution",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=authorized,
            active_testing_allowed=active_testing_allowed,
        )
    )

    preview = create_tracked_nuclei_preview(
        database,
        execution.execution_id,
        NucleiDryRunRequest(
            target_url="https://example.com/",
            authorized=True,
            active_testing=True,
            approval_granted=True,
            rate_limit_per_second=1,
            concurrency=1,
            timeout_seconds=7,
        ),
        evidence_root=tmp_path / "preview",
    )

    preparation = create_tracked_nuclei_preparation(
        database,
        execution.execution_id,
        NucleiExecutionRequest(
            preview=preview.preview,
            authorization_confirmed=True,
            active_testing_allowed=True,
            explicitly_approved=True,
        ),
        evidence_root=tmp_path / "preparation",
    )

    return execution.execution_id, preparation


def make_request(preparation, **overrides):
    values = {
        "target_url": preparation.plan.target_url,
        "arguments": preparation.plan.arguments,
        "authorization_confirmed": True,
        "active_testing_allowed": True,
        "explicitly_approved": True,
    }
    values.update(overrides)
    return NucleiExecutionVerificationRequest(**values)


def test_verifies_exact_persisted_nuclei_preparation(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    verified = verify_persisted_nuclei_preparation(
        database,
        execution_id,
        make_request(preparation),
    )

    assert verified.execution.state is ExecutionState.PLANNED
    assert (
        verified.evidence.evidence_id
        == preparation.evidence.evidence_id
    )
    assert verified.plan.arguments == preparation.plan.arguments
    assert verified.binding.arguments == preparation.binding.arguments
    assert verified.binding.executed is False
    assert verified.binding.network_activity is False
    assert verified.binding.subprocess_started is False
    assert (
        verified.evidence_file_sha256
        == preparation.evidence.sha256
    )
    assert (
        verified.evidence_file_size_bytes
        == preparation.evidence.size_bytes
    )


def test_requires_fresh_explicit_approval(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="Fresh explicit operator approval",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(
                preparation,
                explicitly_approved=False,
            ),
        )


def test_rejects_changed_arguments(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    with pytest.raises(
        NucleiExecutionVerificationError,
        match="matching persisted Nuclei preparation",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(
                preparation,
                arguments=(
                    *preparation.plan.arguments,
                    "-severity",
                    "critical",
                ),
            ),
        )


def test_rejects_changed_target(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="not associated with this execution",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(
                preparation,
                target_url="https://outside.test/",
            ),
        )


def test_rejects_missing_preparation_file(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    Path(preparation.evidence.path).unlink()

    with pytest.raises(
        NucleiExecutionVerificationError,
        match="evidence file is missing",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(preparation),
        )


def test_rejects_tampered_preparation_file(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    Path(preparation.evidence.path).write_text(
        '{"tampered": true}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        NucleiExecutionVerificationError,
        match="file size does not match|SHA-256 does not match",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(preparation),
        )


def test_rejects_non_planned_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    database.transition_execution(
        execution_id,
        ExecutionState.RUNNING,
        actor="test",
        reason="Simulated premature transition.",
    )

    with pytest.raises(
        InvalidStateTransitionError,
        match="requires an execution in 'planned' state",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(preparation),
        )


def test_rejects_preparation_with_execution_flag_changed(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation = create_preparation(
        database,
        tmp_path,
    )

    with database.connect() as connection:
        import json

        row = connection.execute(
            """
            SELECT metadata_json
            FROM evidence
            WHERE evidence_id = ?
            """,
            (preparation.evidence.evidence_id,),
        ).fetchone()

        metadata = json.loads(row["metadata_json"])
        metadata["runner_invoked"] = True

        connection.execute(
            """
            UPDATE evidence
            SET metadata_json = ?
            WHERE evidence_id = ?
            """,
            (
                json.dumps(metadata),
                preparation.evidence.evidence_id,
            ),
        )

    with pytest.raises(
        NucleiExecutionVerificationError,
        match="matching persisted Nuclei preparation",
    ):
        verify_persisted_nuclei_preparation(
            database,
            execution_id,
            make_request(preparation),
        )

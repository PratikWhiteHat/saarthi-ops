"""Tests for the non-executing restricted-worker control plane."""

from __future__ import annotations

import json

import pytest

from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate
from saarthi_ai.persistence.restricted_worker_jobs import (
    WorkerJobError,
    WorkerJobState,
    approve_worker_job,
    create_worker_job,
    get_worker_job,
    list_worker_jobs,
    run_mock_worker,
)


def _database(tmp_path) -> tuple[SaarthiDatabase, str]:
    database = SaarthiDatabase(tmp_path / "worker.db")
    database.initialize()
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Worker control-plane test",
            asset_types=["url"],
            targets=["https://example.test/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
        )
    )
    return database, execution.execution_id


def test_creates_hashed_non_executable_job(tmp_path) -> None:
    database, execution_id = _database(tmp_path)

    job = create_worker_job(
        database,
        execution_id,
        tool_name="sqlmap",
        target_display="https://example.test/item?id=<redacted>",
        purpose="Validate one approved parameter.",
        timeout_seconds=60,
        rate_limit_per_second=2,
    )

    assert job.state is WorkerJobState.AWAITING_APPROVAL
    assert job.manifest["execution_contract"] == {
        "command_included": False,
        "arguments_included": False,
        "raw_shell_allowed": False,
        "automatic_retry": False,
    }
    assert len(job.manifest_sha256) == 64
    assert list_worker_jobs(database, execution_id=execution_id) == [job]


def test_records_approval_without_dispatch(tmp_path) -> None:
    database, execution_id = _database(tmp_path)
    job = create_worker_job(
        database,
        execution_id,
        tool_name="ffuf",
        target_display="https://example.test/<candidate>",
        purpose="Record a future bounded worker proposal.",
        timeout_seconds=30,
        rate_limit_per_second=1,
    )

    approved = approve_worker_job(
        database,
        job.job_id,
        actor="operator",
        reason="Approved for the recorded scope.",
    )

    assert approved.state is WorkerJobState.APPROVED
    assert approved.approval_actor == "operator"
    assert approved.result is None


def test_only_inert_mock_adapter_can_dispatch(tmp_path) -> None:
    database, execution_id = _database(tmp_path)
    job = create_worker_job(
        database,
        execution_id,
        tool_name="sqlmap",
        target_display="https://example.test/item?id=<redacted>",
        purpose="Non-executing proposal.",
        timeout_seconds=30,
        rate_limit_per_second=1,
    )
    approve_worker_job(
        database,
        job.job_id,
        actor="operator",
        reason="Approve control-plane record only.",
    )

    with pytest.raises(WorkerJobError, match="Only an inert mock"):
        run_mock_worker(database, job.job_id)


def test_mock_worker_completes_without_process_or_network(tmp_path) -> None:
    database, execution_id = _database(tmp_path)
    job = create_worker_job(
        database,
        execution_id,
        tool_name="mock",
        adapter_name="mock",
        target_display="local://inert-control-plane-test",
        purpose="Exercise the worker lifecycle without a tool.",
        timeout_seconds=5,
        rate_limit_per_second=1,
    )
    approve_worker_job(
        database,
        job.job_id,
        actor="operator",
        reason="Run the inert lifecycle test.",
    )

    completed = run_mock_worker(database, job.job_id)

    assert completed.state is WorkerJobState.COMPLETED
    assert completed.result is not None
    assert completed.result["network_activity"] is False
    assert completed.result["subprocess_started"] is False


def test_rejects_tampered_manifest(tmp_path) -> None:
    database, execution_id = _database(tmp_path)
    job = create_worker_job(
        database,
        execution_id,
        tool_name="mock",
        adapter_name="mock",
        target_display="local://inert",
        purpose="Integrity test.",
        timeout_seconds=5,
        rate_limit_per_second=1,
    )
    with database.connect() as connection:
        connection.execute(
            "UPDATE restricted_worker_jobs SET manifest_json = ? WHERE job_id = ?",
            (json.dumps({"tampered": True}), job.job_id),
        )

    with pytest.raises(WorkerJobError, match="integrity"):
        get_worker_job(database, job.job_id)

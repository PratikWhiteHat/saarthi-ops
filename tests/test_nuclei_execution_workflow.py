from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.execution.nuclei_adapter import (
    NucleiDryRunRequest,
    NucleiExecutionRequest,
)
from saarthi_ai.execution.tool_runner import (
    ToolOutputEvent,
    ToolRunnerError,
    ToolRunResult,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import (
    AuditEventType,
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
    create_tracked_nuclei_preparation,
)
from saarthi_ai.persistence.nuclei_preview_workflow import (
    create_tracked_nuclei_preview,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(
        tmp_path / "nuclei-execution.db"
    )
    repository.initialize()
    return repository


def create_preparation(
    database: SaarthiDatabase,
    tmp_path: Path,
):
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Controlled Nuclei Execution",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
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

    request = NucleiExecutionVerificationRequest(
        target_url=preparation.plan.target_url,
        arguments=preparation.plan.arguments,
        authorization_confirmed=True,
        active_testing_allowed=True,
        explicitly_approved=True,
    )

    return execution.execution_id, preparation, request


def successful_runner(profile, arguments, *, on_output=None):
    stdout = '{"template-id":"safe-example"}\n'
    stderr = ""

    if on_output is not None:
        on_output(
            ToolOutputEvent(
                tool_name="nuclei",
                stream="stdout",
                line='{"template-id":"safe-example"}',
            )
        )

    return ToolRunResult(
        tool_name=profile.name,
        executable="/test/bin/nuclei",
        arguments=tuple(arguments),
        exit_code=0,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=hashlib.sha256(
            stdout.encode("utf-8")
        ).hexdigest(),
        stderr_sha256=hashlib.sha256(
            stderr.encode("utf-8")
        ).hexdigest(),
        timed_out=False,
    )


def test_executes_with_injected_runner_and_persists_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, preparation, request = create_preparation(
        database,
        tmp_path,
    )

    result = run_tracked_nuclei_execution(
        database,
        execution_id,
        request,
        runner=successful_runner,
        evidence_root=tmp_path / "execution",
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert (
        result.evidence.evidence_type
        is EvidenceType.CONTROLLED_NUCLEI_EXECUTION
    )
    assert (
        result.result.preparation_evidence_id
        == preparation.evidence.evidence_id
    )
    assert result.result.exit_code == 0
    assert result.result.timed_out is False
    assert result.result.automatic_retry is False

    evidence_bytes = Path(result.evidence.path).read_bytes()
    payload = json.loads(evidence_bytes)

    assert (
        hashlib.sha256(evidence_bytes).hexdigest()
        == result.evidence.sha256
    )
    assert payload["phase"] == "6J.3"
    assert payload["runtime"]["exit_code"] == 0
    assert payload["runtime"]["automatic_retry"] is False
    assert payload["execution"] == {
        "executed": True,
        "network_activity": True,
        "subprocess_started": True,
        "runner_invoked": True,
        "executable_resolved": True,
        "automatic_retry": False,
    }

    event_types = {
        event.event_type
        for event in database.list_audit_events(execution_id)
    }

    assert AuditEventType.APPROVAL_RECORDED in event_types
    assert AuditEventType.TOOL_STARTED in event_types
    assert AuditEventType.TOOL_OUTPUT in event_types
    assert AuditEventType.TOOL_COMPLETED in event_types


def test_timeout_persists_evidence_then_fails_execution(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, _, request = create_preparation(
        database,
        tmp_path,
    )

    def timeout_runner(profile, arguments, *, on_output=None):
        stdout = "started\n"
        stderr = ""

        return ToolRunResult(
            tool_name=profile.name,
            executable="/test/bin/nuclei",
            arguments=tuple(arguments),
            exit_code=-1,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(
                stdout.encode("utf-8")
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                stderr.encode("utf-8")
            ).hexdigest(),
            timed_out=True,
        )

    with pytest.raises(
        NucleiExecutionWorkflowError,
        match="timed out",
    ):
        run_tracked_nuclei_execution(
            database,
            execution_id,
            request,
            runner=timeout_runner,
            evidence_root=tmp_path / "execution",
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )

    evidence = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_EXECUTION,
    )

    assert len(evidence) == 1
    assert evidence[0].metadata["timed_out"] is True
    assert evidence[0].metadata["automatic_retry"] is False


def test_nonzero_exit_persists_evidence_then_fails(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, _, request = create_preparation(
        database,
        tmp_path,
    )

    def failing_runner(profile, arguments, *, on_output=None):
        stdout = ""
        stderr = "template loading failed\n"

        return ToolRunResult(
            tool_name=profile.name,
            executable="/test/bin/nuclei",
            arguments=tuple(arguments),
            exit_code=2,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(
                stdout.encode("utf-8")
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                stderr.encode("utf-8")
            ).hexdigest(),
            timed_out=False,
        )

    with pytest.raises(
        NucleiExecutionWorkflowError,
        match="exit code 2",
    ):
        run_tracked_nuclei_execution(
            database,
            execution_id,
            request,
            runner=failing_runner,
            evidence_root=tmp_path / "execution",
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )

    evidence = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_EXECUTION,
    )

    assert len(evidence) == 1
    assert evidence[0].metadata["exit_code"] == 2


def test_runner_error_fails_without_execution_evidence(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, _, request = create_preparation(
        database,
        tmp_path,
    )

    def broken_runner(profile, arguments, *, on_output=None):
        raise ToolRunnerError("simulated runner failure")

    with pytest.raises(
        NucleiExecutionWorkflowError,
        match="failed safely",
    ):
        run_tracked_nuclei_execution(
            database,
            execution_id,
            request,
            runner=broken_runner,
            evidence_root=tmp_path / "execution",
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )

    evidence = database.list_evidence(
        execution_id,
        evidence_type=EvidenceType.CONTROLLED_NUCLEI_EXECUTION,
    )

    assert evidence == []


def test_rejects_runner_argument_mismatch(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    execution_id, _, request = create_preparation(
        database,
        tmp_path,
    )

    def mismatched_runner(profile, arguments, *, on_output=None):
        stdout = ""
        stderr = ""

        return ToolRunResult(
            tool_name=profile.name,
            executable="/test/bin/nuclei",
            arguments=(*tuple(arguments), "-severity", "critical"),
            exit_code=0,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            timed_out=False,
        )

    with pytest.raises(
        NucleiExecutionWorkflowError,
        match="arguments do not match",
    ):
        run_tracked_nuclei_execution(
            database,
            execution_id,
            request,
            runner=mismatched_runner,
            evidence_root=tmp_path / "execution",
        )

    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )


def test_registration_failure_removes_orphan_file(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id, _, request = create_preparation(
        database,
        tmp_path,
    )
    evidence_root = tmp_path / "execution"

    original_add_evidence = database.add_evidence

    def fail_execution_registration(
        execution_id_value,
        evidence_request,
        *,
        actor="system",
    ):
        if (
            evidence_request.evidence_type
            is EvidenceType.CONTROLLED_NUCLEI_EXECUTION
        ):
            raise RuntimeError("simulated registration failure")

        return original_add_evidence(
            execution_id_value,
            evidence_request,
            actor=actor,
        )

    monkeypatch.setattr(
        database,
        "add_evidence",
        fail_execution_registration,
    )

    with pytest.raises(
        NucleiExecutionWorkflowError,
        match="failed safely",
    ):
        run_tracked_nuclei_execution(
            database,
            execution_id,
            request,
            runner=successful_runner,
            evidence_root=evidence_root,
        )

    assert list(evidence_root.glob("*.json")) == []
    assert (
        database.get_execution(execution_id).state
        is ExecutionState.FAILED
    )

    failures = [
        event
        for event in database.list_audit_events(execution_id)
        if (
            event.event_type is AuditEventType.TOOL_FAILED
            and event.details.get("phase_code") == "6J.3"
        )
    ]

    assert len(failures) == 1
    assert failures[0].details["orphan_file_removed"] is True
    assert failures[0].details["automatic_retry"] is False

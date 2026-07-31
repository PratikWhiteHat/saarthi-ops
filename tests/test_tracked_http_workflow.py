from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.execution.http_models import (
    HttpMetadataCollectionRequest,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.http_workflow import (
    run_tracked_http_collection,
)
from saarthi_ai.persistence.models import (
    ExecutionCreate,
    ExecutionState,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    """Create an isolated database."""

    repository = SaarthiDatabase(tmp_path / "tracked-http.db")
    repository.initialize()
    return repository


def create_execution(database: SaarthiDatabase) -> str:
    """Create an authorized Web execution."""

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Tracked HTTP VAPT",
            asset_types=["web"],
            targets=["https://example.com/"],
            authorization_confirmed=True,
            active_testing_allowed=False,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


def build_request() -> HttpMetadataCollectionRequest:
    """Create a scoped metadata request."""

    return HttpMetadataCollectionRequest(
        assessment=AssessmentRequest(
            name="Tracked HTTP VAPT",
            targets=[
                AssessmentTarget(
                    asset_type=AssetType.WEB,
                    value="https://example.com",
                )
            ],
            authorization_confirmed=True,
        ),
        target="https://example.com",
    )


@pytest.mark.asyncio
async def test_tracked_http_collection(
    database: SaarthiDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful collection should complete and register evidence."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=b"hello",
            request=request,
        )

    from saarthi_ai.persistence import http_workflow

    original = http_workflow.collect_http_metadata

    async def mocked_collect(request, *, evidence_root=None):
        return await original(
            request,
            transport=httpx.MockTransport(handler),
            evidence_root=evidence_root,
        )

    monkeypatch.setattr(
        http_workflow,
        "collect_http_metadata",
        mocked_collect,
    )

    execution_id = create_execution(database)

    result = await run_tracked_http_collection(
        database,
        execution_id,
        build_request(),
        evidence_root=tmp_path,
    )

    assert result.execution.state is ExecutionState.COMPLETED
    assert result.collection.status_code == 200
    assert result.evidence.evidence_type.value == "http_metadata"

    evidence = database.list_evidence(execution_id)
    assert len(evidence) == 1

    events = database.list_audit_events(execution_id)
    event_types = [event.event_type.value for event in events]

    assert "tool_started" in event_types
    assert "tool_completed" in event_types
    assert "evidence_added" in event_types


@pytest.mark.asyncio
async def test_execution_target_must_match(
    database: SaarthiDatabase,
    tmp_path: Path,
) -> None:
    """Collector target must belong to the execution scope."""

    execution_id = create_execution(database)

    request = build_request().model_copy(
        update={
            "assessment": AssessmentRequest(
                name="Different Target",
                targets=[
                    AssessmentTarget(
                        asset_type=AssetType.WEB,
                        value="https://other.example.com",
                    )
                ],
                authorization_confirmed=True,
            ),
            "target": "https://other.example.com",
        }
    )

    with pytest.raises(
        Exception,
        match="not associated with this execution",
    ):
        await run_tracked_http_collection(
            database,
            execution_id,
            request,
            evidence_root=tmp_path,
        )

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    ExecutionNotFoundError,
    InvalidStateTransitionError,
    PersistenceError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.models import (
    AuditEventRecord,
    EvidenceCreate,
    EvidenceRecord,
    EvidenceType,
    ExecutionCreate,
    ExecutionRecord,
    ExecutionState,
    StateTransitionRequest,
)

router = APIRouter(
    prefix="/v1/executions",
    tags=["execution-history"],
)

_database = SaarthiDatabase(DEFAULT_DATABASE_PATH)
_database.initialize()


def get_database() -> SaarthiDatabase:
    """Return the configured Saarthi persistence repository."""

    return _database


DatabaseDependency = Annotated[
    SaarthiDatabase,
    Depends(get_database),
]


@router.post(
    "",
    response_model=ExecutionRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_execution_endpoint(
    request: ExecutionCreate,
    database: DatabaseDependency,
) -> ExecutionRecord:
    """Create a persistent authorized assessment execution."""

    try:
        return database.create_execution(request)
    except PersistenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[ExecutionRecord],
)
async def list_executions_endpoint(
    database: DatabaseDependency,
    execution_state: Annotated[
        ExecutionState | None,
        Query(alias="state"),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=1_000),
    ] = 100,
) -> list[ExecutionRecord]:
    """List recent assessment executions."""

    try:
        return database.list_executions(
            state=execution_state,
            limit=limit,
        )
    except PersistenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "/{execution_id}",
    response_model=ExecutionRecord,
)
async def get_execution_endpoint(
    execution_id: str,
    database: DatabaseDependency,
) -> ExecutionRecord:
    """Retrieve one assessment execution."""

    try:
        return database.get_execution(execution_id)
    except ExecutionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/{execution_id}/transition",
    response_model=ExecutionRecord,
)
async def transition_execution_endpoint(
    execution_id: str,
    request: StateTransitionRequest,
    database: DatabaseDependency,
) -> ExecutionRecord:
    """Apply a validated execution-state transition."""

    try:
        return database.transition_execution(
            execution_id,
            request.new_state,
            actor=request.actor,
            reason=request.reason,
        )
    except ExecutionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except InvalidStateTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get(
    "/{execution_id}/audit",
    response_model=list[AuditEventRecord],
)
async def list_audit_events_endpoint(
    execution_id: str,
    database: DatabaseDependency,
) -> list[AuditEventRecord]:
    """Return the immutable audit history for an execution."""

    try:
        return database.list_audit_events(execution_id)
    except ExecutionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/{execution_id}/evidence",
    response_model=EvidenceRecord,
    status_code=status.HTTP_201_CREATED,
)
async def add_evidence_endpoint(
    execution_id: str,
    request: EvidenceCreate,
    database: DatabaseDependency,
) -> EvidenceRecord:
    """Register an item in the execution evidence catalog."""

    try:
        return database.add_evidence(
            execution_id,
            request,
            actor="api",
        )
    except ExecutionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except PersistenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "/{execution_id}/evidence",
    response_model=list[EvidenceRecord],
)
async def list_evidence_endpoint(
    execution_id: str,
    database: DatabaseDependency,
    evidence_type: Annotated[
        EvidenceType | None,
        Query(),
    ] = None,
) -> list[EvidenceRecord]:
    """List evidence registered for an execution."""

    try:
        return database.list_evidence(
            execution_id,
            evidence_type=evidence_type,
        )
    except ExecutionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

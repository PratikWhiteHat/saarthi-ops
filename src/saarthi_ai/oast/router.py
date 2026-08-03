from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)

from saarthi_ai.oast.manager import (
    MAX_BODY_BYTES,
    LocalOastManager,
    OastCorrelationExpiredError,
    OastCorrelationNotFoundError,
    OastObservationRejectedError,
)
from saarthi_ai.oast.models import OastObservation, OastProtocol
from saarthi_ai.persistence.database import (
    DEFAULT_DATABASE_PATH,
    InvalidStateTransitionError,
    SaarthiDatabase,
)
from saarthi_ai.persistence.oast_workflow import (
    OastObservationWorkflowError,
    persist_oast_observation,
)

router = APIRouter(
    prefix="/v1/oast",
    tags=["local-oast"],
)

_manager = LocalOastManager()
_database = SaarthiDatabase(DEFAULT_DATABASE_PATH)
_database.initialize()


def get_oast_manager() -> LocalOastManager:
    """Return the local in-memory OAST correlation manager."""

    return _manager


OastManagerDependency = Annotated[
    LocalOastManager,
    Depends(get_oast_manager),
]


def get_oast_database() -> SaarthiDatabase:
    """Return the database used for OAST observation evidence."""

    return _database


OastDatabaseDependency = Annotated[
    SaarthiDatabase,
    Depends(get_oast_database),
]


def _source_address(request: Request) -> str:
    if request.client is None:
        return ""

    return request.client.host


async def _bounded_body_size(request: Request) -> int:
    content_length = request.headers.get("content-length")

    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header.",
            ) from exc

        if declared_size < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header.",
            )

        if declared_size > MAX_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=(
                    f"Callback body exceeds the "
                    f"{MAX_BODY_BYTES}-byte limit."
                ),
            )

    body = await request.body()

    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"Callback body exceeds the "
                f"{MAX_BODY_BYTES}-byte limit."
            ),
        )

    return len(body)


@router.api_route(
    "/callback/{raw_token}",
    methods=["GET", "POST", "HEAD", "OPTIONS"],
    response_model=OastObservation,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_oast_callback(
    raw_token: str,
    request: Request,
    manager: OastManagerDependency,
    database: OastDatabaseDependency,
) -> OastObservation | Response:
    """Accept one bounded loopback callback and correlate its token."""

    body_size = await _bounded_body_size(request)

    protocol = (
        OastProtocol.HTTPS
        if request.url.scheme.lower() == "https"
        else OastProtocol.HTTP
    )

    try:
        observation = manager.observe(
            raw_token=raw_token,
            protocol=protocol,
            request_method=request.method,
            request_path="/v1/oast/callback/[REDACTED]",
            source_address=_source_address(request),
            headers=dict(request.headers),
            body_size=body_size,
        )
    except OastCorrelationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active callback correlation was found.",
        ) from exc
    except OastCorrelationExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="The callback correlation has expired.",
        ) from exc
    except OastObservationRejectedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    correlation = manager.get_correlation(observation.token_id)

    if correlation is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Matched correlation is no longer available.",
        )

    try:
        persist_oast_observation(
            database,
            observation,
            correlation,
            actor="api-oast-callback-manager",
        )
    except InvalidStateTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except OastObservationWorkflowError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist the correlated observation.",
        ) from exc

    if request.method == "HEAD":
        return Response(status_code=status.HTTP_202_ACCEPTED)

    return observation

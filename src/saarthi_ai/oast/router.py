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

router = APIRouter(
    prefix="/v1/oast",
    tags=["local-oast"],
)

_manager = LocalOastManager()


def get_oast_manager() -> LocalOastManager:
    """Return the local in-memory OAST correlation manager."""

    return _manager


OastManagerDependency = Annotated[
    LocalOastManager,
    Depends(get_oast_manager),
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

    if request.method == "HEAD":
        return Response(status_code=status.HTTP_202_ACCEPTED)

    return observation

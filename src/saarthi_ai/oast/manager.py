from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from threading import RLock
from uuid import uuid4

from saarthi_ai.blind_validation.tokens import hash_token
from saarthi_ai.oast.models import (
    OastCorrelation,
    OastCorrelationStatus,
    OastObservation,
    OastProtocol,
)

MAX_BODY_BYTES = 16_384
MAX_HEADER_VALUE_LENGTH = 1_024
MAX_SELECTED_HEADERS = 12

ALLOWED_OBSERVATION_HEADERS = {
    "accept",
    "content-type",
    "user-agent",
    "x-forwarded-for",
    "x-request-id",
}


class OastManagerError(RuntimeError):
    """Base error raised by the local OAST manager."""


class OastCorrelationNotFoundError(OastManagerError):
    """Raised when no active correlation matches the supplied token."""


class OastCorrelationExpiredError(OastManagerError):
    """Raised when a matching correlation has expired."""


class OastObservationRejectedError(OastManagerError):
    """Raised when an observation exceeds configured safety bounds."""


def is_loopback_address(address: str) -> bool:
    normalized = address.strip().lower()

    return normalized in {
        "127.0.0.1",
        "::1",
        "localhost",
        "testclient",
    }


def sanitize_headers(
    headers: dict[str, str],
) -> dict[str, str]:
    sanitized: dict[str, str] = {}

    for name, value in headers.items():
        normalized_name = name.strip().lower()

        if normalized_name not in ALLOWED_OBSERVATION_HEADERS:
            continue

        if len(sanitized) >= MAX_SELECTED_HEADERS:
            break

        sanitized[normalized_name] = value[:MAX_HEADER_VALUE_LENGTH]

    return sanitized


class LocalOastManager:
    """Thread-safe in-memory correlation manager for loopback callbacks."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._correlations: dict[str, OastCorrelation] = {}
        self._observations: list[OastObservation] = []

    def register(
        self,
        correlation: OastCorrelation,
    ) -> None:
        if not correlation.token_hash:
            raise ValueError("Correlation token hash is required.")

        if correlation.created_at.tzinfo is None:
            raise ValueError("Correlation creation time must be timezone-aware.")

        if correlation.expires_at.tzinfo is None:
            raise ValueError("Correlation expiry time must be timezone-aware.")

        if correlation.expires_at <= correlation.created_at:
            raise ValueError("Correlation expiry must be after creation.")

        with self._lock:
            self._correlations[correlation.token_id] = correlation

    def observe(
        self,
        *,
        raw_token: str,
        protocol: OastProtocol,
        request_method: str,
        request_path: str,
        source_address: str,
        headers: dict[str, str] | None = None,
        body_size: int = 0,
        now: datetime | None = None,
    ) -> OastObservation:
        if not is_loopback_address(source_address):
            raise OastObservationRejectedError(
                "Only loopback callback sources are permitted."
            )

        if body_size < 0 or body_size > MAX_BODY_BYTES:
            raise OastObservationRejectedError(
                f"Callback body exceeds the {MAX_BODY_BYTES}-byte limit."
            )

        if not raw_token:
            raise OastCorrelationNotFoundError(
                "A correlation token is required."
            )

        observed_at = now or datetime.now(UTC)

        if observed_at.tzinfo is None:
            raise ValueError("Observation time must be timezone-aware.")

        supplied_hash = hash_token(raw_token)

        with self._lock:
            correlation = next(
                (
                    item
                    for item in self._correlations.values()
                    if item.token_hash == supplied_hash
                ),
                None,
            )

            if correlation is None:
                raise OastCorrelationNotFoundError(
                    "No matching correlation was found."
                )

            if observed_at >= correlation.expires_at:
                self._correlations[correlation.token_id] = replace(
                    correlation,
                    status=OastCorrelationStatus.EXPIRED,
                )
                raise OastCorrelationExpiredError(
                    "The matching correlation has expired."
                )

            observation = OastObservation(
                observation_id=f"oast-observation-{uuid4()}",
                token_id=correlation.token_id,
                execution_id=correlation.execution_id,
                protocol=protocol,
                observed_at=observed_at,
                request_method=request_method.upper().strip(),
                request_path=request_path,
                source_address=source_address,
                selected_headers=sanitize_headers(headers or {}),
                body_size=body_size,
            )

            self._observations.append(observation)
            self._correlations[correlation.token_id] = replace(
                correlation,
                status=OastCorrelationStatus.OBSERVED,
            )

            return observation

    def get_correlation(
        self,
        token_id: str,
    ) -> OastCorrelation | None:
        with self._lock:
            return self._correlations.get(token_id)

    def list_observations(
        self,
        *,
        execution_id: str | None = None,
    ) -> tuple[OastObservation, ...]:
        with self._lock:
            observations = tuple(self._observations)

        if execution_id is None:
            return observations

        return tuple(
            observation
            for observation in observations
            if observation.execution_id == execution_id
        )

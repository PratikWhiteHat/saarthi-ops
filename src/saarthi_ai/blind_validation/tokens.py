from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from saarthi_ai.blind_validation.models import CorrelationToken

DEFAULT_TOKEN_TTL_SECONDS = 900
MIN_TOKEN_TTL_SECONDS = 60
MAX_TOKEN_TTL_SECONDS = 3600
TOKEN_BYTES = 24


def hash_token(token_value: str) -> str:
    if not token_value:
        raise ValueError("Token value must not be empty.")

    return hashlib.sha256(token_value.encode("utf-8")).hexdigest()


def generate_correlation_token(
    *,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    now: datetime | None = None,
) -> CorrelationToken:
    if not MIN_TOKEN_TTL_SECONDS <= ttl_seconds <= MAX_TOKEN_TTL_SECONDS:
        raise ValueError(
            "Token TTL must be between "
            f"{MIN_TOKEN_TTL_SECONDS} and {MAX_TOKEN_TTL_SECONDS} seconds."
        )

    created_at = now or datetime.now(UTC)

    if created_at.tzinfo is None:
        raise ValueError("Token creation time must be timezone-aware.")

    token_value = secrets.token_urlsafe(TOKEN_BYTES)

    return CorrelationToken(
        token_id=f"blind-token-{uuid4()}",
        token_value=token_value,
        token_hash=hash_token(token_value),
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=ttl_seconds),
    )


def token_is_expired(
    token: CorrelationToken,
    *,
    now: datetime | None = None,
) -> bool:
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Expiry comparison time must be timezone-aware.")

    return current_time >= token.expires_at


def token_matches(
    candidate_token: str,
    expected_hash: str,
) -> bool:
    if not candidate_token or not expected_hash:
        return False

    candidate_hash = hash_token(candidate_token)

    return secrets.compare_digest(candidate_hash, expected_hash)

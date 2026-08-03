from datetime import UTC, datetime, timedelta

import pytest

from saarthi_ai.blind_validation.tokens import (
    generate_correlation_token,
    hash_token,
    token_is_expired,
    token_matches,
)


def test_generate_token_creates_unique_secure_values() -> None:
    first = generate_correlation_token()
    second = generate_correlation_token()

    assert first.token_id.startswith("blind-token-")
    assert first.token_value
    assert first.token_hash == hash_token(first.token_value)
    assert first.token_value != second.token_value
    assert first.token_hash != second.token_hash


def test_token_hash_does_not_contain_raw_token() -> None:
    token = generate_correlation_token()

    assert token.token_value not in token.token_hash
    assert len(token.token_hash) == 64


def test_token_matching_uses_stored_hash() -> None:
    token = generate_correlation_token()

    assert token_matches(token.token_value, token.token_hash) is True
    assert token_matches("incorrect-token", token.token_hash) is False


def test_token_expiry_is_bounded() -> None:
    now = datetime(2026, 8, 3, 8, 0, tzinfo=UTC)
    token = generate_correlation_token(
        ttl_seconds=300,
        now=now,
    )

    assert token_is_expired(
        token,
        now=now + timedelta(seconds=299),
    ) is False

    assert token_is_expired(
        token,
        now=now + timedelta(seconds=300),
    ) is True


@pytest.mark.parametrize("ttl_seconds", [0, 59, 3601, 7200])
def test_invalid_token_ttl_is_rejected(ttl_seconds: int) -> None:
    with pytest.raises(ValueError, match="Token TTL"):
        generate_correlation_token(ttl_seconds=ttl_seconds)


def test_naive_creation_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_correlation_token(
            now=datetime(2026, 8, 3, 8, 0),
        )


def test_empty_token_cannot_be_hashed() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        hash_token("")

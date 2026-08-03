from datetime import UTC, datetime, timedelta

import pytest

from saarthi_ai.blind_validation.tokens import (
    generate_correlation_token,
)
from saarthi_ai.oast.manager import (
    MAX_BODY_BYTES,
    LocalOastManager,
    OastCorrelationExpiredError,
    OastCorrelationNotFoundError,
    OastObservationRejectedError,
    is_loopback_address,
)
from saarthi_ai.oast.models import (
    OastCorrelation,
    OastCorrelationStatus,
    OastProtocol,
)


def make_correlation(
    *,
    now: datetime,
    ttl_seconds: int = 300,
) -> tuple[OastCorrelation, str]:
    token = generate_correlation_token(
        ttl_seconds=ttl_seconds,
        now=now,
    )

    correlation = OastCorrelation(
        token_id=token.token_id,
        token_hash=token.token_hash,
        execution_id="execution-test",
        protocol=OastProtocol.HTTPS,
        created_at=token.created_at,
        expires_at=token.expires_at,
    )

    return correlation, token.token_value


def test_loopback_address_detection() -> None:
    assert is_loopback_address("127.0.0.1") is True
    assert is_loopback_address("::1") is True
    assert is_loopback_address("testclient") is True
    assert is_loopback_address("192.0.2.10") is False


def test_matching_token_creates_observation() -> None:
    now = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    correlation, raw_token = make_correlation(now=now)

    manager = LocalOastManager()
    manager.register(correlation)

    observation = manager.observe(
        raw_token=raw_token,
        protocol=OastProtocol.HTTPS,
        request_method="POST",
        request_path="/v1/oast/callback",
        source_address="127.0.0.1",
        headers={
            "User-Agent": "Saarthi test",
            "Authorization": "must-not-be-recorded",
        },
        body_size=12,
        now=now + timedelta(seconds=5),
    )

    assert observation.token_id == correlation.token_id
    assert observation.execution_id == "execution-test"
    assert observation.request_method == "POST"
    assert observation.selected_headers == {
        "user-agent": "Saarthi test",
    }

    stored = manager.get_correlation(correlation.token_id)

    assert stored is not None
    assert stored.status is OastCorrelationStatus.OBSERVED
    assert manager.list_observations() == (observation,)


def test_raw_token_is_not_present_in_observation_repr() -> None:
    now = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    correlation, raw_token = make_correlation(now=now)

    manager = LocalOastManager()
    manager.register(correlation)

    observation = manager.observe(
        raw_token=raw_token,
        protocol=OastProtocol.HTTP,
        request_method="GET",
        request_path="/v1/oast/callback",
        source_address="::1",
        now=now + timedelta(seconds=1),
    )

    assert raw_token not in repr(observation)


def test_unknown_token_is_rejected() -> None:
    manager = LocalOastManager()

    with pytest.raises(OastCorrelationNotFoundError):
        manager.observe(
            raw_token="unknown-token",
            protocol=OastProtocol.HTTP,
            request_method="GET",
            request_path="/v1/oast/callback",
            source_address="127.0.0.1",
        )


def test_expired_token_is_rejected_and_marked_expired() -> None:
    now = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    correlation, raw_token = make_correlation(
        now=now,
        ttl_seconds=60,
    )

    manager = LocalOastManager()
    manager.register(correlation)

    with pytest.raises(OastCorrelationExpiredError):
        manager.observe(
            raw_token=raw_token,
            protocol=OastProtocol.HTTP,
            request_method="GET",
            request_path="/v1/oast/callback",
            source_address="127.0.0.1",
            now=now + timedelta(seconds=60),
        )

    stored = manager.get_correlation(correlation.token_id)

    assert stored is not None
    assert stored.status is OastCorrelationStatus.EXPIRED


def test_non_loopback_source_is_rejected() -> None:
    now = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    correlation, raw_token = make_correlation(now=now)

    manager = LocalOastManager()
    manager.register(correlation)

    with pytest.raises(
        OastObservationRejectedError,
        match="loopback",
    ):
        manager.observe(
            raw_token=raw_token,
            protocol=OastProtocol.HTTP,
            request_method="GET",
            request_path="/v1/oast/callback",
            source_address="192.0.2.10",
        )


def test_oversized_body_is_rejected() -> None:
    now = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    correlation, raw_token = make_correlation(now=now)

    manager = LocalOastManager()
    manager.register(correlation)

    with pytest.raises(
        OastObservationRejectedError,
        match="byte limit",
    ):
        manager.observe(
            raw_token=raw_token,
            protocol=OastProtocol.HTTP,
            request_method="POST",
            request_path="/v1/oast/callback",
            source_address="127.0.0.1",
            body_size=MAX_BODY_BYTES + 1,
        )

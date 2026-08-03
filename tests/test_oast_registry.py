from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from saarthi_ai.blind_validation.tokens import generate_correlation_token
from saarthi_ai.oast.models import (
    OastCorrelation,
    OastCorrelationStatus,
    OastProtocol,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate
from saarthi_ai.persistence.oast_registry import (
    OastCorrelationAlreadyExistsError,
    PersistentOastCorrelationRegistry,
)


@pytest.fixture
def database(tmp_path: Path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "oast-registry.db")
    repository.initialize()
    return repository


@pytest.fixture
def execution_id(
    database: SaarthiDatabase,
) -> str:
    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Phase 4C Persistent Registry",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return execution.execution_id


@pytest.fixture
def registry(
    database: SaarthiDatabase,
) -> PersistentOastCorrelationRegistry:
    correlation_registry = PersistentOastCorrelationRegistry(database)
    correlation_registry.initialize()
    return correlation_registry


def make_correlation(
    execution_id: str,
) -> tuple[OastCorrelation, str]:
    now = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)
    token = generate_correlation_token(
        ttl_seconds=300,
        now=now,
    )

    return (
        OastCorrelation(
            token_id=token.token_id,
            token_hash=token.token_hash,
            execution_id=execution_id,
            protocol=OastProtocol.HTTPS,
            created_at=token.created_at,
            expires_at=token.expires_at,
        ),
        token.token_value,
    )


def test_registry_round_trip_stores_hash_only(
    registry: PersistentOastCorrelationRegistry,
    database: SaarthiDatabase,
    execution_id: str,
) -> None:
    correlation, raw_token = make_correlation(execution_id)

    registry.register(correlation)

    stored = registry.get_by_token_id(correlation.token_id)

    assert stored == correlation
    assert registry.get_by_token_hash(
        correlation.token_hash
    ) == correlation

    with database.connect() as connection:
        columns = connection.execute(
            "PRAGMA table_info(oast_correlations)"
        ).fetchall()

        row = connection.execute(
            """
            SELECT *
            FROM oast_correlations
            WHERE token_id = ?
            """,
            (correlation.token_id,),
        ).fetchone()

    column_names = {
        str(column["name"])
        for column in columns
    }

    assert "token_value" not in column_names
    assert "raw_token" not in column_names
    assert row is not None
    assert raw_token not in repr(dict(row))


def test_registry_lists_correlations_for_execution(
    registry: PersistentOastCorrelationRegistry,
    execution_id: str,
) -> None:
    first, _ = make_correlation(execution_id)
    second, _ = make_correlation(execution_id)

    registry.register(first)
    registry.register(second)

    stored = registry.list_for_execution(execution_id)

    assert {item.token_id for item in stored} == {
        first.token_id,
        second.token_id,
    }


def test_registry_updates_status(
    registry: PersistentOastCorrelationRegistry,
    execution_id: str,
) -> None:
    correlation, _ = make_correlation(execution_id)
    registry.register(correlation)

    updated = registry.update_status(
        correlation.token_id,
        OastCorrelationStatus.OBSERVED,
        updated_at=correlation.created_at + timedelta(seconds=5),
    )

    assert updated is not None
    assert updated.status is OastCorrelationStatus.OBSERVED
    assert updated.token_hash == correlation.token_hash


def test_duplicate_token_hash_is_rejected(
    registry: PersistentOastCorrelationRegistry,
    execution_id: str,
) -> None:
    correlation, _ = make_correlation(execution_id)
    registry.register(correlation)

    duplicate = OastCorrelation(
        token_id="blind-token-different",
        token_hash=correlation.token_hash,
        execution_id=execution_id,
        protocol=correlation.protocol,
        created_at=correlation.created_at,
        expires_at=correlation.expires_at,
    )

    with pytest.raises(OastCorrelationAlreadyExistsError):
        registry.register(duplicate)


def test_invalid_hash_is_rejected(
    registry: PersistentOastCorrelationRegistry,
    execution_id: str,
) -> None:
    now = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)

    correlation = OastCorrelation(
        token_id="blind-token-invalid",
        token_hash="not-a-sha256",
        execution_id=execution_id,
        protocol=OastProtocol.HTTP,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    with pytest.raises(ValueError, match="SHA-256"):
        registry.register(correlation)

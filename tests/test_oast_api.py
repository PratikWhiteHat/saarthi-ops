from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from saarthi_ai.blind_validation.tokens import generate_correlation_token
from saarthi_ai.main import app
from saarthi_ai.oast.manager import MAX_BODY_BYTES, LocalOastManager
from saarthi_ai.oast.models import OastCorrelation, OastProtocol
from saarthi_ai.oast.router import (
    get_oast_database,
    get_oast_manager,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate


@pytest.fixture
def manager() -> LocalOastManager:
    return LocalOastManager()


@pytest.fixture
def database(tmp_path) -> SaarthiDatabase:
    repository = SaarthiDatabase(tmp_path / "oast-api.db")
    repository.initialize()

    repository.create_execution(
        ExecutionCreate(
            assessment_name="Phase 4C API Test",
            asset_types=["web"],
            targets=["example.com"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=False,
        )
    )

    return repository


@pytest.fixture
def client(
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> TestClient:
    app.dependency_overrides[get_oast_manager] = lambda: manager
    app.dependency_overrides[get_oast_database] = lambda: database

    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def register_correlation(
    manager: LocalOastManager,
    database: SaarthiDatabase,
    *,
    ttl_seconds: int = 300,
) -> tuple[str, str]:
    now = datetime.now(UTC)
    token = generate_correlation_token(
        ttl_seconds=ttl_seconds,
        now=now,
    )

    manager.register(
        OastCorrelation(
            token_id=token.token_id,
            token_hash=token.token_hash,
            execution_id=database.list_executions(limit=1)[0].execution_id,
            protocol=OastProtocol.HTTP,
            created_at=token.created_at,
            expires_at=token.expires_at,
        )
    )

    return token.token_id, token.token_value


def test_matching_loopback_callback_is_accepted(
    client: TestClient,
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> None:
    token_id, raw_token = register_correlation(manager, database)

    response = client.post(
        f"/v1/oast/callback/{raw_token}",
        content=b"safe-test-body",
        headers={
            "User-Agent": "Saarthi API test",
            "Authorization": "must-not-be-recorded",
        },
    )

    assert response.status_code == 202

    payload = response.json()

    assert payload["token_id"] == token_id
    expected_execution_id = (
        database.list_executions(limit=1)[0].execution_id
    )
    assert payload["execution_id"] == expected_execution_id
    assert payload["request_method"] == "POST"
    assert payload["request_path"] == "/v1/oast/callback/[REDACTED]"
    assert payload["body_size"] == len(b"safe-test-body")
    assert payload["selected_headers"]["user-agent"] == (
        "Saarthi API test"
    )
    assert "authorization" not in payload["selected_headers"]
    assert raw_token not in response.text


def test_unknown_token_returns_generic_404(
    client: TestClient,
) -> None:
    raw_token = "unknown-secret-token"

    response = client.get(
        f"/v1/oast/callback/{raw_token}",
    )

    assert response.status_code == 404
    assert raw_token not in response.text
    assert "No active callback correlation" in response.text


def test_expired_token_returns_410_without_leaking_token(
    client: TestClient,
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> None:
    now = datetime.now(UTC)
    token = generate_correlation_token(
        ttl_seconds=60,
        now=now - timedelta(seconds=120),
    )

    manager.register(
        OastCorrelation(
            token_id=token.token_id,
            token_hash=token.token_hash,
            execution_id=database.list_executions(limit=1)[0].execution_id,
            protocol=OastProtocol.HTTP,
            created_at=token.created_at,
            expires_at=token.expires_at,
        )
    )

    response = client.get(
        f"/v1/oast/callback/{token.token_value}",
    )

    assert response.status_code == 410
    assert token.token_value not in response.text


def test_oversized_callback_body_is_rejected(
    client: TestClient,
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> None:
    _, raw_token = register_correlation(manager, database)

    response = client.post(
        f"/v1/oast/callback/{raw_token}",
        content=b"a" * (MAX_BODY_BYTES + 1),
    )

    assert response.status_code == 413
    assert raw_token not in response.text
    assert manager.list_observations() == ()


def test_head_callback_returns_no_body(
    client: TestClient,
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> None:
    _, raw_token = register_correlation(manager, database)

    response = client.head(
        f"/v1/oast/callback/{raw_token}",
    )

    assert response.status_code == 202
    assert response.content == b""
    assert len(manager.list_observations()) == 1


def test_callback_loads_correlation_from_persistent_registry(
    client: TestClient,
    manager: LocalOastManager,
    database: SaarthiDatabase,
) -> None:
    from saarthi_ai.blind_validation.models import (
        BlindValidationRequest,
        CallbackProtocol,
    )
    from saarthi_ai.persistence.blind_validation_workflow import (
        run_tracked_blind_validation,
    )

    execution_id = (
        database.list_executions(limit=1)[0].execution_id
    )

    result = run_tracked_blind_validation(
        database,
        BlindValidationRequest(
            execution_id=execution_id,
            target_url="https://example.com/",
            authorized=True,
            active_testing=True,
            explicitly_approved=True,
            callback_protocol=CallbackProtocol.HTTPS,
            requested_poll_attempts=2,
            requested_poll_interval_seconds=5,
        ),
    )

    assert manager.get_correlation(result.token.token_id) is None

    response = client.get(
        f"/v1/oast/callback/{result.token.token_value}",
    )

    assert response.status_code == 202
    assert response.json()["token_id"] == result.token.token_id

    loaded = manager.get_correlation(result.token.token_id)

    assert loaded is not None
    assert loaded.status.value == "observed"
    assert result.token.token_value not in response.text

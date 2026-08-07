"""Tests deriving an automatic-validation config from the Phase 6 chain."""

from __future__ import annotations

import pytest

from saarthi_ai.automation.chain_config import (
    ChainConfigError,
    build_auto_validation_config_from_chain,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate


def _database(tmp_path) -> SaarthiDatabase:
    database = SaarthiDatabase(tmp_path / "chain.db")
    database.initialize()
    return database


def _create_parent(
    database: SaarthiDatabase,
    *,
    target: str,
    orchestration_id: str = "orchestration-test-1",
    intrusive: bool = True,
    domain: str | None = "app.example.com",
) -> str:
    metadata = {
        "execution_role": "orchestration_parent",
        "orchestration_id": orchestration_id,
        "rate_limit_per_second": 3,
    }
    if domain is not None:
        metadata["target_domain"] = domain

    execution = database.create_execution(
        ExecutionCreate(
            assessment_name="Chain test engagement",
            asset_types=["url"],
            targets=[target],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=intrusive,
            metadata=metadata,
        )
    )
    return execution.execution_id


def test_derives_target_and_candidates_from_parent(tmp_path) -> None:
    database = _database(tmp_path)
    parent_id = _create_parent(
        database,
        target="https://app.example.com/item?id=1&cat=books",
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
    )

    assert derived.source_execution_id == parent_id
    assert derived.orchestration_id == "orchestration-test-1"
    assert derived.config.target_url == (
        "https://app.example.com/item?id=1&cat=books"
    )
    assert "app.example.com" in derived.config.allowed_hosts
    assert derived.sqlmap_parameters == ("id", "cat")
    assert {c.parameter for c in derived.config.sqlmap_candidates} == {
        "id",
        "cat",
    }
    # Rate limit is taken from parent metadata, clamped to [1, 20].
    assert derived.config.nuclei_rate_limit == 3


def test_intrusive_disabled_yields_nuclei_only(tmp_path) -> None:
    database = _database(tmp_path)
    _create_parent(
        database,
        target="https://app.example.com/item?id=1",
        intrusive=False,
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
        confirmed_poc=True,
        single_row_dump=True,
    )

    assert derived.config.sqlmap_candidates == ()
    assert derived.sqlmap_parameters == ()
    assert derived.config.intrusive_testing is False
    # Confirmed-PoC is force-disabled when intrusive testing is not allowed.
    assert derived.config.sqlmap_confirmed_poc is False
    assert derived.config.sqlmap_poc_single_row_dump is False


def test_confirmed_poc_flags_flow_through_when_intrusive(tmp_path) -> None:
    database = _database(tmp_path)
    _create_parent(
        database,
        target="https://app.example.com/item?id=1",
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
        confirmed_poc=True,
        single_row_dump=True,
    )

    assert derived.config.sqlmap_confirmed_poc is True
    assert derived.config.sqlmap_poc_single_row_dump is True


def test_picks_latest_orchestration_parent(tmp_path) -> None:
    database = _database(tmp_path)
    _create_parent(
        database,
        target="https://old.example.com/a?x=1",
        orchestration_id="orchestration-old",
        domain="old.example.com",
    )
    newest = _create_parent(
        database,
        target="https://new.example.com/b?y=2",
        orchestration_id="orchestration-new",
        domain="new.example.com",
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
    )

    assert derived.source_execution_id == newest
    assert derived.config.target_url == "https://new.example.com/b?y=2"


def test_specific_orchestration_id_selects_that_chain(tmp_path) -> None:
    database = _database(tmp_path)
    wanted = _create_parent(
        database,
        target="https://old.example.com/a?x=1",
        orchestration_id="orchestration-old",
        domain="old.example.com",
    )
    _create_parent(
        database,
        target="https://new.example.com/b?y=2",
        orchestration_id="orchestration-new",
        domain="new.example.com",
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
        orchestration_id="orchestration-old",
    )

    assert derived.source_execution_id == wanted
    assert derived.config.target_url == "https://old.example.com/a?x=1"


def test_no_orchestration_parent_raises(tmp_path) -> None:
    database = _database(tmp_path)
    # A child-only execution should not be treated as a chain root.
    database.create_execution(
        ExecutionCreate(
            assessment_name="Child only",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            metadata={"execution_role": "orchestration_child"},
        )
    )

    with pytest.raises(ChainConfigError):
        build_auto_validation_config_from_chain(database, approved=True)


def test_empty_database_raises(tmp_path) -> None:
    database = _database(tmp_path)

    with pytest.raises(ChainConfigError):
        build_auto_validation_config_from_chain(database, approved=True)


def test_derived_config_passes_validation(tmp_path) -> None:
    from saarthi_ai.automation.auto_validation import _validate_config

    database = _database(tmp_path)
    _create_parent(
        database,
        target="https://app.example.com/item?id=1",
    )

    derived = build_auto_validation_config_from_chain(
        database,
        approved=True,
        confirmed_poc=True,
    )

    # Should not raise: the chain-derived config is internally consistent.
    _validate_config(derived.config)

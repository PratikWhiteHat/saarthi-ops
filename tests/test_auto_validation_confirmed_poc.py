"""Tests for confirmed-PoC gating in automatic SQLMap validation."""

from __future__ import annotations

import pytest

from saarthi_ai.automation.auto_validation import (
    ALWAYS_PROHIBITED_SQLMAP_SWITCHES,
    SQLMAP_CONFIRMED_POC_SWITCHES,
    AutoValidationConfig,
    AutoValidationError,
    SqlmapCandidate,
    _sqlmap_arguments,
    _validate_config,
)


def _config(**overrides) -> AutoValidationConfig:
    base = dict(
        target_url="https://app.example.com/item?id=1",
        allowed_hosts=("app.example.com",),
        authorized=True,
        active_testing=True,
        intrusive_testing=True,
        approved=True,
        sqlmap_candidates=(
            SqlmapCandidate(
                url="https://app.example.com/item?id=1",
                parameter="id",
                method="GET",
            ),
        ),
    )
    base.update(overrides)
    return AutoValidationConfig(**base)


def _candidate() -> SqlmapCandidate:
    return SqlmapCandidate(
        url="https://app.example.com/item?id=1",
        parameter="id",
        method="GET",
    )


def test_detection_only_default_has_no_extraction_switches(tmp_path) -> None:
    config = _config()

    arguments = _sqlmap_arguments(config, _candidate(), tmp_path / "out")

    assert "--dump" not in arguments
    for switch in SQLMAP_CONFIRMED_POC_SWITCHES:
        assert switch not in arguments


def test_confirmed_poc_adds_readonly_identity_switches(tmp_path) -> None:
    config = _config(sqlmap_confirmed_poc=True)

    arguments = _sqlmap_arguments(config, _candidate(), tmp_path / "out")

    for switch in SQLMAP_CONFIRMED_POC_SWITCHES:
        assert switch in arguments
    # Identity proof alone must not dump rows.
    assert "--dump" not in arguments


def test_single_row_dump_is_bounded(tmp_path) -> None:
    config = _config(
        sqlmap_confirmed_poc=True,
        sqlmap_poc_single_row_dump=True,
    )

    arguments = _sqlmap_arguments(config, _candidate(), tmp_path / "out")

    assert "--dump" in arguments
    assert "--start=1" in arguments
    assert "--stop=1" in arguments


def test_confirmed_poc_never_enables_shells_or_evasion(tmp_path) -> None:
    config = _config(
        sqlmap_confirmed_poc=True,
        sqlmap_poc_single_row_dump=True,
    )

    arguments = _sqlmap_arguments(config, _candidate(), tmp_path / "out")

    for switch in ALWAYS_PROHIBITED_SQLMAP_SWITCHES:
        assert switch not in arguments
    # Detection evasion and OS access are never present.
    assert "--tamper" not in arguments
    assert "--os-shell" not in arguments
    assert "--file-read" not in arguments


def test_single_row_dump_requires_confirmed_poc() -> None:
    config = _config(sqlmap_poc_single_row_dump=True)

    with pytest.raises(AutoValidationError):
        _validate_config(config)


def test_confirmed_poc_requires_intrusive_permission() -> None:
    config = _config(
        intrusive_testing=False,
        sqlmap_candidates=(),
        sqlmap_confirmed_poc=True,
    )

    with pytest.raises(AutoValidationError):
        _validate_config(config)


def test_nuclei_only_run_allowed_without_intrusive() -> None:
    # No SQLMap candidates and no confirmed-PoC => intrusive not required.
    config = _config(
        intrusive_testing=False,
        sqlmap_candidates=(),
    )

    # Should not raise.
    _validate_config(config)


def test_confirmed_poc_enumerates_databases_then_stops(tmp_path) -> None:
    config = _config(sqlmap_confirmed_poc=True)

    arguments = _sqlmap_arguments(config, _candidate(), tmp_path / "out")

    # Proceeds to list databases as the PoC endpoint...
    assert "--dbs" in arguments
    # ...and stops there: no table/column/row extraction.
    assert "--tables" not in arguments
    assert "--columns" not in arguments
    assert "--dump" not in arguments
    assert "--dump-all" not in arguments

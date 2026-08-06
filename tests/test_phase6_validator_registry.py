"""Tests for the official Phase 6C validator catalogue."""

from __future__ import annotations

from saarthi_ai.controlled_validation.validator_registry import (
    PHASE_6_VALIDATOR_REGISTRY,
    ValidationLevel,
    ValidatorStatus,
    list_phase6_validators,
    summarize_phase6_validator_modules,
    validator_module_tool_rows,
)


def test_registry_covers_all_official_module_families() -> None:
    assert len(PHASE_6_VALIDATOR_REGISTRY) == 81
    assert {
        item.module_code
        for item in PHASE_6_VALIDATOR_REGISTRY
    } == {
        "6C.1",
        "6C.2",
        "6C.3",
        "6C.4",
        "6C.5",
        "6C.6",
        "6C.7",
    }
    assert len(
        {
            item.validator_id
            for item in PHASE_6_VALIDATOR_REGISTRY
        }
    ) == len(PHASE_6_VALIDATOR_REGISTRY)


def test_implemented_validators_map_to_real_actions() -> None:
    implemented = {
        item.name: item.implementation_action
        for item in PHASE_6_VALIDATOR_REGISTRY
        if item.status is ValidatorStatus.IMPLEMENTED
    }

    assert implemented == {
        "Clickjacking Validation": "clickjacking_header_validation",
        "CSRF Validation": "csrf_protection_surface_validation",
        (
            "Excessive Data Exposure"
        ): "api_data_exposure_surface_validation",
    }


def test_upload_surface_is_partial_under_official_6c6() -> None:
    upload = next(
        item
        for item in list_phase6_validators("6C.6")
        if item.name == "Unrestricted File Upload"
    )

    assert upload.module_name == "File & Execution Attacks"
    assert upload.status is ValidatorStatus.PARTIAL
    assert upload.level is ValidationLevel.L1_SAFE_DETECTION
    assert (
        upload.implementation_action
        == "file_upload_surface_validation"
    )


def test_high_impact_execution_validators_are_manual_only() -> None:
    manual = {
        (item.module_code, item.name)
        for item in PHASE_6_VALIDATOR_REGISTRY
        if item.status is ValidatorStatus.MANUAL_ONLY
    }

    assert ("6C.1", "OS Command Injection") in manual
    assert ("6C.3", "Remote Code Execution") in manual
    assert ("6C.6", "File Execution") in manual
    assert ("6C.6", "Uploaded Script Execution") in manual


def test_all_non_command_injection_types_have_safe_surface_analysis() -> None:
    injection_items = list_phase6_validators("6C.1")

    assert len(injection_items) == 13
    assert sum(
        item.status is ValidatorStatus.PARTIAL
        for item in injection_items
    ) == 12
    assert sum(
        item.status is ValidatorStatus.MANUAL_ONLY
        for item in injection_items
    ) == 1
    assert all(
        item.implementation_action == "injection_surface_validation"
        for item in injection_items
        if item.status is ValidatorStatus.PARTIAL
    )


def test_module_summaries_are_deterministic() -> None:
    summaries = summarize_phase6_validator_modules()

    assert tuple(item.module_code for item in summaries) == (
        "6C.1",
        "6C.2",
        "6C.3",
        "6C.4",
        "6C.5",
        "6C.6",
        "6C.7",
    )
    browser = summaries[1]
    assert browser.total == 13
    assert browser.implemented == 2
    assert browser.display_status == "IN PROGRESS"


def test_registry_builds_tui_module_rows() -> None:
    rows = validator_module_tool_rows()

    assert len(rows) == 7
    assert rows[0][0] == "Saarthi 6C.1"
    assert rows[1] == (
        "Saarthi 6C.2",
        "Browser-Side Attacks (2 ready, 0 partial, 13 total)",
        "IN PROGRESS",
    )

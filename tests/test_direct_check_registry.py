from saarthi_ai.checks.models import CheckCategory, CheckMode
from saarthi_ai.checks.registry import (
    DIRECT_CHECK_REGISTRY,
    get_direct_check,
    list_direct_checks,
)


def test_registry_contains_initial_safe_checks() -> None:
    assert "security-headers" in DIRECT_CHECK_REGISTRY
    assert "information-disclosure" in DIRECT_CHECK_REGISTRY
    assert "cors-configuration" in DIRECT_CHECK_REGISTRY
    assert "open-redirect" in DIRECT_CHECK_REGISTRY


def test_registry_contains_critical_check_categories() -> None:
    assert "sqli-candidate" in DIRECT_CHECK_REGISTRY
    assert "command-injection-candidate" in DIRECT_CHECK_REGISTRY
    assert "rce-confirmation" in DIRECT_CHECK_REGISTRY


def test_rce_confirmation_is_high_impact() -> None:
    definition = get_direct_check("rce-confirmation")

    assert definition is not None
    assert definition.category is CheckCategory.RCE
    assert definition.mode is CheckMode.HIGH_IMPACT
    assert definition.requires_explicit_approval is True


def test_sqli_candidate_is_bounded() -> None:
    definition = get_direct_check("sqli-candidate")

    assert definition is not None
    assert definition.category is CheckCategory.SQL_INJECTION
    assert definition.max_requests == 3


def test_unknown_check_returns_none() -> None:
    assert get_direct_check("unknown-check") is None


def test_list_direct_checks_returns_all_definitions() -> None:
    checks = list_direct_checks()

    assert len(checks) == len(DIRECT_CHECK_REGISTRY)
    assert all(check.check_id for check in checks)

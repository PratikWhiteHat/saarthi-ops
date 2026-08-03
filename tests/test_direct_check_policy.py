from saarthi_ai.checks.models import (
    CheckCategory,
    CheckDecision,
    CheckMode,
    CheckRisk,
    DirectCheckDefinition,
    DirectCheckRequest,
)
from saarthi_ai.checks.policy import evaluate_direct_check


def make_definition(
    *,
    mode: CheckMode = CheckMode.DIRECT,
    destructive: bool = False,
    requires_explicit_approval: bool = False,
    max_requests: int = 5,
    allowed_methods: tuple[str, ...] = ("GET",),
) -> DirectCheckDefinition:
    return DirectCheckDefinition(
        check_id="security-headers",
        name="Security Headers",
        category=CheckCategory.SECURITY_HEADERS,
        risk=CheckRisk.LOW,
        mode=mode,
        destructive=destructive,
        requires_explicit_approval=requires_explicit_approval,
        max_requests=max_requests,
        allowed_methods=allowed_methods,
    )


def make_request(
    *,
    authorized: bool = True,
    active_testing: bool = True,
    explicitly_approved: bool = False,
    requested_method: str = "GET",
    requested_requests: int = 1,
) -> DirectCheckRequest:
    return DirectCheckRequest(
        execution_id="execution-test",
        target_url="https://example.com/",
        check_id="security-headers",
        authorized=authorized,
        active_testing=active_testing,
        explicitly_approved=explicitly_approved,
        requested_method=requested_method,
        requested_requests=requested_requests,
    )


def test_allows_authorized_bounded_direct_check() -> None:
    result = evaluate_direct_check(make_definition(), make_request())

    assert result.decision is CheckDecision.ALLOW


def test_denies_unauthorized_target() -> None:
    result = evaluate_direct_check(
        make_definition(),
        make_request(authorized=False),
    )

    assert result.decision is CheckDecision.DENY
    assert "authorization" in result.reason.lower()


def test_denies_when_active_testing_is_not_enabled() -> None:
    result = evaluate_direct_check(
        make_definition(),
        make_request(active_testing=False),
    )

    assert result.decision is CheckDecision.DENY
    assert "active-testing" in result.reason.lower()


def test_denies_request_count_above_limit() -> None:
    result = evaluate_direct_check(
        make_definition(max_requests=2),
        make_request(requested_requests=3),
    )

    assert result.decision is CheckDecision.DENY
    assert "maximum" in result.reason.lower()


def test_requires_approval_when_definition_requires_it() -> None:
    result = evaluate_direct_check(
        make_definition(requires_explicit_approval=True),
        make_request(),
    )

    assert result.decision is CheckDecision.REQUIRE_APPROVAL


def test_allows_explicitly_approved_check() -> None:
    result = evaluate_direct_check(
        make_definition(requires_explicit_approval=True),
        make_request(explicitly_approved=True),
    )

    assert result.decision is CheckDecision.ALLOW


def test_denies_destructive_check() -> None:
    result = evaluate_direct_check(
        make_definition(destructive=True),
        make_request(explicitly_approved=True),
    )

    assert result.decision is CheckDecision.DENY
    assert "destructive" in result.reason.lower()


def test_denies_high_impact_check() -> None:
    result = evaluate_direct_check(
        make_definition(mode=CheckMode.HIGH_IMPACT),
        make_request(explicitly_approved=True),
    )

    assert result.decision is CheckDecision.DENY
    assert "high-impact" in result.reason.lower()


def test_denies_method_not_allowed_by_definition() -> None:
    result = evaluate_direct_check(
        make_definition(allowed_methods=("GET",)),
        make_request(requested_method="POST"),
    )

    assert result.decision is CheckDecision.DENY
    assert "not allowed" in result.reason.lower()


def test_requires_approval_for_non_safe_allowed_method() -> None:
    result = evaluate_direct_check(
        make_definition(allowed_methods=("POST",)),
        make_request(requested_method="POST"),
    )

    assert result.decision is CheckDecision.REQUIRE_APPROVAL


def test_denies_blocked_http_method() -> None:
    result = evaluate_direct_check(
        make_definition(allowed_methods=("DELETE",)),
        make_request(
            requested_method="DELETE",
            explicitly_approved=True,
        ),
    )

    assert result.decision is CheckDecision.DENY
    assert "blocked" in result.reason.lower()


def test_denies_invalid_target_url() -> None:
    request = DirectCheckRequest(
        execution_id="execution-test",
        target_url="example.com",
        check_id="security-headers",
        authorized=True,
        active_testing=True,
    )

    result = evaluate_direct_check(make_definition(), request)

    assert result.decision is CheckDecision.DENY
    assert "valid http" in result.reason.lower()

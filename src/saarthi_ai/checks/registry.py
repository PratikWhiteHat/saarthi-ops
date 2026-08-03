from __future__ import annotations

from saarthi_ai.checks.models import (
    CheckCategory,
    CheckMode,
    CheckRisk,
    DirectCheckDefinition,
)

DIRECT_CHECK_REGISTRY: dict[str, DirectCheckDefinition] = {
    "security-headers": DirectCheckDefinition(
        check_id="security-headers",
        name="Security Headers Review",
        category=CheckCategory.SECURITY_HEADERS,
        risk=CheckRisk.LOW,
        mode=CheckMode.PASSIVE,
        requires_active_testing=False,
        max_requests=1,
        allowed_methods=("GET", "HEAD"),
        description="Reviews HTTP response security headers.",
    ),
    "information-disclosure": DirectCheckDefinition(
        check_id="information-disclosure",
        name="Information Disclosure Review",
        category=CheckCategory.INFORMATION_DISCLOSURE,
        risk=CheckRisk.LOW,
        mode=CheckMode.PASSIVE,
        requires_active_testing=False,
        max_requests=2,
        allowed_methods=("GET", "HEAD"),
        description="Reviews responses for exposed version and diagnostic information.",
    ),
    "cors-configuration": DirectCheckDefinition(
        check_id="cors-configuration",
        name="CORS Configuration Check",
        category=CheckCategory.CORS,
        risk=CheckRisk.LOW,
        mode=CheckMode.DIRECT,
        max_requests=3,
        allowed_methods=("GET", "OPTIONS"),
        description="Performs bounded CORS behavior validation.",
    ),
    "open-redirect": DirectCheckDefinition(
        check_id="open-redirect",
        name="Open Redirect Check",
        category=CheckCategory.OPEN_REDIRECT,
        risk=CheckRisk.MEDIUM,
        mode=CheckMode.DIRECT,
        requires_explicit_approval=True,
        max_requests=3,
        allowed_methods=("GET",),
        description="Performs controlled redirect validation using approved markers.",
    ),
    "sqli-candidate": DirectCheckDefinition(
        check_id="sqli-candidate",
        name="SQL Injection Candidate Analysis",
        category=CheckCategory.SQL_INJECTION,
        risk=CheckRisk.HIGH,
        mode=CheckMode.DIRECT,
        requires_explicit_approval=True,
        max_requests=3,
        allowed_methods=("GET", "POST"),
        description=(
            "Registers bounded, non-destructive SQL injection candidate checks. "
            "Database extraction is not permitted in Phase 4A."
        ),
    ),
    "command-injection-candidate": DirectCheckDefinition(
        check_id="command-injection-candidate",
        name="Command Injection Candidate Analysis",
        category=CheckCategory.COMMAND_INJECTION,
        risk=CheckRisk.CRITICAL,
        mode=CheckMode.DIRECT,
        requires_explicit_approval=True,
        max_requests=2,
        allowed_methods=("GET", "POST"),
        description=(
            "Registers non-destructive command-injection candidate validation. "
            "No unrestricted commands or system modification are permitted."
        ),
    ),
    "rce-confirmation": DirectCheckDefinition(
        check_id="rce-confirmation",
        name="Remote Code Execution Confirmation",
        category=CheckCategory.RCE,
        risk=CheckRisk.CRITICAL,
        mode=CheckMode.HIGH_IMPACT,
        requires_explicit_approval=True,
        max_requests=1,
        allowed_methods=("GET", "POST"),
        description=(
            "High-impact RCE confirmation placeholder. Execution is denied "
            "by Phase 4A policy."
        ),
    ),
}


def get_direct_check(check_id: str) -> DirectCheckDefinition | None:
    return DIRECT_CHECK_REGISTRY.get(check_id)


def list_direct_checks() -> tuple[DirectCheckDefinition, ...]:
    return tuple(DIRECT_CHECK_REGISTRY.values())

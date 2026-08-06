"""Official Phase 6C attack-validator catalogue and readiness status."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ValidatorStatus(StrEnum):
    """Current implementation state for a roadmap validator."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    PLANNED = "planned"
    REQUIRES_AUTHENTICATED_WORKFLOW = (
        "requires_authenticated_workflow"
    )
    MANUAL_ONLY = "manual_only"


class ValidationLevel(StrEnum):
    """Roadmap validation level."""

    L1_SAFE_DETECTION = "L1-safe-detection"
    L2_SAFE_CONFIRMATION = "L2-safe-confirmation"
    L3_CONTROLLED_CONFIRMATION = "L3-controlled-confirmation"
    L4_MANUAL_VALIDATION = "L4-manual-validation"


@dataclass(frozen=True)
class ValidatorDefinition:
    """One official roadmap validator and its delivery constraints."""

    validator_id: str
    module_code: str
    module_name: str
    name: str
    level: ValidationLevel
    status: ValidatorStatus
    requires_authentication: bool = False
    implementation_action: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class ValidatorModuleSummary:
    """Aggregate readiness for one official validator family."""

    module_code: str
    module_name: str
    total: int
    implemented: int
    partial: int
    planned: int
    requires_authenticated_workflow: int
    manual_only: int

    @property
    def display_status(self) -> str:
        if self.implemented == self.total:
            return "COMPLETED"
        if self.implemented or self.partial:
            return "IN PROGRESS"
        return "PLANNED"


_MODULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "6C.1": (
        "Injection Testing",
        (
            "SQL Injection",
            "NoSQL Injection",
            "OS Command Injection",
            "LDAP Injection",
            "XXE Injection",
            "XPath/XQuery Injection",
            "Server-Side Template Injection",
            "Expression Language Injection",
            "CRLF/Header Injection",
            "Host Header Injection",
            "Email Header Injection",
            "Log Injection",
            "ORM/Query Language Injection",
        ),
    ),
    "6C.2": (
        "Browser-Side Attacks",
        (
            "Reflected XSS",
            "Stored XSS",
            "DOM-Based XSS",
            "HTML Injection",
            "CSS Injection",
            "DOM Clobbering",
            "Prototype Pollution",
            "Open Redirect",
            "Clickjacking Validation",
            "postMessage Origin Validation",
            "WebSocket Authentication Validation",
            "CORS Exploitation",
            "CSRF Validation",
        ),
    ),
    "6C.3": (
        "Server-Side Request & Parser Attacks",
        (
            "Remote Code Execution",
            "Blind SSRF",
            "XXE",
            "XML Entity Expansion",
            "Path Traversal",
            "Local File Inclusion",
            "Remote File Inclusion",
            "Unsafe URL Fetch",
            "Archive Extraction Traversal",
            "Unsafe Deserialization",
            "HTTP Parameter Pollution",
        ),
    ),
    "6C.4": (
        "Authentication & Session Attacks",
        (
            "Username Enumeration",
            "Weak Rate Limiting",
            "Account Lockout",
            "Password Reuse Abuse",
            "MFA Bypass Testing",
            "Session Fixation",
            "Session Hijacking",
            "JWT/IDOR Abuse",
            "Token Replay Attacks",
            "Privilege Escalation",
            "OIDC/OAuth Validation",
            "Tenant Isolation Failures",
        ),
    ),
    "6C.5": (
        "Authorization & Access Control",
        (
            "Horizontal Privilege Escalation",
            "Vertical Privilege Escalation",
            "Object-Level Authorization",
            "Function-Level Authorization",
            "Tenant Isolation",
            "Object Ownership Reference",
            "Role-Based Access Control",
            "Admin Function Access",
            "API Access Control",
        ),
    ),
    "6C.6": (
        "File & Execution Attacks",
        (
            "Unrestricted File Upload",
            "Content-Type Bypass",
            "Extension Bypass",
            "Filename Manipulation",
            "Path Manipulation",
            "Insecure File Parse Tests",
            "File Execution",
            "Uploaded Script Execution",
            "Uploaded Storage Issues",
            "Access-Control Validation",
        ),
    ),
    "6C.7": (
        "API & Business Logic Attacks",
        (
            "Mass Assignment",
            "Excessive Data Exposure",
            "Object-Level Authorization",
            "Function-Level Authorization",
            "GraphQL Injection",
            "GraphQL Depth Exploitation",
            "Parameter Tampering",
            "Price/Quantity Manipulation",
            "Workflow Bypass",
            "Logic Abuse",
            "Race Condition Validation",
            "Coupon/Promotion Abuse",
            "Refund/Payment Flow Abuse",
        ),
    ),
}

_IMPLEMENTATION_OVERRIDES: dict[
    tuple[str, str],
    tuple[
        ValidatorStatus,
        ValidationLevel,
        str | None,
        str | None,
    ],
] = {
    ("6C.2", "Clickjacking Validation"): (
        ValidatorStatus.IMPLEMENTED,
        ValidationLevel.L1_SAFE_DETECTION,
        "clickjacking_header_validation",
        "Header-only protection analysis; no exploit page is generated.",
    ),
    ("6C.2", "CSRF Validation"): (
        ValidatorStatus.IMPLEMENTED,
        ValidationLevel.L1_SAFE_DETECTION,
        "csrf_protection_surface_validation",
        "Form and protection-signal analysis without submission.",
    ),
    ("6C.3", "HTTP Parameter Pollution"): (
        ValidatorStatus.PARTIAL,
        ValidationLevel.L1_SAFE_DETECTION,
        "http_parameter_surface_validation",
        "Duplicate and ambiguous parameter surfaces are detected only.",
    ),
    ("6C.4", "Session Fixation"): (
        ValidatorStatus.PARTIAL,
        ValidationLevel.L1_SAFE_DETECTION,
        "session_cookie_attribute_validation",
        "Cookie hardening is implemented; fixation confirmation is pending.",
    ),
    ("6C.6", "Unrestricted File Upload"): (
        ValidatorStatus.PARTIAL,
        ValidationLevel.L1_SAFE_DETECTION,
        "file_upload_surface_validation",
        "Upload surfaces are detected; no file is submitted.",
    ),
    ("6C.7", "Excessive Data Exposure"): (
        ValidatorStatus.IMPLEMENTED,
        ValidationLevel.L1_SAFE_DETECTION,
        "api_data_exposure_surface_validation",
        "Only aggregate sensitive field-name categories are retained.",
    ),
}

_AUTHENTICATED_MODULES = frozenset({"6C.4", "6C.5"})
_AUTHENTICATED_API_VALIDATORS = frozenset(
    {
        "Mass Assignment",
        "Object-Level Authorization",
        "Function-Level Authorization",
        "Parameter Tampering",
        "Price/Quantity Manipulation",
        "Workflow Bypass",
        "Logic Abuse",
        "Race Condition Validation",
        "Coupon/Promotion Abuse",
        "Refund/Payment Flow Abuse",
    }
)
_MANUAL_ONLY_VALIDATORS = frozenset(
    {
        ("6C.1", "OS Command Injection"),
        ("6C.3", "Remote Code Execution"),
        ("6C.3", "Remote File Inclusion"),
        ("6C.6", "File Execution"),
        ("6C.6", "Uploaded Script Execution"),
        ("6C.7", "Refund/Payment Flow Abuse"),
    }
)


def _slug(value: str) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "-",
        value.lower(),
    ).strip("-")


def _definition(
    module_code: str,
    module_name: str,
    name: str,
) -> ValidatorDefinition:
    override = _IMPLEMENTATION_OVERRIDES.get((module_code, name))
    if override is not None:
        status, level, action, note = override
        return ValidatorDefinition(
            validator_id=f"{module_code.lower()}-{_slug(name)}",
            module_code=module_code,
            module_name=module_name,
            name=name,
            level=level,
            status=status,
            requires_authentication=(
                module_code in _AUTHENTICATED_MODULES
            ),
            implementation_action=action,
            note=note,
        )

    if (module_code, name) in _MANUAL_ONLY_VALIDATORS:
        return ValidatorDefinition(
            validator_id=f"{module_code.lower()}-{_slug(name)}",
            module_code=module_code,
            module_name=module_name,
            name=name,
            level=ValidationLevel.L4_MANUAL_VALIDATION,
            status=ValidatorStatus.MANUAL_ONLY,
            requires_authentication=module_code in {"6C.4", "6C.7"},
        )

    requires_authentication = (
        module_code in _AUTHENTICATED_MODULES
        or (
            module_code == "6C.7"
            and name in _AUTHENTICATED_API_VALIDATORS
        )
    )
    return ValidatorDefinition(
        validator_id=f"{module_code.lower()}-{_slug(name)}",
        module_code=module_code,
        module_name=module_name,
        name=name,
        level=(
            ValidationLevel.L3_CONTROLLED_CONFIRMATION
            if requires_authentication
            else ValidationLevel.L2_SAFE_CONFIRMATION
        ),
        status=(
            ValidatorStatus.REQUIRES_AUTHENTICATED_WORKFLOW
            if requires_authentication
            else ValidatorStatus.PLANNED
        ),
        requires_authentication=requires_authentication,
    )


PHASE_6_VALIDATOR_REGISTRY: tuple[ValidatorDefinition, ...] = tuple(
    _definition(module_code, module_name, validator_name)
    for module_code, (module_name, validator_names) in _MODULES.items()
    for validator_name in validator_names
)


def list_phase6_validators(
    module_code: str | None = None,
) -> tuple[ValidatorDefinition, ...]:
    """Return the full catalogue or one official module family."""

    if module_code is None:
        return PHASE_6_VALIDATOR_REGISTRY
    normalized = module_code.strip().upper()
    return tuple(
        item
        for item in PHASE_6_VALIDATOR_REGISTRY
        if item.module_code.upper() == normalized
    )


def summarize_phase6_validator_modules(
) -> tuple[ValidatorModuleSummary, ...]:
    """Return deterministic readiness totals for each roadmap family."""

    summaries: list[ValidatorModuleSummary] = []
    for module_code, (module_name, _names) in _MODULES.items():
        items = list_phase6_validators(module_code)
        counts = {
            status: sum(item.status is status for item in items)
            for status in ValidatorStatus
        }
        summaries.append(
            ValidatorModuleSummary(
                module_code=module_code,
                module_name=module_name,
                total=len(items),
                implemented=counts[ValidatorStatus.IMPLEMENTED],
                partial=counts[ValidatorStatus.PARTIAL],
                planned=counts[ValidatorStatus.PLANNED],
                requires_authenticated_workflow=counts[
                    ValidatorStatus.REQUIRES_AUTHENTICATED_WORKFLOW
                ],
                manual_only=counts[ValidatorStatus.MANUAL_ONLY],
            )
        )
    return tuple(summaries)


def validator_module_tool_rows() -> tuple[
    tuple[str, str, str],
    ...,
]:
    """Build compact TUI tool rows from the central registry."""

    return tuple(
        (
            f"Saarthi {summary.module_code}",
            (
                f"{summary.module_name} "
                f"({summary.implemented} ready, "
                f"{summary.partial} partial, {summary.total} total)"
            ),
            summary.display_status,
        )
        for summary in summarize_phase6_validator_modules()
    )

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CheckRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckCategory(StrEnum):
    SECURITY_HEADERS = "security_headers"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    RCE = "rce"


class CheckMode(StrEnum):
    PASSIVE = "passive"
    DIRECT = "direct"
    HIGH_IMPACT = "high_impact"


class CheckDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class DirectCheckDefinition:
    check_id: str
    name: str
    category: CheckCategory
    risk: CheckRisk
    mode: CheckMode
    requires_active_testing: bool = True
    requires_explicit_approval: bool = False
    destructive: bool = False
    max_requests: int = 5
    allowed_methods: tuple[str, ...] = ("GET",)
    description: str = ""


@dataclass(frozen=True)
class DirectCheckRequest:
    execution_id: str
    target_url: str
    check_id: str
    authorized: bool
    active_testing: bool
    explicitly_approved: bool = False
    requested_method: str = "GET"
    requested_requests: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyResult:
    decision: CheckDecision
    reason: str

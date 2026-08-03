from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class BlindValidationStatus(StrEnum):
    CREATED = "created"
    WAITING = "waiting"
    OBSERVED = "observed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    FAILED = "failed"


class CallbackProtocol(StrEnum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"


class BlindValidationDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class CorrelationToken:
    token_id: str
    token_value: str
    token_hash: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class BlindValidationRequest:
    execution_id: str
    target_url: str
    authorized: bool
    active_testing: bool
    explicitly_approved: bool
    callback_protocol: CallbackProtocol
    requested_poll_attempts: int = 1
    requested_poll_interval_seconds: int = 5
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class BlindValidationPolicyResult:
    decision: BlindValidationDecision
    reason: str


@dataclass(frozen=True)
class BlindValidationObservation:
    token_id: str
    protocol: CallbackProtocol
    observed_at: datetime
    source_address: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    metadata: dict[str, Any] | None = None

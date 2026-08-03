from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class OastCorrelationStatus(StrEnum):
    REGISTERED = "registered"
    OBSERVED = "observed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class OastProtocol(StrEnum):
    HTTP = "http"
    HTTPS = "https"


@dataclass(frozen=True)
class OastCorrelation:
    token_id: str
    token_hash: str
    execution_id: str
    protocol: OastProtocol
    created_at: datetime
    expires_at: datetime
    status: OastCorrelationStatus = OastCorrelationStatus.REGISTERED


@dataclass(frozen=True)
class OastObservation:
    observation_id: str
    token_id: str
    execution_id: str
    protocol: OastProtocol
    observed_at: datetime
    request_method: str
    request_path: str
    source_address: str
    selected_headers: dict[str, str] = field(default_factory=dict)
    body_size: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

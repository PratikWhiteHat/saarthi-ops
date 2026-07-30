from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from saarthi_ai.assessments.schemas import AssessmentRequest


class RedirectHop(BaseModel):
    """One redirect observed during controlled collection."""

    url: str
    status_code: int
    location: str


class HttpMetadataCollectionRequest(BaseModel):
    """Request for controlled HTTP metadata collection."""

    assessment: AssessmentRequest
    target: str = Field(min_length=1, max_length=2_048)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_body_bytes: int = Field(
        default=65_536,
        ge=1_024,
        le=1_048_576,
    )


class HttpMetadataCollectionResponse(BaseModel):
    """Result of a controlled HTTP metadata request."""

    execution_id: str
    evidence_id: str
    collected_at: datetime
    target: str
    final_url: str
    status_code: int
    http_version: str
    content_type: str | None
    headers: dict[str, str]
    redirect_chain: list[RedirectHop]
    body_bytes_captured: int
    body_truncated: bool
    body_sha256: str
    evidence_path: str

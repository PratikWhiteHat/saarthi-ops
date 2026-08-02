"""Structured models for Phase 3E JavaScript intelligence."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class JavaScriptFetchRecord(BaseModel):
    """Metadata for one controlled JavaScript fetch."""

    url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    body_bytes_captured: int = 0
    body_truncated: bool = False
    body_sha256: str | None = None
    error: str | None = None


class JavaScriptEndpointRecord(BaseModel):
    """One endpoint-like value extracted from JavaScript."""

    value: str
    kind: str
    source_url: str
    in_scope: bool
    absolute_url: str | None = None


class JavaScriptParameterRecord(BaseModel):
    """One candidate parameter name extracted from JavaScript."""

    name: str
    source_url: str


class JavaScriptSecretCandidate(BaseModel):
    """Redacted metadata for a possible embedded secret."""

    secret_type: str
    source_url: str
    fingerprint_sha256: str
    redacted_preview: str
    confidence: str


class JavaScriptAssetRecord(BaseModel):
    """Normalized intelligence produced from one JavaScript asset."""

    fetch: JavaScriptFetchRecord
    endpoints: list[JavaScriptEndpointRecord] = Field(default_factory=list)
    parameters: list[JavaScriptParameterRecord] = Field(default_factory=list)
    websocket_urls: list[str] = Field(default_factory=list)
    source_map_urls: list[str] = Field(default_factory=list)
    secret_candidates: list[JavaScriptSecretCandidate] = Field(default_factory=list)
    framework_indicators: list[str] = Field(default_factory=list)


class JavaScriptCollectionResult(BaseModel):
    """Structured Phase 3E JavaScript intelligence evidence."""

    schema_version: str = "1.0"
    collector: str = "saarthi-javascript-intelligence"

    collector_execution_id: str
    collector_evidence_id: str

    source_evidence_path: str
    source_collector_execution_id: str | None = None
    source_collector_evidence_id: str | None = None

    domain: str
    input_javascript_count: int
    fetched_javascript_count: int
    failed_fetch_count: int
    endpoint_count: int
    parameter_count: int
    websocket_count: int
    source_map_count: int
    secret_candidate_count: int

    rejected_inputs: list[str] = Field(default_factory=list)
    assets: list[JavaScriptAssetRecord] = Field(default_factory=list)

    collected_at: datetime
    evidence_path: str
    evidence_sha256: str
    evidence_size_bytes: int

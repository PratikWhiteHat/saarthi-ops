"""Structured models for Phase 3C live-host and HTTP intelligence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HttpIntelligenceToolRun(BaseModel):
    """Safe execution metadata for ProjectDiscovery httpx."""

    tool_name: str
    available: bool
    executable: str | None = None
    arguments: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stderr_excerpt: str | None = None
    error: str | None = None


class HttpIntelligenceRecord(BaseModel):
    """One normalized live HTTP service returned by httpx."""

    input: str
    url: str
    scheme: str
    host: str
    port: int | None = None
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = Field(default_factory=list)
    webserver: str | None = None
    content_length: int | None = None
    ip: str | None = None
    final_url: str | None = None
    redirect_chain: list[dict[str, Any]] = Field(default_factory=list)
    tls: dict[str, Any] | None = None


class HttpIntelligenceCollectionResult(BaseModel):
    """Structured Phase 3C live-host intelligence evidence."""

    schema_version: str = "1.0"
    collector: str = "projectdiscovery-httpx"
    collector_execution_id: str
    collector_evidence_id: str
    source_evidence_path: str
    source_collector_execution_id: str | None = None
    source_collector_evidence_id: str | None = None
    domain: str
    input_count: int
    live_service_count: int
    malformed_line_count: int = 0
    rejected_inputs: list[str] = Field(default_factory=list)
    rejected_results: list[str] = Field(default_factory=list)
    records: list[HttpIntelligenceRecord] = Field(default_factory=list)
    tool_run: HttpIntelligenceToolRun
    collected_at: datetime
    evidence_path: str
    evidence_sha256: str
    evidence_size_bytes: int

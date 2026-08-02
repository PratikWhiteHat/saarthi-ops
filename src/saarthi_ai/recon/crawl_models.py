"""Structured models for Phase 3D crawling and URL intelligence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CrawlToolRun(BaseModel):
    """Safe execution metadata for ProjectDiscovery Katana."""

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


class CrawlParameterRecord(BaseModel):
    """One normalized URL or form parameter."""

    name: str
    location: str
    value: str | None = None


class CrawlFormRecord(BaseModel):
    """One HTML form discovered during crawling."""

    page_url: str
    action_url: str
    method: str
    parameters: list[CrawlParameterRecord] = Field(default_factory=list)


class CrawlUrlRecord(BaseModel):
    """One normalized in-scope URL discovered by Katana."""

    url: str
    scheme: str
    host: str
    port: int | None = None
    path: str
    query: str | None = None
    fragment: str | None = None
    method: str = "GET"
    source_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    parameters: list[CrawlParameterRecord] = Field(default_factory=list)
    is_javascript: bool = False
    is_websocket: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class CrawlCollectionResult(BaseModel):
    """Structured Phase 3D crawl evidence."""

    schema_version: str = "1.0"
    collector: str = "projectdiscovery-katana"

    collector_execution_id: str
    collector_evidence_id: str

    source_evidence_path: str
    source_collector_execution_id: str | None = None
    source_collector_evidence_id: str | None = None

    domain: str
    input_service_count: int
    crawled_service_count: int
    discovered_url_count: int
    form_count: int
    parameter_count: int
    javascript_url_count: int
    websocket_url_count: int

    malformed_line_count: int = 0
    rejected_inputs: list[str] = Field(default_factory=list)
    rejected_results: list[str] = Field(default_factory=list)

    urls: list[CrawlUrlRecord] = Field(default_factory=list)
    forms: list[CrawlFormRecord] = Field(default_factory=list)

    tool_runs: list[CrawlToolRun] = Field(default_factory=list)

    collected_at: datetime
    evidence_path: str
    evidence_sha256: str
    evidence_size_bytes: int

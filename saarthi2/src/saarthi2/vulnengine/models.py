"""Typed models for the vulnerability identification engine.

Pydantic (consistent with :mod:`saarthi2.engine.models`) so the App Model can be
produced by Ollama structured output and validated at the boundary, and so tasks
and findings serialize cleanly to the run context and the findings store.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SurfaceType(StrEnum):
    """The kind of input surface — drives the feature->vuln matrix."""

    SEARCH = "search"
    OBJECT_REF = "object_ref"
    URL_PARAM = "url_param"
    FILE_UPLOAD = "file_upload"
    AUTH_FIELD = "auth_field"
    REDIRECT = "redirect"
    GENERIC = "generic"


class InputSurface(BaseModel):
    """One place the app takes input — a form, a query param, an upload."""

    url: str
    params: list[str] = Field(default_factory=list)
    method: str = "GET"
    type: SurfaceType = SurfaceType.GENERIC
    auth_required: bool = False
    # Grounded, code-detected signals attached to THIS surface (e.g.
    # "reflects_input", "numeric_id", "url_like_value"). The planner routes on these.
    signals: list[str] = Field(default_factory=list)
    # Per-parameter grounded signals, so the planner routes each class to the
    # parameter that actually earned it (idor_bola to the numeric id, not to a
    # free-text field on the same form).
    param_signals: dict[str, list[str]] = Field(default_factory=dict)
    # Example values observed in the crawl (used to seed/mutate payloads, e.g. the
    # neighbour ids for an IDOR probe). Not part of routing.
    example_values: dict[str, str] = Field(default_factory=dict)


class AppModel(BaseModel):
    """A structured understanding of the target, built from the authenticated crawl."""

    app_type: str = "unknown"
    tech_stack: list[str] = Field(default_factory=list)
    roles_seen: list[str] = Field(default_factory=list)
    key_features: list[str] = Field(default_factory=list)
    input_surfaces: list[InputSurface] = Field(default_factory=list)
    interesting_signals: list[str] = Field(default_factory=list)

    @property
    def is_populated(self) -> bool:
        """The hard gate: TEST cannot start without at least one input surface."""

        return bool(self.input_surfaces)


class TestTask(BaseModel):
    """One planned test: probe ``param`` on ``endpoint`` for ``vuln_class``."""

    endpoint: str
    param: str | None = None
    method: str = "GET"
    vuln_class: str
    surface_type: SurfaceType = SurfaceType.GENERIC
    # Higher runs first. The matrix seeds a base priority; the model may reorder.
    priority: int = 0
    auth_required: bool = False
    # Which grounded signals justified this task (for the report/audit trail).
    signals: list[str] = Field(default_factory=list)

    def key(self) -> tuple[str, str, str, str]:
        return (self.method.upper(), self.endpoint, self.param or "", self.vuln_class)


class ResponseSignals(BaseModel):
    """What ``http_send`` returns — signals, not raw HTML.

    The tester and oracle judge findings from these, so a huge response body
    never floods the model context and comparisons stay cheap and deterministic.
    """

    status: int = 0
    resp_len: int = 0
    time_ms: int = 0
    body_sha256: str = ""
    reflections: list[str] = Field(default_factory=list)
    # Location header for redirect analysis (empty when not a redirect).
    location: str = ""
    # Kept out of the model's view but available to the oracle for content checks.
    body: str = Field(default="", exclude=True, repr=False)

    @classmethod
    def from_response(
        cls, status: int, body: str, time_ms: int, *, markers: list[str] | None = None,
        location: str = "",
    ) -> ResponseSignals:
        reflections = [m for m in (markers or []) if m and m in body]
        return cls(
            status=status,
            resp_len=len(body),
            time_ms=time_ms,
            body_sha256=hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            reflections=reflections,
            location=location,
            body=body,
        )


class FindingStatus(StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    DROPPED = "dropped"


class FindingSource(StrEnum):
    AI = "ai"
    ORACLE = "oracle"


# Default severity per vuln class (the matrix config can override per row later).
_DEFAULT_SEVERITY = {
    "sqli": "critical",
    "sqli_boolean": "critical",
    "sqli_time": "critical",
    "auth_bypass": "critical",
    "idor_bola": "high",
    "ssrf": "high",
    "blind_ssrf": "high",
    "stored_xss": "high",
    "xss": "medium",
    "reflected_xss": "medium",
    "open_redirect": "low",
    "price_tamper": "high",
    "coupon_logic": "medium",
}


def severity_for(vuln_class: str) -> str:
    return _DEFAULT_SEVERITY.get(vuln_class, "medium")


class Finding(BaseModel):
    """A structured finding — the product of the pipeline.

    Prose lives ONLY in ``summary``. Everything else is typed so the oracle,
    the store, and the dashboard can reason over it. Suspected findings come from
    TEST (source="ai"); the oracle promotes them to confirmed (source="oracle").
    """

    id: str
    vuln_class: str
    severity: str = "info"
    url: str = ""
    param: str | None = None
    method: str = "GET"
    status: FindingStatus = FindingStatus.SUSPECTED
    source: FindingSource = FindingSource.AI
    confidence: float = 0.0
    summary: str = ""
    # The request that produced it: {method, url, param, payload, headers, body}.
    request: dict[str, Any] = Field(default_factory=dict)
    # Verification evidence: {diff, timing, callback, response, ...}.
    evidence: dict[str, Any] = Field(default_factory=dict)

    def location(self) -> str:
        return f"{self.url}{f' (param={self.param})' if self.param else ''}"

    def to_row(self) -> dict[str, Any]:
        """Flatten to the shape the findings store persists (see state.record_findings)."""

        return {
            "tool": "vulnengine",
            "rule_id": self.vuln_class,
            "severity": self.severity,
            "message": self.summary,
            "location": self.location(),
            "vuln_class": self.vuln_class,
            "status": self.status.value,
            "source": self.source.value,
            "confidence": self.confidence,
            "url": self.url,
            "param": self.param or "",
            "method": self.method,
            "summary": self.summary,
            "evidence": self.evidence,
            "request": self.request,
        }

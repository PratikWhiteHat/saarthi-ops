from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from saarthi_ai.assessments.schemas import (
    AssessmentRequest,
    AssessmentTarget,
    AssetType,
)
from saarthi_ai.execution.http_collector import (
    HttpCollectionScopeError,
    collect_http_metadata,
)
from saarthi_ai.execution.http_models import (
    HttpMetadataCollectionRequest,
)


def build_request(
    target: str = "https://example.com/",
    *,
    max_body_bytes: int = 65_536,
) -> HttpMetadataCollectionRequest:
    """Create an authorized HTTP metadata collection request."""

    assessment = AssessmentRequest(
        name="Authorized Web VAPT",
        targets=[
            AssessmentTarget(
                asset_type=AssetType.WEB,
                value="https://example.com",
            )
        ],
        authorization_confirmed=True,
        allow_active_testing=False,
        allow_intrusive_testing=False,
    )

    return HttpMetadataCollectionRequest(
        assessment=assessment,
        target=target,
        timeout_seconds=10,
        max_redirects=3,
        max_body_bytes=max_body_bytes,
    )


@pytest.mark.asyncio
async def test_collect_http_metadata(tmp_path: Path) -> None:
    """Collector should preserve metadata and redact sensitive headers."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "session=secret",
            },
            content=b"hello",
            request=request,
        )

    result = await collect_http_metadata(
        build_request(),
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path,
    )

    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.content_type == "text/html"
    assert result.body_bytes_captured == 5
    assert result.body_truncated is False
    assert result.headers["set-cookie"] == "<redacted>"
    assert len(result.body_sha256) == 64
    assert (tmp_path / f"{result.evidence_id}.json").exists()


@pytest.mark.asyncio
async def test_same_origin_redirect_is_allowed(
    tmp_path: Path,
) -> None:
    """Same-origin redirects should be followed safely."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                status_code=302,
                headers={"Location": "/login"},
                request=request,
            )

        return httpx.Response(
            status_code=200,
            content=b"login page",
            request=request,
        )

    result = await collect_http_metadata(
        build_request(),
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path,
    )

    assert result.status_code == 200
    assert result.final_url == "https://example.com/login"
    assert len(result.redirect_chain) == 1
    assert result.redirect_chain[0].status_code == 302
    assert result.redirect_chain[0].location == "https://example.com/login"


@pytest.mark.asyncio
async def test_cross_origin_redirect_is_blocked(
    tmp_path: Path,
) -> None:
    """Redirects outside the authorized origin must be rejected."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "https://outside.example.net/"},
            request=request,
        )

    with pytest.raises(
        HttpCollectionScopeError,
        match="Cross-origin redirect blocked",
    ):
        await collect_http_metadata(
            build_request(),
            transport=httpx.MockTransport(handler),
            evidence_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_unscoped_target_is_blocked(
    tmp_path: Path,
) -> None:
    """Requested URL must exactly match an authorized target."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            request=request,
        )

    with pytest.raises(
        HttpCollectionScopeError,
        match="does not exactly match",
    ):
        await collect_http_metadata(
            build_request(target="https://other.example.com/"),
            transport=httpx.MockTransport(handler),
            evidence_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_response_body_is_limited(
    tmp_path: Path,
) -> None:
    """Collector must stop capturing at the configured byte limit."""

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            content=b"A" * 10_000,
            request=request,
        )

    result = await collect_http_metadata(
        build_request(max_body_bytes=1_024),
        transport=httpx.MockTransport(handler),
        evidence_root=tmp_path,
    )

    assert result.body_bytes_captured == 1_024
    assert result.body_truncated is True

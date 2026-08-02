from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from saarthi_ai.recon import javascript_collector
from saarthi_ai.recon.javascript_collector import (
    JavaScriptInputError,
    collect_javascript_intelligence,
)


def write_crawl_evidence(
    path: Path,
    *,
    domain: str = "example.com",
) -> Path:
    """Write representative Phase 3D crawl evidence."""

    payload = {
        "domain": domain,
        "collector_execution_id": "crawl-run-test",
        "collector_evidence_id": "crawl-evidence-test",
        "urls": [
            {
                "url": "https://example.com/assets/app.js",
                "is_javascript": True,
            },
            {
                "url": "https://example.com/assets/app.js",
                "is_javascript": True,
            },
            {
                "url": "https://outside.test/assets/outside.js",
                "is_javascript": True,
            },
            {
                "url": "https://example.com/",
                "is_javascript": False,
            },
        ],
    }

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return path


@pytest.mark.asyncio
async def test_collect_javascript_intelligence_extracts_redacted_data(
    tmp_path: Path,
) -> None:
    """The collector should extract intelligence without storing source code."""

    source = write_crawl_evidence(tmp_path / "crawl.json")

    secret = "ABCDEFGHIJKLMNOPQRSTUVWX"

    javascript_body = f'''
const api = "/api/users?userId=123";
const socket = "wss://api.example.com/socket";
const api_key = "{secret}";
const framework = "react-dom";
//# sourceMappingURL=app.js.map
'''.encode()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://example.com/assets/app.js")

        return httpx.Response(
            200,
            headers={
                "content-type": "text/javascript",
                "content-length": str(len(javascript_body)),
            },
            content=javascript_body,
            request=request,
        )

    result = await collect_javascript_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
        transport=httpx.MockTransport(handler),
    )

    assert result.domain == "example.com"
    assert result.input_javascript_count == 1
    assert result.fetched_javascript_count == 1
    assert result.failed_fetch_count == 0
    assert result.endpoint_count == 2
    assert result.parameter_count >= 1
    assert result.websocket_count == 1
    assert result.source_map_count == 1
    assert result.secret_candidate_count == 1
    assert "https://outside.test/assets/outside.js" in (result.rejected_inputs)

    asset = result.assets[0]

    assert asset.fetch.status_code == 200
    assert asset.fetch.content_type == "text/javascript"
    assert asset.fetch.body_sha256 == hashlib.sha256(javascript_body).hexdigest()
    assert asset.fetch.body_truncated is False

    endpoint_values = {endpoint.value for endpoint in asset.endpoints}

    assert "/api/users?userId=123" in endpoint_values
    assert "wss://api.example.com/socket" in endpoint_values

    assert any(parameter.name == "userId" for parameter in asset.parameters)

    assert asset.websocket_urls == ["wss://api.example.com/socket"]

    assert asset.source_map_urls == ["https://example.com/assets/app.js.map"]

    assert "React" in asset.framework_indicators

    candidate = asset.secret_candidates[0]

    assert candidate.secret_type == "generic-api-key"
    assert candidate.fingerprint_sha256 == hashlib.sha256(secret.encode()).hexdigest()
    assert candidate.redacted_preview == "ABCD…UVWX"
    assert secret not in candidate.redacted_preview

    evidence_path = Path(result.evidence_path)
    evidence_bytes = evidence_path.read_bytes()
    evidence_text = evidence_bytes.decode("utf-8")

    assert result.evidence_sha256 == hashlib.sha256(evidence_bytes).hexdigest()
    assert result.evidence_size_bytes == len(evidence_bytes)

    assert secret not in evidence_text
    assert javascript_body.decode() not in evidence_text
    assert '"body"' not in evidence_text

    serialized_asset = json.dumps(
        asset.model_dump(mode="json"),
        ensure_ascii=False,
    )
    assert secret not in serialized_asset


@pytest.mark.asyncio
async def test_javascript_body_capture_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JavaScript response bodies must respect the configured byte cap."""

    source = write_crawl_evidence(tmp_path / "crawl.json")

    monkeypatch.setattr(
        javascript_collector,
        "MAX_BODY_BYTES",
        32,
    )

    body = b"A" * 100

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/javascript",
            },
            content=body,
            request=request,
        )

    result = await collect_javascript_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
        transport=httpx.MockTransport(handler),
    )

    asset = result.assets[0]

    assert asset.fetch.body_bytes_captured == 32
    assert asset.fetch.body_truncated is True
    assert asset.fetch.body_sha256 == hashlib.sha256(b"A" * 32).hexdigest()


@pytest.mark.asyncio
async def test_javascript_network_failure_is_recorded(
    tmp_path: Path,
) -> None:
    """One failed fetch should be recorded without aborting collection."""

    source = write_crawl_evidence(tmp_path / "crawl.json")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "connection refused",
            request=request,
        )

    result = await collect_javascript_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
        transport=httpx.MockTransport(handler),
    )

    assert result.input_javascript_count == 1
    assert result.fetched_javascript_count == 0
    assert result.failed_fetch_count == 1
    assert result.assets[0].fetch.status_code is None
    assert "connection refused" in (result.assets[0].fetch.error or "")


@pytest.mark.asyncio
async def test_missing_crawl_evidence_raises(
    tmp_path: Path,
) -> None:
    """A missing Phase 3D evidence file must be rejected."""

    with pytest.raises(
        JavaScriptInputError,
        match="does not exist",
    ):
        await collect_javascript_intelligence(
            tmp_path / "missing.json",
            evidence_root=tmp_path,
        )


@pytest.mark.asyncio
async def test_no_valid_javascript_urls_raises(
    tmp_path: Path,
) -> None:
    """Evidence without valid scoped JavaScript must be rejected."""

    source = tmp_path / "crawl.json"
    source.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "urls": [
                    {
                        "url": "https://outside.test/app.js",
                        "is_javascript": True,
                    },
                    {
                        "url": "https://example.com/",
                        "is_javascript": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        JavaScriptInputError,
        match="no valid in-scope JavaScript URLs",
    ):
        await collect_javascript_intelligence(
            source,
            evidence_root=tmp_path,
        )

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.execution.tool_runner import ToolRunResult
from saarthi_ai.recon import crawl_collector
from saarthi_ai.recon.crawl_collector import (
    CrawlInputError,
    collect_crawl_intelligence,
)


def write_http_intelligence_evidence(
    path: Path,
    *,
    domain: str = "example.com",
) -> Path:
    """Write representative Phase 3C evidence."""

    payload = {
        "domain": domain,
        "collector_execution_id": "http-intelligence-run-test",
        "collector_evidence_id": "http-intelligence-evidence-test",
        "records": [
            {"url": "https://example.com"},
            {"url": "https://api.example.com"},
            {"url": "https://api.example.com"},
            {"url": "https://outside.test"},
            {"url": ""},
        ],
    }

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return path


def tool_result(stdout: str) -> ToolRunResult:
    """Return a successful controlled Katana execution result."""

    return ToolRunResult(
        tool_name="projectdiscovery-katana",
        executable="/approved/katana",
        arguments=("-jsonl",),
        exit_code=0,
        stdout=stdout,
        stderr="",
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        timed_out=False,
    )


def test_collect_crawl_intelligence_parses_and_filters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Katana JSONL should become normalized scoped crawl evidence."""

    source = write_http_intelligence_evidence(tmp_path / "http-intelligence.json")

    stdout = "\n".join(
        [
            json.dumps(
                {
                    "depth": 1,
                    "tag": "a",
                    "source": "https://example.com/",
                    "technologies": ["WordPress"],
                    "request": {
                        "method": "GET",
                        "endpoint": ("https://example.com/search?q=saarthi&page=1#results"),
                        "raw": "must not be persisted",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Content-Type": "text/html; charset=UTF-8",
                        },
                        "body": "must not be persisted",
                    },
                    "forms": [
                        {
                            "action": "https://example.com/contact",
                            "method": "POST",
                            "inputs": [
                                {
                                    "name": "email",
                                    "value": "",
                                },
                                {
                                    "name": "message",
                                },
                            ],
                        }
                    ],
                }
            ),
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": ("https://example.com/search?q=saarthi&page=1"),
                    },
                    "response": {
                        "status_code": 200,
                    },
                }
            ),
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": ("https://example.com/assets/app.js"),
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "content-type": ("application/javascript"),
                        },
                    },
                }
            ),
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": "https://outside.test/admin",
                    },
                    "response": {
                        "status_code": 200,
                    },
                }
            ),
            "not-json",
        ]
    )

    monkeypatch.setattr(
        crawl_collector,
        "resolve_executable",
        lambda profile: "/approved/katana",
    )
    monkeypatch.setattr(
        crawl_collector,
        "run_tool",
        lambda profile, arguments: tool_result(stdout),
    )

    result = collect_crawl_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
    )

    assert result.domain == "example.com"
    assert result.input_service_count == 2
    assert result.crawled_service_count == 1
    assert result.discovered_url_count == 2
    assert result.form_count == 1
    assert result.parameter_count == 4
    assert result.javascript_url_count == 1
    assert result.websocket_url_count == 0
    assert result.malformed_line_count == 1

    assert "https://outside.test" in result.rejected_inputs
    assert "https://outside.test/admin" in result.rejected_results

    search_record = next(record for record in result.urls if record.path == "/search")

    assert search_record.host == "example.com"
    assert search_record.fragment is None
    assert search_record.status_code == 200
    assert search_record.content_type == ("text/html; charset=UTF-8")
    assert [parameter.name for parameter in search_record.parameters] == [
        "q",
        "page",
    ]
    assert search_record.metadata["depth"] == 1
    assert search_record.metadata["tag"] == "a"
    assert search_record.metadata["technologies"] == ["WordPress"]

    javascript_record = next(record for record in result.urls if record.path == "/assets/app.js")

    assert javascript_record.is_javascript is True

    form = result.forms[0]

    assert form.page_url.startswith("https://example.com/search")
    assert form.action_url == "https://example.com/contact"
    assert form.method == "POST"
    assert [parameter.name for parameter in form.parameters] == [
        "email",
        "message",
    ]

    evidence_path = Path(result.evidence_path)
    evidence_bytes = evidence_path.read_bytes()
    evidence_text = evidence_bytes.decode("utf-8")

    assert evidence_path.exists()
    assert result.evidence_sha256 == hashlib.sha256(evidence_bytes).hexdigest()
    assert result.evidence_size_bytes == len(evidence_bytes)

    assert "must not be persisted" not in evidence_text
    assert '"body"' not in evidence_text
    assert '"raw"' not in evidence_text


def test_missing_http_intelligence_evidence_raises(
    tmp_path: Path,
) -> None:
    """A missing Phase 3C evidence file must be rejected."""

    with pytest.raises(
        CrawlInputError,
        match="does not exist",
    ):
        collect_crawl_intelligence(
            tmp_path / "missing.json",
            evidence_root=tmp_path,
        )


def test_no_valid_in_scope_urls_raises(
    tmp_path: Path,
) -> None:
    """Evidence containing no approved URLs must be rejected."""

    source = tmp_path / "http-intelligence.json"
    source.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "records": [
                    {"url": "https://outside.test"},
                    {"url": "ftp://example.com/archive"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        CrawlInputError,
        match="no valid in-scope URLs",
    ):
        collect_crawl_intelligence(
            source,
            evidence_root=tmp_path,
        )


def test_katana_timeout_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out Katana execution must fail safely."""

    source = write_http_intelligence_evidence(tmp_path / "http-intelligence.json")

    monkeypatch.setattr(
        crawl_collector,
        "resolve_executable",
        lambda profile: "/approved/katana",
    )
    monkeypatch.setattr(
        crawl_collector,
        "run_tool",
        lambda profile, arguments: ToolRunResult(
            tool_name="projectdiscovery-katana",
            executable="/approved/katana",
            arguments=tuple(arguments),
            exit_code=-1,
            stdout="",
            stderr="timeout",
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            timed_out=True,
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="timed out",
    ):
        collect_crawl_intelligence(
            source,
            evidence_root=tmp_path,
        )


def test_katana_nonzero_exit_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsuccessful Katana exit code must fail safely."""

    source = write_http_intelligence_evidence(tmp_path / "http-intelligence.json")

    monkeypatch.setattr(
        crawl_collector,
        "resolve_executable",
        lambda profile: "/approved/katana",
    )
    monkeypatch.setattr(
        crawl_collector,
        "run_tool",
        lambda profile, arguments: ToolRunResult(
            tool_name="projectdiscovery-katana",
            executable="/approved/katana",
            arguments=tuple(arguments),
            exit_code=2,
            stdout="",
            stderr="collector failed",
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            timed_out=False,
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="exited unsuccessfully: 2",
    ):
        collect_crawl_intelligence(
            source,
            evidence_root=tmp_path,
        )

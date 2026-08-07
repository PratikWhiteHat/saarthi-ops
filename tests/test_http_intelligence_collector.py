from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saarthi_ai.execution.tool_runner import ToolRunResult
from saarthi_ai.recon import http_intelligence_collector
from saarthi_ai.recon.http_intelligence_collector import (
    HttpIntelligenceInputError,
    collect_http_intelligence,
)


def write_subdomain_evidence(
    path: Path,
    *,
    domain: str = "example.com",
) -> Path:
    payload = {
        "domain": domain,
        "collector_execution_id": "subdomain-run-test",
        "collector_evidence_id": "subdomain-evidence-test",
        "candidates": [
            {"hostname": "example.com"},
            {"hostname": "api.example.com"},
            {"hostname": "api.example.com"},
            {"hostname": "outside.test"},
            {"hostname": ""},
        ],
    }

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return path


def tool_result(stdout: str) -> ToolRunResult:
    return ToolRunResult(
        tool_name="projectdiscovery-httpx",
        executable="/approved/httpx",
        arguments=("-json",),
        exit_code=0,
        stdout=stdout,
        stderr="",
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        timed_out=False,
    )


def test_collect_http_intelligence_parses_and_filters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = write_subdomain_evidence(tmp_path / "subdomains.json")

    stdout = "\n".join(
        [
            json.dumps(
                {
                    "input": "api.example.com",
                    "url": "https://api.example.com",
                    "status_code": 200,
                    "title": "API",
                    "tech": ["nginx", "Python"],
                    "webserver": "nginx",
                    "content_length": 123,
                    "host_ip": "192.0.2.10",
                    "port": 443,
                    "tls": {"subject_cn": "api.example.com"},
                }
            ),
            json.dumps(
                {
                    "input": "api.example.com",
                    "url": "https://api.example.com",
                    "status_code": 200,
                }
            ),
            json.dumps(
                {
                    "input": "outside.test",
                    "url": "https://outside.test",
                    "status_code": 200,
                }
            ),
            "not-json",
        ]
    )

    monkeypatch.setattr(
        http_intelligence_collector,
        "resolve_executable",
        lambda profile: "/approved/httpx",
    )
    monkeypatch.setattr(
        http_intelligence_collector,
        "run_tool",
        lambda profile, arguments, **_kw: tool_result(stdout),
    )

    result = collect_http_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
    )

    assert result.domain == "example.com"
    assert result.input_count == 2
    assert result.live_service_count == 1
    assert result.malformed_line_count == 1
    assert "outside.test" in result.rejected_inputs
    assert "https://outside.test" in result.rejected_results
    assert result.records[0].host == "api.example.com"
    assert result.records[0].status_code == 200
    evidence_path = Path(result.evidence_path)
    evidence_bytes = evidence_path.read_bytes()

    assert evidence_path.exists()
    assert result.evidence_sha256 == hashlib.sha256(evidence_bytes).hexdigest()
    assert result.evidence_size_bytes == len(evidence_bytes)


def test_missing_subdomain_evidence_raises(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        HttpIntelligenceInputError,
        match="does not exist",
    ):
        collect_http_intelligence(
            tmp_path / "missing.json",
            evidence_root=tmp_path,
        )


def test_no_valid_in_scope_hosts_raises(
    tmp_path: Path,
) -> None:
    source = tmp_path / "subdomains.json"
    source.write_text(
        json.dumps(
            {
                "domain": "example.com",
                "candidates": [
                    {"hostname": "outside.test"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        HttpIntelligenceInputError,
        match="no valid in-scope hostnames",
    ):
        collect_http_intelligence(
            source,
            evidence_root=tmp_path,
        )


def test_httpx_timeout_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = write_subdomain_evidence(tmp_path / "subdomains.json")

    monkeypatch.setattr(
        http_intelligence_collector,
        "resolve_executable",
        lambda profile: "/approved/httpx",
    )
    monkeypatch.setattr(
        http_intelligence_collector,
        "run_tool",
        lambda profile, arguments, **_kw: ToolRunResult(
            tool_name="projectdiscovery-httpx",
            executable="/approved/httpx",
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
        collect_http_intelligence(
            source,
            evidence_root=tmp_path,
        )


def test_httpx_streams_only_parsed_in_scope_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from saarthi_ai.execution.tool_runner import ToolOutputEvent

    source = write_subdomain_evidence(
        tmp_path / "subdomains.json"
    )

    valid_line = json.dumps(
        {
            "input": "api.example.com",
            "url": (
                "https://api.example.com/"
                "?access_token=must-not-be-logged"
            ),
            "status_code": 200,
            "title": "Private dashboard",
            "tech": ["nginx", "PHP"],
            "webserver": "nginx",
            "content_length": 123,
        }
    )

    outside_line = json.dumps(
        {
            "input": "outside.test",
            "url": "https://outside.test/",
            "status_code": 200,
        }
    )

    monkeypatch.setattr(
        http_intelligence_collector,
        "resolve_executable",
        lambda profile: "/approved/httpx",
    )

    def fake_run_tool(
        profile,
        arguments,
        *,
        on_output=None,
        abort_check=None,
    ):
        if on_output is not None:
            on_output(
                ToolOutputEvent(
                    tool_name=profile.name,
                    stream="stdout",
                    line=valid_line,
                )
            )
            on_output(
                ToolOutputEvent(
                    tool_name=profile.name,
                    stream="stdout",
                    line=outside_line,
                )
            )
            on_output(
                ToolOutputEvent(
                    tool_name=profile.name,
                    stream="stderr",
                    line="Authorization: Bearer secret",
                )
            )

        return tool_result(
            valid_line + "\n" + outside_line + "\n"
        )

    monkeypatch.setattr(
        http_intelligence_collector,
        "run_tool",
        fake_run_tool,
    )

    records = []

    collect_http_intelligence(
        source,
        evidence_root=tmp_path / "evidence",
        progress_callback=records.append,
    )

    assert len(records) == 1
    assert records[0].host == "api.example.com"
    assert records[0].status_code == 200

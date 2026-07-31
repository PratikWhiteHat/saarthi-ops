from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from saarthi_ai.execution.tool_runner import ToolRunResult
from saarthi_ai.recon import subdomain_collector
from saarthi_ai.recon.subdomain_collector import (
    SubdomainCollectionError,
    collect_subdomains,
)


class FakeCtClient:
    """Minimal crt.sh client used by collector tests."""

    def __init__(self, payload: list[object]) -> None:
        self.payload = payload

    def get(self, endpoint: str, params: dict[str, str]) -> httpx.Response:
        request = httpx.Request(
            "GET",
            endpoint,
            params=params,
        )

        return httpx.Response(
            200,
            json=self.payload,
            request=request,
        )


def tool_result(
    tool_name: str,
    stdout: str,
    *,
    exit_code: int = 0,
    stderr: str = "",
    timed_out: bool = False,
) -> ToolRunResult:
    """Build deterministic controlled-tool output."""

    return ToolRunResult(
        tool_name=tool_name,
        executable=f"/approved/{tool_name}",
        arguments=(),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        timed_out=timed_out,
    )


def test_collect_subdomains_merges_all_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector should deduplicate and preserve source attribution."""

    def fake_resolve(profile):
        return f"/approved/{profile.name}"

    def fake_run(profile, arguments):
        if profile.name == "subfinder":
            return tool_result(
                "subfinder",
                "api.example.com\nshared.example.com\n",
            )

        if profile.name == "amass":
            return tool_result(
                "amass",
                "admin.example.com\nshared.example.com\n",
            )

        if profile.name == "assetfinder":
            return tool_result(
                "assetfinder",
                "cdn.example.com\noutside.test\n",
            )

        raise AssertionError(profile.name)

    monkeypatch.setattr(
        subdomain_collector,
        "resolve_executable",
        fake_resolve,
    )
    monkeypatch.setattr(
        subdomain_collector,
        "run_tool",
        fake_run,
    )

    client = FakeCtClient(
        [
            {
                "name_value": (
                    "*.wild.example.com\n"
                    "shared.example.com\n"
                    "mail.example.com"
                )
            }
        ]
    )

    result = collect_subdomains(
        "example.com",
        evidence_root=tmp_path,
        client=client,  # type: ignore[arg-type]
    )

    candidates = {
        candidate.hostname: candidate
        for candidate in result.candidates
    }

    assert set(candidates) == {
        "admin.example.com",
        "api.example.com",
        "cdn.example.com",
        "example.com",
        "mail.example.com",
        "shared.example.com",
        "wild.example.com",
    }

    assert candidates["shared.example.com"].sources == [
        "amass",
        "certificate-transparency",
        "subfinder",
    ]
    assert candidates["wild.example.com"].wildcard_source is True
    assert candidates["example.com"].sources == ["scope-root"]

    assert "outside.test" in result.rejected_names
    assert result.source == "multi-provider"
    assert len(result.tool_runs) == 4
    assert Path(result.evidence_path).exists()
    assert len(result.evidence_sha256) == 64
    assert result.evidence_size_bytes > 0


def test_missing_local_tool_is_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unavailable tools should not fail the whole workflow."""

    def fake_resolve(profile):
        if profile.name == "subfinder":
            return None

        return f"/approved/{profile.name}"

    def fake_run(profile, arguments):
        return tool_result(
            profile.name,
            "",
        )

    monkeypatch.setattr(
        subdomain_collector,
        "resolve_executable",
        fake_resolve,
    )
    monkeypatch.setattr(
        subdomain_collector,
        "run_tool",
        fake_run,
    )

    result = collect_subdomains(
        "example.com",
        evidence_root=tmp_path,
        client=FakeCtClient([]),  # type: ignore[arg-type]
    )

    subfinder_run = next(
        run
        for run in result.tool_runs
        if run.tool_name == "subfinder"
    )

    assert subfinder_run.available is False
    assert "not installed" in (subfinder_run.error or "")
    assert any(
        candidate.hostname == "example.com"
        for candidate in result.candidates
    )


def test_provider_timeout_is_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timed-out providers should be captured without losing other results."""

    def fake_resolve(profile):
        return f"/approved/{profile.name}"

    def fake_run(profile, arguments):
        if profile.name == "amass":
            return tool_result(
                "amass",
                "",
                exit_code=-1,
                timed_out=True,
            )

        return tool_result(
            profile.name,
            f"{profile.name}.example.com\n",
        )

    monkeypatch.setattr(
        subdomain_collector,
        "resolve_executable",
        fake_resolve,
    )
    monkeypatch.setattr(
        subdomain_collector,
        "run_tool",
        fake_run,
    )

    result = collect_subdomains(
        "example.com",
        evidence_root=tmp_path,
        client=FakeCtClient([]),  # type: ignore[arg-type]
    )

    amass_run = next(
        run
        for run in result.tool_runs
        if run.tool_name == "amass"
    )

    assert amass_run.timed_out is True
    assert any(
        candidate.hostname == "subfinder.example.com"
        for candidate in result.candidates
    )


def test_all_providers_failure_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collector should fail when every passive provider fails."""

    monkeypatch.setattr(
        subdomain_collector,
        "resolve_executable",
        lambda profile: None,
    )

    class TimeoutClient:
        def get(self, endpoint: str, params: dict[str, str]):
            raise httpx.TimeoutException("timeout")

    with pytest.raises(
        SubdomainCollectionError,
        match="All passive subdomain providers failed",
    ):
        collect_subdomains(
            "example.com",
            evidence_root=tmp_path,
            client=TimeoutClient(),  # type: ignore[arg-type]
        )


def test_out_of_scope_results_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tool output must remain inside the approved parent domain."""

    monkeypatch.setattr(
        subdomain_collector,
        "resolve_executable",
        lambda profile: f"/approved/{profile.name}",
    )
    monkeypatch.setattr(
        subdomain_collector,
        "run_tool",
        lambda profile, arguments: tool_result(
            profile.name,
            "api.example.com\nexample.com.attacker.test\n",
        ),
    )

    result = collect_subdomains(
        "example.com",
        evidence_root=tmp_path,
        client=FakeCtClient([]),  # type: ignore[arg-type]
    )

    hostnames = {
        candidate.hostname
        for candidate in result.candidates
    }

    assert "api.example.com" in hostnames
    assert "example.com.attacker.test" not in hostnames
    assert "example.com.attacker.test" in result.rejected_names

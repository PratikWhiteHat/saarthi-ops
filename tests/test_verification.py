"""Tests for the finding-verification / false-positive filter."""

from __future__ import annotations

import json

from saarthi_ai.automation.verification import (
    FindingVerdict,
    classify_sqlmap_run,
    parse_nuclei_findings,
    verify_findings,
    verify_nuclei_finding,
)
from saarthi_ai.execution.tool_runner import ToolRunResult

ALLOWED = ("app.example.com",)


def _nuclei_line(template: str, url: str, severity: str = "info") -> str:
    return json.dumps(
        {
            "template-id": template,
            "info": {"severity": severity},
            "matched-at": url,
        }
    )


def _fake_result(stdout: str, *, timed_out: bool = False) -> ToolRunResult:
    return ToolRunResult(
        tool_name="nuclei",
        executable="/x/nuclei",
        arguments=(),
        exit_code=(-1 if timed_out else 0),
        stdout=stdout,
        stderr="",
        stdout_sha256="",
        stderr_sha256="",
        timed_out=timed_out,
    )


def test_parse_nuclei_findings_ignores_noise():
    stdout = (
        _nuclei_line("tech-detect", "https://app.example.com/")
        + "\nnot json\n"
        + _nuclei_line("cve-x", "https://app.example.com/a")
    )
    assert len(parse_nuclei_findings(stdout)) == 2


def test_nuclei_reproduces_is_confirmed():
    finding = json.loads(
        _nuclei_line("tech-detect", "https://app.example.com/")
    )

    def runner(profile, arguments, **kwargs):
        return _fake_result(
            _nuclei_line("tech-detect", "https://app.example.com/")
        )

    verdict = verify_nuclei_finding(
        finding, allowed_hosts=ALLOWED, runner=runner
    )
    assert verdict.verdict is FindingVerdict.CONFIRMED


def test_nuclei_not_reproduced_is_false_positive():
    finding = json.loads(
        _nuclei_line("flaky-check", "https://app.example.com/")
    )

    def runner(profile, arguments, **kwargs):
        return _fake_result("")  # nothing re-fired

    verdict = verify_nuclei_finding(
        finding, allowed_hosts=ALLOWED, runner=runner
    )
    assert verdict.verdict is FindingVerdict.FALSE_POSITIVE


def test_nuclei_out_of_scope_is_not_rerun():
    finding = json.loads(
        _nuclei_line("tech-detect", "https://evil.other.com/")
    )
    called = {"ran": False}

    def runner(profile, arguments, **kwargs):
        called["ran"] = True
        return _fake_result("")

    verdict = verify_nuclei_finding(
        finding, allowed_hosts=ALLOWED, runner=runner
    )
    assert verdict.verdict is FindingVerdict.LIKELY
    assert called["ran"] is False  # never re-run out of scope


def test_nuclei_timeout_is_likely():
    finding = json.loads(
        _nuclei_line("slow-check", "https://app.example.com/")
    )

    def runner(profile, arguments, **kwargs):
        return _fake_result("", timed_out=True)

    verdict = verify_nuclei_finding(
        finding, allowed_hosts=ALLOWED, runner=runner
    )
    assert verdict.verdict is FindingVerdict.LIKELY


def test_sqlmap_negative_is_false_positive_not_confirmed():
    # "do not appear to be injectable" contains "injectable" - must be FP.
    run = {
        "stdout": "all tested parameters do not appear to be injectable",
        "parameter": "id",
        "url": "https://app.example.com/?id=1",
        "exit_code": 0,
    }
    result = classify_sqlmap_run(run)
    assert result is not None
    assert result.verdict is FindingVerdict.FALSE_POSITIVE


def test_sqlmap_vulnerable_is_confirmed():
    run = {
        "stdout": "GET parameter 'id' is vulnerable.",
        "parameter": "id",
        "url": "https://app.example.com/?id=1",
        "exit_code": 0,
    }
    result = classify_sqlmap_run(run)
    assert result is not None
    assert result.verdict is FindingVerdict.CONFIRMED


def test_verify_findings_end_to_end():
    stdout = _nuclei_line("tech-detect", "https://app.example.com/")

    def runner(profile, arguments, **kwargs):
        # Re-fires the template -> confirmed.
        return _fake_result(
            _nuclei_line("tech-detect", "https://app.example.com/")
        )

    sqlmap = (
        {
            "stdout": "parameter 'id' is vulnerable",
            "parameter": "id",
            "url": "https://app.example.com/?id=1",
            "exit_code": 0,
        },
    )
    verified = verify_findings(
        stdout, sqlmap, allowed_hosts=ALLOWED, runner=runner
    )
    verdicts = {v.source_tool: v.verdict for v in verified}
    assert verdicts["nuclei"] is FindingVerdict.CONFIRMED
    assert verdicts["sqlmap"] is FindingVerdict.CONFIRMED

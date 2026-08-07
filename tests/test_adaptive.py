"""Tests for the adaptive tool controller."""

from __future__ import annotations

import stat
from pathlib import Path

from saarthi_ai.automation.adaptive import (
    AdaptiveCondition,
    apply_adaptation,
    detect_condition,
    plan_adaptation,
    run_tool_adaptively,
)
from saarthi_ai.execution.tool_runner import ToolProfile

WAF_LINE = "the back-end DBMS is protected by some kind of WAF/IPS"


def test_detects_conditions_per_tool():
    assert detect_condition("sqlmap", WAF_LINE) is AdaptiveCondition.WAF
    assert (
        detect_condition("sqlmap", "connection reset by peer, reconnecting")
        is AdaptiveCondition.CONNECTION_RESET
    )
    assert (
        detect_condition("sqlmap", "got HTTP 429 (Too Many Requests)")
        is AdaptiveCondition.RATE_LIMITED
    )
    assert (
        detect_condition("nuclei", "context deadline exceeded")
        is AdaptiveCondition.CONNECTION_RESET
    )
    assert detect_condition("sqlmap", "just a normal line") is None


def test_waf_bypass_is_gated():
    no_bypass = plan_adaptation(
        "sqlmap", AdaptiveCondition.WAF, 2, allow_waf_bypass=False
    )
    assert "--tamper" not in no_bypass.set_flags
    assert "--random-agent" not in no_bypass.add_flags

    bypass = plan_adaptation(
        "sqlmap", AdaptiveCondition.WAF, 2, allow_waf_bypass=True
    )
    assert bypass.set_flags["--tamper"]
    assert "--random-agent" in bypass.add_flags


def test_adaptation_never_adds_dangerous_flags():
    for condition in AdaptiveCondition:
        for attempt in (1, 2, 3):
            for allow in (True, False):
                plan = plan_adaptation(
                    "sqlmap", condition, attempt, allow_waf_bypass=allow
                )
                if plan is None:
                    continue
                blob = " ".join(
                    list(plan.set_flags) + list(plan.add_flags)
                )
                for banned in (
                    "--os-shell",
                    "--file-read",
                    "--file-write",
                    "--dump",
                    "--sql-shell",
                ):
                    assert banned not in blob


def test_apply_adaptation_both_arg_styles():
    sql = apply_adaptation(
        ["-p", "id", "--timeout=10"],
        plan_adaptation(
            "sqlmap",
            AdaptiveCondition.CONNECTION_RESET,
            1,
            allow_waf_bypass=False,
        ),
    )
    assert "--timeout=20" in sql
    assert "--retries=3" in sql

    nuclei = apply_adaptation(
        ["-rate-limit", "5", "-timeout", "10"],
        plan_adaptation(
            "nuclei",
            AdaptiveCondition.RATE_LIMITED,
            1,
            allow_waf_bypass=False,
        ),
    )
    assert nuclei[nuclei.index("-rate-limit") + 1] == "1"


def _fake_tool(tmp_path: Path, script: str) -> ToolProfile:
    path = tmp_path / "faketool"
    path.write_text("#!/usr/bin/env python3\n" + script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return ToolProfile(
        name="sqlmap",
        executable_candidates=(str(path),),
        timeout_seconds=30,
    )


def test_run_tool_adaptively_recovers_after_waf(tmp_path):
    # Succeeds only once --random-agent has been added by the controller.
    profile = _fake_tool(
        tmp_path,
        "import sys, time\n"
        "if any(a == '--random-agent' for a in sys.argv):\n"
        "    print('clean run', flush=True); sys.exit(0)\n"
        f"print({WAF_LINE!r}, flush=True)\n"
        "time.sleep(2)\n",
    )

    events = []
    result = run_tool_adaptively(
        profile,
        ["-u", "http://target.test/?id=1", "-p", "id"],
        allow_waf_bypass=True,
        max_attempts=3,
        on_adapt=events.append,
    )

    assert result.exit_code == 0
    assert "clean run" in result.stdout
    assert len(events) == 1
    assert events[0].condition is AdaptiveCondition.WAF
    assert "--random-agent" in events[0].arguments


def test_run_tool_adaptively_no_bypass_never_uses_evasion(tmp_path):
    # Always reports WAF; with bypass disabled it must never gain evasion flags.
    profile = _fake_tool(
        tmp_path,
        "import time\n"
        f"print({WAF_LINE!r}, flush=True)\n"
        "time.sleep(2)\n",
    )

    events = []
    run_tool_adaptively(
        profile,
        ["-u", "http://target.test/?id=1", "-p", "id"],
        allow_waf_bypass=False,
        max_attempts=3,
        on_adapt=events.append,
    )

    assert events, "expected the controller to adapt at least once"
    for event in events:
        assert "--random-agent" not in event.arguments
        assert not any(a.startswith("--tamper") for a in event.arguments)

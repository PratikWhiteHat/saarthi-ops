"""End-to-end TUI wiring test for the chain-derived validation launcher.

This exercises the key binding -> worker -> live-log plumbing with the tool
runner fully stubbed, so it performs no network activity and does not require
nuclei or sqlmap to be installed.
"""

from __future__ import annotations

import pytest

from saarthi_ai.automation.auto_validation import AutomaticValidationResult
from saarthi_ai.execution.tool_runner import ToolOutputEvent
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionCreate
from saarthi_ai.tui.app import SaarthiDashboard


def _seed_chain(tmp_path):
    path = tmp_path / "tui.db"
    database = SaarthiDatabase(path)
    database.initialize()
    database.create_execution(
        ExecutionCreate(
            assessment_name="TUI launch test",
            asset_types=["url"],
            targets=["https://app.example.com/item?id=1"],
            authorization_confirmed=True,
            active_testing_allowed=True,
            intrusive_testing_allowed=True,
            metadata={
                "execution_role": "orchestration_parent",
                "orchestration_id": "orchestration-tui-1",
                "target_domain": "app.example.com",
                "rate_limit_per_second": 2,
            },
        )
    )
    return path


def _fake_run_factory(captured):
    def fake_run(config, *, on_output=None, on_log=None):
        captured["config"] = config
        if on_log is not None:
            on_log("[fake] starting")
        if on_output is not None:
            on_output(
                ToolOutputEvent(
                    tool_name="nuclei",
                    stream="stdout",
                    line="fake-finding-line",
                )
            )
        return AutomaticValidationResult(
            run_id="run-1",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            evidence_path="/tmp/evidence/run-1/automatic-validation.json",
            nuclei={"exit_code": 0},
            sqlmap=(),
        )

    return fake_run


@pytest.mark.asyncio
async def test_pressing_v_launches_chain_validation(tmp_path, monkeypatch):
    path = _seed_chain(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(
        "saarthi_ai.automation.auto_validation.run_automatic_validation",
        _fake_run_factory(captured),
    )

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        await pilot.press("v")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app._validation_running is False
        # The chain target was derived and passed to the runner.
        assert captured["config"].target_url == (
            "https://app.example.com/item?id=1"
        )
        # Confirmed-PoC on, single-row dump off for the lowercase 'v' path.
        assert captured["config"].sqlmap_confirmed_poc is True
        assert captured["config"].sqlmap_poc_single_row_dump is False
        # Streamed output and completion markers landed in the live log.
        joined = "\n".join(app._live_validation_lines)
        assert "fake-finding-line" in joined
        assert "Evidence" in joined


@pytest.mark.asyncio
async def test_shift_v_enables_single_row_dump(tmp_path, monkeypatch):
    path = _seed_chain(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(
        "saarthi_ai.automation.auto_validation.run_automatic_validation",
        _fake_run_factory(captured),
    )

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        await pilot.press("V")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert captured["config"].sqlmap_confirmed_poc is True
        assert captured["config"].sqlmap_poc_single_row_dump is True


@pytest.mark.asyncio
async def test_missing_chain_reports_error(tmp_path, monkeypatch):
    # Empty (but initialized) DB => no orchestration parent => clean error.
    path = tmp_path / "empty.db"
    database = SaarthiDatabase(path)
    database.initialize()

    called = {"ran": False}

    def fake_run(config, *, on_output=None, on_log=None):
        called["ran"] = True
        raise AssertionError("runner must not be called without a chain")

    monkeypatch.setattr(
        "saarthi_ai.automation.auto_validation.run_automatic_validation",
        fake_run,
    )

    app = SaarthiDashboard(database_path=path)
    async with app.run_test() as pilot:
        await pilot.press("v")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert called["ran"] is False
        assert app._validation_running is False
        joined = "\n".join(app._live_validation_lines)
        assert "[ERR]" in joined

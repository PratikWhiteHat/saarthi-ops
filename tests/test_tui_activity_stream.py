"""Tests for the real-time, append-only activity log streaming."""

from __future__ import annotations

import pytest
from textual.widgets import ProgressBar, Static

from saarthi_ai.tui.app import (
    MAX_LIVE_VALIDATION_LINES,
    SaarthiDashboard,
)


@pytest.mark.asyncio
async def test_activity_log_appends_incrementally(tmp_path):
    # Missing DB -> demo snapshot; we drive the sync helper directly.
    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.pause()

        # Growing activity is tracked as append-only.
        app._sync_activity_log(["a", "b"])
        assert app._rendered_lines[-2:] == ["a", "b"]

        app._sync_activity_log(["a", "b", "c"])
        assert app._rendered_lines == ["a", "b", "c"]

        # A live tool line is appended after the DB activity.
        app._append_validation_line("[INF] live tool line")
        assert app._rendered_lines[-1] == "[INF] live tool line"

        # A subsequent refresh with unchanged DB activity keeps the live
        # line at the tail (no duplication, no reset).
        app._sync_activity_log(["a", "b", "c"])
        assert app._rendered_lines == [
            "a",
            "b",
            "c",
            "[INF] live tool line",
        ]

        # A new DB activity set that is not a prefix triggers a full redraw.
        app._sync_activity_log(["x", "y"])
        assert app._rendered_lines == ["x", "y", "[INF] live tool line"]


@pytest.mark.asyncio
async def test_run_overlay_shows_running_stage(tmp_path):
    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.pause()

        progress = app.query_one("#phase-progress", ProgressBar)
        summary = app.query_one("#orchestration-summary", Static)

        from textual.widgets import Button, Input

        url_input = app.query_one("#target-url-input", Input)
        button = app.query_one("#authorize-button", Button)
        note = app.query_one("#authorize-note", Static)

        # Idle: determinate progress bar, editable bar.
        assert progress.total is not None
        assert url_input.disabled is False

        # A live run makes progress indeterminate and status RUNNING, and
        # shows the live target in a locked TARGET & AUTHORIZE bar.
        app._validation_running = True
        app._run_target = "https://app.example.com/?id=1"
        app._set_run_stage("Nuclei + SQLMap")
        await pilot.pause()
        assert progress.total is None
        assert "RUNNING · Nuclei + SQLMap" in str(summary.render())
        assert url_input.value == "https://app.example.com/?id=1"
        assert url_input.disabled is True
        assert button.disabled is True
        assert "RUNNING" in str(note.render())

        # Finishing restores the determinate bar and re-enables the bar.
        app._finish_validation()
        await pilot.pause()
        assert progress.total is not None
        assert url_input.value == ""
        assert url_input.disabled is False
        assert button.disabled is False


@pytest.mark.asyncio
async def test_live_validation_lines_are_capped(tmp_path):
    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.pause()

        for index in range(MAX_LIVE_VALIDATION_LINES + 50):
            app._append_validation_line(f"line-{index}")

        assert len(app._live_validation_lines) == MAX_LIVE_VALIDATION_LINES
        # The newest line is retained; the oldest are trimmed.
        assert app._live_validation_lines[-1] == (
            f"line-{MAX_LIVE_VALIDATION_LINES + 49}"
        )

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_dataset_quality_script() -> None:
    """The reviewed dataset must pass all quality checks."""

    result = subprocess.run(
        [sys.executable, "scripts/check_dataset_quality.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dataset quality check passed" in result.stdout

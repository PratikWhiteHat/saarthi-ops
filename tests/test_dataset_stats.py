from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_dataset_statistics_script() -> None:
    """The dataset statistics report must run successfully."""

    result = subprocess.run(
        [sys.executable, "scripts/dataset_stats.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Saarthi Dataset Statistics" in result.stdout
    assert "Records:" in result.stdout
    assert "Categories:" in result.stdout
    assert "Difficulty:" in result.stdout

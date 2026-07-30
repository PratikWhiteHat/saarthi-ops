from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_dataset_validation_script() -> None:
    """The reviewed dataset must pass schema validation."""

    result = subprocess.run(
        [sys.executable, "scripts/validate_dataset.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dataset validation passed" in result.stdout

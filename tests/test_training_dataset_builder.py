from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ROOT = PROJECT_ROOT / "datasets/examples"


def count_source_records() -> int:
    """Count canonical source records."""

    total = 0

    for dataset_file in EXAMPLES_ROOT.rglob("*.jsonl"):
        with dataset_file.open(encoding="utf-8") as file:
            total += sum(1 for line in file if line.strip())

    return total


def count_jsonl_records(path: Path) -> int:
    """Count records in a generated JSONL file."""

    with path.open(encoding="utf-8") as file:
        return sum(1 for line in file if line.strip())


def test_training_dataset_builder(tmp_path: Path) -> None:
    """The builder must create complete non-overlapping splits."""

    result = subprocess.run(
        [
            sys.executable,
            "scripts/build_training_dataset.py",
            "--output-root",
            str(tmp_path),
            "--seed",
            "42",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr

    paths = {
        "train": tmp_path / "train/saarthi_train.jsonl",
        "validation": (tmp_path / "validation/saarthi_validation.jsonl"),
        "test": tmp_path / "test/saarthi_test.jsonl",
    }

    for path in paths.values():
        assert path.exists()
        assert count_jsonl_records(path) > 0

    generated_total = sum(count_jsonl_records(path) for path in paths.values())

    assert generated_total == count_source_records()

    manifest_path = tmp_path / "processed/split_manifest.json"
    assert manifest_path.exists()

    with manifest_path.open(encoding="utf-8") as file:
        manifest = json.load(file)

    split_ids = [
        record_id for identifiers in manifest["splits"].values() for record_id in identifiers
    ]

    assert len(split_ids) == len(set(split_ids))
    assert manifest["total_records"] == generated_total

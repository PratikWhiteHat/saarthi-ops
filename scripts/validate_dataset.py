from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "datasets/schemas/instruction.schema.json"
DATASET_ROOT = PROJECT_ROOT / "datasets/examples"


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON document."""

    with path.open(encoding="utf-8") as file:
        return json.load(file)


def validate_datasets() -> tuple[list[str], int, int]:
    """Validate every JSONL record in the examples directory."""

    schema = load_json(SCHEMA_PATH)
    validator = Draft202012Validator(schema)

    errors: list[str] = []
    seen_ids: set[str] = set()
    record_count = 0
    dataset_files = sorted(DATASET_ROOT.rglob("*.jsonl"))

    if not dataset_files:
        return ["No JSONL dataset files were found."], 0, 0

    for dataset_file in dataset_files:
        relative_path = dataset_file.relative_to(PROJECT_ROOT)

        with dataset_file.open(encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                record_count += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{relative_path}:{line_number}: invalid JSON: {exc.msg}")
                    continue

                if not isinstance(record, dict):
                    errors.append(f"{relative_path}:{line_number}: record must be a JSON object")
                    continue

                record_id = record.get("id")

                if isinstance(record_id, str):
                    if record_id in seen_ids:
                        errors.append(f"{relative_path}:{line_number}: duplicate id '{record_id}'")

                    seen_ids.add(record_id)

                validation_errors = sorted(
                    validator.iter_errors(record),
                    key=lambda error: [str(item) for item in error.path],
                )

                for error in validation_errors:
                    location = ".".join(str(item) for item in error.path)
                    location = location or "<root>"

                    errors.append(f"{relative_path}:{line_number}: {location}: {error.message}")

    return errors, record_count, len(dataset_files)


def main() -> int:
    """Run dataset validation and print the result."""

    errors, record_count, file_count = validate_datasets()

    if errors:
        print("Dataset validation failed:\n")

        for error in errors:
            print(f"- {error}")

        return 1

    print(f"Dataset validation passed: {record_count} records across {file_count} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

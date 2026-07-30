from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "datasets/schemas/instruction.schema.json"
SOURCE_REGISTRY_PATH = PROJECT_ROOT / "datasets/provenance/sources.jsonl"
DATASET_ROOT = PROJECT_ROOT / "datasets/examples"


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from a file."""

    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object.")

    return data


def load_source_registry() -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load and validate approved dataset sources."""

    sources: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    if not SOURCE_REGISTRY_PATH.exists():
        return {}, ["Dataset source registry does not exist."]

    with SOURCE_REGISTRY_PATH.open(encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line:
                continue

            location = f"datasets/provenance/sources.jsonl:{line_number}"

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{location}: invalid JSON: {exc.msg}")
                continue

            if not isinstance(entry, dict):
                errors.append(f"{location}: source entry must be a JSON object")
                continue

            source_name = entry.get("source")
            license_name = entry.get("license")

            if not isinstance(source_name, str) or not source_name.strip():
                errors.append(f"{location}: source must be a non-empty string")
                continue

            if source_name in sources:
                errors.append(f"{location}: duplicate source '{source_name}'")
                continue

            if not isinstance(license_name, str) or not license_name.strip():
                errors.append(f"{location}: license must be a non-empty string")

            if entry.get("approved") is not True:
                errors.append(f"{location}: source '{source_name}' is not approved")

            if entry.get("allowed_for_training") is not True:
                errors.append(f"{location}: source '{source_name}' is not allowed for training")

            sources[source_name] = entry

    if not sources:
        errors.append("No approved dataset sources were found.")

    return sources, errors


def validate_record_source(
    record: dict[str, Any],
    source_registry: dict[str, dict[str, Any]],
    location: str,
) -> list[str]:
    """Validate a record's source and license."""

    errors: list[str] = []
    source_name = record.get("source")
    record_license = record.get("license")

    if not isinstance(source_name, str):
        return errors

    source_entry = source_registry.get(source_name)

    if source_entry is None:
        errors.append(f"{location}: source '{source_name}' is not in the approved registry")
        return errors

    if source_entry.get("approved") is not True:
        errors.append(f"{location}: source '{source_name}' is not approved")

    if source_entry.get("allowed_for_training") is not True:
        errors.append(f"{location}: source '{source_name}' is not allowed for training")

    registered_license = source_entry.get("license")

    if record_license != registered_license:
        errors.append(
            f"{location}: license '{record_license}' does not match "
            f"registered license '{registered_license}'"
        )

    return errors


def validate_review_status(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Require human review for accepted dataset records."""

    metadata = record.get("metadata")

    if not isinstance(metadata, dict):
        return [f"{location}: metadata must be a JSON object"]

    if metadata.get("reviewed") is not True:
        return [f"{location}: record has not been approved by a reviewer"]

    return []


def validate_datasets() -> tuple[list[str], int, int]:
    """Validate all reviewed JSONL dataset records."""

    schema = load_json(SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    source_registry, registry_errors = load_source_registry()

    errors = list(registry_errors)
    seen_ids: set[str] = set()
    record_count = 0
    dataset_files = sorted(DATASET_ROOT.rglob("*.jsonl"))

    if not dataset_files:
        errors.append("No JSONL dataset files were found.")
        return errors, 0, 0

    for dataset_file in dataset_files:
        relative_path = dataset_file.relative_to(PROJECT_ROOT)

        with dataset_file.open(encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                record_count += 1
                location = f"{relative_path}:{line_number}"

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{location}: invalid JSON: {exc.msg}")
                    continue

                if not isinstance(record, dict):
                    errors.append(f"{location}: record must be a JSON object")
                    continue

                record_id = record.get("id")

                if isinstance(record_id, str):
                    if record_id in seen_ids:
                        errors.append(f"{location}: duplicate id '{record_id}'")

                    seen_ids.add(record_id)

                schema_errors = sorted(
                    validator.iter_errors(record),
                    key=lambda error: [str(item) for item in error.path],
                )

                for error in schema_errors:
                    field = ".".join(str(item) for item in error.path)
                    field = field or "<root>"

                    errors.append(f"{location}: {field}: {error.message}")

                errors.extend(
                    validate_record_source(
                        record,
                        source_registry,
                        location,
                    )
                )

                errors.extend(validate_review_status(record, location))

    return errors, record_count, len(dataset_files)


def main() -> int:
    """Run validation and print the result."""

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

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = PROJECT_ROOT / "datasets/examples"
SCHEMA_PATH = PROJECT_ROOT / "datasets/schemas/instruction.schema.json"


def load_categories() -> list[str]:
    """Load the permitted categories from the dataset schema."""

    with SCHEMA_PATH.open(encoding="utf-8") as file:
        schema = json.load(file)

    categories = schema.get("properties", {}).get("category", {}).get("enum", [])

    return [category for category in categories if isinstance(category, str)]


def load_records() -> tuple[list[dict[str, Any]], int]:
    """Load all reviewed dataset records."""

    records: list[dict[str, Any]] = []
    dataset_files = sorted(DATASET_ROOT.rglob("*.jsonl"))

    for dataset_file in dataset_files:
        with dataset_file.open(encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    relative_path = dataset_file.relative_to(PROJECT_ROOT)
                    raise ValueError(
                        f"{relative_path}:{line_number}: invalid JSON: {exc.msg}"
                    ) from exc

                if not isinstance(record, dict):
                    relative_path = dataset_file.relative_to(PROJECT_ROOT)
                    raise ValueError(f"{relative_path}:{line_number}: record must be a JSON object")

                records.append(record)

    return records, len(dataset_files)


def average_length(
    records: list[dict[str, Any]],
    field: str,
) -> float:
    """Calculate the average character length of a text field."""

    lengths = [len(value) for record in records if isinstance((value := record.get(field)), str)]

    if not lengths:
        return 0.0

    return sum(lengths) / len(lengths)


def print_category_stats(
    categories: list[str],
    category_counts: Counter[str],
) -> None:
    """Print record counts for every supported category."""

    print("\nCategories:")

    for category in categories:
        print(f"- {category}: {category_counts[category]}")


def print_difficulty_stats(
    difficulty_counts: Counter[str],
) -> None:
    """Print difficulty distribution."""

    print("\nDifficulty:")

    for difficulty in ("basic", "intermediate", "advanced"):
        print(f"- {difficulty}: {difficulty_counts[difficulty]}")


def main() -> int:
    """Generate a dataset coverage and balance report."""

    try:
        records, file_count = load_records()
        categories = load_categories()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Dataset statistics failed: {exc}")
        return 1

    if not records:
        print("Dataset statistics failed: no dataset records found.")
        return 1

    category_counts: Counter[str] = Counter()
    difficulty_counts: Counter[str] = Counter()
    reviewed_count = 0

    for record in records:
        category = record.get("category")

        if isinstance(category, str):
            category_counts[category] += 1

        metadata = record.get("metadata")

        if isinstance(metadata, dict):
            difficulty = metadata.get("difficulty")

            if isinstance(difficulty, str):
                difficulty_counts[difficulty] += 1

            if metadata.get("reviewed") is True:
                reviewed_count += 1

    covered_categories = sum(1 for category in categories if category_counts[category] > 0)

    coverage = covered_categories / len(categories) * 100 if categories else 0.0

    print("Saarthi Dataset Statistics")
    print("==========================")
    print(f"Records: {len(records)}")
    print(f"Files: {file_count}")
    print(f"Reviewed records: {reviewed_count}")
    print(f"Category coverage: {covered_categories}/{len(categories)}")
    print(f"Coverage percentage: {coverage:.1f}%")
    print(f"Average instruction length: {average_length(records, 'instruction'):.1f} characters")
    print(f"Average context length: {average_length(records, 'context'):.1f} characters")
    print(f"Average response length: {average_length(records, 'response'):.1f} characters")

    print_category_stats(categories, category_counts)
    print_difficulty_stats(difficulty_counts)

    missing_categories = [category for category in categories if category_counts[category] == 0]

    if missing_categories:
        print("\nMissing categories:")

        for category in missing_categories:
            print(f"- {category}")
    else:
        print("\nAll supported categories contain records.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

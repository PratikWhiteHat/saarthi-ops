from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_ROOT = PROJECT_ROOT / "datasets/examples"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "datasets"

SYSTEM_MESSAGE = (
    "You are Saarthi AI, a security-specialized assistant for authorized "
    "security testing, defensive validation, security research, and "
    "professional reporting. Answer accurately, distinguish evidence from "
    "assumptions, and never fabricate tool results."
)


def normalize_text(value: str) -> str:
    """Normalize text for duplicate-scenario detection."""

    return " ".join(value.lower().split())


def load_records(input_root: Path) -> list[dict[str, Any]]:
    """Load reviewed canonical records from JSONL files."""

    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_scenarios: set[str] = set()

    dataset_files = sorted(input_root.rglob("*.jsonl"))

    if not dataset_files:
        raise ValueError(f"No JSONL files were found in {input_root}.")

    for dataset_file in dataset_files:
        with dataset_file.open(encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                location = f"{dataset_file}:{line_number}"

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{location}: invalid JSON: {exc.msg}") from exc

                if not isinstance(record, dict):
                    raise ValueError(f"{location}: record must be a JSON object")

                record_id = record.get("id")

                if not isinstance(record_id, str) or not record_id:
                    raise ValueError(f"{location}: record must have a valid id")

                if record_id in seen_ids:
                    raise ValueError(f"{location}: duplicate id '{record_id}'")

                instruction = record.get("instruction")
                context = record.get("context", "")

                if not isinstance(instruction, str):
                    raise ValueError(f"{location}: instruction must be a string")

                if not isinstance(context, str):
                    raise ValueError(f"{location}: context must be a string")

                scenario_key = normalize_text(f"{instruction}\n{context}")

                if scenario_key in seen_scenarios:
                    raise ValueError(f"{location}: duplicate scenario detected")

                metadata = record.get("metadata")

                if not isinstance(metadata, dict):
                    raise ValueError(f"{location}: metadata must be an object")

                if metadata.get("reviewed") is not True:
                    raise ValueError(f"{location}: record has not been reviewed")

                seen_ids.add(record_id)
                seen_scenarios.add(scenario_key)
                records.append(record)

    return records


def build_user_message(record: dict[str, Any]) -> str:
    """Create the model's user message from a canonical record."""

    instruction = str(record["instruction"]).strip()
    context = str(record.get("context", "")).strip()

    if context:
        return f"Instruction:\n{instruction}\n\nContext:\n{context}"

    return f"Instruction:\n{instruction}"


def convert_record(record: dict[str, Any]) -> dict[str, Any]:
    """Convert a canonical record to chat-training format."""

    metadata = record.get("metadata", {})

    return {
        "id": record["id"],
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_MESSAGE,
            },
            {
                "role": "user",
                "content": build_user_message(record),
            },
            {
                "role": "assistant",
                "content": str(record["response"]).strip(),
            },
        ],
        "metadata": {
            "category": record["category"],
            "difficulty": metadata.get("difficulty"),
            "source": record["source"],
            "license": record["license"],
        },
    }


def split_records(
    records: list[dict[str, Any]],
    *,
    seed: int,
) -> dict[str, list[dict[str, Any]]]:
    """Create deterministic train, validation, and test splits."""

    if len(records) < 3:
        raise ValueError("At least three records are required to create all splits.")

    shuffled = list(records)
    random.Random(seed).shuffle(shuffled)

    total = len(shuffled)
    train_count = max(1, int(total * 0.8))
    validation_count = max(1, int(total * 0.1))

    if train_count + validation_count >= total:
        train_count = total - 2
        validation_count = 1

    return {
        "train": shuffled[:train_count],
        "validation": shuffled[train_count : train_count + validation_count],
        "test": shuffled[train_count + validation_count :],
    }


def write_jsonl(
    path: Path,
    records: list[dict[str, Any]],
) -> None:
    """Write records to a JSONL file."""

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_manifest(
    output_root: Path,
    splits: dict[str, list[dict[str, Any]]],
    *,
    seed: int,
) -> None:
    """Write a manifest describing split membership."""

    manifest = {
        "seed": seed,
        "total_records": sum(len(records) for records in splits.values()),
        "counts": {split_name: len(records) for split_name, records in splits.items()},
        "splits": {
            split_name: [str(record["id"]) for record in records]
            for split_name, records in splits.items()
        },
    }

    manifest_path = output_root / "processed/split_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    with manifest_path.open("w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
        file.write("\n")


def build_datasets(
    input_root: Path,
    output_root: Path,
    *,
    seed: int,
) -> dict[str, int]:
    """Build all training-ready dataset splits."""

    canonical_records = load_records(input_root)
    converted_records = [convert_record(record) for record in canonical_records]

    splits = split_records(converted_records, seed=seed)

    output_paths = {
        "train": output_root / "train/saarthi_train.jsonl",
        "validation": (output_root / "validation/saarthi_validation.jsonl"),
        "test": output_root / "test/saarthi_test.jsonl",
    }

    for split_name, output_path in output_paths.items():
        write_jsonl(output_path, splits[split_name])

    write_manifest(output_root, splits, seed=seed)

    return {split_name: len(records) for split_name, records in splits.items()}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Build Saarthi training dataset splits.")
    parser.add_argument(
        "--input-root",
        type=Path,
        default=DEFAULT_INPUT_ROOT,
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )

    return parser.parse_args()


def main() -> int:
    """Build and report the generated dataset splits."""

    args = parse_args()

    try:
        counts = build_datasets(
            args.input_root,
            args.output_root,
            seed=args.seed,
        )
    except (OSError, ValueError) as exc:
        print(f"Dataset build failed: {exc}")
        return 1

    total = sum(counts.values())

    print("Saarthi training dataset built successfully.")
    print(f"Total records: {total}")
    print(f"Training records: {counts['train']}")
    print(f"Validation records: {counts['validation']}")
    print(f"Test records: {counts['test']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

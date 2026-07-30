from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = PROJECT_ROOT / "datasets/examples"
SOURCE_REGISTRY = PROJECT_ROOT / "datasets/provenance/sources.jsonl"

CATEGORY_CONFIG = {
    "web_security": ("web_security.jsonl", "web"),
    "api_security": ("api_security.jsonl", "api"),
    "cloud_security": ("cloud_security.jsonl", "cloud"),
    "active_directory": ("active_directory.jsonl", "ad"),
    "linux_security": ("linux_security.jsonl", "linux"),
    "windows_security": ("windows_security.jsonl", "windows"),
    "reporting": ("reporting.jsonl", "report"),
    "methodology": ("methodology.jsonl", "method"),
}

DIFFICULTIES = ("basic", "intermediate", "advanced")


def choose_option(label: str, options: list[str]) -> str:
    """Ask the user to select one option."""

    print(f"\n{label}")

    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")

    while True:
        value = input("Selection: ").strip()

        try:
            selected = int(value)
        except ValueError:
            print("Enter a number.")
            continue

        if 1 <= selected <= len(options):
            return options[selected - 1]

        print("Choose one of the listed numbers.")


def prompt_multiline(label: str, *, required: bool = True) -> str:
    """Read multiple lines until the user enters END."""

    print(f"\n{label}")
    print("Type END on a separate line when finished.")

    lines: list[str] = []

    while True:
        line = input()

        if line.strip() == "END":
            break

        lines.append(line)

    value = "\n".join(lines).strip()

    if required and not value:
        raise ValueError(f"{label} cannot be empty.")

    return value


def prompt_required(label: str) -> str:
    """Read a required single-line value."""

    while True:
        value = input(f"{label}: ").strip()

        if value:
            return value

        print(f"{label} cannot be empty.")


def load_sources() -> dict[str, dict[str, Any]]:
    """Load approved dataset sources."""

    sources: dict[str, dict[str, Any]] = {}

    with SOURCE_REGISTRY.open(encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line:
                continue

            entry = json.loads(line)

            if not isinstance(entry, dict):
                continue

            if entry.get("approved") is not True:
                continue

            if entry.get("allowed_for_training") is not True:
                continue

            source_name = entry.get("source")

            if isinstance(source_name, str):
                sources[source_name] = entry

    if not sources:
        raise ValueError("No approved training sources were found.")

    return sources


def load_records() -> list[dict[str, Any]]:
    """Load all current dataset records."""

    records: list[dict[str, Any]] = []

    for dataset_file in sorted(DATASET_ROOT.glob("*.jsonl")):
        with dataset_file.open(encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()

                if not line:
                    continue

                record = json.loads(line)

                if isinstance(record, dict):
                    records.append(record)

    return records


def generate_record_id(
    prefix: str,
    records: list[dict[str, Any]],
) -> str:
    """Generate the next numeric identifier."""

    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    highest = 0

    for record in records:
        record_id = record.get("id")

        if not isinstance(record_id, str):
            continue

        match = pattern.match(record_id)

        if match:
            highest = max(highest, int(match.group(1)))

    return f"{prefix}-{highest + 1:04d}"


def normalize_text(value: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(value.lower().split())


def ensure_unique(
    instruction: str,
    context: str,
    records: list[dict[str, Any]],
) -> None:
    """Reject duplicate instruction and context combinations."""

    candidate = normalize_text(f"{instruction}\n{context}")

    for record in records:
        existing_instruction = record.get("instruction", "")
        existing_context = record.get("context", "")

        if not isinstance(existing_instruction, str):
            continue

        if not isinstance(existing_context, str):
            existing_context = ""

        existing = normalize_text(f"{existing_instruction}\n{existing_context}")

        if candidate == existing:
            raise ValueError(f"Duplicate scenario found in {record.get('id')}.")


def append_record(path: Path, record: dict[str, Any]) -> None:
    """Append one record to a JSONL file."""

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def remove_last_record(path: Path) -> None:
    """Remove the most recently appended record."""

    with path.open(encoding="utf-8") as file:
        lines = file.readlines()

    while lines and not lines[-1].strip():
        lines.pop()

    if lines:
        lines.pop()

    with path.open("w", encoding="utf-8") as file:
        file.writelines(lines)


def run_project_check(script_name: str) -> None:
    """Run one dataset validation script."""

    result = subprocess.run(
        [sys.executable, f"scripts/{script_name}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise ValueError(result.stdout + result.stderr)


def main() -> int:
    """Create and validate one dataset record."""

    print("Saarthi Dataset Authoring CLI")
    print("=============================")

    output_path: Path | None = None

    try:
        records = load_records()
        sources = load_sources()

        category = choose_option(
            "Choose a category:",
            list(CATEGORY_CONFIG),
        )
        difficulty = choose_option(
            "Choose a difficulty:",
            list(DIFFICULTIES),
        )
        source_name = choose_option(
            "Choose an approved source:",
            list(sources),
        )

        instruction = prompt_multiline("Instruction")
        context = prompt_multiline("Context", required=False)
        response = prompt_multiline("Expected response")
        reviewer = prompt_required("Reviewer name")

        ensure_unique(instruction, context, records)

        filename, prefix = CATEGORY_CONFIG[category]
        record_id = generate_record_id(prefix, records)
        source = sources[source_name]

        record = {
            "id": record_id,
            "category": category,
            "instruction": instruction,
            "context": context,
            "response": response,
            "source": source_name,
            "license": source["license"],
            "safety": {
                "authorized_use_only": True,
                "contains_sensitive_data": False,
            },
            "metadata": {
                "difficulty": difficulty,
                "created_by": reviewer,
                "reviewed": True,
            },
        }

        print("\nRecord preview:")
        print(json.dumps(record, indent=2, ensure_ascii=False))

        confirmation = input("\nSave this record? [y/N]: ").strip().lower()

        if confirmation != "y":
            print("Record was not saved.")
            return 0

        output_path = DATASET_ROOT / filename
        append_record(output_path, record)

        try:
            run_project_check("validate_dataset.py")
            run_project_check("check_dataset_quality.py")
        except ValueError:
            remove_last_record(output_path)
            raise

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"\nRecord creation failed:\n{exc}")
        return 1

    print(f"\nRecord {record_id} saved successfully.")

    if output_path is not None:
        print(f"File: {output_path.relative_to(PROJECT_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

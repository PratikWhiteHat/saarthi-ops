from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = PROJECT_ROOT / "datasets/examples"

PLACEHOLDER_PATTERNS = (
    re.compile(r"\bTODO\b", re.IGNORECASE),
    re.compile(r"\bTBD\b", re.IGNORECASE),
    re.compile(r"\blorem ipsum\b", re.IGNORECASE),
    re.compile(r"\bfill this\b", re.IGNORECASE),
)

SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer token": re.compile(
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b",
        re.IGNORECASE,
    ),
}

IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?![\d.])"
)

ALLOWED_IP_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def normalize_text(value: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(value.lower().split())


def load_records() -> tuple[list[tuple[Path, int, dict[str, Any]]], list[str]]:
    """Load JSONL records from the reviewed examples directory."""

    records: list[tuple[Path, int, dict[str, Any]]] = []
    errors: list[str] = []

    dataset_files = sorted(DATASET_ROOT.rglob("*.jsonl"))

    if not dataset_files:
        return [], ["No reviewed JSONL dataset files were found."]

    for dataset_file in dataset_files:
        relative_path = dataset_file.relative_to(PROJECT_ROOT)

        with dataset_file.open(encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                location = f"{relative_path}:{line_number}"

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{location}: invalid JSON: {exc.msg}")
                    continue

                if not isinstance(record, dict):
                    errors.append(f"{location}: record must be a JSON object")
                    continue

                records.append((relative_path, line_number, record))

    return records, errors


def check_record_lengths(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Check instruction, context, and response lengths."""

    errors: list[str] = []

    instruction = record.get("instruction")
    context = record.get("context", "")
    response = record.get("response")

    if isinstance(instruction, str):
        if len(instruction.strip()) < 10:
            errors.append(f"{location}: instruction is too short")

        if len(instruction) > 1_000:
            errors.append(f"{location}: instruction is too long")

    if isinstance(context, str) and len(context) > 5_000:
        errors.append(f"{location}: context is too long")

    if isinstance(response, str):
        if len(response.strip()) < 30:
            errors.append(f"{location}: response is too short")

        if len(response) > 10_000:
            errors.append(f"{location}: response is too long")

    return errors


def check_placeholders(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Detect unfinished placeholder text."""

    errors: list[str] = []

    for field in ("instruction", "context", "response"):
        value = record.get(field)

        if not isinstance(value, str):
            continue

        for pattern in PLACEHOLDER_PATTERNS:
            if pattern.search(value):
                errors.append(
                    f"{location}: field '{field}' contains placeholder text '{pattern.pattern}'"
                )

    return errors


def check_secrets(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Detect common secret formats."""

    errors: list[str] = []
    combined_text = " ".join(
        value
        for value in (
            record.get("instruction"),
            record.get("context"),
            record.get("response"),
        )
        if isinstance(value, str)
    )

    for secret_name, pattern in SECRET_PATTERNS.items():
        if pattern.search(combined_text):
            errors.append(f"{location}: possible {secret_name} detected")

    return errors


def check_ip_addresses(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Require reserved example IP addresses in reviewed data."""

    errors: list[str] = []
    combined_text = " ".join(
        value
        for value in (
            record.get("instruction"),
            record.get("context"),
            record.get("response"),
        )
        if isinstance(value, str)
    )

    for match in IPV4_PATTERN.finditer(combined_text):
        address_text = match.group(0)

        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue

        if not any(address in network for network in ALLOWED_IP_NETWORKS):
            errors.append(
                f"{location}: IP address '{address_text}' is not from an approved example range"
            )

    return errors


def check_safety_metadata(
    record: dict[str, Any],
    location: str,
) -> list[str]:
    """Require safe and reviewed metadata."""

    errors: list[str] = []
    safety = record.get("safety")
    metadata = record.get("metadata")

    if isinstance(safety, dict):
        if safety.get("authorized_use_only") is not True:
            errors.append(f"{location}: authorized_use_only must be true")

        if safety.get("contains_sensitive_data") is not False:
            errors.append(f"{location}: contains_sensitive_data must be false")

    if isinstance(metadata, dict):
        if metadata.get("reviewed") is not True:
            errors.append(f"{location}: reviewed must be true")

    return errors


def check_duplicate_scenarios(
    records: list[tuple[Path, int, dict[str, Any]]],
) -> list[str]:
    """Detect duplicate instruction and context combinations."""

    errors: list[str] = []
    seen: dict[str, str] = {}

    for relative_path, line_number, record in records:
        location = f"{relative_path}:{line_number}"
        instruction = record.get("instruction", "")
        context = record.get("context", "")

        if not isinstance(instruction, str):
            continue

        if not isinstance(context, str):
            context = ""

        scenario_key = normalize_text(f"{instruction} {context}")

        previous_location = seen.get(scenario_key)

        if previous_location is not None:
            errors.append(f"{location}: duplicate scenario already found at {previous_location}")
        else:
            seen[scenario_key] = location

    return errors


def check_quality() -> tuple[list[str], int]:
    """Run all dataset quality checks."""

    records, errors = load_records()

    errors.extend(check_duplicate_scenarios(records))

    for relative_path, line_number, record in records:
        location = f"{relative_path}:{line_number}"

        errors.extend(check_record_lengths(record, location))
        errors.extend(check_placeholders(record, location))
        errors.extend(check_secrets(record, location))
        errors.extend(check_ip_addresses(record, location))
        errors.extend(check_safety_metadata(record, location))

    return errors, len(records)


def main() -> int:
    """Run the dataset quality gate."""

    errors, record_count = check_quality()

    if errors:
        print("Dataset quality check failed:\n")

        for error in errors:
            print(f"- {error}")

        return 1

    print(f"Dataset quality check passed: {record_count} records checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

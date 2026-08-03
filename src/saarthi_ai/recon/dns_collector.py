from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import dns.exception
import dns.resolver
from pydantic import BaseModel, Field

SUPPORTED_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
)


class DnsCollectionError(RuntimeError):
    """Raised when controlled DNS collection cannot be completed."""


class DnsRecord(BaseModel):
    """One normalized DNS record."""

    record_type: str
    value: str
    ttl: int | None = None


class DnsCollectionResult(BaseModel):
    """Structured result returned by the DNS collector."""

    collector_execution_id: str
    collector_evidence_id: str
    domain: str
    nameserver: str | None
    records: dict[str, list[DnsRecord]]
    errors: dict[str, str] = Field(default_factory=dict)
    collected_at: datetime
    evidence_path: str
    evidence_sha256: str
    evidence_size_bytes: int


def normalize_domain(domain: str) -> str:
    """Normalize and validate a DNS domain name."""

    value = domain.strip().lower().rstrip(".")

    if not value:
        raise DnsCollectionError("A domain is required.")

    if "://" in value or "/" in value:
        raise DnsCollectionError("Provide a domain name only, without a URL scheme or path.")

    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DnsCollectionError("The domain name is invalid.") from exc

    if len(ascii_domain) > 253:
        raise DnsCollectionError("The domain name exceeds 253 characters.")

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        raise DnsCollectionError("The DNS collector requires a fully qualified domain name.")

    for label in labels:
        if not label or len(label) > 63:
            raise DnsCollectionError("The domain contains an invalid DNS label.")

        if label.startswith("-") or label.endswith("-"):
            raise DnsCollectionError("DNS labels cannot begin or end with a hyphen.")

        if not all(character.isalnum() or character == "-" for character in label):
            raise DnsCollectionError("The domain contains unsupported characters.")

    return ascii_domain


def _normalize_answer(record_type: str, answer: Any) -> str:
    """Normalize a dnspython answer into a stable string."""

    if record_type == "MX":
        return f"{answer.preference} {str(answer.exchange).rstrip('.')}"

    if record_type in {"CNAME", "NS"}:
        return str(answer.target).rstrip(".")

    if record_type == "TXT":
        strings = getattr(answer, "strings", None)

        if strings:
            return "".join(value.decode("utf-8", errors="replace") for value in strings)

    return str(answer).rstrip(".")


def collect_dns_records(
    domain: str,
    *,
    evidence_root: Path | None = None,
    resolver: dns.resolver.Resolver | None = None,
    progress_callback: Callable[[DnsRecord], None] | None = None,
) -> DnsCollectionResult:
    """Collect controlled DNS records and write structured JSON evidence."""

    normalized_domain = normalize_domain(domain)
    active_resolver = resolver or dns.resolver.Resolver()

    collector_execution_id = f"dns-run-{uuid4()}"
    collector_evidence_id = f"dns-evidence-{uuid4()}"
    collected_at = datetime.now(UTC)

    records: dict[str, list[DnsRecord]] = {}
    errors: dict[str, str] = {}

    for record_type in SUPPORTED_RECORD_TYPES:
        records[record_type] = []

        try:
            answer = active_resolver.resolve(
                normalized_domain,
                record_type,
                raise_on_no_answer=False,
                lifetime=5.0,
            )

            if answer.rrset is None:
                continue

            ttl = answer.rrset.ttl

            for item in answer:
                record = DnsRecord(
                    record_type=record_type,
                    value=_normalize_answer(record_type, item),
                    ttl=ttl,
                )
                records[record_type].append(record)

                if progress_callback is not None:
                    progress_callback(record)

        except dns.resolver.NXDOMAIN as exc:
            raise DnsCollectionError(f"Domain '{normalized_domain}' does not exist.") from exc

        except dns.resolver.NoNameservers:
            errors[record_type] = "No nameservers were available."

        except dns.resolver.LifetimeTimeout:
            errors[record_type] = "DNS query timed out."

        except dns.exception.DNSException as exc:
            errors[record_type] = str(exc)

    nameserver = None

    if active_resolver.nameservers:
        nameserver = str(active_resolver.nameservers[0])

    evidence_directory = evidence_root or Path("evidence") / "dns"
    evidence_directory.mkdir(parents=True, exist_ok=True)

    evidence_file = evidence_directory / f"{collector_evidence_id}.json"

    evidence_payload = {
        "schema_version": "1.0",
        "collector": "internal-dns-collector",
        "collector_execution_id": collector_execution_id,
        "collector_evidence_id": collector_evidence_id,
        "domain": normalized_domain,
        "nameserver": nameserver,
        "record_types": list(SUPPORTED_RECORD_TYPES),
        "records": {
            key: [record.model_dump(mode="json") for record in value]
            for key, value in records.items()
        },
        "errors": errors,
        "collected_at": collected_at.isoformat(),
    }

    evidence_bytes = json.dumps(
        evidence_payload,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")

    evidence_file.write_bytes(evidence_bytes)

    return DnsCollectionResult(
        collector_execution_id=collector_execution_id,
        collector_evidence_id=collector_evidence_id,
        domain=normalized_domain,
        nameserver=nameserver,
        records=records,
        errors=errors,
        collected_at=collected_at,
        evidence_path=str(evidence_file),
        evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
        evidence_size_bytes=len(evidence_bytes),
    )

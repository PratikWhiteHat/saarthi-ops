from __future__ import annotations

from pathlib import Path

import dns.resolver
import pytest

from saarthi_ai.recon.dns_collector import (
    DnsCollectionError,
    collect_dns_records,
    normalize_domain,
)


def test_normalize_domain() -> None:
    assert normalize_domain("Example.COM.") == "example.com"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "https://example.com",
        "example.com/path",
        "-example.com",
    ],
)
def test_normalize_domain_rejects_invalid_values(value: str) -> None:
    with pytest.raises(DnsCollectionError):
        normalize_domain(value)


class FakeAnswer:
    def __init__(self, values: list[object], ttl: int = 300) -> None:
        self._values = values
        self.rrset = type("FakeRrset", (), {"ttl": ttl})()

    def __iter__(self):
        return iter(self._values)


class FakeARecord:
    def __str__(self) -> str:
        return "192.0.2.10"


class FakeResolver:
    nameservers = ["192.0.2.53"]

    def resolve(
        self,
        domain: str,
        record_type: str,
        *,
        raise_on_no_answer: bool,
        lifetime: float,
    ) -> FakeAnswer:
        assert domain == "example.com"
        assert raise_on_no_answer is False
        assert lifetime == 5.0

        if record_type == "A":
            return FakeAnswer([FakeARecord()])

        answer = FakeAnswer([])
        answer.rrset = None
        return answer


def test_collect_dns_records_writes_evidence(tmp_path: Path) -> None:
    result = collect_dns_records(
        "example.com",
        evidence_root=tmp_path,
        resolver=FakeResolver(),  # type: ignore[arg-type]
    )

    assert result.domain == "example.com"
    assert result.nameserver == "192.0.2.53"
    assert len(result.records["A"]) == 1
    assert result.records["A"][0].value == "192.0.2.10"
    assert result.evidence_size_bytes > 0
    assert len(result.evidence_sha256) == 64
    assert Path(result.evidence_path).exists()


class NxDomainResolver:
    nameservers = ["192.0.2.53"]

    def resolve(
        self,
        domain: str,
        record_type: str,
        *,
        raise_on_no_answer: bool,
        lifetime: float,
    ) -> object:
        raise dns.resolver.NXDOMAIN


def test_collect_dns_records_rejects_nxdomain(tmp_path: Path) -> None:
    with pytest.raises(
        DnsCollectionError,
        match="does not exist",
    ):
        collect_dns_records(
            "example.com",
            evidence_root=tmp_path,
            resolver=NxDomainResolver(),  # type: ignore[arg-type]
        )

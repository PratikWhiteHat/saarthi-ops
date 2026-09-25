"""Offline tests for conservative CVE intelligence matching."""

from __future__ import annotations

import hashlib
import json

import pytest

from saarthi_ai.cve import sync as cve_sync
from saarthi_ai.cve import workflow as cve_workflow
from saarthi_ai.cve.catalog import CveCatalog
from saarthi_ai.cve.matcher import match_cpe
from saarthi_ai.cve.parser import CveFeedError
from saarthi_ai.cve.workflow import run_cve_intelligence
from saarthi_ai.orchestration.models import OrchestrationPhase, OrchestrationPhaseResult
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import EvidenceCreate, EvidenceType, ExecutionState
from saarthi_ai.persistence.orchestration_workflow import (
    create_orchestration,
    create_phase_execution,
)
from saarthi_ai.recon.http_intelligence_collector import _extract_cpes


def _nvd() -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2025-12345",
                    "descriptions": [{"lang": "en", "value": "Example issue."}],
                    "published": "2025-01-01T00:00:00.000",
                    "lastModified": "2025-01-02T00:00:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {"type": "Primary", "cvssData": {"baseScore": 8.1,
                             "baseSeverity": "HIGH", "version": "3.1"}}
                        ]
                    },
                    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "2.0",
                        "versionEndExcluding": "3.0",
                    }]}]}],
                }
            }
        ]
    }


def test_nvd_kev_import_and_conservative_match(tmp_path):
    catalog = CveCatalog(tmp_path / "cve.db")
    assert catalog.import_nvd(_nvd()) == 1
    assert catalog.import_kev({"vulnerabilities": [{
        "cveID": "CVE-2025-12345", "dateAdded": "2025-02-01", "vendorProject": "Example",
        "product": "Widget", "requiredAction": "Apply update",
    }]}) == 1
    found = match_cpe(catalog, "cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*")
    assert len(found) == 1
    assert found[0].applicability == "candidate"
    assert found[0].cve.exploited_in_wild is True
    assert found[0].priority_score > 70
    assert match_cpe(catalog, "cpe:2.3:a:example:widget:3.0:*:*:*:*:*:*:*") == []
    assert match_cpe(catalog, "cpe:2.3:a:other:widget:2.5:*:*:*:*:*:*:*") == []


def test_unknown_version_is_not_confirmed(tmp_path):
    catalog = CveCatalog(tmp_path / "cve.db")
    catalog.import_nvd(_nvd())
    found = match_cpe(catalog, "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*")
    assert found[0].applicability == "version_unknown"


def test_bad_feed_does_not_erase_existing_kev(tmp_path):
    catalog = CveCatalog(tmp_path / "cve.db")
    catalog.import_kev({"vulnerabilities": [{"cveID": "CVE-2025-12345"}]})
    with pytest.raises(CveFeedError):
        catalog.import_kev({"vulnerabilities": []})
    assert catalog.stats()["counts"]["kev"] == 1


def test_complex_configuration_requires_review(tmp_path):
    document = _nvd()
    document["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0][
        "operator"
    ] = "AND"
    catalog = CveCatalog(tmp_path / "cve.db")
    catalog.import_nvd(document)
    found = match_cpe(catalog, "cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*")
    assert found[0].applicability == "review_required"


def test_sync_does_not_send_nvd_key_to_cisa(tmp_path, monkeypatch):
    catalog = CveCatalog(tmp_path / "cve.db")
    headers_seen = []

    class FakeClient:
        def __init__(self, *, headers, **_kwargs):
            self.headers = headers
            headers_seen.append(headers)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def fake_fetch(client, url, _params=None):
        if url == cve_sync.NVD_URL:
            return {**_nvd(), "totalResults": 1}
        return {"vulnerabilities": [{"cveID": "CVE-2025-12345"}]}

    monkeypatch.setenv("NVD_API_KEY", "private-test-key")
    monkeypatch.setattr(cve_sync.httpx, "Client", FakeClient)
    monkeypatch.setattr(cve_sync, "_fetch_json", fake_fetch)
    assert cve_sync.sync_official_feeds(catalog) == {"nvd": 1, "kev": 1}
    assert headers_seen[0]["apiKey"] == "private-test-key"
    assert "apiKey" not in headers_seen[1]


def test_online_lookup_uses_only_observed_cpe(tmp_path, monkeypatch):
    catalog = CveCatalog(tmp_path / "cve.db")
    parameters = []

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def fake_fetch(_client, _url, params=None):
        parameters.append(params)
        return {**_nvd(), "totalResults": 1}

    monkeypatch.setattr(cve_sync.httpx, "Client", FakeClient)
    monkeypatch.setattr(cve_sync, "_fetch_json", fake_fetch)
    monkeypatch.setattr(cve_sync.time, "sleep", lambda _seconds: None)
    versioned = "cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*"
    unknown = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
    result = cve_sync.lookup_cpes_online(catalog, [versioned, unknown])
    assert result.queried_cpes == 2
    assert {next(iter(item)) for item in parameters} == {"cpeName", "virtualMatchString"}
    assert all("example.com" not in json.dumps(item) for item in parameters)
    assert catalog.stats()["counts"]["cves"] == 1


def test_httpx_cpe_extraction_accepts_strings_and_objects():
    assert _extract_cpes({"cpe": [
        "cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*",
        {"cpe": "cpe:2.3:a:example:other:*:*:*:*:*:*:*:*"},
        {"cpe": "not-a-cpe"},
    ]}) == [
        "cpe:2.3:a:example:other:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*",
    ]


def test_tui_cve_phase_persists_hashed_candidate_evidence(tmp_path, monkeypatch):
    database = SaarthiDatabase(tmp_path / "assessment.db")
    database.initialize()
    context = create_orchestration(
        database, assessment_name="CVE test", target_url="https://example.com/",
        active_testing_allowed=True,
    )
    source_child = create_phase_execution(
        database, context, phase=OrchestrationPhase.HTTP_INTELLIGENCE,
        phase_name="HTTP intelligence", active_testing_allowed=False,
    )
    source_path = tmp_path / "http-intelligence.json"
    source_bytes = json.dumps({"records": [{
        "url": "https://example.com/path?token=secret",
        "cpes": ["cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*"],
    }]}).encode()
    source_path.write_bytes(source_bytes)
    registered = database.add_evidence(
        source_child.execution_id,
        EvidenceCreate(
            evidence_type=EvidenceType.HTTP_INTELLIGENCE_RESULT,
            source="test-httpx", path=str(source_path),
            sha256=hashlib.sha256(source_bytes).hexdigest(),
        ),
    )
    catalog_path = tmp_path / "cve.db"
    catalog = CveCatalog(catalog_path)
    catalog.import_nvd(_nvd())
    catalog.import_kev({"vulnerabilities": [{"cveID": "CVE-2025-12345"}]})
    queried = []

    def fake_lookup(_catalog, cpes):
        queried.extend(cpes)
        return cve_sync.OnlineLookupResult(1, 0, False)

    monkeypatch.setattr(cve_workflow, "lookup_cpes_online", fake_lookup)
    result = run_cve_intelligence(
        database, context,
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.HTTP_INTELLIGENCE,
            execution_id=source_child.execution_id,
            evidence_id=registered.evidence_id,
            evidence_path=str(source_path),
        ),
        evidence_root=tmp_path / "evidence", catalog_path=catalog_path,
        refresh=True,
    )
    assert result.candidates == 1
    assert result.observed_cpes == 1
    assert result.online_status == "complete"
    assert queried == ["cpe:2.3:a:example:widget:2.5:*:*:*:*:*:*:*"]
    assert database.get_execution(result.phase.execution_id).state is ExecutionState.COMPLETED
    artifact = json.loads((tmp_path / "evidence" / "cve-intelligence.json").read_text())
    assert artifact["candidates"][0]["cve"]["cve_id"] == "CVE-2025-12345"
    assert artifact["online_status"] == "complete"
    assert artifact["candidates"][0]["observed_urls"] == ["https://example.com/path"]
    assert "secret" not in json.dumps(artifact)
    evidence = database.list_evidence(result.phase.execution_id)
    assert evidence[0].sha256 == hashlib.sha256(
        (tmp_path / "evidence" / "cve-intelligence.json").read_bytes()
    ).hexdigest()

    def unavailable_lookup(_catalog, _cpes):
        raise CveFeedError("NVD temporarily unavailable")

    monkeypatch.setattr(cve_workflow, "lookup_cpes_online", unavailable_lookup)
    fallback = run_cve_intelligence(
        database, context,
        OrchestrationPhaseResult(
            phase=OrchestrationPhase.HTTP_INTELLIGENCE,
            execution_id=source_child.execution_id,
            evidence_id=registered.evidence_id,
            evidence_path=str(source_path),
        ),
        evidence_root=tmp_path / "fallback-evidence", catalog_path=catalog_path,
        refresh=True,
    )
    assert fallback.online_status == "unavailable"
    assert fallback.candidates == 1
    fallback_artifact = json.loads(
        (tmp_path / "fallback-evidence" / "cve-intelligence.json").read_text()
    )
    assert fallback_artifact["online_error"] == "NVD temporarily unavailable"

"""Validate and normalize official NVD 2.0 and CISA KEV JSON documents."""

from __future__ import annotations

import re
from collections.abc import Iterator

from saarthi_ai.cve.models import CpeMatch, CveRecord

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")


class CveFeedError(ValueError):
    """A feed document has an unsupported or invalid structure."""


def _text(value: object, limit: int = 2_000) -> str | None:
    return str(value)[:limit] if isinstance(value, str) and value else None


def _english(items: object) -> str:
    if not isinstance(items, list):
        return ""
    for item in items:
        if isinstance(item, dict) and item.get("lang") == "en":
            return _text(item.get("value")) or ""
    return ""


def _cvss(metrics: object) -> tuple[float | None, str | None, str | None]:
    if not isinstance(metrics, dict):
        return None, None, None
    for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(field)
        if not isinstance(entries, list):
            continue
        for entry in sorted(
            (item for item in entries if isinstance(item, dict)),
            key=lambda item: item.get("type") != "Primary",
        ):
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            try:
                score = float(data["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= score <= 10:
                continue
            severity = _text(data.get("baseSeverity") or entry.get("baseSeverity"), 20)
            version = _text(data.get("version"), 10)
            return score, severity, version
    return None, None, None


def _matches(configurations: object, cve_id: str) -> Iterator[CpeMatch]:
    if not isinstance(configurations, list):
        return
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue
        configuration_complex = len(nodes) > 1
        stack = [(node, configuration_complex) for node in nodes]
        while stack:
            node, inherited_complex = stack.pop()
            if not isinstance(node, dict):
                continue
            children = node.get("children")
            child_nodes = children if isinstance(children, list) else []
            complex_node = (
                inherited_complex
                or node.get("operator", "OR") != "OR"
                or bool(node.get("negate"))
                or bool(child_nodes)
            )
            stack.extend((child, True) for child in child_nodes)
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            if any(isinstance(item, dict) and item.get("vulnerable") is False for item in matches):
                complex_node = True
            for item in matches:
                if not isinstance(item, dict):
                    continue
                criteria = _text(item.get("criteria"), 500)
                if not criteria or not criteria.startswith("cpe:2.3:"):
                    continue
                yield CpeMatch(
                    cve_id=cve_id,
                    criteria=criteria,
                    vulnerable=item.get("vulnerable") is True,
                    version_start_including=_text(item.get("versionStartIncluding"), 100),
                    version_start_excluding=_text(item.get("versionStartExcluding"), 100),
                    version_end_including=_text(item.get("versionEndIncluding"), 100),
                    version_end_excluding=_text(item.get("versionEndExcluding"), 100),
                    complex_configuration=complex_node,
                )


def parse_nvd_document(document: object) -> list[tuple[CveRecord, tuple[CpeMatch, ...]]]:
    """Return CVEs and affected CPE rules from an NVD CVE API 2.0 response."""

    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise CveFeedError("NVD document must contain a vulnerabilities array.")
    output: list[tuple[CveRecord, tuple[CpeMatch, ...]]] = []
    for wrapper in document["vulnerabilities"]:
        item = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(item, dict):
            continue
        cve_id = item.get("id")
        if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
            continue
        if item.get("vulnStatus") in {"Rejected", "REJECT"}:
            continue
        score, severity, version = _cvss(item.get("metrics"))
        references = item.get("references")
        exploit_reference = isinstance(references, list) and any(
            isinstance(ref, dict)
            and isinstance(ref.get("tags"), list)
            and "Exploit" in ref["tags"]
            for ref in references
        )
        output.append(
            (
                CveRecord(
                    cve_id=cve_id,
                    description=_english(item.get("descriptions")),
                    published=_text(item.get("published"), 50),
                    modified=_text(item.get("lastModified"), 50),
                    cvss_score=score,
                    cvss_severity=severity,
                    cvss_version=version,
                    exploit_reference=exploit_reference,
                ),
                tuple(_matches(item.get("configurations"), cve_id)),
            )
        )
    return output


def parse_kev_document(document: object) -> list[dict[str, str]]:
    """Return validated KEV entries using CISA's published field names."""

    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise CveFeedError("CISA KEV document must contain a vulnerabilities array.")
    output: list[dict[str, str]] = []
    for item in document["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
            continue
        output.append(
            {
                "cve_id": cve_id,
                "date_added": _text(item.get("dateAdded"), 50) or "",
                "due_date": _text(item.get("dueDate"), 50) or "",
                "required_action": _text(item.get("requiredAction"), 1_000) or "",
                "ransomware_use": _text(item.get("knownRansomwareCampaignUse"), 30) or "",
                "vendor": _text(item.get("vendorProject"), 200) or "",
                "product": _text(item.get("product"), 200) or "",
                "name": _text(item.get("vulnerabilityName"), 300) or "",
            }
        )
    return output

"""Conservative CPE matching: candidates are never confirmed vulnerabilities."""

from __future__ import annotations

import re

from saarthi_ai.cve.catalog import CveCatalog
from saarthi_ai.cve.models import CpeMatch, CveCandidate, CveRecord

_NUMERIC_VERSION = re.compile(r"^[0-9]+(?:[._-][0-9]+)*$")


def _version_parts(version: str) -> tuple[int, ...] | None:
    if not _NUMERIC_VERSION.fullmatch(version):
        return None
    return tuple(int(part) for part in re.split(r"[._-]", version))


def _compare(a: str, b: str) -> int | None:
    left, right = _version_parts(a), _version_parts(b)
    if left is None or right is None:
        return None
    width = max(len(left), len(right))
    left += (0,) * (width - len(left))
    right += (0,) * (width - len(right))
    return (left > right) - (left < right)


def _applies(version: str, match: CpeMatch) -> tuple[bool, str, str]:
    criteria_version = match.criteria.split(":")[5]
    if version in {"*", "-"}:
        return True, "version_unknown", "Observed version is unknown."
    if criteria_version not in {"*", version}:
        return False, "", ""
    for boundary, inclusive, lower in (
        (match.version_start_including, True, True),
        (match.version_start_excluding, False, True),
        (match.version_end_including, True, False),
        (match.version_end_excluding, False, False),
    ):
        if boundary is None:
            continue
        order = _compare(version, boundary)
        if order is None:
            return True, "review_required", "Version range uses a non-numeric version."
        if (lower and (order < 0 or (order == 0 and not inclusive))) or (
            not lower and (order > 0 or (order == 0 and not inclusive))
        ):
            return False, "", ""
    if match.complex_configuration or "*" in match.criteria.split(":")[2:5]:
        return True, "review_required", "NVD rule is broad or has additional conditions."
    return True, "candidate", "CPE and version match an NVD affected-product rule."


def _priority(cve: CveRecord) -> int:
    score = round((cve.cvss_score or 0) * 6)
    if cve.exploited_in_wild:
        score += 30
    if cve.exploit_reference:
        score += 10
    return min(score, 100)


def match_cpe(catalog: CveCatalog, observed_cpe: str, limit: int = 100) -> list[CveCandidate]:
    """Find locally cached CVE candidates for one explicitly observed CPE 2.3 string."""

    parts = observed_cpe.split(":")
    if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
        raise ValueError("Expected a CPE 2.3 string, e.g. cpe:2.3:a:vendor:product:1.2:*")
    part, vendor, product, version = parts[2:6]
    if any(value in {"", "*", "-"} for value in (part, vendor, product)):
        raise ValueError("Observed CPE must specify part, vendor, and product.")
    candidates: dict[str, CveCandidate] = {}
    for match in catalog.list_matches(part, vendor, product):
        applicable, state, reason = _applies(version, match)
        if not applicable:
            continue
        record = catalog.get_record(match.cve_id)
        if record is None:
            continue
        candidate = CveCandidate(
            cve=record, observed_cpe=observed_cpe,
            matching_criteria=match.criteria, priority_score=_priority(record),
            applicability=state, reason=reason,
        )
        previous = candidates.get(record.cve_id)
        if previous is None or (
            previous.applicability != "candidate" and state == "candidate"
        ):
            candidates[record.cve_id] = candidate
    return sorted(
        candidates.values(), key=lambda item: (-item.priority_score, item.cve.cve_id)
    )[:limit]

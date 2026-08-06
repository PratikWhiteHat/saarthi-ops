"""Value-redacted Phase 6C.4 session-cookie attribute analysis."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

MAX_COOKIE_HEADERS = 50
MAX_COOKIE_HEADER_CHARACTERS = 4_096


class SessionCookieClassification(StrEnum):
    """Conservative cookie-hardening classification."""

    HARDENED = "hardened"
    REVIEW_RECOMMENDED = "review_recommended"
    NO_COOKIES_OBSERVED = "no_cookies_observed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CookieAttributeObservation:
    """Cookie attributes with the name hashed and value discarded."""

    cookie_name_sha256: str
    secure: bool
    http_only: bool
    same_site: str | None
    path_is_root: bool
    domain_present: bool
    host_prefix: bool
    secure_prefix: bool
    issues: tuple[str, ...]


@dataclass(frozen=True)
class SessionCookieValidationResult:
    """Safe aggregate derived from Set-Cookie headers in memory."""

    validator_id: str
    classification: SessionCookieClassification
    reason: str
    cookie_count: int
    cookies_with_issues: int
    issue_counts: tuple[tuple[str, int], ...]
    cookie_observations: tuple[CookieAttributeObservation, ...]
    analysis_truncated: bool
    malformed_header_count: int
    cookie_values_discarded: bool = True
    raw_set_cookie_stored: bool = False
    cookie_replayed: bool = False
    credential_header_sent: bool = False
    payload_generated: bool = False


def _name_fingerprint(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def analyze_session_cookie_attributes(
    set_cookie_headers: tuple[str, ...],
) -> SessionCookieValidationResult:
    """Inspect cookie attributes without retaining names or values."""

    analysis_truncated = (
        len(set_cookie_headers) > MAX_COOKIE_HEADERS
        or any(
            len(header) > MAX_COOKIE_HEADER_CHARACTERS
            for header in set_cookie_headers[:MAX_COOKIE_HEADERS]
        )
    )
    observations: list[CookieAttributeObservation] = []
    malformed_count = 0
    issue_counts: dict[str, int] = {}

    for raw_header in set_cookie_headers[:MAX_COOKIE_HEADERS]:
        header = raw_header[:MAX_COOKIE_HEADER_CHARACTERS]
        segments = [
            segment.strip()
            for segment in header.split(";")
            if segment.strip()
        ]
        if not segments or "=" not in segments[0]:
            malformed_count += 1
            continue

        cookie_name, _separator, _discarded_value = (
            segments[0].partition("=")
        )
        cookie_name = cookie_name.strip()
        if not cookie_name:
            malformed_count += 1
            continue

        attributes: dict[str, str | None] = {}
        for segment in segments[1:]:
            attribute_name, separator, attribute_value = (
                segment.partition("=")
            )
            normalized_name = attribute_name.strip().lower()
            if not normalized_name:
                continue
            attributes[normalized_name] = (
                attribute_value.strip()
                if separator
                else None
            )

        secure = "secure" in attributes
        http_only = "httponly" in attributes
        same_site_value = attributes.get("samesite")
        same_site = (
            same_site_value.lower()
            if isinstance(same_site_value, str)
            else None
        )
        path_value = attributes.get("path")
        path_is_root = (
            isinstance(path_value, str)
            and path_value.strip() == "/"
        )
        domain_present = "domain" in attributes
        host_prefix = cookie_name.startswith("__Host-")
        secure_prefix = cookie_name.startswith("__Secure-")
        issues: set[str] = set()

        if not secure:
            issues.add("missing_secure")
        if not http_only:
            issues.add("missing_http_only")
        if same_site not in {"strict", "lax", "none"}:
            issues.add("missing_or_invalid_same_site")
        if same_site == "none" and not secure:
            issues.add("same_site_none_without_secure")
        if host_prefix and (
            not secure or not path_is_root or domain_present
        ):
            issues.add("invalid_host_prefix_attributes")
        if secure_prefix and not secure:
            issues.add("invalid_secure_prefix_attributes")

        for issue in issues:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1

        observations.append(
            CookieAttributeObservation(
                cookie_name_sha256=_name_fingerprint(cookie_name),
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                path_is_root=path_is_root,
                domain_present=domain_present,
                host_prefix=host_prefix,
                secure_prefix=secure_prefix,
                issues=tuple(sorted(issues)),
            )
        )

    if analysis_truncated or malformed_count:
        classification = SessionCookieClassification.INCONCLUSIVE
        reason = (
            "Cookie headers exceeded bounded parsing limits or contained "
            "malformed syntax; values were discarded."
        )
    elif not observations:
        classification = (
            SessionCookieClassification.NO_COOKIES_OBSERVED
        )
        reason = "No Set-Cookie header was observed in the response."
    elif issue_counts:
        classification = (
            SessionCookieClassification.REVIEW_RECOMMENDED
        )
        reason = (
            "One or more cookies omit recommended security attributes; "
            "cookie purpose and impact require manual review."
        )
    else:
        classification = SessionCookieClassification.HARDENED
        reason = (
            "Observed cookies use Secure, HttpOnly, and a recognized "
            "SameSite attribute."
        )

    return SessionCookieValidationResult(
        validator_id="6C.4-session-cookie-attribute-validation",
        classification=classification,
        reason=reason,
        cookie_count=len(observations),
        cookies_with_issues=sum(
            bool(item.issues) for item in observations
        ),
        issue_counts=tuple(sorted(issue_counts.items())),
        cookie_observations=tuple(observations),
        analysis_truncated=analysis_truncated,
        malformed_header_count=malformed_count,
    )

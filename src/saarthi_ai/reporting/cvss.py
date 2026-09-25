"""Deterministic CVSS v3.1 base-score support for report findings.

The report's severity remains authoritative (it comes from the vulnerability
library / coverage verdict). CVSS here is *supporting rigor*: a defensible base
vector + score attached to each finding. Vectors are chosen by finding type when
a type template's computed band matches the assigned severity; otherwise a
generic per-severity vector is used so the displayed CVSS band never contradicts
the finding's stated severity. The score itself is computed from the vector with
the official CVSS 3.1 formula — nothing is faked.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from saarthi_ai.exploit_confirmation.models import Severity

# --- CVSS 3.1 metric weights -------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope (Changed grants slightly higher weight).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass(frozen=True)
class CvssResult:
    """A CVSS 3.1 base vector + computed score + derived severity band."""

    vector: str
    score: float
    severity: Severity

    @property
    def available(self) -> bool:
        return bool(self.vector) and self.vector != "N/A"


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= value."""

    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS 3.1 base score from a metric dict (AV, AC, ...)."""

    scope_changed = metrics["S"].upper() == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    exploitability = (
        8.22
        * _AV[metrics["AV"]]
        * _AC[metrics["AC"]]
        * pr_table[metrics["PR"]]
        * _UI[metrics["UI"]]
    )

    iss = 1 - (
        (1 - _CIA[metrics["C"]])
        * (1 - _CIA[metrics["I"]])
        * (1 - _CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> Severity:
    """Map a base score onto the qualitative CVSS 3.1 severity band."""

    if score <= 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def _vector_string(metrics: dict[str, str]) -> str:
    body = "/".join(f"{key}:{metrics[key]}" for key in _METRIC_ORDER)
    return f"CVSS:3.1/{body}"


def _result(metrics: dict[str, str]) -> CvssResult:
    score = base_score(metrics)
    return CvssResult(
        vector=_vector_string(metrics),
        score=score,
        severity=severity_from_score(score),
    )


# --- Finding-type templates --------------------------------------------------
# (keyword tuple -> representative base metrics). First match wins; used only
# when the template's computed band equals the finding's assigned severity.
_TYPE_TEMPLATES: tuple[tuple[tuple[str, ...], dict[str, str]], ...] = (
    (
        ("remote code execution", "rce", "command injection", "deserial"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "H", "I": "H", "A": "H"},
    ),
    (
        ("sql injection", "sqli", "nosql"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "H", "I": "H", "A": "H"},
    ),
    (
        ("ssrf", "server-side request", "server side request"),
        {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C",
         "C": "H", "I": "N", "A": "N"},
    ),
    (
        ("xxe", "xml external"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "H", "I": "N", "A": "N"},
    ),
    (
        ("authentication bypass", "auth bypass", "broken authentication",
         "account takeover", "privilege escalation"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "H", "I": "H", "A": "N"},
    ),
    (
        ("idor", "broken access control", "authorization", "bola", "bfla"),
        {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U",
         "C": "H", "I": "N", "A": "N"},
    ),
    (
        ("stored", "persistent xss"),
        {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C",
         "C": "L", "I": "L", "A": "N"},
    ),
    (
        ("cross-site scripting", "xss", "cross site scripting"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
         "C": "L", "I": "L", "A": "N"},
    ),
    (
        ("csrf", "cross-site request forgery", "cross site request forgery"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U",
         "C": "L", "I": "L", "A": "N"},
    ),
    (
        ("open redirect",),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
         "C": "L", "I": "N", "A": "N"},
    ),
    (
        ("denial of service", "dos"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "N", "I": "N", "A": "H"},
    ),
    (
        ("information disclosure", "sensitive data", "data exposure",
         "info leak", "information leak"),
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
         "C": "H", "I": "N", "A": "N"},
    ),
    (
        ("cors", "cross-origin"),
        {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "C",
         "C": "L", "I": "N", "A": "N"},
    ),
    (
        ("cookie", "httponly", "secure flag", "samesite", "missing header",
         "security header", "tls", "ssl", "clickjack", "x-frame"),
        {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U",
         "C": "L", "I": "N", "A": "N"},
    ),
)

# Generic per-severity fallbacks, each calibrated to sit inside its band.
_GENERIC: dict[Severity, dict[str, str]] = {
    Severity.CRITICAL: {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                        "C": "H", "I": "H", "A": "H"},
    Severity.HIGH: {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                    "C": "H", "I": "N", "A": "N"},
    Severity.MEDIUM: {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
                      "C": "L", "I": "L", "A": "N"},
    Severity.LOW: {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U",
                   "C": "L", "I": "N", "A": "N"},
}


def classify(title: str, severity: Severity) -> CvssResult:
    """Return a CVSS result for a finding, band-aligned to ``severity``.

    Informational findings get no score. Otherwise a finding-type template is
    used when its computed band matches the assigned severity; failing that, a
    generic per-severity vector is used so the CVSS band always agrees with the
    finding's stated severity.
    """

    if severity is Severity.INFO:
        return CvssResult(vector="N/A", score=0.0, severity=Severity.INFO)

    haystack = title.lower()
    for keywords, metrics in _TYPE_TEMPLATES:
        if any(keyword in haystack for keyword in keywords):
            result = _result(metrics)
            if result.severity is severity:
                return result

    return _result(_GENERIC[severity])


__all__ = [
    "CvssResult",
    "base_score",
    "classify",
    "severity_from_score",
]

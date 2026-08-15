"""Best-effort local-LLM narrative for the assessment report.

Only prose is model-generated (executive summary). Findings, severities, and
evidence are deterministic. If the model is unavailable the caller falls back to
a templated summary so the report always generates.
"""

from __future__ import annotations

from saarthi_ai.llm.ollama_client import SaarthiOllamaClient
from saarthi_ai.reporting.models import ReportModel
from saarthi_ai.schemas.chat import Message

MAX_SUMMARY_TOKENS = 550

REPORT_SUMMARY_SYSTEM_PROMPT = (
    "You are a senior application-security consultant writing the Executive "
    "Summary of an AUTHORIZED web-application penetration-test report for a "
    "non-technical audience. Use ONLY the finding counts and titles provided; "
    "never invent findings, hosts, exploitation detail, or numbers. Write 2-4 "
    "plain, professional sentences: the overall posture, the most serious "
    "themes, and the need for remediation by severity. No markdown, no lists, "
    "no preamble."
)


def build_summary_prompt(model: ReportModel) -> str:
    """Render the report model as the summary user message."""

    counts = model.severity_counts
    lines = [
        f"Target: {model.target or model.engagement.app_name}",
        f"Total findings: {len(model.findings)}",
        (
            "Severity breakdown: "
            f"critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, "
            f"informational={counts['info']}"
        ),
        f"Highest severity: {model.highest_severity.value}",
        "",
        "Finding titles (worst first):",
    ]
    lines += [
        f"  - [{f.severity.value}] {f.title}"
        for f in model.sorted_findings[:20]
    ] or ["  - (no findings)"]
    lines += ["", "Write the executive summary."]
    return "\n".join(lines)


def fallback_summary(model: ReportModel) -> str:
    """Templated executive summary used when the model is unavailable."""

    counts = model.severity_counts
    total = len(model.findings)
    if total == 0:
        return (
            f"{model.engagement.company} conducted an authorized "
            f"{model.engagement.test_type} box web-application penetration "
            f"test of {model.engagement.app_name}. No exploitable "
            "vulnerabilities were confirmed within the assessment window; "
            "continued periodic testing is recommended."
        )
    parts = []
    for label, key in (
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
    ):
        if counts[key]:
            parts.append(f"{counts[key]} {label}")
    breakdown = ", ".join(parts) if parts else "several informational"
    return (
        f"{model.engagement.company} conducted an authorized "
        f"{model.engagement.test_type} box web-application penetration test of "
        f"{model.engagement.app_name}. The assessment identified {total} "
        f"finding(s) ({breakdown}). It is advised to remediate the "
        "vulnerabilities in order of severity, prioritizing the highest-risk "
        "issues, in line with organizational policy."
    )


async def generate_executive_summary(
    client: SaarthiOllamaClient,
    model: ReportModel,
    *,
    num_predict: int = MAX_SUMMARY_TOKENS,
) -> str:
    """Ask the local model for an executive summary (raises on model errors)."""

    prompt = build_summary_prompt(model)
    content, _thinking = await client.chat(
        [Message(role="user", content=prompt)],
        system_prompt=REPORT_SUMMARY_SYSTEM_PROMPT,
        num_predict=num_predict,
    )
    return content.strip()


__all__ = [
    "REPORT_SUMMARY_SYSTEM_PROMPT",
    "build_summary_prompt",
    "fallback_summary",
    "generate_executive_summary",
]

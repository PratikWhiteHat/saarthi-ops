"""Render a :class:`ReportModel` to a Markdown report.

Markdown is the terminal-friendly, diff-able companion to the `.docx`/JSON
deliverables. It mirrors the same sections: metadata, executive summary, scope,
summary-of-findings, remediation roadmap, detailed findings (with CVSS), and a
methodology/tools/severity-key appendix.
"""

from __future__ import annotations

from pathlib import Path

from saarthi_ai.reporting.models import (
    ReportModel,
    priority_band,
    severity_rating_key,
)


def _md_escape(text: str) -> str:
    """Escape pipe characters so free text does not break table cells."""

    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _detailed_block(model: ReportModel) -> list[str]:
    lines: list[str] = ["## Detailed Findings", ""]
    if not model.findings:
        lines += ["No findings were recorded for this engagement.", ""]
        return lines
    for finding in model.sorted_findings:
        priority, label, _ = priority_band(finding.severity)
        lines.append(f"### {finding.section_id} {finding.title}")
        lines.append("")
        lines.append(f"- **Rating:** {finding.display_rating} ({priority})")
        if finding.cvss_vector and finding.cvss_vector != "N/A":
            lines.append(
                f"- **CVSS v3.1:** {finding.cvss_score} "
                f"(`{finding.cvss_vector}`)"
            )
        lines.append(
            "- **Exploited / Verified:** "
            f"{'Yes' if finding.exploited_verified else 'No'}"
        )
        if finding.affected_urls:
            joined = ", ".join(finding.affected_urls)
            lines.append(f"- **Affected URL(s):** {joined}")
        lines.append("")
        for heading, value in (
            ("Description", finding.description),
            ("Security Risk", finding.security_risk),
            ("Recommendation", finding.recommendation),
            ("Reference(s)", finding.references),
            ("Proof of Concept", finding.proof_of_concept),
        ):
            if value:
                lines.append(f"**{heading}**")
                lines.append("")
                lines.append(value.strip())
                lines.append("")
    return lines


def render_report_markdown(model: ReportModel, destination: str | Path) -> Path:
    """Render ``model`` to ``destination`` as a Markdown report."""

    meta = model.engagement
    counts = model.severity_counts
    lines: list[str] = [
        f"# Web Application Penetration Test Report — {meta.app_name}",
        "",
        f"- **Prepared by:** {meta.author} ({meta.company})",
    ]
    if meta.reviewer:
        lines.append(f"- **Reviewed by:** {meta.reviewer}")
    lines += [
        f"- **Classification:** {meta.classification}",
        f"- **Status:** {meta.status_label}",
        f"- **Test type:** {meta.test_type} box",
    ]
    if meta.report_date:
        lines.append(f"- **Date:** {meta.report_date}")
    lines += [
        f"- **Overall security posture:** {model.overall_posture}",
        "",
        "## Executive Summary",
        "",
        model.executive_summary or "",
        "",
        "## Scope of Work",
        "",
    ]
    scope = meta.scope_urls or ([model.target] if model.target else [])
    lines += [f"- {url}" for url in scope] or ["- (no scope recorded)"]
    lines += [
        "",
        "## Summary of Findings",
        "",
        (
            f"Findings — critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, "
            f"informational={counts['info']}."
        ),
        "",
        "| S. No. | Title | Rating | Exploited / Verified | Ref |",
        "| --- | --- | --- | --- | --- |",
    ]
    for index, finding in enumerate(model.sorted_findings, start=1):
        lines.append(
            f"| {index} | {_md_escape(finding.title)} "
            f"| {finding.summary_rating} "
            f"| {'Yes' if finding.exploited_verified else 'No'} "
            f"| {finding.section_id} |"
        )

    # Remediation roadmap.
    lines += [
        "",
        "## Remediation Roadmap",
        "",
        "| Priority | Finding | Rating | Effort | Recommendation |",
        "| --- | --- | --- | --- | --- |",
    ]
    roadmap = model.remediation_roadmap
    if roadmap:
        for item in roadmap:
            lines.append(
                f"| {item.priority} | {_md_escape(item.title)} "
                f"| {item.severity.value} | {item.effort} "
                f"| {_md_escape(item.recommendation) or '—'} |"
            )
    else:
        lines.append("| — | No remediation items | — | — | — |")

    lines += ["", *_detailed_block(model)]

    # Appendix.
    lines += ["## Appendix", "", "### Methodology", "", model.methodology or ""]
    lines += ["", "### Tools Used", ""]
    if model.tools_used:
        lines += [f"- {tool}" for tool in model.tools_used]
    else:
        lines.append("- (no tool evidence recorded)")
    lines += [
        "",
        "### Severity Rating Key",
        "",
        "| Priority | Rating | CVSS Range |",
        "| --- | --- | --- |",
    ]
    for row in severity_rating_key():
        lines.append(
            f"| {row['priority']} | {row['rating']} | {row['cvss_range']} |"
        )
    lines.append("")

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


__all__ = ["render_report_markdown"]

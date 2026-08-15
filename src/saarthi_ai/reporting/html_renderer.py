"""Render a :class:`ReportModel` to a self-contained, print-ready HTML report.

The HTML is dependency-free (inline CSS, no external assets) so it renders
identically offline and can be "printed to PDF" from any browser. It carries the
same sections as the `.docx`/Markdown deliverables, including CVSS, a remediation
roadmap, and the methodology/tools/severity-key appendix.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from saarthi_ai.reporting.models import (
    ReportModel,
    priority_band,
    severity_rating_key,
)

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 2.5rem auto; max-width: 60rem; padding: 0 1.5rem;
  color: #1a1a1a; line-height: 1.5;
}
h1 { font-size: 1.9rem; border-bottom: 3px solid #2b3a67; padding-bottom: .4rem; }
h2 { margin-top: 2.2rem; color: #2b3a67; border-bottom: 1px solid #d0d5dd; }
h3 { margin-top: 1.6rem; color: #1a2540; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .93rem; }
th, td { border: 1px solid #c7ccd6; padding: .5rem .6rem; text-align: left;
  vertical-align: top; }
th { background: #eef1f7; }
.meta { list-style: none; padding: 0; }
.meta li { margin: .2rem 0; }
.finding { padding: .6rem 0; border-bottom: 1px dashed #d0d5dd; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: .4rem;
  font-size: .8rem; font-weight: 600; color: #fff; }
.sev-critical { background: #8b0000; }
.sev-high { background: #c0392b; }
.sev-medium { background: #d68910; }
.sev-low { background: #2e86c1; }
.sev-info { background: #6b7280; }
code { background: #f2f3f5; padding: .05rem .3rem; border-radius: .3rem;
  font-size: .85rem; }
.field-label { font-weight: 600; margin-top: .6rem; }
.field-body { white-space: pre-wrap; }
@media print {
  body { margin: 0; max-width: none; font-size: 11pt; }
  h2 { page-break-after: avoid; }
  .finding, tr { page-break-inside: avoid; }
}
"""


def _sev_class(value: str) -> str:
    return f"sev-{value}"


def _badge(value: str, label: str) -> str:
    return f'<span class="badge {_sev_class(value)}">{escape(label)}</span>'


def _field(label: str, body: str) -> str:
    if not body:
        return ""
    return (
        f'<div class="field-label">{escape(label)}</div>'
        f'<div class="field-body">{escape(body.strip())}</div>'
    )


def render_report_html(model: ReportModel, destination: str | Path) -> Path:
    """Render ``model`` to ``destination`` as a standalone HTML report."""

    meta = model.engagement
    counts = model.severity_counts
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(meta.app_name)} — Penetration Test Report</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>Web Application Penetration Test Report — "
        f"{escape(meta.app_name)}</h1>",
        '<ul class="meta">',
        f"<li><strong>Prepared by:</strong> {escape(meta.author)} "
        f"({escape(meta.company)})</li>",
    ]
    if meta.reviewer:
        parts.append(
            f"<li><strong>Reviewed by:</strong> {escape(meta.reviewer)}</li>"
        )
    parts += [
        f"<li><strong>Classification:</strong> "
        f"{escape(meta.classification)}</li>",
        f"<li><strong>Status:</strong> {escape(meta.status_label)}</li>",
        f"<li><strong>Test type:</strong> {escape(meta.test_type)} box</li>",
    ]
    if meta.report_date:
        parts.append(
            f"<li><strong>Date:</strong> {escape(meta.report_date)}</li>"
        )
    parts += [
        f"<li><strong>Overall security posture:</strong> "
        f"{escape(model.overall_posture)}</li>",
        "</ul>",
        "<h2>Executive Summary</h2>",
        f"<p>{escape(model.executive_summary or '')}</p>",
        "<h2>Scope of Work</h2><ul>",
    ]
    scope = meta.scope_urls or ([model.target] if model.target else [])
    parts += [f"<li>{escape(url)}</li>" for url in scope] or [
        "<li>(no scope recorded)</li>"
    ]
    parts += [
        "</ul>",
        "<h2>Summary of Findings</h2>",
        f"<p>Findings — critical={counts['critical']}, high={counts['high']}, "
        f"medium={counts['medium']}, low={counts['low']}, "
        f"informational={counts['info']}.</p>",
        "<table><thead><tr><th>S. No.</th><th>Title</th><th>Rating</th>"
        "<th>Exploited / Verified</th><th>Ref</th></tr></thead><tbody>",
    ]
    for index, finding in enumerate(model.sorted_findings, start=1):
        parts.append(
            f"<tr><td>{index}</td><td>{escape(finding.title)}</td>"
            f"<td>{_badge(finding.severity.value, finding.summary_rating)}</td>"
            f"<td>{'Yes' if finding.exploited_verified else 'No'}</td>"
            f"<td>{escape(finding.section_id)}</td></tr>"
        )
    parts.append("</tbody></table>")

    # Remediation roadmap.
    parts += [
        "<h2>Remediation Roadmap</h2>",
        "<table><thead><tr><th>Priority</th><th>Finding</th><th>Rating</th>"
        "<th>Effort</th><th>Recommendation</th></tr></thead><tbody>",
    ]
    for item in model.remediation_roadmap:
        parts.append(
            f"<tr><td>{escape(item.priority)}</td>"
            f"<td>{escape(item.title)}</td>"
            f"<td>{_badge(item.severity.value, item.severity.value.title())}</td>"
            f"<td>{escape(item.effort)}</td>"
            f"<td>{escape(item.recommendation) or '—'}</td></tr>"
        )
    if not model.remediation_roadmap:
        parts.append(
            "<tr><td colspan='5'>No remediation items.</td></tr>"
        )
    parts.append("</tbody></table>")

    # Detailed findings.
    parts.append("<h2>Detailed Findings</h2>")
    if not model.findings:
        parts.append("<p>No findings were recorded for this engagement.</p>")
    for finding in model.sorted_findings:
        priority = priority_band(finding.severity)[0]
        parts.append('<div class="finding">')
        parts.append(
            f"<h3>{escape(finding.section_id)} {escape(finding.title)} "
            f"{_badge(finding.severity.value, priority)}</h3>"
        )
        parts.append(f"<div>Rating: {escape(finding.display_rating)}</div>")
        if finding.cvss_vector and finding.cvss_vector != "N/A":
            parts.append(
                f"<div>CVSS v3.1: {finding.cvss_score} "
                f"<code>{escape(finding.cvss_vector)}</code></div>"
            )
        parts.append(
            "<div>Exploited / Verified: "
            f"{'Yes' if finding.exploited_verified else 'No'}</div>"
        )
        if finding.affected_urls:
            joined = escape(", ".join(finding.affected_urls))
            parts.append(f"<div>Affected URL(s): {joined}</div>")
        for label, value in (
            ("Description", finding.description),
            ("Security Risk", finding.security_risk),
            ("Recommendation", finding.recommendation),
            ("Reference(s)", finding.references),
            ("Proof of Concept", finding.proof_of_concept),
        ):
            parts.append(_field(label, value))
        parts.append("</div>")

    # Appendix.
    parts += [
        "<h2>Appendix</h2>",
        "<h3>Methodology</h3>",
        f"<p>{escape(model.methodology or '')}</p>",
        "<h3>Tools Used</h3><ul>",
    ]
    parts += [f"<li>{escape(tool)}</li>" for tool in model.tools_used] or [
        "<li>(no tool evidence recorded)</li>"
    ]
    parts += [
        "</ul>",
        "<h3>Severity Rating Key</h3>",
        "<table><thead><tr><th>Priority</th><th>Rating</th>"
        "<th>CVSS Range</th></tr></thead><tbody>",
    ]
    for row in severity_rating_key():
        parts.append(
            f"<tr><td>{row['priority']}</td><td>{row['rating']}</td>"
            f"<td>{row['cvss_range']}</td></tr>"
        )
    parts += ["</tbody></table>", "</body></html>"]

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


__all__ = ["render_report_html"]

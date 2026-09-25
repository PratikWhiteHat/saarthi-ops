"""Render a :class:`ReportModel` into the pack's `.docx` report template.

The renderer fills scalar placeholders, populates the scope and
summary-of-findings tables, and inserts one eight-field detailed-finding table
per finding at the ``[[FINDINGS HERE]]`` marker. When no template is installed
it builds a clean standalone document so a report is always produced.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from saarthi_ai.knowledge.docx_text import replace_text_everywhere
from saarthi_ai.reporting.models import (
    ReportFinding,
    ReportModel,
    severity_rating_key,
)

FINDINGS_MARKER = "[[FINDINGS HERE]]"


def _finding_rows(finding: ReportFinding) -> list[tuple[str, str]]:
    """Return the (label, value) rows for a detailed-finding table.

    The CVSS row is included only when a vector was assigned (informational
    findings carry none).
    """

    rows: list[tuple[str, str]] = [
        ("Vulnerability", finding.title),
        ("Affected URL(s)", "\n".join(finding.affected_urls) or "N/A"),
        ("Vulnerability Rating", finding.display_rating),
    ]
    if finding.cvss_vector and finding.cvss_vector != "N/A":
        rows.append(
            ("CVSS v3.1", f"{finding.cvss_score}  {finding.cvss_vector}")
        )
    rows += [
        ("Description", finding.description),
        ("Security Risk", finding.security_risk),
        ("Recommendation", finding.recommendation),
        ("Reference(s)", finding.references),
        ("Proof of Concept (PoC)", finding.proof_of_concept),
    ]
    return rows


def _placeholder_map(model: ReportModel) -> dict[str, str]:
    """Build the scalar placeholder → value map (longest keys first)."""

    meta = model.engagement
    # Insertion order matters: replace the longer TESTINGCOMPANYSHORT before
    # its TESTINGCOMPANY prefix.
    return {
        "TESTINGCOMPANYSHORT": meta.resolved_company_short(),
        "TESTINGCOMPANY": meta.company,
        "REVIEWERNAME": meta.reviewer or meta.author,
        "NAMENAME": meta.author,
        "ORGNAME": meta.org_name,
        "APPNAME": meta.app_name,
        "BLACKGRAY": meta.test_type,
        "REVALIDATIONFINAL": meta.status_label,
        "OVERALLPOSTURE": model.overall_posture,
        "Dth MMM 2025": meta.report_date or "",
    }


def _set_cell_text(cell: Any, text: str, *, bold: bool = False) -> None:
    """Replace a cell's content with ``text``, one paragraph per line."""

    lines = (text or "").split("\n") or [""]
    cell.text = lines[0]
    if cell.paragraphs and cell.paragraphs[0].runs:
        cell.paragraphs[0].runs[0].bold = bold
    for extra in lines[1:]:
        paragraph = cell.add_paragraph(extra)
        if bold and paragraph.runs:
            paragraph.runs[0].bold = True


def _row_texts(table: Any, row_index: int = 0) -> list[str]:
    if row_index >= len(table.rows):
        return []
    return [cell.text.strip().lower() for cell in table.rows[row_index].cells]


def _find_table(document: Any, must_contain: tuple[str, ...]) -> Any | None:
    """Return the first table whose header row contains all substrings."""

    for table in document.tables:
        header = " | ".join(_row_texts(table))
        if all(token in header for token in must_contain):
            return table
    return None


def _clear_data_rows(table: Any) -> None:
    """Remove every row after the header row."""

    tbl = table._tbl
    for row in list(table.rows)[1:]:
        tbl.remove(row._tr)


def _apply_table_style(document: Any, table: Any) -> None:
    for style_name in ("Table Grid", "TableGrid"):
        try:
            table.style = document.styles[style_name]
            return
        except KeyError:
            continue


def _fill_scope_table(document: Any, model: ReportModel) -> None:
    table = _find_table(document, ("s. no", "url"))
    if table is None:
        return
    _clear_data_rows(table)
    urls = model.engagement.scope_urls or ([model.target] if model.target else [])
    for index, url in enumerate(urls, start=1):
        cells = table.add_row().cells
        cells[0].text = str(index)
        cells[1].text = url


def _fill_summary_table(document: Any, model: ReportModel) -> None:
    table = _find_table(document, ("s. no", "title", "risk"))
    if table is None:
        return
    _clear_data_rows(table)
    for index, finding in enumerate(model.sorted_findings, start=1):
        finding.number = index
        cells = table.add_row().cells
        values = [
            str(index),
            finding.title,
            finding.summary_rating,
            "Yes" if finding.exploited_verified else "No",
            finding.section_id,
        ]
        for cell, value in zip(cells, values, strict=False):
            cell.text = value


def _build_finding_table(document: Any, finding: ReportFinding) -> Any:
    rows = _finding_rows(finding)
    table = document.add_table(rows=len(rows), cols=2)
    _apply_table_style(document, table)
    for row, (label, value) in zip(table.rows, rows, strict=True):
        _set_cell_text(row.cells[0], label, bold=True)
        _set_cell_text(row.cells[1], value or "")
    return table


def _append_remediation_section(document: Any, model: ReportModel) -> None:
    """Append a prioritized remediation-roadmap table to the document."""

    heading = document.add_paragraph("Remediation Roadmap")
    _style_heading(document, heading, level=1)
    table = document.add_table(rows=1, cols=5)
    _apply_table_style(document, table)
    for cell, label in zip(
        table.rows[0].cells,
        ("Priority", "Finding", "Rating", "Effort", "Recommendation"),
        strict=False,
    ):
        _set_cell_text(cell, label, bold=True)
    roadmap = model.remediation_roadmap
    if not roadmap:
        cells = table.add_row().cells
        cells[0].text = "—"
        cells[1].text = "No remediation items"
        return
    for item in roadmap:
        cells = table.add_row().cells
        values = (
            item.priority,
            item.title,
            item.severity.value.title(),
            item.effort,
            item.recommendation or "—",
        )
        for cell, value in zip(cells, values, strict=False):
            _set_cell_text(cell, value)


def _append_appendix(document: Any, model: ReportModel) -> None:
    """Append the methodology, tools-used, and severity-key appendix."""

    heading = document.add_paragraph("Appendix")
    _style_heading(document, heading, level=1)

    methodology = document.add_paragraph("Methodology")
    _style_heading(document, methodology, level=2)
    document.add_paragraph(model.methodology or "")

    tools = document.add_paragraph("Tools Used")
    _style_heading(document, tools, level=2)
    if model.tools_used:
        for tool in model.tools_used:
            document.add_paragraph(f"• {tool}")
    else:
        document.add_paragraph("(no tool evidence recorded)")

    key = document.add_paragraph("Severity Rating Key")
    _style_heading(document, key, level=2)
    table = document.add_table(rows=1, cols=3)
    _apply_table_style(document, table)
    for cell, label in zip(
        table.rows[0].cells,
        ("Priority", "Rating", "CVSS Range"),
        strict=False,
    ):
        _set_cell_text(cell, label, bold=True)
    for row in severity_rating_key():
        cells = table.add_row().cells
        cells[0].text = row["priority"]
        cells[1].text = row["rating"]
        cells[2].text = row["cvss_range"]


def _insert_detailed_findings(document: Any, model: ReportModel) -> None:
    """Insert detailed-finding tables at the findings marker paragraph."""

    marker = None
    for paragraph in document.paragraphs:
        if FINDINGS_MARKER in paragraph.text:
            marker = paragraph
            break

    findings = model.sorted_findings
    if marker is None:
        # No marker: append at the end under a heading.
        _append_detailed_heading(document)
        for finding in findings:
            _append_finding_block(document, finding)
        return

    ref = marker._p
    for finding in findings:
        heading = document.add_paragraph(
            f"{finding.section_id} {finding.title}"
        )
        _style_heading(document, heading, level=2)
        ref.addnext(heading._p)
        ref = heading._p

        table = _build_finding_table(document, finding)
        ref.addnext(table._tbl)
        ref = table._tbl

        spacer = document.add_paragraph("")
        ref.addnext(spacer._p)
        ref = spacer._p

    # Remove the marker paragraph itself.
    marker._p.getparent().remove(marker._p)


def _style_heading(document: Any, paragraph: Any, *, level: int) -> None:
    for name in (f"Heading {level}", "Heading 2", "Heading 1"):
        try:
            paragraph.style = document.styles[name]
            return
        except KeyError:
            continue


def _append_detailed_heading(document: Any) -> None:
    heading = document.add_paragraph("Detailed Findings")
    _style_heading(document, heading, level=1)


def _append_finding_block(document: Any, finding: ReportFinding) -> None:
    heading = document.add_paragraph(f"{finding.section_id} {finding.title}")
    _style_heading(document, heading, level=2)
    _build_finding_table(document, finding)
    document.add_paragraph("")


def _build_fallback_document(model: ReportModel) -> Any:
    """Build a clean report when no template is installed."""

    from docx import Document

    document = Document()
    meta = model.engagement
    document.add_heading(
        f"Web Application Penetration Test Report — {meta.app_name}", level=0
    )
    document.add_paragraph(f"Prepared by: {meta.author} ({meta.company})")
    if meta.reviewer:
        document.add_paragraph(f"Reviewed by: {meta.reviewer}")
    document.add_paragraph(f"Classification: {meta.classification}")
    if meta.report_date:
        document.add_paragraph(f"Date: {meta.report_date}")

    document.add_heading("Executive Summary", level=1)
    document.add_paragraph(model.executive_summary or "")

    document.add_heading("Scope of Work", level=1)
    for url in meta.scope_urls or ([model.target] if model.target else []):
        document.add_paragraph(url, style="List Bullet")

    document.add_heading("Summary of Findings", level=1)
    counts = model.severity_counts
    document.add_paragraph(
        "Overall security posture: "
        f"{model.overall_posture}. Findings — critical={counts['critical']}, "
        f"high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, informational={counts['info']}."
    )
    summary = document.add_table(rows=1, cols=5)
    _apply_table_style(document, summary)
    header = summary.rows[0].cells
    for cell, label in zip(
        header,
        ("S. No.", "Title", "Risk", "Exploited / Verified", "ID"),
        strict=False,
    ):
        cell.text = label
    for index, finding in enumerate(model.sorted_findings, start=1):
        finding.number = index
        cells = summary.add_row().cells
        for cell, value in zip(
            cells,
            (
                str(index),
                finding.title,
                finding.summary_rating,
                "Yes" if finding.exploited_verified else "No",
                finding.section_id,
            ),
            strict=False,
        ):
            cell.text = value

    _append_detailed_heading(document)
    for finding in model.sorted_findings:
        _append_finding_block(document, finding)
    return document


def render_report_docx(
    model: ReportModel,
    destination: str | Path,
    *,
    template_path: str | Path | None = None,
) -> Path:
    """Render ``model`` to ``destination`` as a `.docx` report."""

    from docx import Document

    if template_path is not None and Path(template_path).exists():
        document = Document(str(template_path))
        replace_text_everywhere(document, _placeholder_map(model))
        _fill_scope_table(document, model)
        _fill_summary_table(document, model)
        _insert_detailed_findings(document, model)
    else:
        document = _build_fallback_document(model)

    # Remediation roadmap + appendix close out both the template and fallback
    # documents so every report is submission-complete.
    _append_remediation_section(document, model)
    _append_appendix(document, model)

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    document.save(str(path))
    return path


__all__ = ["FINDINGS_MARKER", "render_report_docx"]

"""Best-effort, local-first PDF export for the assessment report.

PDF is optional: it is produced only when a local LibreOffice/soffice binary is
available to convert the `.docx` (highest fidelity). Nothing is sent off-machine
and no heavy native rendering dependency is added. When no converter is present
the caller keeps the print-ready HTML (browser "print to PDF") and this returns
``None`` without raising.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

# Common names / locations for a headless LibreOffice on macOS and Linux.
_SOFFICE_NAMES = ("soffice", "libreoffice")
_MAC_SOFFICE = Path("/Applications/LibreOffice.app/Contents/MacOS/soffice")


def find_soffice() -> str | None:
    """Return the path to a usable LibreOffice/soffice binary, or None."""

    for name in _SOFFICE_NAMES:
        found = shutil.which(name)
        if found:
            return found
    if _MAC_SOFFICE.exists():
        return str(_MAC_SOFFICE)
    return None


def pdf_export_available() -> bool:
    """Whether local PDF export (via LibreOffice) is possible on this machine."""

    return find_soffice() is not None


def render_report_pdf(
    source: str | Path,
    destination: str | Path,
    *,
    timeout: float = 120.0,
) -> Path | None:
    """Convert ``source`` (.docx/.html) to a PDF at ``destination``.

    Returns the PDF path on success, or ``None`` when no local converter is
    available or the conversion fails — reporting must never abort on PDF.
    """

    soffice = find_soffice()
    if soffice is None:
        return None

    source = Path(source)
    destination = Path(destination)
    if not source.exists():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        # A private user profile avoids clashing with a running LibreOffice.
        profile = Path(tmp) / "profile"
        try:
            subprocess.run(
                [
                    soffice,
                    f"-env:UserInstallation=file://{profile}",
                    "--headless",
                    "--convert-to",
                    "pdf",
                    "--outdir",
                    tmp,
                    str(source),
                ],
                check=True,
                capture_output=True,
                timeout=timeout,
            )
        except (subprocess.SubprocessError, OSError):
            return None

        produced = Path(tmp) / f"{source.stem}.pdf"
        if not produced.exists():
            return None
        shutil.move(str(produced), str(destination))

    return destination if destination.exists() else None


__all__ = ["find_soffice", "pdf_export_available", "render_report_pdf"]

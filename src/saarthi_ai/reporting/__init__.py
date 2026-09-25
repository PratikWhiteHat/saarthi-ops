"""Phase 8A reporting — assemble a VAPT report from an engagement's evidence.

The report is built deterministically from the run's confirmed/actionable
findings (mapped to the local vulnerability library for canonical write-ups) and
rendered into the pack's `.docx` template plus a machine-readable JSON sidecar.
The local model contributes only narrative prose (executive summary, posture),
best-effort — the report still generates when the model is offline.
"""

from saarthi_ai.reporting.builder import build_report_model
from saarthi_ai.reporting.models import (
    EngagementMeta,
    ReportFinding,
    ReportModel,
)

__all__ = [
    "EngagementMeta",
    "ReportFinding",
    "ReportModel",
    "build_report_model",
]

"""AI-assisted analysis of assessment-run evidence."""

from saarthi_ai.analysis.engine import (
    AnalysisError,
    PhaseDigest,
    RunDigest,
    analyze_run,
    build_analysis_prompt,
    build_phase_prompt,
    comment_on_live_output,
    explain_adaptation,
    gather_phase_digest,
    gather_run_digest,
    suggest_for_phase,
)
from saarthi_ai.analysis.quality import (
    QualityAnalysisError,
    QualityAnalysisResult,
    SourceReference,
    analyze_run_quality,
    persist_quality_analysis,
    render_quality_analysis,
)

__all__ = [
    "AnalysisError",
    "PhaseDigest",
    "QualityAnalysisError",
    "QualityAnalysisResult",
    "RunDigest",
    "SourceReference",
    "analyze_run",
    "analyze_run_quality",
    "build_analysis_prompt",
    "build_phase_prompt",
    "comment_on_live_output",
    "explain_adaptation",
    "gather_phase_digest",
    "gather_run_digest",
    "persist_quality_analysis",
    "render_quality_analysis",
    "suggest_for_phase",
]

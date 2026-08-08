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

__all__ = [
    "AnalysisError",
    "PhaseDigest",
    "RunDigest",
    "analyze_run",
    "build_analysis_prompt",
    "build_phase_prompt",
    "comment_on_live_output",
    "explain_adaptation",
    "gather_phase_digest",
    "gather_run_digest",
    "suggest_for_phase",
]

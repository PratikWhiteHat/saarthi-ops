"""Automatic, permission-gated security validation workflows."""

# NOTE: modules that depend on ``analysis.engine`` (``proposals``,
# ``agent_loop``) are intentionally NOT re-exported here. ``analysis.engine``
# imports ``automation.adaptive``, which runs this package ``__init__``; pulling
# an analysis-dependent module in at that point creates a circular import.
# Import those directly from their submodules instead.
from saarthi_ai.automation.auto_validation import (
    AutomaticValidationResult,
    AutoValidationConfig,
    AutoValidationError,
    SqlmapCandidate,
    run_automatic_validation,
)
from saarthi_ai.automation.chain_config import (
    ChainConfigError,
    ChainDerivedValidation,
    build_auto_validation_config_from_chain,
)

__all__ = [
    "AutoValidationConfig",
    "AutoValidationError",
    "AutomaticValidationResult",
    "ChainConfigError",
    "ChainDerivedValidation",
    "SqlmapCandidate",
    "build_auto_validation_config_from_chain",
    "run_automatic_validation",
]

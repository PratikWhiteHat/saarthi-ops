"""Phase-code normalization: completed 6D/6E/6F children must render DONE.

Regression test — child executions store the full OrchestrationPhase value
(e.g. "6F-post-exploitation"), which previously did not collapse to the "6F"
roadmap code, so those phases never showed DONE in the workflow-status panel.
"""

from __future__ import annotations

from saarthi_ai.orchestration.models import OrchestrationPhase
from saarthi_ai.tui.app import normalize_phase_code, phase_rows


def test_normalize_collapses_all_suffixed_phase_codes() -> None:
    assert normalize_phase_code("6D-authenticated-workflow") == "6D"
    assert normalize_phase_code("6E-exploit-confirmation") == "6E"
    assert normalize_phase_code("6F-post-exploitation") == "6F"
    # Existing behavior preserved.
    assert normalize_phase_code("4A-cors") == "4A"
    assert normalize_phase_code("6C-safe-validator") == "6C"
    # Unsuffixed codes are untouched.
    assert normalize_phase_code("3E") == "3E"
    assert normalize_phase_code("6A") == "6A"


def test_every_orchestration_phase_value_normalizes_to_a_base_phase() -> None:
    from saarthi_ai.tui.app import BASE_PHASES

    base_codes = {code for code, _ in BASE_PHASES}
    for phase in OrchestrationPhase:
        assert normalize_phase_code(phase.value) in base_codes, phase.value


def test_completed_6def_render_done() -> None:
    completed = [
        OrchestrationPhase.AUTHENTICATED_WORKFLOW.value,
        OrchestrationPhase.EXPLOIT_CONFIRMATION.value,
        OrchestrationPhase.POST_EXPLOITATION.value,
    ]
    rows = phase_rows("6F — POST-EXPLOITATION SIMULATION", completed)
    status = {code: state for _marker, code, _name, state, _done in rows}
    assert status["6D"] == "DONE"
    assert status["6E"] == "DONE"
    assert status["6F"] == "DONE"

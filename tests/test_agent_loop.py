"""The autonomous AI hunt loop stays bounded, gated, and convergent."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from saarthi_ai.analysis.engine import RunDigest
from saarthi_ai.automation.agent_loop import (
    FAST_MAX_ITERATIONS,
    FAST_NUCLEI_CONCURRENCY,
    FAST_NUCLEI_PROCESS_TIMEOUT_SECONDS,
    FAST_NUCLEI_RATE_LIMIT,
    ITERATION_HARD_CEILING,
    AgentAutonomy,
    AgentLoopConfig,
    AgentLoopResult,
    _fast_filter_actions,
    apply_fast_profile,
    gate_action,
    run_agent_loop,
)
from saarthi_ai.automation.auto_validation import (
    AutomaticValidationResult,
    AutoValidationConfig,
)
from saarthi_ai.automation.chain_config import ChainDerivedValidation
from saarthi_ai.automation.proposals import (
    ProposedAction,
    build_action_derived,
    enumerate_candidate_actions,
)


def _base(
    parameters: Sequence[str],
    *,
    orchestration_id: str = "orch-1",
    authorized: bool = True,
    active_testing: bool = True,
    intrusive_testing: bool = True,
    allowed_hosts: tuple[str, ...] = ("target.test",),
) -> ChainDerivedValidation:
    config = AutoValidationConfig(
        target_url="https://target.test/item?id=1",
        allowed_hosts=allowed_hosts,
        authorized=authorized,
        active_testing=active_testing,
        intrusive_testing=intrusive_testing,
        approved=True,
    )
    return ChainDerivedValidation(
        config=config,
        orchestration_id=orchestration_id,
        source_execution_id="exec-parent",
        assessment_name="loop-test",
        target_url=config.target_url,
        allowed_hosts=allowed_hosts,
        sqlmap_parameters=tuple(parameters),
    )


def _digest(
    *,
    evidence_total: int = 0,
    nuclei_healthy: bool = True,
) -> RunDigest:
    # A "healthy" nuclei summary suppresses the rescan_nuclei candidate so a
    # test can control the exact action menu; empty/timed-out re-enables it.
    nuclei_summary = (
        "nuclei exit=0 timed_out=false template_hits=3"
        if nuclei_healthy
        else None
    )
    return RunDigest(
        orchestration_id="orch-1",
        parent_execution_id="exec-parent",
        target="https://target.test/item?id=1",
        parent_state="completed",
        assessment_name="loop-test",
        phases=(("6C", "completed"),),
        evidence_counts={"tool_output": evidence_total},
        nuclei_summary=nuclei_summary,
    )


def _result(run_id: str = "run-x") -> AutomaticValidationResult:
    return AutomaticValidationResult(
        run_id=run_id,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        evidence_path=f"evidence/{run_id}",
        nuclei={"exit_code": 0},
        sqlmap=(),
    )


async def _passthrough_annotate(
    _client: object,
    actions: list[ProposedAction],
    _digest: RunDigest,
) -> list[ProposedAction]:
    """Deterministic stand-in for the LLM: keep the enumerated order."""

    return actions


def _run(
    base_provider,
    digest_provider,
    action_runner,
    config: AgentLoopConfig,
    **kwargs,
) -> AgentLoopResult:
    return asyncio.run(
        run_agent_loop(
            client=object(),
            base_provider=base_provider,
            digest_provider=digest_provider,
            action_runner=action_runner,
            config=config,
            annotate=_passthrough_annotate,
            **kwargs,
        )
    )


# --- gate_action: the deterministic safety veto ------------------------------


def test_gate_allows_valid_confirm_sqli() -> None:
    action = ProposedAction(
        kind="confirm_sqli",
        label="Confirm SQLi on 'id'",
        rationale="flagged",
        param="id",
        technique="BT",
    )
    assert gate_action(action, _base(["id"])) is None


def test_gate_rejects_disallowed_kind() -> None:
    action = ProposedAction(kind="dump_database", label="dump", rationale="x")
    reason = gate_action(action, _base(["id"]))
    assert reason is not None and "allowlist" in reason


def test_gate_rejects_intrusive_without_permission() -> None:
    action = ProposedAction(
        kind="confirm_sqli", label="Confirm", rationale="x",
        param="id", technique="BT",
    )
    reason = gate_action(action, _base(["id"], intrusive_testing=False))
    assert reason is not None and "intrusive" in reason


def test_gate_rejects_unsafe_technique() -> None:
    action = ProposedAction(
        kind="confirm_sqli", label="Confirm", rationale="x",
        param="id", technique="U",  # UNION — outside blind-only safe set
    )
    reason = gate_action(action, _base(["id"]))
    assert reason is not None and "technique" in reason


def test_gate_rejects_without_scope() -> None:
    action = ProposedAction(
        kind="rescan_nuclei", label="Re-run nuclei", rationale="x",
    )
    reason = gate_action(action, _base(["id"], allowed_hosts=()))
    assert reason is not None and "scope" in reason


# --- fast profile ------------------------------------------------------------


def test_apply_fast_profile_bumps_nuclei_knobs() -> None:
    base = _base(["id"]).config
    fast = apply_fast_profile(base)
    assert fast.nuclei_rate_limit >= FAST_NUCLEI_RATE_LIMIT
    assert fast.nuclei_concurrency >= FAST_NUCLEI_CONCURRENCY
    assert fast.nuclei_process_timeout_seconds <= FAST_NUCLEI_PROCESS_TIMEOUT_SECONDS
    # everything else (scope, permissions) is preserved
    assert fast.allowed_hosts == base.allowed_hosts
    assert fast.intrusive_testing == base.intrusive_testing


def test_fast_filter_drops_rescan_and_broad_cve_tag() -> None:
    actions = [
        ProposedAction(kind="rescan_nuclei", label="full sweep", rationale="x"),
        ProposedAction(
            kind="targeted_nuclei", label="tech", rationale="x",
            nuclei_tags=("cve", "nginx", "php"),
        ),
        ProposedAction(
            kind="confirm_sqli", label="sqli", rationale="x",
            param="id", technique="BT",
        ),
    ]
    out = _fast_filter_actions(actions)
    kinds = [a.kind for a in out]
    assert "rescan_nuclei" not in kinds  # full sweep dropped
    assert "confirm_sqli" in kinds  # non-nuclei actions untouched
    targeted = next(a for a in out if a.kind == "targeted_nuclei")
    assert "cve" not in targeted.nuclei_tags
    assert set(targeted.nuclei_tags) == {"nginx", "php"}


def test_fast_filter_keeps_cve_when_it_is_the_only_tag() -> None:
    actions = [
        ProposedAction(
            kind="targeted_nuclei", label="t", rationale="x",
            nuclei_tags=("cve",),
        )
    ]
    out = _fast_filter_actions(actions)
    # never leave the action tag-less; fall back to the original set
    assert out[0].nuclei_tags == ("cve",)


def test_fast_config_flag_defaults_off() -> None:
    assert AgentLoopConfig().fast is False
    assert AgentLoopConfig(fast=True).fast is True
    assert FAST_MAX_ITERATIONS <= ITERATION_HARD_CEILING


def test_gate_allows_targeted_nuclei_without_intrusive() -> None:
    # nuclei is non-intrusive scanning; it only needs active-testing, not
    # intrusive authorization.
    action = ProposedAction(
        kind="targeted_nuclei", label="tech nuclei", rationale="x",
        nuclei_tags=("wordpress", "cve"),
    )
    assert gate_action(action, _base([], intrusive_testing=False)) is None


# --- run_agent_loop: control flow -------------------------------------------


def test_yolo_executes_then_converges_on_repeats() -> None:
    """With a fixed menu, yolo runs each action once, then converges."""

    calls: list[ProposedAction] = []

    def runner(action, _base):
        calls.append(action)
        return _result(f"run-{len(calls)}")

    # Evidence grows on every read so runs never look "dry"; convergence must
    # therefore come from the repeat-action detector, not stalled evidence.
    counter = {"n": 0}

    def digest_provider(_base):
        counter["n"] += 1
        return _digest(evidence_total=counter["n"], nuclei_healthy=False)

    result = _run(
        lambda: _base(["id"]),
        digest_provider,
        runner,
        AgentLoopConfig(
            autonomy=AgentAutonomy.YOLO, max_iterations=8, max_dry_rounds=2
        ),
    )

    # Three distinct actions exist for a params-bearing target with intrusive
    # testing (confirm_sqli id + rescan_nuclei + confirm_xss); each runs once
    # before the loop detects only-repeats remain.
    assert result.executed_count == 3
    assert {c.kind for c in calls} == {
        "confirm_sqli",
        "rescan_nuclei",
        "confirm_xss",
    }
    assert "converged" in result.stop_reason


def test_stops_at_iteration_budget() -> None:
    """A fresh action each round means the loop stops only at the cap."""

    counter = {"n": 0}

    def base_provider():
        counter["n"] += 1
        return _base([f"p{counter['n']}"])  # new parameter -> new signature

    def digest_provider(_base):
        return _digest(evidence_total=counter["n"], nuclei_healthy=True)

    runs: list[str] = []

    def runner(action, _base):
        runs.append(action.param or action.kind)
        return _result()

    result = _run(
        base_provider,
        digest_provider,
        runner,
        AgentLoopConfig(
            autonomy=AgentAutonomy.YOLO, max_iterations=3, max_dry_rounds=5
        ),
    )

    assert result.executed_count == 3
    assert len(result.iterations) == 3
    assert result.stop_reason == "reached iteration budget"


def test_converges_when_runs_produce_no_new_evidence() -> None:
    """Distinct actions but static evidence -> no-new-evidence convergence."""

    counter = {"n": 0}

    def base_provider():
        counter["n"] += 1
        return _base([f"p{counter['n']}"])

    # Constant evidence total: every executed run looks "dry".
    def digest_provider(_base):
        return _digest(evidence_total=5, nuclei_healthy=True)

    result = _run(
        base_provider,
        digest_provider,
        lambda a, b: _result(),
        AgentLoopConfig(
            autonomy=AgentAutonomy.YOLO, max_iterations=9, max_dry_rounds=2
        ),
    )

    assert result.executed_count == 2
    assert "no new evidence" in result.stop_reason


def test_abort_check_stops_immediately() -> None:
    ran = {"count": 0}

    def runner(a, b):
        ran["count"] += 1
        return _result()

    result = _run(
        lambda: _base(["id"]),
        lambda b: _digest(nuclei_healthy=False),
        runner,
        AgentLoopConfig(autonomy=AgentAutonomy.YOLO, max_iterations=5),
        abort_check=lambda: True,
    )

    assert ran["count"] == 0
    assert result.executed_count == 0
    assert result.stop_reason == "aborted by operator"


def test_propose_mode_never_executes() -> None:
    ran = {"count": 0}

    def runner(a, b):
        ran["count"] += 1
        return _result()

    result = _run(
        lambda: _base(["id"]),
        lambda b: _digest(nuclei_healthy=False),
        runner,
        AgentLoopConfig(autonomy=AgentAutonomy.PROPOSE, max_iterations=5),
    )

    assert ran["count"] == 0
    assert result.executed_count == 0
    assert result.queued  # actions were handed back for approval
    assert "propose-only" in result.stop_reason


def test_gate_mode_queues_approval_required_action() -> None:
    ran = {"count": 0}

    def runner(a, b):
        ran["count"] += 1
        return _result()

    result = _run(
        lambda: _base(["id"]),
        lambda b: _digest(nuclei_healthy=False),
        runner,
        AgentLoopConfig(autonomy=AgentAutonomy.GATE, max_iterations=5),
    )

    # The enumerated actions default to the needs_approval tier, so gate mode
    # runs nothing and hands them back.
    assert ran["count"] == 0
    assert result.queued
    assert "gate mode" in result.stop_reason


def test_converges_with_no_candidate_actions() -> None:
    """A healthy run with nothing left to probe converges without executing."""

    result = _run(
        # no sqlmap params, no intrusive (so no XSS action), healthy nuclei
        lambda: _base([], intrusive_testing=False),
        lambda b: _digest(nuclei_healthy=True),  # nuclei fine -> no rescan
        lambda a, b: _result(),
        AgentLoopConfig(autonomy=AgentAutonomy.YOLO, max_dry_rounds=2),
    )

    assert result.executed_count == 0
    assert "no further actions" in result.stop_reason


def test_execution_error_does_not_crash_loop() -> None:
    def runner(a, b):
        raise RuntimeError("tool blew up")

    result = _run(
        lambda: _base(["id"]),
        lambda b: _digest(nuclei_healthy=False),
        runner,
        AgentLoopConfig(autonomy=AgentAutonomy.YOLO, max_dry_rounds=2),
    )

    assert result.executed_count == 0
    assert any("failed" in step.note.lower() for step in result.iterations)


def test_iteration_count_is_clamped_to_hard_ceiling() -> None:
    config = AgentLoopConfig(max_iterations=1_000)
    assert config.effective_max_iterations() == ITERATION_HARD_CEILING
    assert AgentLoopConfig(max_iterations=0).effective_max_iterations() == 1


# --- widened menu: xsstrike as a first-class action + focused tools ----------


def test_menu_includes_xss_when_target_has_params_and_intrusive() -> None:
    actions = enumerate_candidate_actions(_base(["id"]), _digest(nuclei_healthy=False))
    kinds = {a.kind for a in actions}
    assert kinds == {"confirm_sqli", "rescan_nuclei", "confirm_xss"}


def test_menu_omits_xss_without_intrusive() -> None:
    actions = enumerate_candidate_actions(
        _base(["id"], intrusive_testing=False), _digest(nuclei_healthy=False)
    )
    assert "confirm_xss" not in {a.kind for a in actions}


def test_menu_omits_xss_when_target_has_no_query_params() -> None:
    base = _base(["id"])
    no_query = dataclasses_replace_target(base, "https://target.test/plain")
    actions = enumerate_candidate_actions(no_query, _digest(nuclei_healthy=False))
    assert "confirm_xss" not in {a.kind for a in actions}


def test_build_action_derived_focuses_one_tool_per_kind() -> None:
    base = _base(["id"])
    sqli = build_action_derived(
        base,
        ProposedAction(
            kind="confirm_sqli", label="x", rationale="x",
            param="id", technique="BT",
        ),
    )
    nuclei = build_action_derived(
        base, ProposedAction(kind="rescan_nuclei", label="x", rationale="x")
    )
    xss = build_action_derived(
        base, ProposedAction(kind="confirm_xss", label="x", rationale="x")
    )
    assert sqli.config.tools == ("sqlmap",)
    assert nuclei.config.tools == ("nuclei",)
    assert xss.config.tools == ("xsstrike",)
    # A focused XSS/nuclei pass never carries sqlmap candidates.
    assert xss.config.sqlmap_candidates == ()
    assert nuclei.config.sqlmap_candidates == ()


def test_gate_allows_confirm_xss_with_intrusive() -> None:
    action = ProposedAction(kind="confirm_xss", label="XSS", rationale="x")
    assert gate_action(action, _base(["id"])) is None


def test_gate_rejects_confirm_xss_without_intrusive() -> None:
    action = ProposedAction(kind="confirm_xss", label="XSS", rationale="x")
    reason = gate_action(action, _base(["id"], intrusive_testing=False))
    assert reason is not None and "XSS" in reason


def dataclasses_replace_target(
    base: ChainDerivedValidation, target_url: str
) -> ChainDerivedValidation:
    """Return a copy of ``base`` pointed at a different target URL."""

    import dataclasses

    config = dataclasses.replace(base.config, target_url=target_url)
    return dataclasses.replace(base, config=config, target_url=target_url)

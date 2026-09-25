"""Autonomous AI hunt loop (propose -> gate -> execute -> re-observe -> repeat).

This is Saarthi's answer to an Osmedeus-style "AI agent runs tools repeatedly"
loop, rebuilt to fit Saarthi's safety model. Unlike a generic agentic loop, the
local model NEVER emits raw commands and can NEVER invent an action: on every
iteration the code enumerates the SAME fixed, non-destructive action menu used
by ``automation.proposals`` (from the current run's evidence), the model only
selects/orders that menu, and a deterministic gate vetoes anything outside the
allowlist before it can run. Approved actions execute through the identical
vetted pipeline as an operator run (scope allowlist, engagement authorization,
adaptive throttle, verification).

The loop therefore composes two layers of control:

* an OUTER, AI-driven iteration that re-reads evidence and picks the next
  bounded action, and
* the INNER adaptive tool control inside ``run_automatic_validation`` that
  retries a single tool under WAF / rate-limit / reconnect conditions.

Preserved invariants (held even in the fully autonomous ``yolo`` tier):

* scope allowlist — the loop can only touch the engagement's authorized hosts;
* non-destructive constraints — no dump/shell/evasion (inherited from the base
  config; ``build_action_derived`` forces the single-row dump off regardless);
* engagement permissions — active/intrusive testing must already be recorded on
  the persisted parent execution, so the loop can never exceed what the operator
  authorized for the engagement;
* rate limiting / adaptive throttling — DoS protection stays on.

The only friction ``yolo`` removes is the per-run human approval for an
already-authorized engagement, exactly as the operator requested.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

from saarthi_ai.analysis.engine import RunDigest
from saarthi_ai.automation.auto_validation import (
    AutomaticValidationResult,
    AutoValidationConfig,
)
from saarthi_ai.automation.chain_config import ChainDerivedValidation
from saarthi_ai.automation.fingerprint import select_nuclei_tags
from saarthi_ai.automation.proposals import (
    _SAFE_TECHNIQUES,
    ALLOWED_KINDS,
    ProposedAction,
    annotate_actions,
    build_action_derived,
    enumerate_candidate_actions,
)
from saarthi_ai.llm.ollama_client import SaarthiOllamaClient

DEFAULT_MAX_ITERATIONS = 6
DEFAULT_MAX_WALL_SECONDS = 3_600.0
DEFAULT_MAX_DRY_ROUNDS = 2

# Hard ceiling: even if a caller passes a larger value, the loop never runs more
# than this many autonomous tool iterations against a live target.
ITERATION_HARD_CEILING = 25

# --- Fast profile ------------------------------------------------------------
# Trades coverage for speed: more load on the target (higher rate/concurrency,
# still within the validator's 1-20 / 1-10 caps and adaptive throttle), a
# shorter per-run timeout, no full-template rescan, and the broad high-volume
# nuclei tags dropped so only stack-specific templates run.
FAST_NUCLEI_RATE_LIMIT = 15
FAST_NUCLEI_CONCURRENCY = 10
FAST_NUCLEI_PROCESS_TIMEOUT_SECONDS = 600
FAST_MAX_ITERATIONS = 3
FAST_MAX_WALL_SECONDS = 900.0
# Broad, high-volume tags dropped in fast mode (the stack-specific tags stay).
_FAST_DROP_TAGS = frozenset({"cve", "cves"})


def apply_fast_profile(config: AutoValidationConfig) -> AutoValidationConfig:
    """Return a copy of the nuclei config tuned for a quick loop.

    Raises the rate limit / concurrency (bounded by the validator's own caps and
    still subject to adaptive throttling if the target pushes back) and shortens
    the per-run process timeout so a slow scan gives up sooner.
    """

    return dataclasses.replace(
        config,
        nuclei_rate_limit=max(config.nuclei_rate_limit, FAST_NUCLEI_RATE_LIMIT),
        nuclei_concurrency=max(config.nuclei_concurrency, FAST_NUCLEI_CONCURRENCY),
        nuclei_process_timeout_seconds=min(
            config.nuclei_process_timeout_seconds,
            FAST_NUCLEI_PROCESS_TIMEOUT_SECONDS,
        ),
    )


def _fast_filter_actions(
    actions: list[ProposedAction],
) -> list[ProposedAction]:
    """Trim the menu for fast mode: drop the full rescan, shrink broad tags."""

    trimmed: list[ProposedAction] = []
    for action in actions:
        if action.kind == "rescan_nuclei":
            continue  # the full-template sweep is the slowest action
        if action.kind == "targeted_nuclei" and action.nuclei_tags:
            kept = tuple(t for t in action.nuclei_tags if t not in _FAST_DROP_TAGS)
            # Keep the trimmed set only if something stack-specific remains;
            # otherwise fall back to the original so the action still runs.
            if kept and kept != action.nuclei_tags:
                action = dataclasses.replace(action, nuclei_tags=kept)
        trimmed.append(action)
    return trimmed


class AgentAutonomy(StrEnum):
    """How the loop treats a chosen active action.

    ``YOLO`` runs the chosen action immediately with no per-run approval,
    guarded only by the deterministic gate (scope + allowlist + engagement
    permissions + non-destructive). ``GATE`` only auto-runs ``safe_auto`` tier
    actions and hands any approval-required action back queued. ``PROPOSE``
    never executes; it only returns the ranked queue for the operator.
    """

    YOLO = "yolo"
    GATE = "gate"
    PROPOSE = "propose"


@dataclass(frozen=True)
class AgentLoopConfig:
    """Bounds and autonomy for one autonomous hunt loop."""

    autonomy: AgentAutonomy = AgentAutonomy.YOLO
    max_iterations: int = DEFAULT_MAX_ITERATIONS
    max_wall_seconds: float = DEFAULT_MAX_WALL_SECONDS
    max_dry_rounds: int = DEFAULT_MAX_DRY_ROUNDS
    orchestration_id: str | None = None
    confirmed_poc: bool = True
    # Fast profile: skip the full nuclei rescan and drop broad tags in the menu.
    # The matching nuclei runtime tuning is applied to the base config by the
    # caller via apply_fast_profile().
    fast: bool = False

    def effective_max_iterations(self) -> int:
        """Clamp the requested iteration count to a safe, positive range."""

        return max(1, min(self.max_iterations, ITERATION_HARD_CEILING))


@dataclass(frozen=True)
class AgentIteration:
    """One recorded step of the loop (proposed, gated, and maybe executed)."""

    index: int
    action_kind: str | None
    action_label: str
    rationale: str
    executed: bool
    gate_reason: str | None = None
    run_id: str | None = None
    evidence_path: str | None = None
    new_evidence: bool = False
    note: str = ""


@dataclass(frozen=True)
class AgentLoopResult:
    """Outcome of the whole loop: the transcript plus why it stopped."""

    target: str
    orchestration_id: str | None
    autonomy: str
    stop_reason: str
    iterations: tuple[AgentIteration, ...] = ()
    queued: tuple[ProposedAction, ...] = field(default=())

    @property
    def executed_count(self) -> int:
        """Number of iterations that actually ran a tool."""

        return sum(1 for step in self.iterations if step.executed)


class AgentLoopError(RuntimeError):
    """Raised when the loop cannot start (no chain, no client, etc.)."""


# Types for the injected collaborators (real ones wired by the CLI/TUI; fakes in
# tests). ``BaseProvider`` re-derives the chain config each round because the
# evidence it reads grows as the loop runs. ``DigestProvider`` reads the current
# bounded evidence digest. ``ActionRunner`` executes one gated action and
# returns the vetted-pipeline result.
BaseProvider = Callable[[], ChainDerivedValidation]
DigestProvider = Callable[[ChainDerivedValidation], RunDigest]
ActionRunner = Callable[
    [ProposedAction, ChainDerivedValidation],
    AutomaticValidationResult,
]
EventSink = Callable[[AgentIteration | str], None]


def gate_action(
    action: ProposedAction,
    base: ChainDerivedValidation,
) -> str | None:
    """Deterministic safety veto, independent of the model's choice.

    Returns a human-readable rejection reason, or ``None`` when the action is
    allowed to run. This never trusts the LLM: it re-checks the action kind
    against the fixed allowlist, that scope hosts exist, that the engagement
    actually authorized the required testing level, and that any SQLi technique
    stays within the blind-only safe set.
    """

    if action.kind not in ALLOWED_KINDS:
        return f"action kind '{action.kind}' is not in the allowlist"

    if not base.allowed_hosts:
        return "no allowed hosts (scope) recorded for the engagement"

    config = base.config

    if not (config.authorized and config.active_testing):
        return "engagement has not confirmed authorization / active testing"

    if action.kind == "confirm_sqli":
        if not config.intrusive_testing:
            return "engagement did not authorize intrusive (SQLi) testing"
        technique = action.technique or "BT"
        if technique not in _SAFE_TECHNIQUES:
            return f"SQLi technique '{technique}' is outside the safe blind set"
        if not action.param:
            return "confirm_sqli action is missing its target parameter"

    if action.kind == "confirm_xss" and not config.intrusive_testing:
        # XSStrike injects live payloads, so it is gated like sqlmap/ghauri.
        return "engagement did not authorize intrusive (XSS) testing"

    return None


def _action_signature(action: ProposedAction) -> tuple[str, str, str, str]:
    """Stable identity so the loop can detect it is repeating itself."""

    return (
        action.kind,
        action.param or "",
        action.technique or "",
        ",".join(sorted(action.nuclei_tags)),
    )


def _evidence_fingerprint(digest: RunDigest) -> tuple[int, int, int]:
    """Cheap change-detector: total evidence, verified, and finding counts."""

    return (
        sum(digest.evidence_counts.values()),
        len(digest.verified_findings),
        len(digest.findings),
    )


async def run_agent_loop(
    client: SaarthiOllamaClient,
    base_provider: BaseProvider,
    digest_provider: DigestProvider,
    action_runner: ActionRunner,
    config: AgentLoopConfig,
    *,
    on_event: EventSink | None = None,
    abort_check: Callable[[], bool] | None = None,
    clock: Callable[[], float] | None = None,
    annotate: Callable[
        [SaarthiOllamaClient, list[ProposedAction], RunDigest],
        Awaitable[list[ProposedAction]],
    ]
    | None = None,
) -> AgentLoopResult:
    """Drive the autonomous propose/gate/execute/re-observe loop.

    ``base_provider``/``digest_provider``/``action_runner`` are injected so the
    CLI and TUI can wire the real chain config, digest, and
    ``run_automatic_validation`` while tests pass deterministic fakes with no
    network or Ollama. ``abort_check`` (polled each round) lets an operator stop
    the loop; ``clock`` and ``annotate`` are injection seams for tests.
    """

    import time

    now = clock or time.monotonic
    select = annotate or annotate_actions
    started = now()

    iterations: list[AgentIteration] = []
    executed_signatures: set[tuple[str, str, str, str]] = set()
    dry_rounds = 0
    stop_reason = "reached iteration budget"
    target = "unknown"
    orchestration_id = config.orchestration_id
    queued: tuple[ProposedAction, ...] = ()

    def emit(item: AgentIteration | str) -> None:
        if on_event is not None:
            on_event(item)

    max_iterations = config.effective_max_iterations()

    for index in range(1, max_iterations + 1):
        if abort_check is not None and abort_check():
            stop_reason = "aborted by operator"
            break

        if now() - started > config.max_wall_seconds:
            stop_reason = "wall-clock budget exhausted"
            break

        base = base_provider()
        target = base.target_url
        orchestration_id = base.orchestration_id
        digest = digest_provider(base)

        candidates = enumerate_candidate_actions(base, digest)
        if config.fast:
            candidates = _fast_filter_actions(candidates)
        # Drop actions already executed this loop so the model always advances
        # to fresh work instead of re-proposing a completed step.
        fresh = [
            action
            for action in candidates
            if _action_signature(action) not in executed_signatures
        ]
        if not fresh:
            dry_rounds += 1
            label = (
                "(no candidate actions)"
                if not candidates
                else "(all proposed actions already executed)"
            )
            step = AgentIteration(
                index=index,
                action_kind=None,
                action_label=label,
                rationale="",
                executed=False,
                note="No new bounded actions are derivable from current evidence.",
            )
            iterations.append(step)
            emit(step)
            if dry_rounds >= config.max_dry_rounds:
                stop_reason = "converged: no further actions to propose"
                break
            continue

        ranked = await select(client, fresh, digest)
        action = ranked[0] if ranked else fresh[0]

        reason = gate_action(action, base)
        if reason is not None:
            # A vetoed action must not be retried forever: record its signature
            # so the next round moves on to other work.
            executed_signatures.add(_action_signature(action))
            step = AgentIteration(
                index=index,
                action_kind=action.kind,
                action_label=action.label,
                rationale=action.rationale,
                executed=False,
                gate_reason=reason,
                note=f"Gate vetoed action: {reason}",
            )
            iterations.append(step)
            emit(step)
            continue

        signature = _action_signature(action)

        # PROPOSE: never execute; queue everything worthwhile and stop.
        if config.autonomy is AgentAutonomy.PROPOSE:
            queued = tuple(ranked or fresh)
            stop_reason = "propose-only: actions queued for operator approval"
            break

        # GATE: only auto-run safe_auto tier; hand approval-required actions back.
        if config.autonomy is AgentAutonomy.GATE and action.tier != "safe_auto":
            queued = tuple(ranked or fresh)
            step = AgentIteration(
                index=index,
                action_kind=action.kind,
                action_label=action.label,
                rationale=action.rationale,
                executed=False,
                note="Gate mode: approval-required action queued, not run.",
            )
            iterations.append(step)
            emit(step)
            stop_reason = "gate mode: awaiting operator approval"
            break

        # For a tech-focused nuclei action, let the model pick the final tag
        # subset from the detected stack (falls back to the deterministic set;
        # the result is always constrained to the allowed tag vocabulary).
        run_action = action
        if action.kind == "targeted_nuclei":
            chosen = await select_nuclei_tags(
                client, base.technologies, action.nuclei_tags
            )
            if chosen:
                run_action = dataclasses.replace(action, nuclei_tags=chosen)
                emit(
                    f"[loop] tech-focused nuclei tags: {', '.join(chosen)}"
                )

        before = _evidence_fingerprint(digest)
        try:
            result = action_runner(run_action, base)
        except Exception as error:  # defensive: one bad run must not kill loop
            step = AgentIteration(
                index=index,
                action_kind=action.kind,
                action_label=action.label,
                rationale=action.rationale,
                executed=False,
                note=f"Execution failed: {error}",
            )
            iterations.append(step)
            emit(step)
            dry_rounds += 1
            if dry_rounds >= config.max_dry_rounds:
                stop_reason = "stopped: repeated execution failures"
                break
            continue

        executed_signatures.add(signature)

        after_base = base_provider()
        after = _evidence_fingerprint(digest_provider(after_base))
        new_evidence = after != before
        dry_rounds = 0 if new_evidence else dry_rounds + 1

        step = AgentIteration(
            index=index,
            action_kind=action.kind,
            action_label=action.label,
            rationale=action.rationale,
            executed=True,
            run_id=result.run_id,
            evidence_path=result.evidence_path,
            new_evidence=new_evidence,
            note=(
                "New evidence recorded."
                if new_evidence
                else "No new evidence from this run."
            ),
        )
        iterations.append(step)
        emit(step)

        if not new_evidence and dry_rounds >= config.max_dry_rounds:
            stop_reason = "converged: recent runs produced no new evidence"
            break

    return AgentLoopResult(
        target=target,
        orchestration_id=orchestration_id,
        autonomy=config.autonomy.value,
        stop_reason=stop_reason,
        iterations=tuple(iterations),
        queued=queued,
    )


def default_action_runner(
    *,
    on_output=None,
    on_log=None,
    on_adapt=None,
) -> ActionRunner:
    """Build the real executor: derive the action config and run the pipeline.

    Kept as a factory so the CLI and TUI can supply their own streaming
    callbacks while the loop core stays free of I/O concerns.
    """

    from saarthi_ai.automation.auto_validation import run_automatic_validation

    def _run(
        action: ProposedAction,
        base: ChainDerivedValidation,
    ) -> AutomaticValidationResult:
        derived = build_action_derived(base, action)
        return run_automatic_validation(
            derived.config,
            on_output=on_output,
            on_log=on_log,
            on_adapt=on_adapt,
        )

    return _run

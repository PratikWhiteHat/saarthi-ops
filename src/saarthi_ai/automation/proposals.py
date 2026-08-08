"""AI-proposed next actions for a live assessment (propose -> approve -> run).

The local model does NOT emit raw commands. Instead the code enumerates a
fixed menu of non-destructive, in-scope actions from the current run's
evidence, and the model only selects/prioritises/annotates entries from that
menu. Every proposed action is therefore bounded by construction: it can only
ever re-run the already-approved validation config with a few safe knobs
changed (technique / candidate parameter / nuclei-only). No data dump, no
shells, no evasion, no out-of-scope host — those are simply not representable.

Approved actions execute through the SAME vetted pipeline as an operator run
(allowlist, authorization, confirmation, adaptive throttle, verification).
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass

from saarthi_ai.analysis.engine import RunDigest
from saarthi_ai.automation.auto_validation import SqlmapCandidate
from saarthi_ai.automation.chain_config import ChainDerivedValidation
from saarthi_ai.llm.ollama_client import SaarthiOllamaClient
from saarthi_ai.schemas.chat import Message

# Only these action kinds can ever be proposed or executed.
ALLOWED_KINDS = ("confirm_sqli", "rescan_nuclei")

# Techniques we allow a confirm action to use (subset of sqlmap's BEUSTQ).
# Blind techniques only — fast to confirm and non-destructive.
_SAFE_TECHNIQUES = {"B", "T", "BT"}

MAX_ACTIONS = 6


@dataclass(frozen=True)
class ProposedAction:
    """One bounded, non-destructive action the operator may approve."""

    kind: str
    label: str
    rationale: str
    tier: str = "needs_approval"  # or "safe_auto" (never destructive)
    param: str | None = None
    technique: str | None = None

    def describe(self) -> str:
        gate = "AUTO" if self.tier == "safe_auto" else "APPROVE"
        return f"[{gate}] {self.label} — {self.rationale}"


def _infer_technique(sqlmap_summary: str | None) -> str:
    text = (sqlmap_summary or "").lower()
    if "boolean" in text:
        return "B"
    if "time-based" in text or "time based" in text:
        return "T"
    return "BT"


def enumerate_candidate_actions(
    derived: ChainDerivedValidation,
    digest: RunDigest,
) -> list[ProposedAction]:
    """Build the fixed, safe menu of actions from the current evidence."""

    actions: list[ProposedAction] = []

    technique = _infer_technique(digest.sqlmap_summary)
    if technique not in _SAFE_TECHNIQUES:
        technique = "BT"

    # One focused SQLi confirmation per in-scope GET parameter.
    for param in derived.sqlmap_parameters:
        actions.append(
            ProposedAction(
                kind="confirm_sqli",
                label=(
                    f"Confirm SQLi on '{param}' "
                    f"(sqlmap --technique={technique}, identity proof only)"
                ),
                rationale=(
                    "Focused technique run to confirm the flagged injection "
                    "without a full battery or data dump."
                ),
                param=param,
                technique=technique,
            )
        )

    # Re-run nuclei if the prior pass timed out or looked thin.
    nuclei_text = (digest.nuclei_summary or "").lower()
    if (not nuclei_text) or "timed_out=true" in nuclei_text:
        actions.append(
            ProposedAction(
                kind="rescan_nuclei",
                label="Re-run nuclei (in-scope, throttled) to complete coverage",
                rationale=(
                    "Previous nuclei pass timed out or was thin; re-run under "
                    "the same safe rate to finish the template sweep."
                ),
            )
        )

    return actions[:MAX_ACTIONS]


def build_action_derived(
    base: ChainDerivedValidation,
    action: ProposedAction,
) -> ChainDerivedValidation:
    """Turn an approved action into a safe, re-runnable chain config.

    Only technique / candidate / nuclei-scope knobs change; every safety
    setting (authorization, allowlist, non-destructive PoC, adaptive) is
    inherited from the operator's base config. A single-row dump is always
    forced off here regardless of the base.
    """

    if action.kind not in ALLOWED_KINDS:
        raise ValueError(f"Refusing to build disallowed action: {action.kind}")

    config = base.config

    if action.kind == "confirm_sqli":
        technique = action.technique or "BT"
        if technique not in _SAFE_TECHNIQUES:
            technique = "BT"
        # Restrict to the single flagged parameter.
        candidate = next(
            (
                c
                for c in config.sqlmap_candidates
                if c.parameter == action.param
            ),
            SqlmapCandidate(
                url=base.target_url,
                parameter=action.param or "",
                method="GET",
            ),
        )
        new_config = dataclasses.replace(
            config,
            sqlmap_techniques=technique,
            sqlmap_candidates=(candidate,),
            sqlmap_poc_single_row_dump=False,
        )
    else:  # rescan_nuclei — nuclei-only re-run, no sqlmap
        new_config = dataclasses.replace(
            config,
            sqlmap_candidates=(),
            sqlmap_poc_single_row_dump=False,
        )

    return dataclasses.replace(base, config=new_config)


PROPOSAL_SYSTEM_PROMPT = (
    "You are triaging an AUTHORIZED VAPT run. You are given a NUMBERED menu of "
    "safe, non-destructive follow-up actions the operator may approve. Choose "
    "which are worth running and in what order. You may ONLY reference the "
    "given indices — never invent actions, hosts, params, or commands. Reply "
    "with a JSON array of objects: [{\"index\": <int>, \"rationale\": "
    "\"<one short sentence>\"}], most valuable first. Include only indices that "
    "add value; omit the rest. No prose outside the JSON."
)


def _parse_selection(content: str, count: int) -> list[tuple[int, str]]:
    """Parse the model's JSON selection, dropping anything out of range."""

    text = content.strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        raw = json.loads(text[start : end + 1])
    except (ValueError, TypeError):
        return []
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        if not isinstance(idx, int) or not (0 <= idx < count) or idx in seen:
            continue
        seen.add(idx)
        rationale = str(item.get("rationale") or "").strip()
        out.append((idx, rationale))
    return out


async def annotate_actions(
    client: SaarthiOllamaClient,
    actions: list[ProposedAction],
    digest: RunDigest,
    *,
    num_predict: int = 260,
) -> list[ProposedAction]:
    """Let the model select/reorder/annotate the fixed action menu."""

    if not actions:
        return []

    menu = "\n".join(
        f"{i}. {a.label}" for i, a in enumerate(actions)
    )
    prompt = (
        f"Target: {digest.target}\n"
        f"SQLMap summary: {digest.sqlmap_summary or '(none)'}\n"
        f"Nuclei summary: {digest.nuclei_summary or '(none)'}\n\n"
        f"Action menu:\n{menu}\n\n"
        "Select and order the worthwhile actions."
    )
    try:
        content, _ = await client.chat(
            [Message(role="user", content=prompt)],
            system_prompt=PROPOSAL_SYSTEM_PROMPT,
            num_predict=num_predict,
        )
    except Exception:
        return actions

    selection = _parse_selection(content, len(actions))
    if not selection:
        return actions

    ordered: list[ProposedAction] = []
    for idx, rationale in selection:
        base = actions[idx]
        ordered.append(
            dataclasses.replace(base, rationale=rationale or base.rationale)
        )
    return ordered


async def propose_actions(
    client: SaarthiOllamaClient,
    derived: ChainDerivedValidation,
    digest: RunDigest,
) -> list[ProposedAction]:
    """Full flow: enumerate the safe menu, then AI-select/annotate it."""

    candidates = enumerate_candidate_actions(derived, digest)
    return await annotate_actions(client, candidates, digest)

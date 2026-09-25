"""Tech fingerprinting maps to a fixed nuclei-tag vocabulary and stays bounded."""

from __future__ import annotations

import asyncio

from saarthi_ai.analysis.engine import RunDigest
from saarthi_ai.automation.auto_validation import (
    AutoValidationConfig,
    _nuclei_arguments,
    nuclei_scope_notice,
)
from saarthi_ai.automation.chain_config import ChainDerivedValidation
from saarthi_ai.automation.fingerprint import (
    ALLOWED_NUCLEI_TAGS,
    map_technologies_to_nuclei_tags,
    select_nuclei_tags,
    valid_nuclei_tags,
)
from saarthi_ai.automation.proposals import (
    build_action_derived,
    enumerate_candidate_actions,
)


def _config(nuclei_tags: tuple[str, ...] = ()) -> AutoValidationConfig:
    return AutoValidationConfig(
        target_url="https://target.test/item?id=1",
        allowed_hosts=("target.test",),
        authorized=True,
        active_testing=True,
        intrusive_testing=True,
        approved=True,
        nuclei_tags=nuclei_tags,
    )


def _derived(technologies: tuple[str, ...]) -> ChainDerivedValidation:
    return ChainDerivedValidation(
        config=_config(),
        orchestration_id="orch-1",
        source_execution_id="exec-parent",
        assessment_name="fp-test",
        target_url="https://target.test/item?id=1",
        allowed_hosts=("target.test",),
        sqlmap_parameters=(),
        technologies=technologies,
    )


def _digest() -> RunDigest:
    return RunDigest(
        orchestration_id="orch-1",
        parent_execution_id="exec-parent",
        target="https://target.test/item?id=1",
        parent_state="completed",
        assessment_name="fp-test",
        phases=(("6C", "completed"),),
        nuclei_summary="nuclei exit=0 timed_out=false template_hits=3",
    )


# --- deterministic mapping + validation --------------------------------------


def test_mapping_covers_common_stacks() -> None:
    tags = map_technologies_to_nuclei_tags(("WordPress 6.2", "nginx", "PHP/8.1"))
    assert {"wordpress", "nginx", "php"}.issubset(set(tags))
    # generic high-signal tags are always added when any stack is recognized
    assert {"cve", "misconfig", "exposure"}.issubset(set(tags))
    # every produced tag is inside the allowed vocabulary
    assert set(tags).issubset(ALLOWED_NUCLEI_TAGS)


def test_mapping_empty_for_unknown_stack() -> None:
    assert map_technologies_to_nuclei_tags(("SomeBespokeThing/1.0",)) == ()
    assert map_technologies_to_nuclei_tags(()) == ()


def test_valid_nuclei_tags_rejects_injection_and_unknown() -> None:
    out = valid_nuclei_tags(("cve", "; rm -rf /", "FUZZ", "nginx", "-x", "php"))
    # only well-formed, in-vocabulary tags survive
    assert out == ("cve", "nginx", "php")


# --- nuclei arguments + scope notice -----------------------------------------


def test_nuclei_arguments_include_selected_tags() -> None:
    args = _nuclei_arguments(_config(nuclei_tags=("wordpress", "php", "cve")))
    assert "-tags" in args
    tag_value = args[args.index("-tags") + 1]
    assert set(tag_value.split(",")) == {"wordpress", "php", "cve"}
    # dangerous-tag exclusion is still present alongside the include list
    assert "-exclude-tags" in args


def test_nuclei_arguments_drop_bad_tags_no_flag() -> None:
    # all tags invalid -> no -tags flag emitted (full set, not a broken run)
    args = _nuclei_arguments(_config(nuclei_tags=("; rm", "FUZZ")))
    assert "-tags" not in args


def test_scope_notice_mentions_focused_tags() -> None:
    notice = nuclei_scope_notice(_config(nuclei_tags=("wordpress", "cve")))
    assert any("tech-focused" in line and "wordpress" in line for line in notice)


# --- action wiring -----------------------------------------------------------


def test_enumerate_adds_targeted_nuclei_when_stack_detected() -> None:
    actions = enumerate_candidate_actions(
        _derived(("WordPress", "nginx", "PHP")), _digest()
    )
    targeted = [a for a in actions if a.kind == "targeted_nuclei"]
    assert len(targeted) == 1
    assert {"wordpress", "nginx", "php"}.issubset(set(targeted[0].nuclei_tags))


def test_enumerate_no_targeted_nuclei_without_stack() -> None:
    actions = enumerate_candidate_actions(_derived(()), _digest())
    assert not any(a.kind == "targeted_nuclei" for a in actions)


def test_build_action_derived_targeted_nuclei_sets_tags_and_tool() -> None:
    base = _derived(("WordPress", "php"))
    action = next(
        a
        for a in enumerate_candidate_actions(base, _digest())
        if a.kind == "targeted_nuclei"
    )
    derived = build_action_derived(base, action)
    assert derived.config.tools == ("nuclei",)
    assert derived.config.sqlmap_candidates == ()
    assert set(derived.config.nuclei_tags) == set(action.nuclei_tags)


# --- AI tag selection: constrained + graceful fallback -----------------------


class _FakeClient:
    def __init__(self, reply: str) -> None:
        self._reply = reply

    async def chat(self, *args, **kwargs):  # noqa: D401 - test stub
        return self._reply, None


def test_select_nuclei_tags_constrains_to_candidates() -> None:
    candidates = ("cve", "wordpress", "php", "nginx")
    # model picks indices 0 and 2 -> cve, php
    client = _FakeClient("[0, 2]")
    chosen = asyncio.run(select_nuclei_tags(client, ("WordPress",), candidates))
    assert chosen == ("cve", "php")


def test_select_nuclei_tags_falls_back_on_garbage() -> None:
    candidates = ("cve", "wordpress")
    client = _FakeClient("not json at all")
    chosen = asyncio.run(select_nuclei_tags(client, ("WordPress",), candidates))
    assert chosen == candidates  # fallback = full deterministic set


def test_select_nuclei_tags_falls_back_when_client_errors() -> None:
    class _Boom:
        async def chat(self, *args, **kwargs):
            raise RuntimeError("ollama down")

    candidates = ("cve", "nginx")
    chosen = asyncio.run(select_nuclei_tags(_Boom(), ("nginx",), candidates))
    assert chosen == candidates


def test_select_nuclei_tags_empty_when_no_candidates() -> None:
    chosen = asyncio.run(select_nuclei_tags(_FakeClient("[0]"), ("x",), ()))
    assert chosen == ()

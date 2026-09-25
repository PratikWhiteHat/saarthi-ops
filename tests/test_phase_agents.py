import json

import pytest

from saarthi_ai.analysis.engine import PhaseDigest
from saarthi_ai.analysis.phase_agents import (
    PhaseAgentSupervisor,
    review_phase_agent,
    role_for_phase,
)


@pytest.mark.asyncio
async def test_phase_agent_supplies_skills_and_requires_local_citation():
    digest = PhaseDigest(
        phase_code="4A-cors",
        phase_name="CORS",
        state="completed",
        target="https://example.test",
        signals=("[evidence-123] Observed response headers",),
    )

    class Client:
        async def chat(self, messages, **kwargs):
            assert "direct-check" in kwargs["system_prompt"]
            assert kwargs["include_enabled_skills"] is True
            kwargs["skill_trace"].append("hunt-cors")
            return "- FACT [evidence-123] confidence=high: headers were recorded.", None

    review = await review_phase_agent(Client(), "execution-1", digest)
    assert review.role == "direct-checks"
    assert review.status == "grounded"
    assert review.evidence_refs == ("evidence-123",)
    assert review.skills_supplied == ("hunt-cors",)


@pytest.mark.asyncio
async def test_phase_agent_withholds_uncited_output():
    digest = PhaseDigest(
        phase_code="3A",
        phase_name="DNS",
        state="completed",
        target="example.test",
        signals=("[evidence-123] DNS record",),
    )

    class Client:
        async def chat(self, messages, **kwargs):
            return "No source citation here.", None

    review = await review_phase_agent(Client(), "execution-1", digest)
    assert review.status == "withheld"
    assert not review.evidence_refs


@pytest.mark.asyncio
async def test_phase_agent_withholds_citation_without_confidence():
    digest = PhaseDigest(
        phase_code="3A", phase_name="DNS", state="completed",
        target="example.test", signals=("[evidence-123] DNS record",),
    )

    class Client:
        async def chat(self, messages, **kwargs):
            return "- FACT [evidence-123] DNS record was observed.", None

    review = await review_phase_agent(Client(), "execution-1", digest)
    assert review.status == "withheld"


@pytest.mark.asyncio
async def test_phase_agent_does_not_call_model_without_evidence():
    digest = PhaseDigest("5A", "Planner", "completed", "example.test")
    review = await review_phase_agent(None, "execution-1", digest)
    assert review.status == "no_evidence"


def test_supervisor_records_and_persists_coverage(tmp_path):
    assert role_for_phase("6C-api")[0] == "validation"
    supervisor = PhaseAgentSupervisor("orchestration-test")
    supervisor.record_failure("execution-1", "6C-api", "model timeout")
    path = tmp_path / "supervisor.json"
    supervisor.persist(path)
    payload = json.loads(path.read_text())
    assert payload["summary"]["failed"] == 1
    assert payload["reviews"][0]["phase_code"] == "6C-api"

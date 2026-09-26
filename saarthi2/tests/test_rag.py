"""Skill-library RAG: retrieval, llm-step injection, agent tool, and API."""

from __future__ import annotations

import asyncio
import os

from saarthi2.rag import SkillLibrary

_IDOR = """---
name: hunt-idor
description: Hunting skill for IDOR vulnerabilities.
---

## Attack Surface Signals
Sequential numeric identifiers in URLs like /api/users/123 and object ids in JSON.

## Payload & Detection Patterns
Swap the id: curl -H 'Authorization: Bearer X' https://t/api/users/124 and compare.
"""

_SSRF = """---
name: hunt-ssrf
description: Hunting skill for SSRF vulnerabilities.
---

## Attack Surface Signals
URL/webhook/preview parameters that fetch server-side; cloud metadata at 169.254.169.254.
"""


def _library(tmp_path) -> SkillLibrary:
    for name, text in (("hunt-idor", _IDOR), ("hunt-ssrf", _SSRF)):
        d = tmp_path / "skills" / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(text)
    return SkillLibrary.from_dir(tmp_path / "skills")


def test_load_and_chunk(tmp_path) -> None:
    lib = _library(tmp_path)
    assert not lib.is_empty
    names = {c["name"] for c in lib.catalog()}
    assert names == {"hunt-idor", "hunt-ssrf"}
    # idor has 2 sections, ssrf has 1 -> 3 chunks
    assert len(lib) == 3


def test_retrieve_ranks_relevant_skill_first(tmp_path) -> None:
    lib = _library(tmp_path)
    top = lib.retrieve("idor sequential numeric id in api url", k=1)
    assert top and top[0].skill == "hunt-idor"
    top_ssrf = lib.retrieve("ssrf cloud metadata webhook", k=1)
    assert top_ssrf and top_ssrf[0].skill == "hunt-ssrf"


def test_context_for_formats_block(tmp_path) -> None:
    lib = _library(tmp_path)
    ctx = lib.context_for("idor object id swap", k=2)
    assert "Relevant hunting playbooks" in ctx
    assert "hunt-idor" in ctx


def test_search_and_empty(tmp_path) -> None:
    lib = _library(tmp_path)
    hits = lib.search("metadata 169.254", k=3)
    assert hits and hits[0]["skill"] == "hunt-ssrf"
    empty = SkillLibrary.from_dir(tmp_path / "nope")
    assert empty.is_empty and empty.retrieve("x") == [] and empty.context_for("x") == ""


def test_llm_step_injects_skill_context(tmp_path) -> None:
    from saarthi2.ai.agent import AgentResult
    from saarthi2.engine.context import RunContext
    from saarthi2.engine.models import Step
    from saarthi2.engine.runner import StepDeps
    from saarthi2.steps.llm import handle_llm

    captured: dict = {}

    class _Agent:
        async def run(self, prompt, *, tool_names=None, max_iterations=6, ctx=None, deps=None):
            captured["prompt"] = prompt
            return AgentResult(answer="ok", iterations=1)

    deps = StepDeps(run_command=None, http_request=None, agent=_Agent(), skills=_library(tmp_path))
    step = Step(id="t", uses="llm", with_={"prompt": "How do I hunt idor here?", "skills": True})
    result = asyncio.run(handle_llm(step, RunContext(run_id="r"), deps))
    assert result.status.value == "completed"
    assert "Relevant hunting playbooks" in captured["prompt"]
    assert "hunt-idor" in captured["prompt"]


def test_search_skills_tool(tmp_path) -> None:
    from types import SimpleNamespace

    from saarthi2.tools import default_tool_registry

    tool = default_tool_registry()["search_skills"]
    deps = SimpleNamespace(skills=_library(tmp_path))
    out = asyncio.run(tool.run({"query": "idor api id"}, None, deps))
    assert "hunt-idor" in out
    # graceful when no library
    empty = asyncio.run(tool.run({"query": "x"}, None, SimpleNamespace(skills=None)))
    assert "no skill library" in empty


def test_skills_api(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from saarthi2.config import Settings
    from saarthi2.server import create_app

    _library(tmp_path)  # writes tmp_path/skills
    wf = tmp_path / "wf"
    wf.mkdir()
    settings = Settings(work_dir=tmp_path / "work", workflows_dir=wf)
    # point skills at the corpus we just wrote
    os.environ["SAARTHI2_SKILLS_DIR"] = str(tmp_path / "skills")
    try:
        client = TestClient(create_app(settings))
        catalog = client.get("/api/skills").json()
        assert {c["name"] for c in catalog} == {"hunt-idor", "hunt-ssrf"}
        hits = client.get("/api/skills/search", params={"q": "ssrf metadata"}).json()
        assert hits and hits[0]["skill"] == "hunt-ssrf"
    finally:
        del os.environ["SAARTHI2_SKILLS_DIR"]

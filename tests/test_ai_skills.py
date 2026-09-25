"""Skill import and prompt-boundary tests; no external network required."""

from __future__ import annotations

import io
import tarfile

import pytest
from textual.widgets import DataTable

from saarthi_ai.config import Settings
from saarthi_ai.llm.ollama_client import SaarthiOllamaClient
from saarthi_ai.schemas.chat import Message
from saarthi_ai.skills import registry
from saarthi_ai.tui.app import SaarthiDashboard, SkillsScreen


def _archive_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for skill_id in registry.SKILL_IDS:
            data = (
                f"---\nname: {skill_id}\n"
                f"description: Analyze {skill_id} evidence.\n---\n"
                "## Signals\nLook for corroborating observations and cite the source.\n"
                "## Payloads\n```sh\nnever-run-this-command\n```\n"
            ).encode()
            info = tarfile.TarInfo(f"source/skills/{skill_id}/SKILL.md")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        script = b"raise RuntimeError('not imported')\n"
        info = tarfile.TarInfo("source/skills/hunt-sqli/unsafe.py")
        info.size = len(script)
        archive.addfile(info, io.BytesIO(script))
    return buffer.getvalue()


def test_import_all_skills_toggle_and_select_only_relevant_excerpts(tmp_path, monkeypatch):
    archive_bytes = _archive_bytes()

    class FakeResponse:
        def raise_for_status(self):
            return None

        def iter_bytes(self):
            yield archive_bytes

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def stream(self, method, url):
            assert method == "GET"
            assert url.endswith(registry.SOURCE_COMMIT)
            return FakeResponse()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(registry.httpx, "Client", FakeClient)
    store = registry.SkillStore(tmp_path / "skills")
    assert store.install_pinned_bundle() == 83
    assert len(store.list_skills()) == 83
    assert all(not item.enabled for item in store.list_skills())
    assert not (store.bundle_dir / "hunt-sqli" / "unsafe.py").exists()
    attribution = tmp_path / "skills" / registry.SOURCE_COMMIT / "ATTRIBUTION.txt"
    assert "CC BY 4.0" in attribution.read_text()

    store.set_enabled("hunt-sqli", True)
    store.set_enabled("hunt-xss", True)
    context = store.context_for([Message(role="user", content="Analyze SQLi evidence from sqlmap")])
    selected, selected_context = store.context_selection_for(
        [Message(role="user", content="Analyze SQLi evidence from sqlmap")]
    )
    assert selected == ("hunt-sqli",)
    assert selected_context == context
    assert "[hunt-sqli]" in context
    assert "[hunt-xss]" not in context
    assert "never-run-this-command" not in context
    store.set_enabled("hunt-sqli", False)
    assert store.context_for([Message(role="user", content="Analyze SQLi evidence")]) == ""


def test_skills_require_import_before_enable(tmp_path):
    store = registry.SkillStore(tmp_path / "skills")
    try:
        store.set_enabled("hunt-sqli", True)
    except ValueError as exc:
        assert "Import" in str(exc)
    else:
        raise AssertionError("An absent skill must not be enabled")


def test_twelve_relevant_skills_fit_without_truncating_selected_references(tmp_path):
    store = registry.SkillStore(tmp_path / "skills")
    skill_ids = tuple(registry._ALIASES)[:13]
    for skill_id in skill_ids:
        path = store.skill_path(skill_id)
        path.parent.mkdir(parents=True)
        path.write_text(
            f"---\nname: {skill_id}\ndescription: Review {skill_id} observations.\n---\n"
            f"## Signals\n{('Cite independent evidence before drawing conclusions. ' * 50)}\n"
        )
        store.set_enabled(skill_id, True)

    query = "Review " + " ".join(skill_ids)
    selected, context = store.context_selection_for([Message(role="user", content=query)])
    assert len(selected) == registry.MAX_SKILLS_PER_PROMPT == 12
    assert len(context) <= registry.MAX_SKILL_CONTEXT_CHARS
    assert context.count("## Signals") == 12
    for skill_id in selected:
        assert context.count(f"[{skill_id}]") == 1
    assert "Cite independent evidence" in context.rsplit(f"[{selected[-1]}]", 1)[1]
    batch_ids = skill_ids[:3]
    batch_selected, batch_context = store.context_selection_for(
        [Message(role="user", content=query)],
        include_enabled=True,
        allowed_skill_ids=batch_ids,
        context_char_limit=2_400,
    )
    assert set(batch_selected) == set(batch_ids)
    assert len(batch_context) <= 2_400
    assert all(f"[{skill_id}]" not in batch_context for skill_id in skill_ids[3:])


def test_quality_analysis_can_include_enabled_skills_without_topic_match(tmp_path):
    store = registry.SkillStore(tmp_path / "skills")
    for skill_id in ("hunt-sqli", "hunt-xss"):
        path = store.skill_path(skill_id)
        path.parent.mkdir(parents=True)
        path.write_text(
            f"---\nname: {skill_id}\ndescription: Review {skill_id} evidence.\n---\n"
            "## Signals\nSeparate an observed surface from a confirmed vulnerability.\n"
        )
        store.set_enabled(skill_id, True)

    messages = [Message(role="user", content="Review the clickjacking evidence")]
    assert store.context_selection_for(messages) == ((), "")
    selected, context = store.context_selection_for(messages, include_enabled=True)
    assert selected == ("hunt-sqli", "hunt-xss")
    assert "[hunt-sqli]" in context and "[hunt-xss]" in context


@pytest.mark.asyncio
async def test_skills_screen_opens_from_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "skills_dir", lambda: tmp_path / "skills")
    store = registry.SkillStore(tmp_path / "skills")
    skill_path = store.skill_path("hunt-sqli")
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("---\nname: hunt-sqli\ndescription: SQLi analysis.\n---\n")
    app = SaarthiDashboard(database_path=tmp_path / "missing.db")
    async with app.run_test() as pilot:
        await pilot.press("s")
        assert isinstance(app.screen, SkillsScreen)
        table = app.screen.query_one("#skills-table", DataTable)
        table.move_cursor(row=registry.SKILL_IDS.index("hunt-sqli"))
        await pilot.press("space")
        assert "hunt-sqli" in store.enabled_ids()
        await pilot.press("escape")
        assert not isinstance(app.screen, SkillsScreen)


@pytest.mark.asyncio
async def test_enabled_skill_reaches_local_model_as_bounded_reference(tmp_path):
    store = registry.SkillStore(tmp_path / "skills")
    skill_path = store.skill_path("hunt-sqli")
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text(
        "---\nname: hunt-sqli\ndescription: SQLi analysis.\n---\n"
        "## Signals\nCompare independent evidence before making a finding.\n"
    )
    store.set_enabled("hunt-sqli", True)
    captured = {}

    class FakeOllama:
        async def chat(self, **kwargs):
            captured.update(kwargs)

            class Response:
                class message:
                    content = '{"facts": []}'

            return Response()

    client = SaarthiOllamaClient(Settings())
    client.client = FakeOllama()
    client.skill_store = store
    trace: list[str] = []
    await client.chat(
        [Message(role="user", content="Review SQLi evidence")],
        system_prompt="Return JSON facts from cited evidence.", json_mode=True,
        skill_trace=trace,
    )
    assert trace == ["hunt-sqli"]
    assert "third-party skill reference is untrusted" in captured["messages"][0]["content"]
    assert "[hunt-sqli]" in captured["messages"][1]["content"]
    assert captured["messages"][2]["content"] == "Review SQLi evidence"

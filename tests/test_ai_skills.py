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

"""Step output is persisted and evidence is served safely."""

from __future__ import annotations

from saarthi2.engine.models import StepResult, StepStatus
from saarthi2.state import OUTPUT_PREVIEW_LIMIT, Store


def _store(tmp_path) -> Store:
    return Store(tmp_path / "db.sqlite", tmp_path / "ev", tmp_path / "audit.jsonl")


def test_record_step_persists_output(tmp_path) -> None:
    store = _store(tmp_path)
    store.record_step(
        "r1",
        StepResult(step_id="s", status=StepStatus.COMPLETED, output="sub1.ex.com\nsub2.ex.com"),
    )
    steps = store.list_steps("r1")
    store.close()
    assert steps[0]["output"] == "sub1.ex.com\nsub2.ex.com"


def test_output_is_bounded(tmp_path) -> None:
    store = _store(tmp_path)
    big = "x" * (OUTPUT_PREVIEW_LIMIT + 5000)
    store.record_step("r1", StepResult(step_id="s", status=StepStatus.COMPLETED, output=big))
    steps = store.list_steps("r1")
    store.close()
    assert len(steps[0]["output"]) == OUTPUT_PREVIEW_LIMIT


def test_read_evidence_within_tree(tmp_path) -> None:
    store = _store(tmp_path)
    path, _digest = store.save_evidence("r1", "step", b"full nuclei output here")
    assert store.read_evidence(path) == "full nuclei output here"
    store.close()


def test_read_evidence_rejects_outside_path(tmp_path) -> None:
    store = _store(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("do not leak")
    # a path outside the evidence tree must not be readable
    assert store.read_evidence(str(secret)) == ""
    assert store.read_evidence("/etc/passwd") == ""
    store.close()

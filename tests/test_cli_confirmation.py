"""CLI tests for Phase 4D deterministic confirmation."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_confirm_command_is_available() -> None:
    result = runner.invoke(
        app,
        ["confirm", "--help"],
    )

    assert result.exit_code == 0
    assert "run" in result.stdout
    assert "deterministic" in result.stdout.lower()


def test_confirm_run_loads_execution_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}

    stored_evidence = [
        SimpleNamespace(
            evidence_id="evidence-supporting",
        )
    ]

    class FakeDatabase:
        def list_evidence(self, execution_id):
            captured["loaded_execution_id"] = execution_id
            return stored_evidence

    def fake_workflow(
        database,
        candidate,
        evidence_records,
        *,
        actor,
        evidence_root,
    ):
        captured["database"] = database
        captured["candidate"] = candidate
        captured["evidence_records"] = evidence_records
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return (
            SimpleNamespace(
                status=SimpleNamespace(value="confirmed"),
                reason="Correlated OAST observation confirmed candidate.",
                supporting_evidence_ids=("evidence-supporting",),
                rejected_evidence_ids=(),
            ),
            SimpleNamespace(
                evidence_id="evidence-confirmation",
                path=str(
                    evidence_root / "confirmation-result.json"
                ),
                sha256="a" * 64,
            ),
        )

    database = FakeDatabase()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: database,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_workflow",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "confirm",
            "run",
            "--execution",
            "execution-test",
            "--candidate-id",
            "candidate-001",
            "--title",
            "Potential blind server-side interaction",
            "--candidate-type",
            "blind-interaction",
            "--expected-token-id",
            "blind-token-001",
        ],
    )

    assert result.exit_code == 0

    candidate = captured["candidate"]

    assert captured["loaded_execution_id"] == "execution-test"
    assert captured["evidence_records"] is stored_evidence
    assert candidate.execution_id == "execution-test"
    assert candidate.candidate_id == "candidate-001"
    assert candidate.title == (
        "Potential blind server-side interaction"
    )
    assert candidate.candidate_type == "blind-interaction"
    assert candidate.expected_token_id == "blind-token-001"

    assert captured["actor"] == "cli-confirmation-engine"
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "confirmation-results"
    )

    assert "Confirmation evaluation completed" in result.stdout
    assert "CONFIRMED" in result.stdout
    assert "evidence-supporting" in result.stdout
    assert "No additional security test" in result.stdout


def test_confirm_run_supports_candidate_without_token(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}

    class FakeDatabase:
        def list_evidence(self, execution_id):
            return []

    def fake_workflow(
        database,
        candidate,
        evidence_records,
        *,
        actor,
        evidence_root,
    ):
        captured["candidate"] = candidate

        return (
            SimpleNamespace(
                status=SimpleNamespace(value="unconfirmed"),
                reason="No explicit evidence confirms the candidate.",
                supporting_evidence_ids=(),
                rejected_evidence_ids=(),
            ),
            SimpleNamespace(
                evidence_id="evidence-unconfirmed",
                path=str(evidence_root / "result.json"),
                sha256="b" * 64,
            ),
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: FakeDatabase(),
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_workflow",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "confirm",
            "run",
            "--execution",
            "execution-test",
            "--candidate-id",
            "candidate-002",
            "--title",
            "Potential configuration issue",
            "--candidate-type",
            "configuration",
        ],
    )

    assert result.exit_code == 0
    assert captured["candidate"].expected_token_id is None
    assert "UNCONFIRMED" in result.stdout
    assert "Supporting evidence: none" in result.stdout

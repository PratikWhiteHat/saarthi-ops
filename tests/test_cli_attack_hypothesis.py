"""CLI tests for Phase 6A attack hypothesis generation."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from saarthi_ai.cli import app

runner = CliRunner()


def test_hypotheses_requires_explicit_approval() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "hypotheses",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
        ],
    )

    assert result.exit_code == 1
    normalized = " ".join(result.stdout.split())
    assert "Approval required" in normalized
    assert "Executed: false" in normalized
    assert "Network activity: false" in normalized
    assert "Payload generated: false" in normalized
    assert "Subprocess started: false" in normalized


def test_hypotheses_persists_non_executed_candidate_paths(
    tmp_path,
    monkeypatch,
) -> None:
    import saarthi_ai.cli as cli_module

    captured: dict[str, object] = {}
    hypothesis = SimpleNamespace(
        hypothesis_id="hypothesis-test",
        family=SimpleNamespace(value="injection"),
        title="Parameterized input handling requires validation",
        confidence=SimpleNamespace(value="medium"),
        confidence_score=60,
        validation_risk=SimpleNamespace(value="low"),
        validation_method=SimpleNamespace(
            value="input_handling_observation"
        ),
        supporting_evidence_ids=("evidence-crawl",),
    )

    def fake_workflow(
        database,
        request,
        *,
        actor,
        evidence_root,
    ):
        captured["database"] = database
        captured["request"] = request
        captured["actor"] = actor
        captured["evidence_root"] = evidence_root

        return SimpleNamespace(
            hypothesis_set=SimpleNamespace(
                hypotheses=(hypothesis,),
                considered_evidence_ids=("evidence-crawl",),
                rejected_evidence_ids=(),
                truncated=False,
            ),
            evidence=SimpleNamespace(
                evidence_id="evidence-hypothesis-set",
                path=str(evidence_root / "hypotheses.json"),
                sha256="a" * 64,
            ),
            reused_existing_evidence=False,
        )

    database = object()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: database,
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_attack_hypotheses",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "hypotheses",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--max-hypotheses",
            "10",
            "--approved",
        ],
    )

    assert result.exit_code == 0
    request = captured["request"]

    assert captured["database"] is database
    assert request.execution_id == "execution-test"
    assert request.target_url == "https://example.com/"
    assert request.authorized is True
    assert request.max_hypotheses == 10
    assert captured["actor"] == "cli-attack-hypothesis-engine"
    assert captured["evidence_root"] == (
        tmp_path / "evidence" / "attack-hypothesis-sets"
    )

    normalized = " ".join(result.stdout.split())
    assert "Phase 6A hypothesis set persisted" in normalized
    assert "Hypotheses: 1" in normalized
    assert "hypothesis-test" in normalized
    assert "Family: injection" in normalized
    assert "Confidence: medium (60)" in normalized
    assert "Validation risk: low" in normalized
    assert "Executed: false" in normalized
    assert "Network activity: false" in normalized
    assert "Payload generated: false" in normalized
    assert "Subprocess started: false" in normalized
    assert "Existing evidence reused: false" in normalized
    assert "evidence-hypothesis-set" in normalized
    assert "No validation or security test was executed" in normalized


def test_hypotheses_reports_safe_failure(monkeypatch) -> None:
    import saarthi_ai.cli as cli_module

    def fake_workflow(*args, **kwargs):
        raise cli_module.AttackHypothesisWorkflowError(
            "simulated hypothesis persistence failure"
        )

    monkeypatch.setattr(
        cli_module,
        "get_database",
        lambda: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "create_tracked_attack_hypotheses",
        fake_workflow,
    )

    result = runner.invoke(
        app,
        [
            "controlled",
            "hypotheses",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--approved",
        ],
    )

    assert result.exit_code == 1
    normalized = " ".join(result.stdout.split())
    assert "simulated hypothesis persistence failure" in normalized
    assert "Executed: false" in normalized
    assert "Network activity: false" in normalized
    assert "Payload generated: false" in normalized
    assert "Subprocess started: false" in normalized


def test_hypotheses_enforces_cli_bound() -> None:
    result = runner.invoke(
        app,
        [
            "controlled",
            "hypotheses",
            "--execution",
            "execution-test",
            "--url",
            "https://example.com/",
            "--max-hypotheses",
            "51",
            "--approved",
        ],
    )

    assert result.exit_code != 0


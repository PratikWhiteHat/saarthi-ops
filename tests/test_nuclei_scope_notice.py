"""Read-only Nuclei scope telemetry shown before automatic validation."""

from saarthi_ai.automation.auto_validation import (
    AutoValidationConfig,
    nuclei_scope_notice,
)


def _config(**changes: object) -> AutoValidationConfig:
    values = {
        "target_url": "https://example.test/",
        "allowed_hosts": ("example.test",),
        "authorized": True,
        "active_testing": True,
        "intrusive_testing": False,
        "approved": True,
    }
    values.update(changes)
    return AutoValidationConfig(**values)


def test_default_notice_discloses_full_template_scope_and_limits() -> None:
    notice = nuclei_scope_notice(_config())

    assert "all installed templates (default)" in notice[0]
    assert "5 req/s" in notice[1]
    assert "10800s/process" in notice[1]
    assert "does not select or run templates" in notice[2]


def test_configured_path_notice_does_not_expose_path() -> None:
    notice = nuclei_scope_notice(
        _config(nuclei_templates_path="/private/operator/templates")
    )

    assert "configured template path" in notice[0]
    assert "/private/operator/templates" not in "\n".join(notice)

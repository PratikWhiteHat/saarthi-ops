"""Phase 6D engine — log principals in, then run authZ replay + token hygiene.

Bounded and non-fatal: a failed login or a step error is logged and skipped;
the run still produces whatever findings it could gather. Only redacted
session fingerprints and findings are returned (no secrets).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from saarthi_ai.controlled_validation.authenticated.authz_replay import (
    run_authz_replay,
)
from saarthi_ai.controlled_validation.authenticated.login import perform_login
from saarthi_ai.controlled_validation.authenticated.models import (
    AuthFinding,
    AuthWorkflowConfig,
)
from saarthi_ai.controlled_validation.authenticated.token_hygiene import (
    analyze_tokens,
)


@dataclass(frozen=True)
class AuthWorkflowResult:
    """Redacted, persistable result of a Phase 6D run."""

    target: str
    sessions: tuple[dict, ...]
    findings: tuple[AuthFinding, ...]
    logins_ok: int
    logins_failed: int


def run_authenticated_workflow(
    config: AuthWorkflowConfig,
    *,
    on_log: Callable[[str], None] | None = None,
) -> AuthWorkflowResult:
    """Run the full 6D workflow for a validated config."""

    log = on_log or (lambda _message: None)

    sessions_by_label: dict = {}
    for principal in config.principals[: config.max_principals]:
        session = perform_login(
            principal, timeout=config.request_timeout_seconds
        )
        sessions_by_label[principal.label] = session
        log(
            f"[6D] login {principal.label} ({principal.role}): "
            + ("ok" if session.login_ok else f"FAILED — {session.note}")
        )

    logins_ok = sum(1 for s in sessions_by_label.values() if s.login_ok)

    findings: list[AuthFinding] = []

    try:
        findings.extend(
            run_authz_replay(
                sessions_by_label,
                config.protected_requests[: config.max_requests],
                timeout=config.request_timeout_seconds,
            )
        )
    except Exception as exc:  # non-fatal
        log(f"[6D] authz replay error: {exc}")

    try:
        findings.extend(
            analyze_tokens(
                [s for s in sessions_by_label.values() if s.login_ok]
            )
        )
    except Exception as exc:  # non-fatal
        log(f"[6D] token hygiene error: {exc}")

    for finding in findings:
        log(
            f"[6D][finding] {finding.severity} {finding.kind}: "
            f"{finding.detail}"
        )
    log(
        f"[6D] complete: {logins_ok}/{len(sessions_by_label)} logins, "
        f"{len(findings)} finding(s)."
    )

    return AuthWorkflowResult(
        target=config.target_url,
        sessions=tuple(
            s.fingerprint() for s in sessions_by_label.values()
        ),
        findings=tuple(findings),
        logins_ok=logins_ok,
        logins_failed=len(sessions_by_label) - logins_ok,
    )


__all__ = ["AuthWorkflowResult", "run_authenticated_workflow"]

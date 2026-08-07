"""Derive an automatic Nuclei/SQLMap config from the Phase 6 workflow chain.

The Phase 6 controlled chain (``persistence.phase6_chain_workflow``) does not
persist a ready-to-run candidate list. It records, per orchestration, a parent
execution whose ``targets[0]`` is the authorized target URL, plus child
executions grouped by ``metadata['orchestration_id']``. This module reads the
latest authorized orchestration parent and rebuilds the same inputs the chain
uses -- nuclei against the target URL, and one SQLMap candidate per GET query
parameter -- so the Saarthi OPS launcher runs "as per the workflow chain".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from saarthi_ai.automation.auto_validation import (
    AutoValidationConfig,
    SqlmapCandidate,
)
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import ExecutionRecord

DEFAULT_EVIDENCE_ROOT = Path("evidence/automatic-validation")
MAX_DERIVED_SQLMAP_CANDIDATES = 8
ORCHESTRATION_PARENT_ROLE = "orchestration_parent"


class ChainConfigError(RuntimeError):
    """Raised when no authorized chain target can be derived."""


@dataclass(frozen=True)
class ChainDerivedValidation:
    """A chain-derived config plus the provenance used to build it."""

    config: AutoValidationConfig
    orchestration_id: str | None
    source_execution_id: str
    assessment_name: str
    target_url: str
    allowed_hosts: tuple[str, ...]
    sqlmap_parameters: tuple[str, ...]


def _latest_orchestration_parent(
    executions: list[ExecutionRecord],
    orchestration_id: str | None,
) -> ExecutionRecord | None:
    """Return the newest orchestration-parent execution (list is DESC)."""

    for execution in executions:
        metadata = execution.metadata or {}

        if metadata.get("execution_role") != ORCHESTRATION_PARENT_ROLE:
            continue

        if (
            orchestration_id is not None
            and metadata.get("orchestration_id") != orchestration_id
        ):
            continue

        return execution

    return None


def _derive_sqlmap_candidates(
    target_url: str,
    max_candidates: int,
) -> tuple[tuple[SqlmapCandidate, ...], tuple[str, ...]]:
    """Build one GET candidate per unique query parameter of the target."""

    parameter_names = tuple(
        dict.fromkeys(
            name
            for name, _value in parse_qsl(
                urlsplit(target_url).query,
                keep_blank_values=True,
            )
            if name
        )
    )[:max_candidates]

    candidates = tuple(
        SqlmapCandidate(
            url=target_url,
            parameter=name,
            method="GET",
        )
        for name in parameter_names
    )

    return candidates, parameter_names


def build_auto_validation_config_from_chain(
    database: SaarthiDatabase,
    *,
    approved: bool,
    orchestration_id: str | None = None,
    confirmed_poc: bool = False,
    single_row_dump: bool = False,
    adaptive: bool = True,
    allow_waf_bypass: bool = False,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
    nuclei_templates_path: str | None = None,
    max_sqlmap_candidates: int = MAX_DERIVED_SQLMAP_CANDIDATES,
) -> ChainDerivedValidation:
    """Read the latest authorized orchestration and build a run config.

    Authorization flags come from the persisted parent execution: the run can
    only proceed with the permissions the operator already recorded for that
    engagement. SQLMap candidates are only derived when intrusive testing was
    authorized; otherwise a nuclei-only run is produced.
    """

    executions = database.list_executions(limit=1_000)

    if not executions:
        raise ChainConfigError(
            "No executions are stored; run an assessment workflow first."
        )

    parent = _latest_orchestration_parent(executions, orchestration_id)

    if parent is None:
        raise ChainConfigError(
            "No orchestration-parent execution was found in the chain. "
            "Run the assessment workflow before launching validation."
        )

    if not parent.targets:
        raise ChainConfigError(
            f"Execution {parent.execution_id} has no chain target URL."
        )

    target_url = str(parent.targets[0]).strip()
    parsed = urlsplit(target_url)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ChainConfigError(
            f"Chain target is not an absolute HTTP(S) URL: {target_url!r}"
        )

    metadata = parent.metadata or {}

    allowed = {parsed.hostname.strip().lower()}
    target_domain = metadata.get("target_domain")

    if isinstance(target_domain, str) and target_domain.strip():
        allowed.add(target_domain.strip().lower())

    allowed_hosts = tuple(sorted(allowed))

    intrusive_allowed = bool(parent.intrusive_testing_allowed)

    if intrusive_allowed:
        sqlmap_candidates, sqlmap_parameters = _derive_sqlmap_candidates(
            target_url,
            max_sqlmap_candidates,
        )
    else:
        sqlmap_candidates, sqlmap_parameters = (), ()

    raw_rate_limit = metadata.get("rate_limit_per_second")

    try:
        rate_limit = int(raw_rate_limit)
    except (TypeError, ValueError):
        rate_limit = 5

    rate_limit = max(1, min(rate_limit, 20))

    config = AutoValidationConfig(
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        authorized=bool(parent.authorization_confirmed),
        active_testing=bool(parent.active_testing_allowed),
        intrusive_testing=intrusive_allowed,
        approved=approved,
        sqlmap_candidates=sqlmap_candidates,
        evidence_root=evidence_root,
        nuclei_templates_path=nuclei_templates_path,
        nuclei_rate_limit=rate_limit,
        sqlmap_confirmed_poc=confirmed_poc and intrusive_allowed,
        sqlmap_poc_single_row_dump=(
            single_row_dump and confirmed_poc and intrusive_allowed
        ),
        adaptive=adaptive,
        # WAF bypass is an intrusive evasion technique: only when the
        # engagement authorized intrusive testing and the caller opted in.
        allow_waf_bypass=allow_waf_bypass and intrusive_allowed,
    )

    return ChainDerivedValidation(
        config=config,
        orchestration_id=(
            metadata.get("orchestration_id")
            if isinstance(metadata.get("orchestration_id"), str)
            else None
        ),
        source_execution_id=parent.execution_id,
        assessment_name=parent.assessment_name,
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        sqlmap_parameters=sqlmap_parameters,
    )

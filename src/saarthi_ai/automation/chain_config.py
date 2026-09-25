"""Derive an automatic Nuclei/SQLMap config from the Phase 6 workflow chain.

The Phase 6 controlled chain (``persistence.phase6_chain_workflow``) does not
persist a ready-to-run candidate list. It records, per orchestration, a parent
execution whose ``targets[0]`` is the authorized target URL, plus child
executions grouped by ``metadata['orchestration_id']``. This module reads the
latest authorized orchestration parent and rebuilds the same inputs the chain
uses -- nuclei against the target URL, SQLMap candidates from its GET query,
and eligible POST forms recorded by Phase 3D crawling -- so the Saarthi OPS
launcher runs "as per the workflow chain".
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from saarthi_ai.automation.auto_validation import (
    AutoValidationConfig,
    SqlmapCandidate,
)
from saarthi_ai.automation.fingerprint import detect_target_technologies
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import EvidenceType, ExecutionRecord

DEFAULT_EVIDENCE_ROOT = Path("evidence/automatic-validation")
MAX_DERIVED_SQLMAP_CANDIDATES = 8
ORCHESTRATION_PARENT_ROLE = "orchestration_parent"
ORCHESTRATION_CHILD_ROLE = "orchestration_child"
CRAWL_PHASE_CODE = "3D"
PROJECT_ROOT = Path(__file__).resolve().parents[3]
MAX_CRAWL_EVIDENCE_BYTES = 10 * 1024 * 1024
MAX_POST_FORM_PARAMETERS = 25

# Unattended POST checks must not submit forms that appear to authenticate,
# transfer value, upload content, or mutate/delete application state. Those
# surfaces remain available to an explicitly designed authenticated workflow.
BLOCKED_POST_TOKENS = frozenset(
    {
        "admin",
        "auth",
        "card",
        "checkout",
        "create",
        "csrf",
        "cvv",
        "delete",
        "destroy",
        "file",
        "login",
        "logout",
        "otp",
        "password",
        "payment",
        "purchase",
        "refund",
        "register",
        "remove",
        "reset",
        "secret",
        "signin",
        "signup",
        "token",
        "transfer",
        "update",
        "upload",
    }
)


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
    # Technologies detected on the in-scope target (Phase 3C httpx tech-detect),
    # used to focus nuclei on the matching templates. Empty when unknown.
    technologies: tuple[str, ...] = ()


def _latest_orchestration_parent(
    executions: list[ExecutionRecord],
    orchestration_id: str | None,
) -> ExecutionRecord | None:
    """Return the newest orchestration-parent execution (list is DESC)."""

    for execution in executions:
        metadata = execution.metadata or {}

        if metadata.get("execution_role") != ORCHESTRATION_PARENT_ROLE:
            continue

        if orchestration_id is not None and metadata.get("orchestration_id") != orchestration_id:
            continue

        return execution

    return None


def _derive_get_sqlmap_candidates(
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


def _tokenize(value: str) -> set[str]:
    """Return lowercase identifier/path tokens for conservative filtering."""

    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if token}


def _resolve_evidence_path(raw_path: str) -> Path | None:
    """Resolve an evidence path without accepting arbitrary directories."""

    path = Path(raw_path).expanduser()
    candidates = (
        (path,)
        if path.is_absolute()
        else (
            PROJECT_ROOT / path,
            Path.cwd() / path,
        )
    )

    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file():
            return resolved
    return None


def _read_verified_crawl_payload(
    raw_path: str,
    expected_sha256: str | None,
) -> dict[str, Any] | None:
    """Read one bounded, hash-verified crawl JSON object."""

    path = _resolve_evidence_path(raw_path)
    if path is None:
        return None

    try:
        if path.stat().st_size > MAX_CRAWL_EVIDENCE_BYTES:
            return None
        content = path.read_bytes()
    except OSError:
        return None

    if expected_sha256:
        digest = hashlib.sha256(content).hexdigest()
        if digest.lower() != expected_sha256.strip().lower():
            return None

    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    return payload if isinstance(payload, dict) else None


def _safe_post_form_candidates(
    payload: dict[str, Any],
    *,
    allowed_hosts: tuple[str, ...],
    max_candidates: int,
) -> tuple[SqlmapCandidate, ...]:
    """Convert eligible Phase 3D POST forms to bounded SQLMap candidates."""

    raw_forms = payload.get("forms")
    if not isinstance(raw_forms, list) or max_candidates <= 0:
        return ()

    allowed = {host.strip().lower().rstrip(".") for host in allowed_hosts}
    candidates: list[SqlmapCandidate] = []
    seen: set[tuple[str, str]] = set()

    for raw_form in raw_forms:
        if len(candidates) >= max_candidates:
            break
        if not isinstance(raw_form, dict):
            continue
        if str(raw_form.get("method", "")).strip().upper() != "POST":
            continue

        action_url = str(raw_form.get("action_url", "")).strip()
        parsed = urlsplit(action_url)
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if parsed.scheme.lower() not in {"http", "https"} or hostname not in allowed:
            continue
        if _tokenize(parsed.path) & BLOCKED_POST_TOKENS:
            continue

        raw_parameters = raw_form.get("parameters")
        if not isinstance(raw_parameters, list):
            continue

        parameter_names: list[str] = []
        for raw_parameter in raw_parameters[:MAX_POST_FORM_PARAMETERS]:
            if not isinstance(raw_parameter, dict):
                continue
            name = str(raw_parameter.get("name", "")).strip()
            if not name or len(name) > 200:
                continue
            parameter_names.append(name)

        parameter_names = list(dict.fromkeys(parameter_names))
        if not parameter_names:
            continue
        if any(_tokenize(name) & BLOCKED_POST_TOKENS for name in parameter_names):
            continue

        # Never replay values scraped from the application. Inert placeholders
        # keep generated requests deterministic and avoid retaining secrets.
        data = urlencode([(name, "1") for name in parameter_names])
        for name in parameter_names:
            if len(candidates) >= max_candidates:
                break
            identity = (action_url, name)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(
                SqlmapCandidate(
                    url=action_url,
                    parameter=name,
                    method="POST",
                    data=data,
                    content_type="application/x-www-form-urlencoded",
                )
            )

    return tuple(candidates)


def _derive_post_sqlmap_candidates(
    database: SaarthiDatabase,
    executions: list[ExecutionRecord],
    *,
    orchestration_id: str | None,
    allowed_hosts: tuple[str, ...],
    max_candidates: int,
) -> tuple[SqlmapCandidate, ...]:
    """Derive POST candidates only from this chain's Phase 3D evidence."""

    if not orchestration_id or max_candidates <= 0:
        return ()

    candidates: list[SqlmapCandidate] = []
    seen: set[tuple[str, str]] = set()
    for execution in executions:
        metadata = execution.metadata or {}
        if metadata.get("execution_role") != ORCHESTRATION_CHILD_ROLE:
            continue
        if metadata.get("orchestration_id") != orchestration_id:
            continue
        if metadata.get("phase_code") != CRAWL_PHASE_CODE:
            continue

        for evidence in database.list_evidence(
            execution.execution_id,
            evidence_type=EvidenceType.CRAWL_RESULT,
        ):
            payload = _read_verified_crawl_payload(
                evidence.path,
                evidence.sha256,
            )
            if payload is None:
                continue
            remaining = max_candidates - len(candidates)
            discovered = _safe_post_form_candidates(
                payload,
                allowed_hosts=allowed_hosts,
                # Previously-seen candidates may reappear in newer crawl
                # evidence. Read enough rows to fill the remaining unique
                # capacity after cross-evidence deduplication.
                max_candidates=remaining + len(seen),
            )
            for candidate in discovered:
                identity = (candidate.url, candidate.parameter)
                if identity in seen:
                    continue
                seen.add(identity)
                candidates.append(candidate)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                return tuple(candidates)

    return tuple(candidates)


def build_auto_validation_config_from_chain(
    database: SaarthiDatabase,
    *,
    approved: bool,
    orchestration_id: str | None = None,
    confirmed_poc: bool = False,
    single_row_dump: bool = False,
    adaptive: bool = True,
    allow_waf_bypass: bool = False,
    verify_findings: bool = True,
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
        raise ChainConfigError("No executions are stored; run an assessment workflow first.")

    parent = _latest_orchestration_parent(executions, orchestration_id)

    if parent is None:
        raise ChainConfigError(
            "No orchestration-parent execution was found in the chain. "
            "Run the assessment workflow before launching validation."
        )

    if not parent.targets:
        raise ChainConfigError(f"Execution {parent.execution_id} has no chain target URL.")

    target_url = str(parent.targets[0]).strip()
    parsed = urlsplit(target_url)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ChainConfigError(f"Chain target is not an absolute HTTP(S) URL: {target_url!r}")

    metadata = parent.metadata or {}

    allowed = {parsed.hostname.strip().lower()}
    target_domain = metadata.get("target_domain")

    if isinstance(target_domain, str) and target_domain.strip():
        allowed.add(target_domain.strip().lower())

    allowed_hosts = tuple(sorted(allowed))

    intrusive_allowed = bool(parent.intrusive_testing_allowed)

    if intrusive_allowed:
        get_candidates, get_parameters = _derive_get_sqlmap_candidates(
            target_url,
            max_sqlmap_candidates,
        )
        metadata_orchestration_id = metadata.get("orchestration_id")
        post_candidates = _derive_post_sqlmap_candidates(
            database,
            executions,
            orchestration_id=(
                metadata_orchestration_id if isinstance(metadata_orchestration_id, str) else None
            ),
            allowed_hosts=allowed_hosts,
            max_candidates=max(0, max_sqlmap_candidates - len(get_candidates)),
        )
        sqlmap_candidates = get_candidates + post_candidates
        sqlmap_parameters = get_parameters + tuple(
            candidate.parameter for candidate in post_candidates
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
        sqlmap_poc_single_row_dump=(single_row_dump and confirmed_poc and intrusive_allowed),
        adaptive=adaptive,
        # WAF bypass is an intrusive evasion technique: only when the
        # engagement authorized intrusive testing and the caller opted in.
        allow_waf_bypass=allow_waf_bypass and intrusive_allowed,
        verify_findings=verify_findings,
    )

    chain_orchestration_id = (
        metadata.get("orchestration_id")
        if isinstance(metadata.get("orchestration_id"), str)
        else None
    )
    technologies = detect_target_technologies(
        database,
        orchestration_id=chain_orchestration_id,
        allowed_hosts=allowed_hosts,
    )

    return ChainDerivedValidation(
        config=config,
        orchestration_id=chain_orchestration_id,
        source_execution_id=parent.execution_id,
        assessment_name=parent.assessment_name,
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        sqlmap_parameters=sqlmap_parameters,
        technologies=technologies,
    )

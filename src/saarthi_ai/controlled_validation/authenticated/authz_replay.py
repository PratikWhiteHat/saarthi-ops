"""Phase 6D cross-account authorization replay.

For each owner-tagged protected request, establish the owner's baseline
response, then replay the SAME request as every other principal (GET/HEAD
only). If another principal receives the owner's resource (2xx + identical
body), that is broken authorization — classified by role/tenant as object-level
(IDOR/BOLA), vertical privilege escalation, or tenant-isolation failure.
"""

from __future__ import annotations

import hashlib

import httpx

from saarthi_ai.config import tls_verify
from saarthi_ai.controlled_validation.authenticated.models import (
    AuthFinding,
    AuthSession,
    ProtectedRequest,
)

_USER_AGENT = "Saarthi-AI/0.4 authorized-vapt (6D authz replay)"
_MAX_BODY = 1_000_000

_ROLE_RANK = {
    "guest": 0,
    "anonymous": 0,
    "user": 1,
    "member": 1,
    "customer": 1,
    "staff": 2,
    "manager": 3,
    "admin": 4,
    "superadmin": 5,
    "root": 5,
}


def _rank(role: str | None) -> int:
    return _ROLE_RANK.get((role or "").strip().lower(), 1)


def classify_access(owner: AuthSession, other: AuthSession) -> tuple[str, str]:
    """Classify improper access by other→owner into (kind, severity)."""

    if (owner.tenant or None) != (other.tenant or None):
        return "tenant_isolation", "high"
    if _rank(other.role) < _rank(owner.role):
        return "vertical_privesc", "high"
    return "object_level_authz", "high"


def evaluate_access(
    owner: AuthSession,
    other: AuthSession,
    url: str,
    owner_status: int,
    owner_sha: str,
    other_status: int,
    other_sha: str,
) -> AuthFinding | None:
    """Pure decision: did ``other`` improperly obtain ``owner``'s resource?"""

    owner_ok = 200 <= owner_status < 300
    other_ok = 200 <= other_status < 300
    if not owner_ok or not other_ok:
        return None
    if other_sha != owner_sha:
        return None  # different content → not the same resource
    kind, severity = classify_access(owner, other)
    return AuthFinding(
        kind=kind,
        severity=severity,
        classification=kind,
        detail=(
            f"{other.label} ({other.role}/tenant={other.tenant}) received "
            f"{owner.label}'s resource — identical body, status "
            f"{other_status}."
        ),
        principal=other.label,
        victim=owner.label,
        url=url,
    )


def _session_client(session: AuthSession, timeout: float) -> httpx.Client:
    client = httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        verify=tls_verify(),
        headers={"User-Agent": _USER_AGENT, **session.headers},
    )
    for name, value in session.cookies.items():
        client.cookies.set(name, value)
    return client


def _issue(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    max_body: int = _MAX_BODY,
) -> tuple[int, str]:
    with client.stream(method, url) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) >= max_body:
                break
        digest = hashlib.sha256(bytes(body[:max_body])).hexdigest()
        return response.status_code, digest


def run_authz_replay(
    sessions_by_label: dict[str, AuthSession],
    protected_requests: tuple[ProtectedRequest, ...],
    *,
    timeout: float = 15.0,
) -> list[AuthFinding]:
    """Replay each owner-tagged request as every other principal."""

    findings: list[AuthFinding] = []
    clients = {
        label: _session_client(session, timeout)
        for label, session in sessions_by_label.items()
        if session.login_ok
    }
    try:
        for request in protected_requests:
            owner = sessions_by_label.get(request.owner)
            owner_client = clients.get(request.owner)
            if owner is None or owner_client is None:
                continue
            try:
                owner_status, owner_sha = _issue(
                    owner_client, request.method, request.url
                )
            except httpx.HTTPError:
                continue
            if not 200 <= owner_status < 300:
                continue  # no owner baseline → cannot judge cross-account
            for label, other in sessions_by_label.items():
                if label == request.owner or not other.login_ok:
                    continue
                client = clients.get(label)
                if client is None:
                    continue
                try:
                    other_status, other_sha = _issue(
                        client, request.method, request.url
                    )
                except httpx.HTTPError:
                    continue
                finding = evaluate_access(
                    owner,
                    other,
                    request.url,
                    owner_status,
                    owner_sha,
                    other_status,
                    other_sha,
                )
                if finding is not None:
                    findings.append(finding)
    finally:
        for client in clients.values():
            client.close()
    return findings


__all__ = [
    "classify_access",
    "evaluate_access",
    "run_authz_replay",
]

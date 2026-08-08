"""Phase 6D config + principal/session/finding models.

The operator supplies >=2 authorized accounts (roles/tenants) in an
``authenticated-sessions.json`` file. Each account is either auto-logged-in
(``LoginSpec``) or given pre-captured session material (cookies/headers) as a
fallback for apps auto-login can't handle (MFA/captcha).

SECURITY: passwords and captured session material live only in memory on the
runtime objects. Only ``AuthSession.fingerprint()`` (labels + SHA-256 hashes)
is ever persisted — raw secrets never leave this process.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_METHODS = frozenset({"GET", "HEAD"})


class AuthWorkflowError(RuntimeError):
    """Raised when a 6D config is invalid or unauthorized."""


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _validate_url(url: str, allowed_hosts: tuple[str, ...]) -> str:
    candidate = (url or "").strip()
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise AuthWorkflowError(
            f"Only HTTP and HTTPS URLs are supported: {url!r}"
        )
    if parsed.hostname is None:
        raise AuthWorkflowError(f"Invalid URL: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise AuthWorkflowError(
            "Credentials embedded in URLs are not allowed."
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        raise AuthWorkflowError("URL contains a control character.")
    allowed = {_normalize_host(h) for h in allowed_hosts if h.strip()}
    if _normalize_host(parsed.hostname) not in allowed:
        raise AuthWorkflowError(
            f"Host {parsed.hostname!r} is outside the allowed host list: "
            f"{sorted(allowed)}"
        )
    return candidate


# --------------------------------------------------------------------------
# Config models (from authenticated-sessions.json)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginSpec:
    """How to log a principal in to obtain a session."""

    url: str
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    csrf_from: str | None = None
    csrf_field: str | None = None
    success_status: int | None = None
    success_contains: str | None = None
    token_json_path: str | None = None
    token_header: str | None = None


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """One authorized account under test."""

    label: str
    role: str = "user"
    tenant: str | None = None
    login: LoginSpec | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    logout_url: str | None = None

    @property
    def has_login(self) -> bool:
        return self.login is not None

    @property
    def has_direct_session(self) -> bool:
        return bool(self.cookies or self.headers)


@dataclass(frozen=True)
class ProtectedRequest:
    """A resource request legitimately owned by ``owner`` (read-only)."""

    owner: str
    url: str
    method: str = "GET"


@dataclass(frozen=True)
class AuthWorkflowConfig:
    """Validated Phase 6D run configuration."""

    target_url: str
    allowed_hosts: tuple[str, ...]
    authorized: bool
    active_testing: bool
    principals: tuple[AuthenticatedPrincipal, ...]
    protected_requests: tuple[ProtectedRequest, ...] = ()
    request_timeout_seconds: int = 15
    max_principals: int = 6
    max_requests: int = 25


# --------------------------------------------------------------------------
# Runtime models (never fully persisted)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthSession:
    """A captured session for one principal. Redacted before storage."""

    label: str
    role: str
    tenant: str | None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    login_ok: bool = True
    note: str = ""

    def fingerprint(self) -> dict:
        """Persistable view: labels + hashes only, no secrets."""

        material = json.dumps(
            {
                "cookies": sorted(self.cookies),
                "headers": sorted(self.headers),
                "has_token": self.token is not None,
            },
            sort_keys=True,
        )
        return {
            "label": self.label,
            "role": self.role,
            "tenant": self.tenant,
            "login_ok": self.login_ok,
            "session_sha256": hashlib.sha256(
                material.encode("utf-8")
            ).hexdigest()[:32],
            "note": self.note,
        }


@dataclass(frozen=True)
class AuthFinding:
    """One authenticated-workflow finding (safe to persist)."""

    kind: str
    severity: str
    classification: str
    detail: str
    principal: str | None = None
    victim: str | None = None
    url: str | None = None


# --------------------------------------------------------------------------
# Loader + validation
# --------------------------------------------------------------------------


def _login_from_dict(data: dict) -> LoginSpec:
    return LoginSpec(
        url=str(data["url"]),
        method=str(data.get("method", "POST")).upper(),
        fields={str(k): str(v) for k, v in (data.get("fields") or {}).items()},
        csrf_from=data.get("csrf_from"),
        csrf_field=data.get("csrf_field"),
        success_status=data.get("success", {}).get("status"),
        success_contains=data.get("success", {}).get("contains"),
        token_json_path=data.get("token_json_path"),
        token_header=data.get("token_header"),
    )


def _principal_from_dict(data: dict) -> AuthenticatedPrincipal:
    login = data.get("login")
    return AuthenticatedPrincipal(
        label=str(data["label"]),
        role=str(data.get("role", "user")),
        tenant=data.get("tenant"),
        login=_login_from_dict(login) if login else None,
        cookies={
            str(k): str(v) for k, v in (data.get("cookies") or {}).items()
        },
        headers={
            str(k): str(v) for k, v in (data.get("headers") or {}).items()
        },
        logout_url=data.get("logout_url"),
    )


def _request_from_dict(data: dict) -> ProtectedRequest:
    return ProtectedRequest(
        owner=str(data["owner"]),
        url=str(data["url"]),
        method=str(data.get("method", "GET")).upper(),
    )


def build_auth_workflow_config(raw: dict) -> AuthWorkflowConfig:
    """Build and validate an AuthWorkflowConfig from a raw dict."""

    allowed_hosts = tuple(str(h) for h in (raw.get("allowed_hosts") or ()))
    principals = tuple(
        _principal_from_dict(p) for p in (raw.get("principals") or ())
    )
    requests = tuple(
        _request_from_dict(r) for r in (raw.get("protected_requests") or ())
    )
    config = AuthWorkflowConfig(
        target_url=str(raw.get("target_url", "")),
        allowed_hosts=allowed_hosts,
        authorized=bool(raw.get("authorized", False)),
        active_testing=bool(raw.get("active_testing", False)),
        principals=principals,
        protected_requests=requests,
        request_timeout_seconds=int(raw.get("request_timeout_seconds", 15)),
    )
    _validate_config(config)
    return config


def load_auth_workflow_config(path: str | Path) -> AuthWorkflowConfig:
    """Load + validate an authenticated-sessions.json file."""

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuthWorkflowError(f"Cannot read sessions config: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AuthWorkflowError(f"Invalid sessions JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise AuthWorkflowError("Sessions config must be a JSON object.")
    return build_auth_workflow_config(raw)


def _validate_config(config: AuthWorkflowConfig) -> None:
    if not config.authorized:
        raise AuthWorkflowError("Written authorization must be confirmed.")
    if not config.active_testing:
        raise AuthWorkflowError("Active-testing permission must be confirmed.")
    if not config.allowed_hosts:
        raise AuthWorkflowError(
            "At least one exact allowed hostname is required."
        )
    _validate_url(config.target_url, config.allowed_hosts)

    if not 2 <= len(config.principals) <= config.max_principals:
        raise AuthWorkflowError(
            f"Provide between 2 and {config.max_principals} principals "
            "(cross-account testing needs at least two)."
        )

    labels: set[str] = set()
    for principal in config.principals:
        if not principal.label or principal.label in labels:
            raise AuthWorkflowError(
                f"Principal labels must be unique/non-empty: "
                f"{principal.label!r}"
            )
        labels.add(principal.label)
        if not principal.has_login and not principal.has_direct_session:
            raise AuthWorkflowError(
                f"Principal {principal.label!r} needs a login spec or "
                "direct cookies/headers."
            )
        if principal.login is not None:
            _validate_url(principal.login.url, config.allowed_hosts)
            if principal.login.csrf_from:
                _validate_url(principal.login.csrf_from, config.allowed_hosts)
        if principal.logout_url:
            _validate_url(principal.logout_url, config.allowed_hosts)

    if len(config.protected_requests) > config.max_requests:
        raise AuthWorkflowError(
            f"Too many protected_requests (max {config.max_requests})."
        )
    for request in config.protected_requests:
        if request.method not in ALLOWED_METHODS:
            raise AuthWorkflowError(
                f"protected_requests are read-only; {request.method!r} is "
                f"not allowed (use one of {sorted(ALLOWED_METHODS)})."
            )
        if request.owner not in labels:
            raise AuthWorkflowError(
                f"protected_request owner {request.owner!r} is not a known "
                "principal label."
            )
        _validate_url(request.url, config.allowed_hosts)


__all__ = [
    "ALLOWED_METHODS",
    "AuthFinding",
    "AuthSession",
    "AuthWorkflowConfig",
    "AuthWorkflowError",
    "AuthenticatedPrincipal",
    "LoginSpec",
    "ProtectedRequest",
    "build_auth_workflow_config",
    "load_auth_workflow_config",
]

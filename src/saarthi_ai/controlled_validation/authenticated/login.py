"""Phase 6D login issuer — acquire a session per principal.

Unlike the 6C collector (which forbids credential headers), 6D deliberately
sends operator-supplied credentials/session material to the authorized target
to obtain authenticated sessions. All requests stay within the caller's scope
(the engine validates URLs against allowed_hosts before calling here).
"""

from __future__ import annotations

import json
import re

import httpx

from saarthi_ai.config import tls_verify
from saarthi_ai.controlled_validation.authenticated.models import (
    AuthenticatedPrincipal,
    AuthSession,
    LoginSpec,
)

_USER_AGENT = "Saarthi-AI/0.4 authorized-vapt (6D authenticated workflow)"
_MAX_BODY = 1_000_000


def _client(timeout: float) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        trust_env=False,
        verify=tls_verify(),
        headers={"User-Agent": _USER_AGENT},
    )


def _extract_csrf(html: str, field: str) -> str | None:
    """Pull a hidden CSRF input value out of a login page."""

    name = re.escape(field)
    patterns = (
        rf'name=["\']{name}["\'][^>]*value=["\']([^"\']*)["\']',
        rf'value=["\']([^"\']*)["\'][^>]*name=["\']{name}["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _json_path(text: str, dotted: str) -> str | None:
    try:
        node = json.loads(text)
    except (ValueError, TypeError):
        return None
    for key in dotted.split("."):
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return str(node) if node is not None else None


def _login_succeeded(
    response: httpx.Response,
    spec: LoginSpec,
    cookies: dict[str, str],
    token: str | None,
) -> bool:
    if spec.success_status is not None:
        return response.status_code == spec.success_status
    if spec.success_contains:
        return spec.success_contains in response.text[:_MAX_BODY]
    # Default heuristic: got a session cookie or token, and not an error page.
    return (bool(cookies) or bool(token)) and response.status_code < 400


def perform_login(
    principal: AuthenticatedPrincipal,
    *,
    timeout: float = 15.0,
) -> AuthSession:
    """Log a principal in (or use its direct session) and return an AuthSession.

    Never raises — a failed login yields an AuthSession with login_ok=False so
    the engine can skip that principal and keep going.
    """

    if not principal.has_login and principal.has_direct_session:
        return AuthSession(
            label=principal.label,
            role=principal.role,
            tenant=principal.tenant,
            cookies=dict(principal.cookies),
            headers=dict(principal.headers),
            login_ok=True,
            note="direct session material (no login performed)",
        )

    spec = principal.login
    if spec is None:  # defensive; config validation prevents this
        return AuthSession(
            label=principal.label,
            role=principal.role,
            tenant=principal.tenant,
            login_ok=False,
            note="no login spec and no direct session",
        )

    try:
        with _client(timeout) as client:
            data = dict(spec.fields)
            if spec.csrf_from and spec.csrf_field:
                try:
                    page = client.get(spec.csrf_from)
                    token = _extract_csrf(page.text[:_MAX_BODY], spec.csrf_field)
                    if token:
                        data[spec.csrf_field] = token
                except httpx.HTTPError:
                    pass

            response = client.request(spec.method, spec.url, data=data)

            cookies = dict(client.cookies.items())
            token = None
            if spec.token_header:
                token = response.headers.get(spec.token_header)
            elif spec.token_json_path:
                token = _json_path(response.text[:_MAX_BODY], spec.token_json_path)

            ok = _login_succeeded(response, spec, cookies, token)
            headers: dict[str, str] = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            return AuthSession(
                label=principal.label,
                role=principal.role,
                tenant=principal.tenant,
                cookies=cookies,
                headers=headers,
                token=token,
                login_ok=ok,
                note=(
                    "login ok"
                    if ok
                    else "login did not meet success criteria"
                ),
            )
    except httpx.HTTPError as exc:
        return AuthSession(
            label=principal.label,
            role=principal.role,
            tenant=principal.tenant,
            login_ok=False,
            note=f"login request failed: {exc}",
        )


__all__ = ["perform_login"]

"""Phase 6D session/token hygiene — offline JWT analysis of captured sessions.

Decodes JWTs found in a principal's session (bearer header or a JWT-shaped
cookie) WITHOUT verifying the signature (we only read header/claims) and flags
hygiene issues: unsigned (alg=none), missing/expired expiry, and sensitive
data carried in claims. Pure/offline — no network.
"""

from __future__ import annotations

import base64
import binascii
import json
import time

from saarthi_ai.controlled_validation.authenticated.models import (
    AuthFinding,
    AuthSession,
)

_SENSITIVE_CLAIMS = frozenset(
    {
        "password",
        "pwd",
        "passwd",
        "secret",
        "ssn",
        "credit_card",
        "creditcard",
        "card",
        "cvv",
        "api_key",
        "apikey",
    }
)
_JWT_RE_SEGMENTS = 3


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Return (header, payload) for a JWT, or None if not a decodable JWT."""

    parts = token.split(".")
    if len(parts) != _JWT_RE_SEGMENTS:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _candidate_tokens(session: AuthSession) -> list[str]:
    tokens: list[str] = []
    if session.token:
        tokens.append(session.token)
    for value in session.headers.values():
        stripped = value[7:] if value.lower().startswith("bearer ") else value
        if stripped.count(".") == 2:
            tokens.append(stripped)
    for value in session.cookies.values():
        if value.count(".") == 2:
            tokens.append(value)
    # de-dupe, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for tok in tokens:
        if tok not in seen:
            seen.add(tok)
            unique.append(tok)
    return unique


def analyze_tokens(sessions: list[AuthSession]) -> list[AuthFinding]:
    """Flag JWT hygiene issues across the captured sessions."""

    findings: list[AuthFinding] = []
    now = time.time()
    for session in sessions:
        if not session.login_ok:
            continue
        for token in _candidate_tokens(session):
            decoded = decode_jwt(token)
            if decoded is None:
                continue
            header, payload = decoded
            alg = str(header.get("alg", "")).lower()

            if alg in {"none", ""}:
                findings.append(
                    AuthFinding(
                        kind="jwt_alg_none",
                        severity="high",
                        classification="jwt_alg_none",
                        detail="JWT is unsigned (alg=none) — forgeable.",
                        principal=session.label,
                    )
                )

            if "exp" not in payload:
                findings.append(
                    AuthFinding(
                        kind="jwt_no_expiry",
                        severity="medium",
                        classification="jwt_no_expiry",
                        detail="JWT has no exp claim — token never expires.",
                        principal=session.label,
                    )
                )
            else:
                try:
                    if float(payload["exp"]) < now:
                        findings.append(
                            AuthFinding(
                                kind="jwt_expired_accepted",
                                severity="low",
                                classification="jwt_expired",
                                detail="Session presented an expired JWT.",
                                principal=session.label,
                            )
                        )
                except (TypeError, ValueError):
                    pass

            sensitive = sorted(
                key
                for key in payload
                if str(key).lower() in _SENSITIVE_CLAIMS
            )
            if sensitive:
                findings.append(
                    AuthFinding(
                        kind="jwt_sensitive_claims",
                        severity="medium",
                        classification="jwt_sensitive_claims",
                        detail=(
                            "JWT carries sensitive claims: "
                            + ", ".join(sensitive)
                        ),
                        principal=session.label,
                    )
                )
    return findings


__all__ = ["analyze_tokens", "decode_jwt"]

"""Non-executing, detection-only SQLmap preview for Phase 6C.1."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from saarthi_ai.execution.tool_runner import SQLMAP_PROFILE

MAX_SQLMAP_TIMEOUT_SECONDS = 10
MAX_POST_PARAMETERS = 50
_PARAMETER_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,128}$")

PROHIBITED_SQLMAP_CAPABILITIES = (
    "database_enumeration",
    "data_dumping",
    "password_hash_extraction",
    "sql_shell",
    "os_shell",
    "file_read",
    "file_write",
    "tamper_scripts",
    "crawling",
    "form_discovery",
)


class SqlmapPreviewError(ValueError):
    """Raised when a SQLmap preview proposal fails closed."""


class SqlmapMethod(StrEnum):
    GET = "GET"
    POST = "POST"


class SqlmapPostContentType(StrEnum):
    FORM = "application/x-www-form-urlencoded"
    JSON = "application/json"


@dataclass(frozen=True)
class SqlmapPreviewRequest:
    """Approved SQLi candidate metadata; no POST values are accepted."""

    target_url: str
    parameter_name: str
    method: SqlmapMethod
    authorized: bool
    active_testing: bool
    intrusive_testing: bool
    approval_granted: bool
    post_parameter_names: tuple[str, ...] = ()
    post_content_type: SqlmapPostContentType | None = None
    timeout_seconds: int = 5
    dry_run: bool = True


@dataclass(frozen=True)
class SqlmapInvocationPreview:
    """Redacted SQLmap policy preview that cannot be executed directly."""

    tool_name: str
    method: SqlmapMethod
    target_display_url: str
    target_url_sha256: str
    parameter_name: str
    post_parameter_names: tuple[str, ...]
    post_content_type: SqlmapPostContentType | None
    redacted_arguments: tuple[str, ...]
    timeout_seconds: int
    level: int
    risk: int
    threads: int
    retries: int
    techniques: str
    prohibited_capabilities: tuple[str, ...]
    request_values_stored: bool = False
    executable_arguments_built: bool = False
    executed: bool = False
    network_activity: bool = False
    subprocess_started: bool = False


def _validated_parameter_name(value: str) -> str:
    candidate = value.strip()
    if _PARAMETER_NAME.fullmatch(candidate) is None:
        raise SqlmapPreviewError(
            "SQLmap parameter names must use a bounded safe identifier."
        )
    return candidate


def _redacted_target_url(
    target_url: str,
) -> tuple[str, tuple[str, ...]]:
    candidate = target_url.strip()
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise SqlmapPreviewError(
            "SQLmap requires a credential-free absolute HTTP(S) target."
        )
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in candidate
    ):
        raise SqlmapPreviewError(
            "SQLmap target contains a prohibited control character."
        )

    query_items = parse_qsl(
        parsed.query,
        keep_blank_values=True,
        strict_parsing=False,
    )
    names = tuple(name for name, _value in query_items)
    redacted_query = urlencode(
        [(name, "<redacted>") for name in names]
    )
    display = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            redacted_query,
            "",
        )
    )
    return display, names


def _redacted_post_data(
    names: tuple[str, ...],
    content_type: SqlmapPostContentType,
) -> str:
    if content_type is SqlmapPostContentType.JSON:
        return json.dumps(
            {name: "<redacted>" for name in names},
            separators=(",", ":"),
            sort_keys=True,
        )
    return urlencode([(name, "<redacted>") for name in names])


def build_sqlmap_invocation_preview(
    request: SqlmapPreviewRequest,
) -> SqlmapInvocationPreview:
    """Build a redacted detection-only preview without running SQLmap."""

    if request.dry_run is not True:
        raise SqlmapPreviewError(
            "SQLmap execution is disabled; a dry-run preview is required."
        )
    if request.authorized is not True:
        raise SqlmapPreviewError(
            "SQLmap target authorization must be confirmed."
        )
    if request.active_testing is not True:
        raise SqlmapPreviewError(
            "SQLmap requires active-testing permission."
        )
    if request.intrusive_testing is not True:
        raise SqlmapPreviewError(
            "SQLmap requires intrusive-testing permission."
        )
    if request.approval_granted is not True:
        raise SqlmapPreviewError(
            "Explicit SQLmap preview approval is required."
        )
    if not 1 <= request.timeout_seconds <= MAX_SQLMAP_TIMEOUT_SECONDS:
        raise SqlmapPreviewError(
            "SQLmap timeout must be between 1 and 10 seconds."
        )

    parameter_name = _validated_parameter_name(
        request.parameter_name
    )
    target_display_url, query_parameter_names = (
        _redacted_target_url(request.target_url)
    )
    arguments: list[str] = [
        "-u",
        target_display_url,
        "-p",
        parameter_name,
    ]

    if request.method is SqlmapMethod.GET:
        if parameter_name not in query_parameter_names:
            raise SqlmapPreviewError(
                "The approved GET parameter is absent from the target URL."
            )
        if request.post_parameter_names:
            raise SqlmapPreviewError(
                "GET previews cannot include POST parameter metadata."
            )
        if request.post_content_type is not None:
            raise SqlmapPreviewError(
                "GET previews cannot declare a POST content type."
            )
        post_parameter_names: tuple[str, ...] = ()
        post_content_type = None
    else:
        if request.post_content_type is None:
            raise SqlmapPreviewError(
                "POST previews require an approved content type."
            )
        if not 1 <= len(request.post_parameter_names) <= MAX_POST_PARAMETERS:
            raise SqlmapPreviewError(
                "POST previews require between 1 and 50 parameter names."
            )
        post_parameter_names = tuple(
            _validated_parameter_name(name)
            for name in request.post_parameter_names
        )
        if len(set(post_parameter_names)) != len(
            post_parameter_names
        ):
            raise SqlmapPreviewError(
                "POST parameter names must be unique."
            )
        if parameter_name not in post_parameter_names:
            raise SqlmapPreviewError(
                "The approved SQLi parameter is absent from POST metadata."
            )
        post_content_type = request.post_content_type
        arguments.extend(
            (
                "--method=POST",
                "--data="
                + _redacted_post_data(
                    post_parameter_names,
                    post_content_type,
                ),
            )
        )

    arguments.extend(
        (
            "--batch",
            "--level=1",
            "--risk=1",
            "--threads=1",
            f"--timeout={request.timeout_seconds}",
            "--retries=0",
            "--technique=BE",
            "--disable-coloring",
        )
    )

    return SqlmapInvocationPreview(
        tool_name=SQLMAP_PROFILE.name,
        method=request.method,
        target_display_url=target_display_url,
        target_url_sha256=hashlib.sha256(
            request.target_url.encode("utf-8")
        ).hexdigest(),
        parameter_name=parameter_name,
        post_parameter_names=post_parameter_names,
        post_content_type=post_content_type,
        redacted_arguments=tuple(arguments),
        timeout_seconds=request.timeout_seconds,
        level=1,
        risk=1,
        threads=1,
        retries=0,
        techniques="BE",
        prohibited_capabilities=PROHIBITED_SQLMAP_CAPABILITIES,
    )

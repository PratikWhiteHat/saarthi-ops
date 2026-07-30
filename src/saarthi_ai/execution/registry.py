from __future__ import annotations

from saarthi_ai.assessments.schemas import AssetType
from saarthi_ai.execution.models import ToolDefinition

WEB_AND_API = [AssetType.WEB, AssetType.API]


TOOL_REGISTRY: dict[str, ToolDefinition] = {
    "httpx": ToolDefinition(
        name="httpx",
        description="Collect HTTP metadata from authorized targets.",
        supported_asset_types=WEB_AND_API,
        timeout_seconds=120,
    ),
    "tls-inspector": ToolDefinition(
        name="tls-inspector",
        description="Inspect TLS configuration and certificate metadata.",
        supported_asset_types=WEB_AND_API,
        timeout_seconds=120,
    ),
    "custom-http-client": ToolDefinition(
        name="custom-http-client",
        description="Send controlled HTTP requests and preserve evidence.",
        supported_asset_types=WEB_AND_API,
        timeout_seconds=120,
    ),
    "crawler": ToolDefinition(
        name="crawler",
        description="Discover reachable authorized web application paths.",
        supported_asset_types=[AssetType.WEB],
        timeout_seconds=300,
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        description="Perform controlled web content discovery.",
        supported_asset_types=[AssetType.WEB],
        timeout_seconds=300,
    ),
    "nuclei": ToolDefinition(
        name="nuclei",
        description="Run selected validation templates against scope.",
        supported_asset_types=WEB_AND_API,
        timeout_seconds=600,
    ),
    "browser-automation": ToolDefinition(
        name="browser-automation",
        description="Perform controlled browser workflow validation.",
        supported_asset_types=[AssetType.WEB],
        timeout_seconds=300,
    ),
    "burp-suite": ToolDefinition(
        name="burp-suite",
        description="Integrate approved request and response workflows.",
        supported_asset_types=WEB_AND_API,
        timeout_seconds=600,
    ),
    "openapi-parser": ToolDefinition(
        name="openapi-parser",
        description="Parse supplied OpenAPI specifications.",
        supported_asset_types=[AssetType.API],
        timeout_seconds=60,
    ),
    "postman-parser": ToolDefinition(
        name="postman-parser",
        description="Parse supplied Postman collections.",
        supported_asset_types=[AssetType.API],
        timeout_seconds=60,
    ),
    "schema-fuzzer": ToolDefinition(
        name="schema-fuzzer",
        description="Generate controlled API schema test variations.",
        supported_asset_types=[AssetType.API],
        timeout_seconds=300,
    ),
}

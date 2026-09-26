"""Notifications — Slack, Discord, and Telegram webhooks.

The :class:`Notifier` uses an injected async ``http_request`` (the engine's
seam), so it is fully testable offline. Channels with no configured
webhook/token are skipped.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

HttpRequest = Callable[..., Awaitable[Any]]


class Notifier:
    """Fan a message out to the configured chat channels."""

    def __init__(
        self,
        http_request: HttpRequest,
        *,
        slack_webhook: str = "",
        discord_webhook: str = "",
        telegram_token: str = "",
        telegram_chat: str = "",
    ) -> None:
        self._http = http_request
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.telegram_token = telegram_token
        self.telegram_chat = telegram_chat

    @classmethod
    def from_settings(cls, settings: Any, http_request: HttpRequest) -> Notifier:
        return cls(
            http_request,
            slack_webhook=getattr(settings, "slack_webhook", ""),
            discord_webhook=getattr(settings, "discord_webhook", ""),
            telegram_token=getattr(settings, "telegram_token", ""),
            telegram_chat=getattr(settings, "telegram_chat", ""),
        )

    def configured_channels(self) -> list[str]:
        channels = []
        if self.slack_webhook:
            channels.append("slack")
        if self.discord_webhook:
            channels.append("discord")
        if self.telegram_token and self.telegram_chat:
            channels.append("telegram")
        return channels

    async def send(self, message: str, *, channels: list[str] | None = None) -> dict[str, bool]:
        targets = channels or self.configured_channels()
        results: dict[str, bool] = {}
        for channel in targets:
            handler = getattr(self, f"_send_{channel}", None)
            if handler is None:
                results[channel] = False
                continue
            try:
                await handler(message)
                results[channel] = True
            except Exception:
                results[channel] = False
        return results

    async def _post_json(self, url: str, payload: dict) -> None:
        await self._http(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload),
        )

    async def _send_slack(self, message: str) -> None:
        if not self.slack_webhook:
            raise ValueError("slack not configured")
        await self._post_json(self.slack_webhook, {"text": message})

    async def _send_discord(self, message: str) -> None:
        if not self.discord_webhook:
            raise ValueError("discord not configured")
        await self._post_json(self.discord_webhook, {"content": message})

    async def _send_telegram(self, message: str) -> None:
        if not (self.telegram_token and self.telegram_chat):
            raise ValueError("telegram not configured")
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        await self._post_json(url, {"chat_id": self.telegram_chat, "text": message})

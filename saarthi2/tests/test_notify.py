"""Notifications fan out to configured channels via the http seam."""

from __future__ import annotations

import asyncio
import json

from saarthi2.notify import Notifier


class _FakeHttp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def __call__(self, method, url, *, headers=None, body=None, timeout=30):
        self.calls.append((method, url, json.loads(body) if body else {}))
        return type("R", (), {"status_code": 200, "text": "ok"})()


def test_sends_to_configured_channels() -> None:
    http = _FakeHttp()
    n = Notifier(
        http,
        slack_webhook="https://hooks.slack/x",
        discord_webhook="https://discord/y",
        telegram_token="TOK",
        telegram_chat="123",
    )
    assert set(n.configured_channels()) == {"slack", "discord", "telegram"}
    results = asyncio.run(n.send("hello"))
    assert results == {"slack": True, "discord": True, "telegram": True}
    urls = [c[1] for c in http.calls]
    assert "https://hooks.slack/x" in urls
    assert any("telegram.org" in u for u in urls)
    slack_payload = next(c[2] for c in http.calls if c[1] == "https://hooks.slack/x")
    assert slack_payload["text"] == "hello"


def test_skips_unconfigured_channels() -> None:
    http = _FakeHttp()
    n = Notifier(http, slack_webhook="https://hooks.slack/x")
    assert n.configured_channels() == ["slack"]
    results = asyncio.run(n.send("hi"))
    assert results == {"slack": True}
    assert len(http.calls) == 1


def test_explicit_channel_selection() -> None:
    http = _FakeHttp()
    n = Notifier(http, slack_webhook="s", discord_webhook="d")
    results = asyncio.run(n.send("hi", channels=["discord"]))
    assert results == {"discord": True}
    assert len(http.calls) == 1

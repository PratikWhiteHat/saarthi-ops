"""OllamaChat retries transient failures so one blip doesn't abort a hunt."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from saarthi2.ai.ollama import OllamaChat, OllamaUnavailableError


def _chunk(text: str = "", tool_calls=None):
    return SimpleNamespace(
        message=SimpleNamespace(content=text, thinking="", tool_calls=tool_calls or [])
    )


def _client_only(fake) -> OllamaChat:
    chat = OllamaChat.__new__(OllamaChat)  # bypass the real AsyncClient in __init__
    chat.model = "m"
    chat.num_ctx = 8192
    chat._client = fake
    return chat


def test_stream_retries_then_recovers() -> None:
    class Fake:
        calls = 0

        async def chat(self, **_kw):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("cold load")

            async def gen():
                for token in ("Hel", "lo"):
                    yield _chunk(token)

            return gen()

    chat = _client_only(Fake())

    async def run():
        tokens, message = "", None
        async for ev in chat.stream([{"role": "user", "content": "x"}]):
            if ev["type"] == "token":
                tokens += ev["content"]
            elif ev["type"] == "message":
                message = ev
        return tokens, message

    tokens, message = asyncio.run(run())
    assert tokens == "Hello"
    assert message["content"] == "Hello"
    assert chat._client.calls == 2  # failed once, retried, succeeded


def test_stream_gives_up_after_exhausting_retries() -> None:
    class Fake:
        async def chat(self, **_kw):
            raise ConnectionError("ollama down")

    chat = _client_only(Fake())

    async def run():
        async for _ in chat.stream([{"role": "user", "content": "x"}]):
            pass

    try:
        asyncio.run(run())
    except OllamaUnavailableError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected OllamaUnavailableError")


def test_stream_does_not_retry_after_tokens_emitted() -> None:
    # A failure mid-stream (after tokens shown) must surface, not replay the answer.
    class Fake:
        calls = 0

        async def chat(self, **_kw):
            self.calls += 1

            async def gen():
                yield _chunk("partial")
                raise ConnectionError("dropped mid-stream")

            return gen()

    chat = _client_only(Fake())

    async def run():
        tokens = ""
        async for ev in chat.stream([{"role": "user", "content": "x"}]):
            if ev["type"] == "token":
                tokens += ev["content"]
        return tokens

    try:
        asyncio.run(run())
    except OllamaUnavailableError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected OllamaUnavailableError")
    assert chat._client.calls == 1  # did NOT retry once a token was already shown


def test_chat_retries_then_recovers() -> None:
    class Fake:
        calls = 0

        async def chat(self, **_kw):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("blip")
            return _chunk("final answer")

    chat = _client_only(Fake())
    result = asyncio.run(chat.chat([{"role": "user", "content": "x"}]))
    assert result["content"] == "final answer"
    assert chat._client.calls == 2

"""Thin async wrapper over the local Ollama chat API with tool-calling."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

# Local Ollama can throw transient errors — a cold GPU load right after a model
# switch, a momentary reload, a brief socket hiccup. Without a retry, one such blip
# mid-hunt aborts the whole agent run and discards the recon it already did. Retry a
# few times with a short backoff before giving up.
_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = 0.8


class OllamaUnavailableError(RuntimeError):
    """Raised when the local Ollama service cannot be reached."""


def _normalize(message: Any) -> dict:
    """Normalize an Ollama response message into a plain dict.

    Returns ``{"content": str, "tool_calls": [{"name","arguments"}], "raw": ...}``.
    """

    content = getattr(message, "content", "") or ""
    # Thinking models (e.g. qwen3.5) split reasoning into a separate ``thinking``
    # field. If the model produced only reasoning and no final content, surface the
    # reasoning rather than returning an empty answer.
    if not content.strip():
        content = getattr(message, "thinking", "") or ""
    raw_calls = getattr(message, "tool_calls", None) or []
    tool_calls: list[dict] = []
    for call in raw_calls:
        function = getattr(call, "function", None)
        if function is None:
            continue
        tool_calls.append(
            {
                "name": getattr(function, "name", ""),
                "arguments": dict(getattr(function, "arguments", {}) or {}),
            }
        )
    return {"content": content, "tool_calls": tool_calls, "raw": message}


class OllamaChat:
    """Async chat client bound to one local model."""

    def __init__(self, host: str, model: str, num_ctx: int = 16384) -> None:
        from ollama import AsyncClient

        self.model = model
        # Ollama defaults to a small context (~2-4k). Our prompts are large — a
        # skill-grounded system prompt plus recon/scan tool outputs that ACCUMULATE
        # across a multi-step hunt. At 8192 the context filled up mid-run and Ollama's
        # context-shift crashed the model runner (HTTP 500), aborting the hunt. Qwen2.5
        # trains at 32768, so 16384 gives ample headroom for several tool rounds + the
        # 2048-token reply while staying light on memory (~1 GB extra KV cache).
        self.num_ctx = num_ctx
        self._client = AsyncClient(host=host)

    def _options(self, num_predict: int) -> dict:
        """Generation options tuned for a small local model doing a long hunt.

        ``repeat_penalty``/``repeat_last_n`` are the important part: at low
        temperature these models can fall into a decoding loop and spend the whole
        budget repeating one phrase (e.g. ``-tags saml-... -tags saml-...``), which
        wrecks the report. A firm repeat penalty over a wide window breaks that, and
        a slightly higher temperature keeps output from collapsing to one token.
        """

        return {
            "temperature": 0.3,
            "num_predict": num_predict,
            "num_ctx": self.num_ctx,
            "repeat_penalty": 1.3,
            "repeat_last_n": 256,
        }

    async def chat(
        self,
        messages: list[dict],
        *,
        tools: list[dict] | None = None,
        num_predict: int = 2048,
    ) -> dict:
        from ollama import ResponseError

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                response = await self._client.chat(
                    model=self.model,
                    messages=messages,
                    tools=tools,
                    # Disable the "thinking" channel: on reasoning models (qwen3.5)
                    # the <think> block would otherwise consume the entire
                    # num_predict budget and truncate before any final content.
                    think=False,
                    options=self._options(num_predict),
                )
                return _normalize(response.message)
            except (ConnectionError, OSError, ResponseError) as exc:
                if attempt < _MAX_ATTEMPTS:
                    await asyncio.sleep(_BACKOFF_SECONDS * attempt)
                    continue
                raise OllamaUnavailableError(
                    "Ollama request failed. Confirm the service is running and the "
                    "model is installed."
                ) from exc

    async def stream(
        self,
        messages: list[dict],
        *,
        tools: list[dict] | None = None,
        num_predict: int = 2048,
    ) -> AsyncIterator[dict]:
        """Stream one model turn as incremental events.

        Yields ``{"type":"token","content": <delta>}`` for each text chunk as the
        model produces it (this is what powers the live UI), then a single terminal
        ``{"type":"message", "content", "tool_calls", "raw"}`` with the fully
        assembled turn — tool calls are accumulated across chunks so the agent loop
        can act on them exactly as it does for a non-streamed reply.
        """

        from ollama import ResponseError

        # Retry a failed turn ONLY while no token has been emitted yet (the common
        # cold-load / transient-error case fails at request start). Once tokens have
        # streamed to the caller, a later failure is surfaced rather than retried, so
        # the UI never sees a partial answer replay.
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            content_parts: list[str] = []
            thinking_parts: list[str] = []
            tool_calls: list[dict] = []
            last: Any = None
            yielded = False
            try:
                stream = await self._client.chat(
                    model=self.model,
                    messages=messages,
                    tools=tools,
                    think=False,
                    stream=True,
                    options=self._options(num_predict),
                )
                async for chunk in stream:
                    last = chunk
                    message = getattr(chunk, "message", None)
                    if message is None:
                        continue
                    delta = getattr(message, "content", "") or ""
                    if delta:
                        content_parts.append(delta)
                        yielded = True
                        yield {"type": "token", "content": delta}
                    thought = getattr(message, "thinking", "") or ""
                    if thought:
                        thinking_parts.append(thought)
                    for call in getattr(message, "tool_calls", None) or []:
                        function = getattr(call, "function", None)
                        if function is None:
                            continue
                        tool_calls.append(
                            {
                                "name": getattr(function, "name", ""),
                                "arguments": dict(getattr(function, "arguments", {}) or {}),
                            }
                        )
            except (ConnectionError, OSError, ResponseError) as exc:
                if not yielded and attempt < _MAX_ATTEMPTS:
                    await asyncio.sleep(_BACKOFF_SECONDS * attempt)
                    continue  # nothing shown yet — safe to retry the whole turn
                raise OllamaUnavailableError(
                    "Ollama request failed. Confirm the service is running and the "
                    "model is installed."
                ) from exc

            content = "".join(content_parts)
            # Mirror _normalize: if the model emitted only reasoning, surface that.
            if not content.strip():
                content = "".join(thinking_parts)
            yield {
                "type": "message",
                "content": content,
                "tool_calls": tool_calls,
                "raw": last,
            }
            return

"""Thin async wrapper over the local Ollama chat API with tool-calling."""

from __future__ import annotations

from typing import Any


class OllamaUnavailableError(RuntimeError):
    """Raised when the local Ollama service cannot be reached."""


def _normalize(message: Any) -> dict:
    """Normalize an Ollama response message into a plain dict.

    Returns ``{"content": str, "tool_calls": [{"name","arguments"}], "raw": ...}``.
    """

    content = getattr(message, "content", "") or ""
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

    def __init__(self, host: str, model: str, num_ctx: int = 8192) -> None:
        from ollama import AsyncClient

        self.model = model
        # Ollama defaults to a small context (~2-4k), which truncates our
        # skills+hosts+outputs prompts — the model then loses the target or returns
        # empty. Request a larger window so the full prompt fits.
        self.num_ctx = num_ctx
        self._client = AsyncClient(host=host)

    async def chat(
        self,
        messages: list[dict],
        *,
        tools: list[dict] | None = None,
        num_predict: int = 800,
    ) -> dict:
        from ollama import ResponseError

        try:
            response = await self._client.chat(
                model=self.model,
                messages=messages,
                tools=tools,
                options={"temperature": 0.2, "num_predict": num_predict, "num_ctx": self.num_ctx},
            )
        except (ConnectionError, OSError, ResponseError) as exc:
            raise OllamaUnavailableError(
                "Ollama request failed. Confirm the service is running and the "
                "model is installed."
            ) from exc
        return _normalize(response.message)

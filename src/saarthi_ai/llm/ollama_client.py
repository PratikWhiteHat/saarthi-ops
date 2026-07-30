from collections.abc import Sequence
from typing import Any

from ollama import AsyncClient, ResponseError

from saarthi_ai.config import Settings
from saarthi_ai.prompts.system import SYSTEM_PROMPT
from saarthi_ai.schemas.chat import Message


class OllamaUnavailableError(RuntimeError):
    """Raised when Ollama or the configured model is unavailable."""


class SaarthiOllamaClient:
    """Client used to communicate with the local Ollama service."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = AsyncClient(host=settings.ollama_host)

    async def health(self) -> dict[str, object]:
        """Check whether Ollama and the configured model are available."""

        try:
            response = await self.client.list()
        except (ConnectionError, OSError, ResponseError) as exc:
            raise OllamaUnavailableError(
                f"Cannot reach Ollama at {self.settings.ollama_host}."
            ) from exc

        models = response.models or []

        model_names = sorted(model.model for model in models if model.model)

        configured_model = self.settings.ollama_model
        configured_base = configured_model.split(":", maxsplit=1)[0]

        model_available = configured_model in model_names or any(
            installed.split(":", maxsplit=1)[0] == configured_base for installed in model_names
        )

        return {
            "host": self.settings.ollama_host,
            "configured_model": configured_model,
            "model_available": model_available,
            "installed_models": model_names,
        }

    async def chat(
        self,
        messages: Sequence[Message],
        *,
        think: bool = False,
    ) -> tuple[str, str | None]:
        """Send a chat request to the configured Ollama model."""

        ollama_messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            *[
                {
                    "role": message.role,
                    "content": message.content,
                }
                for message in messages
            ],
        ]

        try:
            response = await self.client.chat(
                model=self.settings.ollama_model,
                messages=ollama_messages,
                think=think,
                options={
                    "temperature": 0.2,
                    "num_predict": 150,
                    "top_p": 0.9,
                    "repeat_penalty": 1.1,
                },
            )
        except (ConnectionError, OSError, ResponseError) as exc:
            raise OllamaUnavailableError(
                "Ollama request failed. Confirm that Ollama is running "
                "and that the configured model has been downloaded."
            ) from exc

        content = response.message.content or ""
        thinking = getattr(response.message, "thinking", None)

        return content.strip(), thinking

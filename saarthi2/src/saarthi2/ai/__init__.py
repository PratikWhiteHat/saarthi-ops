"""Local-LLM (Ollama) agentic layer for Saarthi 2.0."""

from saarthi2.ai.agent import Agent, AgentResult
from saarthi2.ai.ollama import OllamaChat, OllamaUnavailableError

__all__ = ["Agent", "AgentResult", "OllamaChat", "OllamaUnavailableError"]

"""Step-type registry. Add a new step type by registering a handler here."""

from saarthi2.steps.http import handle_http
from saarthi2.steps.llm import handle_llm
from saarthi2.steps.tool import handle_tool

STEP_TYPES = {
    "tool": handle_tool,
    "http": handle_http,
    "llm": handle_llm,
}

__all__ = ["STEP_TYPES", "handle_http", "handle_llm", "handle_tool"]

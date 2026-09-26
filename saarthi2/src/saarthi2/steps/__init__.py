"""Step-type registry. Add a new step type by registering a handler here.

``parallel`` has no handler — it is expanded by the runner (it dispatches its
sub-steps concurrently), so it is listed in ``KNOWN_USES`` for validation only.
"""

from saarthi2.steps.function import handle_function
from saarthi2.steps.http import handle_http
from saarthi2.steps.llm import handle_llm
from saarthi2.steps.notify import handle_notify
from saarthi2.steps.subagent import handle_subagent
from saarthi2.steps.tool import handle_tool

STEP_TYPES = {
    "tool": handle_tool,
    "http": handle_http,
    "llm": handle_llm,
    "function": handle_function,
    "notify": handle_notify,
    "subagent": handle_subagent,
}

# Valid `uses:` values, including runner-expanded types without a handler.
KNOWN_USES = set(STEP_TYPES) | {"parallel"}

__all__ = [
    "KNOWN_USES",
    "STEP_TYPES",
    "handle_function",
    "handle_http",
    "handle_llm",
    "handle_notify",
    "handle_subagent",
    "handle_tool",
]

"""Policy layer — the pluggable seam between the engine and real execution.

The default :class:`PermissiveGate` matches the chosen Osmedeus-style model: it
authorizes everything and only *audits* each action (auditing is logging, not a
restriction). :class:`ScopedGate` is provided as a drop-in that enforces a host
allowlist and blocks a few obviously destructive command tokens — wire it in
when you want containment without changing any step code.
"""

from __future__ import annotations

from urllib.parse import urlsplit


class GateDenied(RuntimeError):
    """Raised by a gate that refuses an action."""


class Gate:
    """Base gate. Override :meth:`check` to enforce a policy."""

    def check(self, kind: str, details: dict) -> None:  # noqa: D401
        """Authorize an action or raise :class:`GateDenied`."""

        return None


class PermissiveGate(Gate):
    """Allows every action; records it to the audit log if a store is given."""

    def __init__(self, store=None) -> None:
        self.store = store

    def check(self, kind: str, details: dict) -> None:
        if self.store is not None:
            self.store.audit("action", {"kind": kind, **details})


class ScopedGate(PermissiveGate):
    """Opt-in containment: host allowlist + a destructive-token denylist.

    Not used by default (the engine ships permissive). Construct the runner with
    this gate to keep commands/requests on the authorized target.
    """

    _DESTRUCTIVE = ("rm -rf", "mkfs", ":(){", "dd if=", "--dump", " shutdown", " reboot")

    def __init__(self, allowed_hosts: tuple[str, ...], store=None) -> None:
        super().__init__(store=store)
        self.allowed_hosts = {h.strip().lower().rstrip(".") for h in allowed_hosts if h}

    def check(self, kind: str, details: dict) -> None:
        if kind == "http":
            host = (urlsplit(str(details.get("url", ""))).hostname or "").lower().rstrip(".")
            if self.allowed_hosts and host not in self.allowed_hosts:
                raise GateDenied(f"host {host!r} is out of scope")
        if kind == "command":
            cmd = str(details.get("cmd", "")).lower()
            for token in self._DESTRUCTIVE:
                if token in cmd:
                    raise GateDenied(f"destructive token blocked: {token.strip()!r}")
        super().check(kind, details)

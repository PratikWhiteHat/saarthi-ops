"""TEST payload selection + mutation — from the templated library, never freeform.

The tester SELECTS the templates registered for a task's vuln class and MUTATES
them by filling runtime placeholders (a per-request marker, a chosen delay, a
traversal path, an attacker host, an OOB domain). ``technique`` is carried through
so the oracle knows how to verify. No payload is model-generated.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saarthi2.vulnengine.config import load_payloads

DEFAULT_SLEEP = 5


@dataclass
class PreparedPayload:
    """A concrete, ready-to-send payload with everything the oracle needs."""

    id: str
    vuln_class: str
    technique: str
    values: dict[str, Any] = field(default_factory=dict)


def new_marker() -> str:
    """A distinctive canary token — reflection proof + headless-exec key."""

    return "sxss" + secrets.token_hex(5)


def _fill(template: str, **subs: Any) -> str:
    out = template
    for key, value in subs.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def select_and_mutate(
    vuln_class: str,
    *,
    config_dir: Path | None = None,
    payloads_cfg: dict[str, Any] | None = None,
    sleep: int = DEFAULT_SLEEP,
    attacker_host: str = "saarthi-oast.example",
    oob_domain: str = "",
    marker_factory=new_marker,
) -> list[PreparedPayload]:
    """Return prepared payloads for ``vuln_class`` (empty if none registered)."""

    cfg = payloads_cfg if payloads_cfg is not None else load_payloads(config_dir)
    templates = cfg.get(vuln_class) or []
    prepared: list[PreparedPayload] = []

    for tpl in templates:
        if not isinstance(tpl, dict):
            continue
        technique = str(tpl.get("technique", "")).strip()
        pid = str(tpl.get("id", f"{vuln_class}-{technique}"))
        values: dict[str, Any]

        if technique == "boolean":
            values = {"true": str(tpl.get("true", "")), "false": str(tpl.get("false", ""))}
        elif technique in ("time", "cmd_time"):
            secs = int(tpl.get("sleep", sleep))
            template = str(tpl.get("template", ""))
            # Keep the raw template so the oracle can re-fill with a larger delay to
            # prove the injected sleep SCALES (a real time-based injection does).
            values = {"value": _fill(template, sleep=secs), "sleep": secs, "template": template}
        elif technique == "error":
            values = {"value": str(tpl.get("payload", tpl.get("template", "")))}
        elif technique in ("reflect", "store"):
            marker = marker_factory()
            values = {"value": _fill(str(tpl.get("template", "")), marker=marker), "marker": marker}
        elif technique == "path_read":
            values = {
                "value": str(tpl.get("template", "")),
                "signature": str(tpl.get("signature", "")),
            }
        elif technique == "redirect":
            values = {
                "value": _fill(str(tpl.get("template", "")), host=attacker_host),
                "host": attacker_host,
            }
        elif technique == "oob":
            if not oob_domain:
                continue  # blind classes need an OOB collector; skip when unset
            values = {
                "value": _fill(str(tpl.get("template", "")), oob=oob_domain),
                "oob": oob_domain,
            }
        elif technique == "idor":
            offsets = tpl.get("offsets") or [1, -1]
            values = {"offsets": [int(o) for o in offsets]}
        else:
            continue

        prepared.append(
            PreparedPayload(id=pid, vuln_class=vuln_class, technique=technique, values=values)
        )
    return prepared

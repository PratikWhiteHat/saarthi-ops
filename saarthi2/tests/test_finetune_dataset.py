"""The LoRA dataset builder (finetune/build_dataset.py)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_BD = Path(__file__).resolve().parent.parent / "finetune" / "build_dataset.py"
_spec = importlib.util.spec_from_file_location("build_dataset", _BD)
bd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bd)

_SKILL = """---
name: hunt-idor
description: Hunting skill for idor vulnerabilities. Use when hunting idor.
report_count: 39
---

Intro text before the first section.

## Attack Surface Signals
Numeric ids in URLs like /api/users/123.

## Payload & Detection Patterns
curl -H 'Authorization: ...' https://x/api/users/124

## Related Skills
See hunt-auth-bypass.
"""


def test_parse_frontmatter() -> None:
    meta, body = bd.parse_frontmatter(_SKILL)
    assert meta["name"] == "hunt-idor"
    assert "idor" in meta["description"].lower()
    assert body.startswith("Intro text")


def test_split_sections() -> None:
    _meta, body = bd.parse_frontmatter(_SKILL)
    sections = dict(bd.split_sections(body))
    assert "Overview" in sections and "Intro text" in sections["Overview"]
    assert "Attack Surface Signals" in sections
    assert "Payload & Detection Patterns" in sections


def test_pretty_name() -> None:
    assert bd.pretty_name("hunt-idor") == "IDOR"
    assert bd.pretty_name("hunt-ssrf") == "SSRF"
    assert "methodology" in bd.pretty_name("bb-methodology")


def test_question_routing() -> None:
    assert "attack-surface" in bd.question_for("Attack Surface Signals", "IDOR").lower()
    assert "payload" in bd.question_for("Payload & Detection Patterns", "IDOR").lower()
    assert "IDOR" in bd.question_for("Some Custom Heading", "IDOR")


def test_build_pairs_shape() -> None:
    meta, body = bd.parse_frontmatter(_SKILL)
    pairs = bd.build_pairs(meta["name"], meta["description"], body)
    assert len(pairs) >= 4  # overview + when-to-use + per-section + full
    for p in pairs:
        roles = [m["role"] for m in p["messages"]]
        assert roles == ["system", "user", "assistant"]
        assert all(m["content"] for m in p["messages"])
    # a section's content is preserved in some assistant turn
    joined = "\n".join(p["messages"][2]["content"] for p in pairs)
    assert "Numeric ids in URLs" in joined


def test_router_pair() -> None:
    r = bd.router_pair("hunt-idor", "Hunting skill for idor.")
    assert "hunt-idor" in r["messages"][2]["content"]


def test_pairs_are_json_serializable() -> None:
    meta, body = bd.parse_frontmatter(_SKILL)
    for p in bd.build_pairs(meta["name"], meta["description"], body):
        json.loads(json.dumps(p))  # round-trips cleanly for JSONL

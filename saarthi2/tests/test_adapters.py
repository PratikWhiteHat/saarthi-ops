"""Tool-adapter catalog and command rendering."""

from __future__ import annotations

import pytest

from saarthi2.adapters import TOOL_ADAPTERS, adapter_catalog, render_adapter_command


def test_render_subfinder() -> None:
    assert render_adapter_command("subfinder", {"target": "ex.com"}) == (
        "subfinder -d ex.com -silent"
    )


def test_missing_placeholder_is_blank() -> None:
    cmd = render_adapter_command("ffuf", {"target": "http://x"})
    assert "http://x/FUZZ" in cmd
    assert "-w " in cmd  # wordlist placeholder rendered blank, flag preserved


def test_extra_args_appended() -> None:
    cmd = render_adapter_command(
        "nuclei", {"target": "http://x", "args": ["-severity", "high"]}
    )
    assert cmd.startswith("nuclei -u http://x")
    assert cmd.endswith("-severity high")


def test_unknown_adapter_rejected() -> None:
    with pytest.raises(ValueError, match="unknown tool adapter"):
        render_adapter_command("nope", {})


def test_catalog_covers_core_tools() -> None:
    names = {a["name"] for a in adapter_catalog()}
    assert {"subfinder", "httpx", "nuclei", "naabu", "katana"} <= names
    assert len(TOOL_ADAPTERS) >= 18


def test_catalog_includes_extended_tools() -> None:
    names = {a["name"] for a in adapter_catalog()}
    assert {"chaos", "tlsx", "asnmap", "mapcidr", "hakrawler", "waymore", "subzy"} <= names
    assert len(TOOL_ADAPTERS) >= 40


def test_render_extended_adapters() -> None:
    assert render_adapter_command("chaos", {"target": "ex.com"}) == "chaos -d ex.com -silent"
    assert render_adapter_command("asnmap", {"target": "ex.com"}) == "asnmap -d ex.com -silent"
    tls = render_adapter_command("tlsx", {"input": "hosts.txt"})
    assert tls.startswith("tlsx -l hosts.txt")


def test_every_adapter_renders_without_error() -> None:
    # A blank param set must never raise (missing placeholders resolve to "").
    for name in TOOL_ADAPTERS:
        assert isinstance(render_adapter_command(name, {}), str)

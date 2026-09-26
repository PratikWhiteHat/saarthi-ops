"""Target normalization (url/slug), nested-var resolution, and ~ expansion.

Regression coverage for the bug where a URL target broke path building:
- vars.workdir with a nested `{{ target_slug }}` stayed literal ("{{ ... }}")
- `https://{{ target }}` double-prefixed a URL target
- `~` in a tool arg was passed literally to the tool under shell=False
"""

from __future__ import annotations

import asyncio

from saarthi2.engine.context import resolve_vars, target_slug, target_url
from saarthi2.engine.loader import load_workflow_from_str
from saarthi2.engine.models import StepStatus
from saarthi2.engine.runner import StepDeps, WorkflowRunner
from saarthi2.runtime import _expand_user_tokens


def test_target_url_no_double_scheme() -> None:
    assert target_url("example.com") == "https://example.com"
    assert target_url("https://ex.com/a?b=1") == "https://ex.com/a?b=1"
    assert target_url("http://ex.com") == "http://ex.com"
    assert target_url("") == ""


def test_target_slug_is_filesystem_safe() -> None:
    assert target_slug("https://www.ex.com/a.php?id=7") == "www_ex_com_a_php_id_7"
    assert target_slug("example.com") == "example_com"
    assert "/" not in target_slug("https://x/y/z")
    assert target_slug("") == "target"


def test_resolve_vars_fixpoint() -> None:
    base = {"target": "https://ex.com/a", "target_slug": "ex_com_a"}
    variables = {"workdir": "~/.s2/loot/{{ target_slug }}", "sub": "{{ vars.workdir }}/x"}
    out = resolve_vars(variables, base)
    assert out["workdir"] == "~/.s2/loot/ex_com_a"
    assert out["sub"] == "~/.s2/loot/ex_com_a/x"


def test_expand_user_tokens() -> None:
    import os

    home = os.path.expanduser("~")
    tokens = _expand_user_tokens(["-o", "~/.saarthi2/x", "keep", "~/y"])
    assert tokens[0] == "-o"
    assert tokens[1] == f"{home}/.saarthi2/x"
    assert tokens[2] == "keep"
    assert tokens[3] == f"{home}/y"


_VULN_LIKE = """
name: vulnlike
vars:
  target: example.com
  workdir: "~/.saarthi2/loot/{{ target_slug }}"
steps:
  - id: nuclei
    uses: tool
    with:
      tool: nuclei
      target: "{{ target_url }}"
      args: ["-o", "{{ vars.workdir }}/nuclei.jsonl"]
"""


def test_url_target_renders_clean_command() -> None:
    """A full-URL target must not double the scheme or leave literal templates."""

    captured: list[str] = []

    async def fake_run_command(cmd, *, timeout=300, shell=False):
        captured.append(cmd)
        return (0, "", "")

    async def fake_http(*a, **k):
        raise AssertionError

    deps = StepDeps(run_command=fake_run_command, http_request=fake_http)
    wf = load_workflow_from_str(_VULN_LIKE)
    result = asyncio.run(
        WorkflowRunner(deps).run(wf, target="https://www.ex.com/php/g.php?id=7")
    )
    assert result.status is StepStatus.COMPLETED
    cmd = captured[0]
    assert "{{" not in cmd and "}}" not in cmd          # no literal templates
    assert "https://https://" not in cmd                # no double scheme
    assert "-u https://www.ex.com/php/g.php?id=7" in cmd
    assert "loot/www_ex_com_php_g_php_id_7/nuclei.jsonl" in cmd  # slug dir, not the URL

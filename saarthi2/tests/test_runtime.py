"""Runtime helpers: prefer the real tool over a Python-shadow script."""

from __future__ import annotations

import os

from saarthi2.runtime import _expand_user_tokens, resolve_tool_binary, strip_ansi


def _write_exe(directory, name, body) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    exe = directory / name
    exe.write_text(body)
    exe.chmod(0o755)
    return str(exe)


def test_prefers_real_tool_over_python_shadow(tmp_path) -> None:
    # A python-shadow (e.g. the httpx library CLI) sits FIRST on PATH; the real
    # ProjectDiscovery binary is later. resolve should pick the real one.
    py_dir = tmp_path / "pybin"
    go_dir = tmp_path / "go" / "bin"
    _write_exe(py_dir, "httpx", "#!/usr/bin/python3\nimport httpx\n")
    real = _write_exe(go_dir, "httpx", "#!/bin/sh\necho real\n")
    path = os.pathsep.join([str(py_dir), str(go_dir)])
    assert resolve_tool_binary("httpx", path=path) == real


def test_prefers_real_tool_over_sh_exec_wrapper(tmp_path) -> None:
    # pip/uv generate a #!/bin/sh exec-wrapper when the interpreter path has spaces
    # (as in this repo's "Saarthi AI/..." path). It must still be detected as Python.
    py_dir = tmp_path / "pybin"
    go_dir = tmp_path / "go" / "bin"
    wrapper = (
        "#!/bin/sh\n"
        "'''exec' \"/Users/x/Saarthi AI/.venv/bin/python\" \"$0\" \"$@\"\n"
        "' '''\nimport httpx\n"
    )
    _write_exe(py_dir, "httpx", wrapper)
    real = _write_exe(go_dir, "httpx", "#!/bin/sh\necho real\n")
    path = os.pathsep.join([str(py_dir), str(go_dir)])
    assert resolve_tool_binary("httpx", path=path) == real


def test_python_only_tool_still_resolves(tmp_path) -> None:
    # semgrep is pip-installed (a python script) with no compiled competitor.
    py_dir = tmp_path / "pybin"
    only = _write_exe(py_dir, "semgrep", "#!/usr/bin/python3\nimport semgrep\n")
    path = os.pathsep.join([str(py_dir), str(tmp_path / "empty")])
    assert resolve_tool_binary("semgrep", path=path) == only


def test_missing_binary_returns_name(tmp_path) -> None:
    path = os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")])
    assert resolve_tool_binary("does-not-exist", path=path) == "does-not-exist"


def test_explicit_path_passthrough() -> None:
    assert resolve_tool_binary("/usr/bin/env") == "/usr/bin/env"


def test_dedupes_duplicate_path_entries(tmp_path) -> None:
    go_dir = tmp_path / "go" / "bin"
    real = _write_exe(go_dir, "nuclei", "#!/bin/sh\n")
    path = os.pathsep.join([str(go_dir), str(go_dir)])  # same dir twice
    assert resolve_tool_binary("nuclei", path=path) == real


def test_expand_user_tokens_unchanged_for_plain_args() -> None:
    assert _expand_user_tokens(["nuclei", "-u", "https://x"]) == ["nuclei", "-u", "https://x"]


def test_strip_ansi() -> None:
    # httpx-style colored line -> plain text
    colored = "\x1b[32m200\x1b[0m \x1b[36mManage Your Billing\x1b[0m \x1b[35mHSTS\x1b[0m"
    assert strip_ansi(colored) == "200 Manage Your Billing HSTS"
    # cursor/erase codes and OSC titles removed too
    assert strip_ansi("a\x1b[2Kb\x1b[1;31mc\x1b[0m") == "abc"
    # plain text untouched
    assert strip_ansi("sub.example.com [200]") == "sub.example.com [200]"

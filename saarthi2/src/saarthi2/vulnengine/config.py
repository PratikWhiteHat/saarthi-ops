"""Load the editable engine config — the feature->vuln matrix and payloads.

Both ship as bundled defaults inside the package and are COPIED to the operator's
``config_dir`` (``~/.saarthi2/config`` by default) on first use, so they can be
grown from real engagements without touching the install. Loading always prefers
the operator's copy and falls back to the bundled default.
"""

from __future__ import annotations

import shutil
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

MATRIX_FILE = "feature_vuln_matrix.yaml"
PAYLOADS_FILE = "payloads.yaml"


def _bundled(name: str) -> Path:
    return Path(str(files("saarthi2.vulnengine") / "data" / name))


def ensure_config(config_dir: Path, name: str) -> Path:
    """Return the operator's copy of ``name``, seeding it from the default once."""

    config_dir = Path(config_dir)
    target = config_dir / name
    if not target.exists():
        config_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_bundled(name), target)
    return target


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_matrix(config_dir: Path | None = None) -> dict[str, Any]:
    """Load the feature->vuln matrix (operator copy if a ``config_dir`` is given)."""

    path = ensure_config(config_dir, MATRIX_FILE) if config_dir else _bundled(MATRIX_FILE)
    return _load_yaml(path)


def load_payloads(config_dir: Path | None = None) -> dict[str, Any]:
    """Load the payload-template library (operator copy if a ``config_dir`` is given)."""

    path = ensure_config(config_dir, PAYLOADS_FILE) if config_dir else _bundled(PAYLOADS_FILE)
    data = _load_yaml(path)
    payloads = data.get("payloads")
    return payloads if isinstance(payloads, dict) else {}

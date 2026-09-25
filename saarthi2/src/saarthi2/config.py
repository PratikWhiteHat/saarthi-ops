"""Runtime configuration for Saarthi 2.0 (env-driven, dependency-light)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings.

    All values come from ``SAARTHI2_*`` environment variables with local-first
    defaults so nothing leaves the operator's machine unless a workflow says so.
    """

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    work_dir: Path = Path.home() / ".saarthi2"

    @property
    def db_path(self) -> Path:
        return self.work_dir / "saarthi2.db"

    @property
    def evidence_dir(self) -> Path:
        return self.work_dir / "evidence"

    @property
    def audit_path(self) -> Path:
        return self.work_dir / "audit.jsonl"

    @property
    def workflows_dir(self) -> Path:
        configured = os.getenv("SAARTHI2_WORKFLOWS_DIR", "").strip()
        if configured:
            return Path(configured).expanduser()
        # Default to the packaged workflows/ dir at the repo root.
        return Path(__file__).resolve().parents[3] / "workflows"


def get_settings() -> Settings:
    """Build settings from the environment."""

    work_dir = os.getenv("SAARTHI2_WORK_DIR", "").strip()
    return Settings(
        ollama_host=os.getenv("SAARTHI2_OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=os.getenv("SAARTHI2_OLLAMA_MODEL", "qwen3.5:9b"),
        work_dir=Path(work_dir).expanduser() if work_dir else Path.home() / ".saarthi2",
    )

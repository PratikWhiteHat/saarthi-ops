"""Runtime configuration for Saarthi 2.0 (env-driven, dependency-light)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bundled_workflows_dir() -> Path:
    """Locate the workflow library bundled inside the package."""

    from importlib.resources import files

    return Path(str(files("saarthi2") / "workflows"))


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings.

    Local-first defaults so nothing leaves the operator's machine unless a
    workflow says so. All fields are plain data, so tests can construct a
    ``Settings(...)`` with temp directories.
    """

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    work_dir: Path = Path.home() / ".saarthi2"
    workflows_dir: Path = field(default_factory=_bundled_workflows_dir)

    # Notifications
    slack_webhook: str = ""
    discord_webhook: str = ""
    telegram_token: str = ""
    telegram_chat: str = ""

    # Distributed / auth
    redis_url: str = ""
    api_key: str = ""

    # Optional PostgreSQL backend (empty -> local SQLite file at db_path)
    database_url: str = ""

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
    def plugins_dir(self) -> Path:
        return self.work_dir / "plugins"

    @property
    def skills_dir(self) -> Path:
        """Bug-hunting skill corpus for RAG (``SAARTHI2_SKILLS_DIR`` overrides)."""

        override = os.getenv("SAARTHI2_SKILLS_DIR", "").strip()
        return Path(override).expanduser() if override else self.work_dir / "skills"


def get_settings() -> Settings:
    """Build settings from ``SAARTHI2_*`` environment variables."""

    work_dir = os.getenv("SAARTHI2_WORK_DIR", "").strip()
    workflows_dir = os.getenv("SAARTHI2_WORKFLOWS_DIR", "").strip()
    env = os.getenv
    return Settings(
        ollama_host=env("SAARTHI2_OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=env("SAARTHI2_OLLAMA_MODEL", "qwen3.5:9b"),
        work_dir=Path(work_dir).expanduser() if work_dir else Path.home() / ".saarthi2",
        workflows_dir=(
            Path(workflows_dir).expanduser() if workflows_dir else _bundled_workflows_dir()
        ),
        slack_webhook=env("SAARTHI2_SLACK_WEBHOOK", ""),
        discord_webhook=env("SAARTHI2_DISCORD_WEBHOOK", ""),
        telegram_token=env("SAARTHI2_TELEGRAM_TOKEN", ""),
        telegram_chat=env("SAARTHI2_TELEGRAM_CHAT", ""),
        redis_url=env("SAARTHI2_REDIS_URL", ""),
        api_key=env("SAARTHI2_API_KEY", ""),
        database_url=env("SAARTHI2_DATABASE_URL", ""),
    )

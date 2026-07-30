from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SAARTHI_",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Saarthi AI"
    environment: str = "development"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    request_timeout_seconds: float = Field(default=180, gt=0)


@lru_cache
def get_settings() -> Settings:
    return Settings()

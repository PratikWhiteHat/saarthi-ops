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

    verify_tls: bool = Field(
        default=False,
        description=(
            "Verify TLS certificates on outbound requests to assessment "
            "targets. Authorized VAPT targets frequently present invalid, "
            "self-signed, or expired certificates, so verification is "
            "disabled by default. Set SAARTHI_VERIFY_TLS=true to require "
            "valid certificates."
        ),
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def tls_verify() -> bool:
    """Whether outbound target HTTP clients verify TLS certificates.

    Defaults to False so authorized targets with invalid/self-signed/expired
    certificates can still be assessed (like ``curl -k`` / nuclei / sqlmap).
    Override with ``SAARTHI_VERIFY_TLS=true`` to require valid certificates.
    """

    return get_settings().verify_tls

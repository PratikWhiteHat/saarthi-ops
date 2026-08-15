from functools import lru_cache
from pathlib import Path

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

    knowledge_dir: str = Field(
        default="",
        description=(
            "Directory holding the local, git-ignored knowledge pack "
            "(parsed vulnerability library `wapt_bible.json` and the report "
            "template `report_template.docx`). Empty resolves to "
            "~/.saarthi/knowledge. Set SAARTHI_KNOWLEDGE_DIR to override."
        ),
    )

    # Report identity — vendor-neutral placeholders filled into the report
    # template so no company/author is hard-coded in the repo.
    report_company: str = Field(
        default="Your Security Team",
        description="Testing organization name printed on the report.",
    )
    report_company_short: str = Field(
        default="",
        description=(
            "Short/abbreviated testing-org name used in prose. Empty falls "
            "back to report_company."
        ),
    )
    report_author: str = Field(
        default="Saarthi Operator",
        description="Report author / 'Prepared By' name.",
    )
    report_reviewer: str = Field(
        default="",
        description="Report reviewer / 'Reviewed By' name.",
    )
    report_classification: str = Field(
        default="Confidential",
        description="Document classification printed on the report.",
    )

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


def knowledge_dir() -> Path:
    """Resolve the local knowledge-pack directory.

    Defaults to ``~/.saarthi/knowledge`` (alongside the execution database) so
    the proprietary vulnerability library and report template stay local and
    out of the repository. Override with ``SAARTHI_KNOWLEDGE_DIR``.
    """

    configured = get_settings().knowledge_dir.strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".saarthi" / "knowledge"


def tls_verify() -> bool:
    """Whether outbound target HTTP clients verify TLS certificates.

    Defaults to False so authorized targets with invalid/self-signed/expired
    certificates can still be assessed (like ``curl -k`` / nuclei / sqlmap).
    Override with ``SAARTHI_VERIFY_TLS=true`` to require valid certificates.
    """

    return get_settings().verify_tls

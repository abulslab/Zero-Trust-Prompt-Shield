"""Settings from the environment (prefix SHIELD_) or a .env file. Provider keys use their usual names."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

Provider = Literal["none", "gemini", "ollama", "anthropic", "openai"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHIELD_", env_file=".env", env_file_encoding="utf-8", extra="ignore", env_ignore_empty=True
    )  # empty values (as in .env.example) mean "use the default"

    # Service
    api_key: SecretStr | None = Field(default=None, description="When set, every /v1 call needs this key.")
    fingerprint_key: SecretStr | None = Field(
        default=None,
        description="Optional HMAC-SHA256 secret key for finding fingerprints to prevent rainbow-table correlation.",
    )
    cors_origins: list[str] = ["http://localhost:3200", "http://127.0.0.1:3200"]
    max_chars: int = 200_000
    rate_limit_per_minute: int = 240
    db_path: str = "data/promptshield.db"
    default_policy: str = "balanced"
    policy_dir: str | None = None  # extra policy packs (YAML) next to the built-in ones
    log_level: str = "INFO"

    # Models: the shield works with none. A provider adds semantic review, prompt optimisation and the guard.
    ai_provider: Provider = "none"
    ai_timeout_s: float | None = None  # default: 30s for cloud providers, 180s for local Ollama
    ai_max_input_chars: int = 24_000
    gemini_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GEMINI_API_KEY", "SHIELD_GEMINI_API_KEY")
    )
    gemini_model: str = "gemini-3.5-flash"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    anthropic_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("ANTHROPIC_API_KEY", "SHIELD_ANTHROPIC_API_KEY")
    )
    anthropic_model: str = "claude-haiku-5-5"
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OPENAI_API_KEY", "SHIELD_OPENAI_API_KEY")
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"


@lru_cache
def get_settings() -> Settings:
    return Settings()

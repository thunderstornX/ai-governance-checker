"""Settings loaded from environment / .env.

The whole tool is designed to run with no keys configured. Each external
provider is *optional*; when none are available the LLM-judge module
returns a ``DISABLED`` JudgeResult and the report runs in rules-only
mode. That mode is exactly what the eval harness measures, so the
published precision/recall numbers do not depend on any paid API."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process configuration. Pulled from env, .env, or constructor args."""

    # Anthropic Claude API.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    anthropic_base_url: str = "https://api.anthropic.com/v1/messages"

    # Local Ollama.
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:1b"

    # Judge timeouts -- each provider gets a generous but bounded budget
    # so an offline daemon does not hang the CLI for a minute.
    judge_timeout_s: float = 20.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


def load_settings(**overrides) -> Settings:
    """Construct Settings, accepting test-time overrides as kwargs."""
    return Settings(**overrides)

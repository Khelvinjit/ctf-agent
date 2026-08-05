"""Configuration loaded from environment variables and an optional .env file."""
from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    openrouter_api_key: str | None = None
    gemini_api_key: str | None = None
    # The classifier and solver deliberately use one configured model.
    model_provider: str = "gemini"
    model_name: str = "gemini-2.5-flash"
    max_iterations: int = 15
    command_timeout_seconds: int = 60
    challenge_timeout_seconds: int = 600
    max_sandbox_expansions: int = 1
    flag_format_regex: str = r"picoCTF\{[^}\n]+\}"
    logs_dir: Path = Path("logs")
    skill_index: Path = Path("ctf_agent/skills/index.sqlite")
    sandbox_image: str = "ctf-sandbox"
    sandbox_memory: str = "768m"
    sandbox_pids_limit: int = 128


def get_settings() -> Settings:
    return Settings()

"""Configuration loaded from environment variables and an optional .env file."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True, slots=True)
class ModelRoute:
    provider: str
    model: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    openrouter_api_key: str | None = None
    gemini_api_key: str | None = None
    groq_api_key: str | None = None
    # The first route. Rate-limited requests rotate through MODEL_ROTATION.
    model_provider: str = "gemini"
    model_name: str = "gemini-3.6-flash"
    model_rotation: str = "gemini:gemini-3.6-flash,groq:openai/gpt-oss-120b,openrouter:openrouter/free"
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

    def model_routes(self, preferred_provider: str | None = None,
                     preferred_model: str | None = None) -> tuple[ModelRoute, ...]:
        """Return the preferred route followed by unique configured fallbacks."""
        allowed_providers = {"gemini", "groq", "openrouter"}
        routes = [ModelRoute((preferred_provider or self.model_provider).lower(), preferred_model or self.model_name)]
        for entry in self.model_rotation.split(","):
            provider, separator, model = entry.strip().partition(":")
            if not separator or not provider or not model:
                raise ValueError("MODEL_ROTATION entries must use provider:model syntax")
            routes.append(ModelRoute(provider.strip().lower(), model.strip()))
        unique: list[ModelRoute] = []
        for route in routes:
            if route.provider not in allowed_providers:
                raise ValueError("MODEL_ROTATION supports only gemini, groq, and openrouter")
            if route not in unique:
                unique.append(route)
        return tuple(unique)


def get_settings() -> Settings:
    return Settings()

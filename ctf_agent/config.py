"""Configuration loaded from environment variables and an optional .env file."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True, slots=True)
class ModelRoute:
    provider: str
    model: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    openrouter_api_key: str | None = None
    gemini_api_key: str | None = None
    gemini_api_keys: tuple[str, ...] = ()
    groq_api_key: str | None = None
    # The first route. Provider failures and exhausted turn budgets rotate
    # through MODEL_ROTATION.
    model_provider: str = "gemini"
    model_name: str = "gemini-3.6-flash"
    model_rotation: str = (
        "gemini:gemini-3.6-flash,groq:openai/gpt-oss-120b,openrouter:openrouter/free"
    )
    max_iterations: int = 15
    command_timeout_seconds: int = 60
    challenge_timeout_seconds: int = 600
    max_sandbox_expansions: int = 1
    has_flag_format: bool = True
    flag_format_regex: str = r"picoCTF\{[^}\n]+\}"
    logs_dir: Path = Path("logs")
    skill_index: Path = Path("ctf_agent/skills/index.sqlite")
    sandbox_image: str = "ctf-sandbox"
    sandbox_memory: str = "768m"
    sandbox_pids_limit: int = 128

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        """Load an arbitrary number of numbered Gemini credentials.

        Pydantic normally reads only declared settings fields, while a key pool
        deliberately has no fixed upper bound.  Inspect both the optional .env
        file and the process environment so GEMINI_API_KEY, GEMINI_API_KEY1,
        GEMINI_API_KEY2, and so on remain supported without a configuration
        change for each additional key.
        """

        def numbered_gemini_keys() -> dict[str, tuple[str, ...]]:
            # Process environment values take precedence over matching .env
            # entries, consistent with BaseSettings' normal source order.
            values = {
                name.lower(): value for name, value in dotenv_settings.env_vars.items()
            }
            values.update(
                {name.lower(): value for name, value in env_settings.env_vars.items()}
            )
            numbered: list[tuple[int, bool, str, str]] = []
            for name, value in values.items():
                match = re.fullmatch(r"gemini_api_key(\d*)", name)
                if not match or not isinstance(value, str) or not value.strip():
                    continue
                suffix = match.group(1)
                numbered.append((int(suffix or 0), bool(suffix), name, value.strip()))
            ordered = [value for _, _, _, value in sorted(numbered)]
            # Accidentally repeated values should not consume duplicate quota
            # attempts or make the pool look larger than it is.
            return {"gemini_api_keys": tuple(dict.fromkeys(ordered))} if ordered else {}

        return (
            init_settings,
            numbered_gemini_keys,
            env_settings,
            dotenv_settings,
            file_secret_settings,
        )

    def configured_gemini_api_keys(self) -> tuple[str, ...]:
        """Return the legacy unnumbered key and the dynamic key pool once each."""
        keys = (self.gemini_api_key, *self.gemini_api_keys)
        return tuple(dict.fromkeys(key.strip() for key in keys if key and key.strip()))

    def model_routes(
        self, preferred_provider: str | None = None, preferred_model: str | None = None
    ) -> tuple[ModelRoute, ...]:
        """Return the preferred route followed by unique configured fallbacks."""
        allowed_providers = {"gemini", "groq", "openrouter"}
        routes = [
            ModelRoute(
                (preferred_provider or self.model_provider).lower(),
                preferred_model or self.model_name,
            )
        ]
        for entry in self.model_rotation.split(","):
            provider, separator, model = entry.strip().partition(":")
            if not separator or not provider or not model:
                raise ValueError(
                    "MODEL_ROTATION entries must use provider:model syntax"
                )
            routes.append(ModelRoute(provider.strip().lower(), model.strip()))
        unique: list[ModelRoute] = []
        for route in routes:
            if route.provider not in allowed_providers:
                raise ValueError(
                    "MODEL_ROTATION supports only gemini, groq, and openrouter"
                )
            if route not in unique:
                unique.append(route)
        return tuple(unique)


def get_settings() -> Settings:
    return Settings()

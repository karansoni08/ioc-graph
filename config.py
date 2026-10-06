"""Application configuration.

Values come from the environment (loaded from `.env` in development). Phase 7 will add
`st.secrets` as a second source for the deployed app; `_lookup` is the single place that
needs to change for that, so the rest of the app never reads the environment directly.

The Anthropic API key is deliberately NOT a field on `Settings`: it is fetched on demand by
`get_api_key()` so it can never be captured in a `repr`, a log line, a Streamlit widget or a
pickled session object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()

API_KEY_VAR = "ANTHROPIC_API_KEY"

DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class ConfigError(RuntimeError):
    """Raised when configuration is missing or unusable."""


def _lookup(name: str) -> str | None:
    """Return a configuration value, or None if it is not set anywhere.

    Phase 7: try `st.secrets` here as a fallback after the environment.
    """
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _lookup_int(name: str, default: int) -> int:
    raw = _lookup(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        # Surface the variable name but never the value, which could be anything.
        raise ConfigError(f"{name} must be a whole number.") from exc


@dataclass(frozen=True)
class Settings:
    """Non-secret settings. Safe to log, display and repr."""

    anthropic_model: str = DEFAULT_MODEL
    anthropic_agent_model: str = DEFAULT_MODEL
    storage_backend: str = "local"
    max_file_mb: int = 5
    max_pages: int = 50
    data_dir: str = "data"

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    model = _lookup("ANTHROPIC_MODEL") or DEFAULT_MODEL
    return Settings(
        anthropic_model=model,
        # Agent mode defaults to the same model until Phase 6 gives it a stronger one.
        anthropic_agent_model=_lookup("ANTHROPIC_AGENT_MODEL") or model,
        storage_backend=_lookup("STORAGE_BACKEND") or "local",
        max_file_mb=_lookup_int("MAX_FILE_MB", 5),
        max_pages=_lookup_int("MAX_PAGES", 50),
        data_dir=_lookup("DATA_DIR") or "data",
    )


def get_api_key() -> str:
    """Return the Anthropic API key.

    Raises ConfigError with a message that names only the variable, never its value, so the
    error is safe to show in the UI or write to a log.
    """
    key = _lookup(API_KEY_VAR)
    if not key:
        raise ConfigError(
            f"{API_KEY_VAR} is not set. Copy .env.example to .env and add your key. "
            "The key is read from .env only and is never written anywhere else."
        )
    return key


def has_api_key() -> bool:
    """True if a key is configured. Used to disable LLM features without raising."""
    return _lookup(API_KEY_VAR) is not None

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


def _from_streamlit_secrets(name: str) -> str | None:
    """Read from `st.secrets`, or None.

    Wrapped in a broad try: outside a Streamlit run, and when no secrets file exists, Streamlit
    raises rather than returning empty, and configuration lookup must never be what crashes the
    app. Imported lazily so non-Streamlit entry points (scripts, pytest) do not load Streamlit.
    """
    try:
        import streamlit as st

        value = st.secrets.get(name)  # type: ignore[union-attr]
    except Exception:
        return None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _lookup(name: str) -> str | None:
    """Return a configuration value, or None if it is not set anywhere.

    Environment first, then `st.secrets`. Environment-first means a local `.env` still wins
    during development even if a secrets file is present, and it keeps the precedence rule
    simple enough to reason about when debugging a deployment.
    """
    value = os.environ.get(name)
    if value is not None and value.strip():
        return value.strip()
    return _from_streamlit_secrets(name)


def _lookup_float(name: str, default: float) -> float:
    raw = _lookup(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number.") from exc


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
    # Phase 3: how many chunks of one report may be sent to the model. The main cost control.
    max_chunks_per_report: int = 6
    max_output_tokens: int = 4000
    # Phase 5 guardrail policy. "high" excludes only HIGH-severity chunks (the default),
    # "medium" is stricter and will over-block, "none" reports without excluding anything.
    injection_block_on: str = "high"
    injection_classifier: str = "none"
    # Phase 6 agent budgets. All three are hard ceilings: an agent loop without them is an
    # unbounded bill.
    agent_max_tool_calls: int = 8
    agent_max_input_tokens: int = 60_000
    agent_max_seconds: int = 120
    # Phase 7 deployment settings. Daily caps bound what a shared link can spend.
    daily_report_limit: int = 20
    daily_agent_limit: int = 5
    daily_spend_limit_usd: float = 2.00
    app_timezone: str = "America/Toronto"
    # Running with no password is a local-development convenience and a disaster in a
    # deployment, so it must be asked for explicitly. Default OFF means a deployment that
    # forgets to set the passwords refuses to serve rather than opening to the internet.
    allow_open_access: bool = False

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
        max_chunks_per_report=_lookup_int("MAX_CHUNKS_PER_REPORT", 6),
        max_output_tokens=_lookup_int("MAX_OUTPUT_TOKENS", 4000),
        injection_block_on=(_lookup("INJECTION_BLOCK_ON") or "high").lower(),
        injection_classifier=(_lookup("INJECTION_CLASSIFIER") or "none").lower(),
        agent_max_tool_calls=_lookup_int("AGENT_MAX_TOOL_CALLS", 8),
        agent_max_input_tokens=_lookup_int("AGENT_MAX_INPUT_TOKENS", 60_000),
        agent_max_seconds=_lookup_int("AGENT_MAX_SECONDS", 120),
        daily_report_limit=_lookup_int("DAILY_REPORT_LIMIT", 20),
        daily_agent_limit=_lookup_int("DAILY_AGENT_LIMIT", 5),
        daily_spend_limit_usd=_lookup_float("DAILY_SPEND_LIMIT_USD", 2.00),
        app_timezone=_lookup("APP_TIMEZONE") or "America/Toronto",
        allow_open_access=(_lookup("ALLOW_OPEN_ACCESS") or "").strip().lower()
        in ("1", "true", "yes"),
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


SUPABASE_URL_VAR = "SUPABASE_URL"
SUPABASE_KEY_VAR = "SUPABASE_SERVICE_KEY"
VIEW_PASSWORD_VAR = "VIEW_PASSWORD"
UPLOAD_PASSWORD_VAR = "UPLOAD_PASSWORD"

# Every secret is read on demand through a function, never stored on Settings. Settings is
# logged, displayed and repr'd in several places; a secret field would eventually leak through
# one of them.
SECRET_VARS = (
    API_KEY_VAR,
    SUPABASE_KEY_VAR,
    VIEW_PASSWORD_VAR,
    UPLOAD_PASSWORD_VAR,
)


def get_supabase_url() -> str:
    value = _lookup(SUPABASE_URL_VAR)
    if not value:
        raise ConfigError(
            f"{SUPABASE_URL_VAR} is not set. Required when STORAGE_BACKEND=supabase."
        )
    return value


def get_supabase_service_key() -> str:
    """The service-role key. Server-side only: it must never reach the browser."""
    value = _lookup(SUPABASE_KEY_VAR)
    if not value:
        raise ConfigError(
            f"{SUPABASE_KEY_VAR} is not set. Required when STORAGE_BACKEND=supabase."
        )
    return value


def get_view_password() -> str | None:
    return _lookup(VIEW_PASSWORD_VAR)


def get_upload_password() -> str | None:
    return _lookup(UPLOAD_PASSWORD_VAR)


def access_control_configured() -> bool:
    """True if at least one password is set.

    When neither is set the app runs open, which is correct for local development and must never
    be the case in a deployment. The UI says so loudly.
    """
    return bool(get_view_password() or get_upload_password())


def has_api_key() -> bool:
    """True if a key is configured. Used to disable LLM features without raising."""
    return _lookup(API_KEY_VAR) is not None

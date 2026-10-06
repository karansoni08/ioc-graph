"""Provider selection.

One place that knows which providers exist, so adding Ollama later is a single new branch.
"""

from __future__ import annotations

from functools import lru_cache

from .base import LLMProvider

KNOWN_PROVIDERS = ("anthropic",)


@lru_cache(maxsize=4)
def get_provider(name: str = "anthropic") -> LLMProvider:
    """Return a provider by name. Cached so the SDK client is reused across reruns."""
    if name == "anthropic":
        # Imported here so that a future provider does not pull in the Anthropic SDK.
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider()
    raise ValueError(f"Unknown LLM provider '{name}'. Known providers: {KNOWN_PROVIDERS}.")

"""The provider-agnostic LLM interface.

Everything above this layer talks to `LLMProvider` only, so a second provider (Ollama, for
example) can be added without touching the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class LLMError(RuntimeError):
    """A provider call failed in a way the caller should handle, not crash on."""


@dataclass
class LLMResponse:
    """One completed model call.

    `data` is the parsed JSON object. Token counts drive cost reporting, so they are part of
    the interface rather than provider-specific extras.
    """

    data: dict[str, Any]
    input_tokens: int
    output_tokens: int
    model: str
    latency_ms: int
    stop_reason: str | None = None
    raw_text: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        """True if the model ran out of output budget, which usually means invalid JSON."""
        return self.stop_reason == "max_tokens"


class LLMProvider(Protocol):
    """Minimal surface the pipeline needs.

    Deliberately narrow: one method, no tools, no streaming. Agent mode in Phase 6 adds its
    own loop rather than widening this, so the pipeline provider can never gain tool access.
    """

    name: str

    def extract_structured(
        self,
        system: str,
        user: str,
        schema: dict[str, Any],
        model: str,
        max_tokens: int = 4000,
    ) -> LLMResponse:
        """Return JSON matching `schema`. Raises `LLMError` on failure."""
        ...

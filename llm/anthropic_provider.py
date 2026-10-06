"""Anthropic implementation of `LLMProvider`.

Output format mechanism
-----------------------
This uses native structured outputs: `output_config={"format": {"type": "json_schema",
"schema": ...}}` on `messages.create`. Verified against the installed SDK (anthropic 1.11.0)
on 2026-10-06.

This is preferred over the forced-tool trick that older code uses for JSON, for two reasons.
It is the current documented mechanism — the older `output_format` parameter is deprecated —
and forced `tool_choice` ("any"/"tool") is now rejected outright by several current models, so
a forced-tool approach would break on a model upgrade. It also keeps CLAUDE.md's rule intact
in the strongest possible way: in pipeline mode the model is given **no tools at all**, not
even a format-only one, so there is nothing to execute and no tool surface to misuse.

The key is read through `config.get_api_key()` at first use and never logged. Request bodies
contain untrusted report text and are never logged either.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import anthropic

from config import get_api_key

from .base import LLMError, LLMProvider, LLMResponse

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 3


class AnthropicProvider(LLMProvider):
    """Calls the Anthropic Messages API with a JSON schema constraint."""

    name = "anthropic"

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: anthropic.Anthropic | None = None

    def _get_client(self) -> anthropic.Anthropic:
        """Create the client on first use.

        Lazy so that importing this module, or running the app with no key configured, does
        not fail: the key is only needed when a call is actually made.
        """
        if self._client is None:
            self._client = anthropic.Anthropic(
                api_key=get_api_key(),
                timeout=self._timeout,
                # The SDK retries 429 and 5xx with exponential backoff for us.
                max_retries=self._max_retries,
            )
        return self._client

    def extract_structured(
        self,
        system: str,
        user: str,
        schema: dict[str, Any],
        model: str,
        max_tokens: int = 4000,
    ) -> LLMResponse:
        client = self._get_client()
        started = time.monotonic()

        try:
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                # Native structured outputs. No `tools` key at all: see the module docstring.
                output_config={"format": {"type": "json_schema", "schema": schema}},
            )
        except anthropic.APIStatusError as exc:
            # exc.message never contains the key; the request body is not included.
            raise LLMError(f"Anthropic API error ({exc.status_code}): {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError("Could not reach the Anthropic API. Check the connection.") from exc

        latency_ms = int((time.monotonic() - started) * 1000)

        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )

        stop_reason = response.stop_reason

        # A safety decline returns HTTP 200, so stop_reason must be checked before the body.
        if stop_reason == "refusal":
            raise LLMError(
                "The model declined to process this content. "
                "This can happen with some security report text."
            )

        if stop_reason == "max_tokens":
            raise LLMError(
                "The model hit its output limit before finishing, so the result was "
                "incomplete. Try a smaller chunk or a higher max_tokens."
            )

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # Surfaced so the orchestrator can do its single retry.
            raise LLMError(f"Model did not return valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise LLMError("Model returned JSON that is not an object.")

        logger.debug(
            "anthropic call complete model=%s in=%s out=%s ms=%s",
            model,
            response.usage.input_tokens,
            response.usage.output_tokens,
            latency_ms,
        )

        return LLMResponse(
            data=data,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=response.model,
            latency_ms=latency_ms,
            stop_reason=stop_reason,
            raw_text=text,
        )

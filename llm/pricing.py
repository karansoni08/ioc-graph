"""Model prices, used for cost estimates shown before and after every call.

Prices verified against Anthropic's published pricing on 2026-10-06, in US dollars per
million tokens. Re-check them when adding a model: an out-of-date table silently misreports
spend, and Phase 7 enforces a daily spend cap using these numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PRICES_VERIFIED = "2026-10-06"


@dataclass(frozen=True)
class ModelPrice:
    """Dollars per million tokens."""

    input_per_mtok: float
    output_per_mtok: float


# Keyed by canonical model id, without any date suffix.
PRICE_TABLE: dict[str, ModelPrice] = {
    "claude-haiku-4-5": ModelPrice(1.00, 5.00),
    "claude-sonnet-5-5": ModelPrice(2.00, 10.00),
    "claude-sonnet-5": ModelPrice(2.00, 10.00),
    "claude-opus-5-5": ModelPrice(4.00, 20.00),
    "claude-opus-5": ModelPrice(5.00, 25.00),
    "claude-fable-5-1": ModelPrice(10.00, 50.00),
    "claude-fable-5": ModelPrice(10.00, 50.00),
}

# Used when a model is not in the table. Deliberately the most expensive current rate so an
# unknown model over-estimates rather than under-estimates, which keeps the spend cap safe.
FALLBACK_PRICE = ModelPrice(10.00, 50.00)

_DATE_SUFFIX = re.compile(r"-\d{8}$")


def canonical_model(model: str) -> str:
    """Strip a trailing date suffix from a model id.

    Current Anthropic model ids carry no date suffix, but older configs (and this project's
    own default, `claude-haiku-4-5-20251001`) do. Normalizing means pricing still resolves.
    """
    return _DATE_SUFFIX.sub("", model.strip())


def get_price(model: str) -> ModelPrice:
    return PRICE_TABLE.get(canonical_model(model), FALLBACK_PRICE)


def is_known_model(model: str) -> bool:
    return canonical_model(model) in PRICE_TABLE


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Cost in US dollars for a call with the given token counts."""
    price = get_price(model)
    return (
        input_tokens / 1_000_000 * price.input_per_mtok
        + output_tokens / 1_000_000 * price.output_per_mtok
    )


def format_cost(cost: float) -> str:
    """Render a cost for the UI, without pretending to more precision than we have."""
    if cost == 0:
        return "$0.00"
    if cost < 0.01:
        return f"${cost:.4f}"
    return f"${cost:.2f}"

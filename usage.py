"""Daily usage caps.

The reservation pattern, and why it is this way round: the estimated *maximum* cost is reserved
**before** the call, then settled down to the actual cost afterwards. Reserving the estimate first
means a burst of simultaneous requests cannot collectively overshoot the cap, which is what would
happen if spend were only recorded after each call completed. Settling afterwards means the day's
recorded spend converges on the truth rather than staying at the worst case.

The check itself is atomic inside Postgres (`reserve_usage`), because doing it in Python is a
race: two sessions can both read "19 of 20 used" and both proceed.

On the local backend there are no caps. Local development is a single user on their own key, and
adding a cap there would only get in the way; the deployed app is where the shared link lives.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from config import Settings

KIND_REPORT = "report"
KIND_AGENT = "agent"


@dataclass
class Reservation:
    """The outcome of asking permission to spend."""

    allowed: bool
    kind: str
    estimated_cost: float
    day: str
    reason: str = ""
    enforced: bool = True

    @property
    def needs_settling(self) -> bool:
        return self.allowed and self.enforced


def today_key(settings: Settings) -> str:
    """Today's date in the app's configured timezone.

    The cap resets at local midnight, so the timezone has to be the app's, not the server's.
    """
    try:
        from zoneinfo import ZoneInfo

        return datetime.now(ZoneInfo(settings.app_timezone)).date().isoformat()
    except Exception:
        # An unknown timezone must not break the cap; UTC is a safe fallback.
        return date.today().isoformat()


def _supports_usage(store: Any) -> bool:
    return hasattr(store, "reserve_usage") and hasattr(store, "settle_usage")


def usage_summary(store: Any, settings: Settings) -> dict[str, Any] | None:
    """Today's counts, or None when the backend does not track usage."""
    if not hasattr(store, "get_usage"):
        return None
    return store.get_usage(today_key(settings))


def reserve(
    store: Any, settings: Settings, kind: str, estimated_cost: float
) -> Reservation:
    """Ask permission to spend. Call this before any LLM request."""
    day = today_key(settings)

    if not _supports_usage(store):
        # Local backend: no caps, and say so rather than pretending one was checked.
        return Reservation(
            allowed=True, kind=kind, estimated_cost=estimated_cost, day=day, enforced=False
        )

    try:
        allowed = store.reserve_usage(
            day,
            kind,
            estimated_cost,
            settings.daily_report_limit,
            settings.daily_agent_limit,
            settings.daily_spend_limit_usd,
        )
    except Exception as exc:  # noqa: BLE001
        # Fail CLOSED: if the cap cannot be checked, do not spend. The alternative is an
        # unbounded bill whenever the database is unreachable.
        return Reservation(
            allowed=False,
            kind=kind,
            estimated_cost=estimated_cost,
            day=day,
            reason=f"The usage limit could not be checked, so the request was blocked: {exc}",
        )

    if allowed:
        return Reservation(allowed=True, kind=kind, estimated_cost=estimated_cost, day=day)

    return Reservation(
        allowed=False,
        kind=kind,
        estimated_cost=estimated_cost,
        day=day,
        reason=limit_message(settings, kind),
    )


def settle(store: Any, reservation: Reservation, actual_cost: float) -> None:
    """Adjust the reserved estimate to what was really spent."""
    if not reservation.needs_settling or not _supports_usage(store):
        return
    delta = actual_cost - reservation.estimated_cost
    store.settle_usage(reservation.day, delta)


def limit_message(settings: Settings, kind: str) -> str:
    """What to tell the user when a cap blocks them."""
    which = "agent runs" if kind == KIND_AGENT else "reports"
    limit = (
        settings.daily_agent_limit if kind == KIND_AGENT else settings.daily_report_limit
    )
    return (
        f"A daily limit was reached ({which}: {limit} per day, or the "
        f"${settings.daily_spend_limit_usd:.2f} daily spend cap). "
        f"Limits reset at midnight {settings.app_timezone}."
    )

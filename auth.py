"""Single shared-password access control.

One password gates the whole app. Enter it and you get everything; without it nothing renders.

This replaced a two-password design that split browsing from spending. The simpler model is what
the owner wanted, and the trade is explicit: **everyone who gets in can spend API credits**, so
the daily caps in `usage.py` are now the only thing limiting what a shared link can cost.

The password is compared with `hmac.compare_digest`, which takes the same time whether the first
character differs or the last. A plain `==` leaks the length of the matching prefix through
timing, which over many attempts is enough to recover the password.

The gate **fails closed**: if no password is configured the app refuses to serve rather than
opening. That is not a theoretical nicety — the first deployment of this project went live on a
public URL with no gate and a working API key, because the previous version fell open when
unconfigured.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass

import streamlit as st

from config import access_control_configured, get_app_password

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
FAILED_ATTEMPT_DELAY_SECONDS = 1.0

_SESSION_AUTHED = "auth_ok"
_SESSION_ATTEMPTS = "auth_attempts"
_SESSION_LOCKED_UNTIL = "auth_locked_until"


@dataclass
class Access:
    """Granted access. With a single password there is only one level."""

    authenticated: bool = True

    @property
    def can_upload(self) -> bool:
        return True

    @property
    def can_spend(self) -> bool:
        """Anyone who is in can spend. The daily caps are the limit, not the role."""
        return True


def check_password(candidate: str) -> bool:
    """Timing-safe comparison against the configured password."""
    expected = get_app_password()
    if not expected or not candidate:
        # An unset password must never be matchable, least of all by empty input.
        return False
    return hmac.compare_digest(candidate, expected)


def is_authenticated() -> bool:
    return bool(st.session_state.get(_SESSION_AUTHED))


def _locked_remaining() -> int:
    remaining = st.session_state.get(_SESSION_LOCKED_UNTIL, 0.0) - time.time()
    return int(remaining) if remaining > 0 else 0


def _render_not_configured() -> None:
    """Shown when no password is set. The app must not open in this state."""
    st.title("IOC Graph")
    st.error(
        "This app is not configured and will not open.\n\n"
        "No APP_PASSWORD is set, so there is nothing protecting it. "
        "Add one to the app's secrets and reload."
    )
    st.caption(
        "Streamlit Community Cloud: Manage app → Settings → Secrets. "
        "Locally: put APP_PASSWORD in .env."
    )


def _render_login() -> None:
    st.title("IOC Graph")
    st.caption("This workspace is private. Enter the access password to continue.")

    remaining = _locked_remaining()
    if remaining:
        minutes, seconds = divmod(remaining, 60)
        st.error(f"Too many failed attempts. Try again in {minutes}m {seconds:02d}s.")
        return

    with st.form("login"):
        candidate = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Enter")

    if not submitted:
        return

    if not check_password(candidate):
        # A fixed delay on every failure slows guessing and costs a legitimate user one second.
        time.sleep(FAILED_ATTEMPT_DELAY_SECONDS)
        attempts = st.session_state.get(_SESSION_ATTEMPTS, 0) + 1
        st.session_state[_SESSION_ATTEMPTS] = attempts
        if attempts >= MAX_ATTEMPTS:
            st.session_state[_SESSION_LOCKED_UNTIL] = time.time() + LOCKOUT_SECONDS
            st.session_state[_SESSION_ATTEMPTS] = 0
            st.error(
                f"Too many failed attempts. This session is locked for "
                f"{LOCKOUT_SECONDS // 60} minutes."
            )
        else:
            st.error(f"Incorrect password. {MAX_ATTEMPTS - attempts} attempt(s) remaining.")
        return

    st.session_state[_SESSION_AUTHED] = True
    st.session_state[_SESSION_ATTEMPTS] = 0
    st.rerun()


def require_access() -> Access:
    """Gate a page. Call this before rendering anything else.

    Renders the gate and calls `st.stop()` when access is not granted, so anything after this
    call only ever runs for an authenticated session.
    """
    if not access_control_configured():
        # Misconfiguration, not a failed login. Deliberately no form: offering one when nothing
        # is configured invites an empty password to be treated as valid.
        _render_not_configured()
        st.stop()

    if not is_authenticated():
        _render_login()
        st.stop()

    access = Access()
    render_sidebar(access)
    return access


def render_sidebar(access: Access) -> None:
    """Log out.

    This used to also show today's reports / agent runs / spend as a four-line block. That moved
    to a one-line strip at the top of the graph page (`render_usage_strip`), which is where it is
    actually looked at. The caps themselves are untouched and still enforced in `usage.reserve`
    before anything spends; the same numbers are also available from the command line with
    `python scripts/maintain.py usage`.
    """
    with st.sidebar:
        if st.button("Log out"):
            for key in (_SESSION_AUTHED, _SESSION_ATTEMPTS, _SESSION_LOCKED_UNTIL):
                st.session_state.pop(key, None)
            st.rerun()


def render_usage_strip() -> None:
    """Today's usage against the daily caps, as one compact line at the top of the page.

    Deliberately built from a native widget rather than a styled HTML bar. A true
    `position: sticky` strip needs injected CSS, and this repo bans `unsafe_allow_html` and
    `st.html` outright — the ban is mechanical (a test fails the build) precisely so it cannot be
    eroded one cosmetic exception at a time. So this sits at the top of the page rather than
    following the scroll.

    Every value is produced by this app's own storage and formatted as a number here, so no
    report- or model-derived text can reach the renderer.
    """
    from config import get_settings
    from storage.factory import get_store
    from usage import today_key, usage_summary

    settings = get_settings()
    try:
        summary = usage_summary(get_store(settings), settings)
    except Exception:
        # The usage readout must never be the reason a page fails to load.
        return
    if summary is None:
        return

    # Spend is labelled "USD" rather than written with "$". st.caption renders markdown, and
    # Streamlit treats a $...$ span as inline LaTeX, so "$0.00/$2.00" lost both signs and set the
    # numbers in math italics. A backslash escape did not survive that preprocessing either, so
    # the currency is named instead of symbolised.
    st.caption(
        f"{today_key(settings)}  ·  "
        f"reports {int(summary['reports'])}/{settings.daily_report_limit}  ·  "
        f"agents {int(summary['agent_runs'])}/{settings.daily_agent_limit}  ·  "
        f"spend {float(summary['spend_usd']):.2f}/"
        f"{settings.daily_spend_limit_usd:.2f} USD"
    )

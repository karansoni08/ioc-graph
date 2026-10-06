"""Shared-password access control.

Two passwords, two roles. `view` can browse the graph and read everything; `upload` can also
ingest reports, run the agent and generate summaries — anything that spends API credits. The
split exists because the link is shared with several people but the API key belongs to one of
them.

Passwords are compared with `hmac.compare_digest`, which takes the same time whether the first
character differs or only the last. A plain `==` leaks the length of the matching prefix through
timing, which over many attempts is enough to recover a password.

This is not a user system. There are no accounts, no password hashing at rest (the passwords live
in secrets, not in a database), and no per-user data. It is a door, and `docs/SECURITY.md` records
exactly what that does and does not buy.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass

import streamlit as st

from config import access_control_configured, get_upload_password, get_view_password

ROLE_VIEW = "view"
ROLE_UPLOAD = "upload"
ROLE_OPEN = "open"

# Role ordering for permission checks.
_RANK = {ROLE_VIEW: 1, ROLE_UPLOAD: 2, ROLE_OPEN: 2}

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
FAILED_ATTEMPT_DELAY_SECONDS = 1.0

_SESSION_ROLE = "auth_role"
_SESSION_ATTEMPTS = "auth_attempts"
_SESSION_LOCKED_UNTIL = "auth_locked_until"


@dataclass
class Access:
    role: str

    @property
    def can_upload(self) -> bool:
        return self.role in (ROLE_UPLOAD, ROLE_OPEN)

    @property
    def can_spend(self) -> bool:
        """Spending API credits is the thing the view role must not be able to do."""
        return self.can_upload


def _check_password(candidate: str) -> str | None:
    """Return the role the password grants, or None.

    Both passwords are always compared, even after the first matches, so the time taken does not
    reveal which one was correct.
    """
    upload_password = get_upload_password()
    view_password = get_view_password()

    upload_match = bool(
        upload_password and hmac.compare_digest(candidate, upload_password)
    )
    view_match = bool(view_password and hmac.compare_digest(candidate, view_password))

    if upload_match:
        return ROLE_UPLOAD
    if view_match:
        return ROLE_VIEW
    return None


def _locked_remaining() -> int:
    locked_until = st.session_state.get(_SESSION_LOCKED_UNTIL, 0.0)
    remaining = locked_until - time.time()
    return int(remaining) if remaining > 0 else 0


def current_role() -> str | None:
    if not access_control_configured():
        return ROLE_OPEN
    return st.session_state.get(_SESSION_ROLE)


def _render_login() -> None:
    st.title("IOC Graph")
    st.caption("This workspace is private. Enter the access password to continue.")

    remaining = _locked_remaining()
    if remaining:
        minutes, seconds = divmod(remaining, 60)
        st.error(
            f"Too many failed attempts. Try again in {minutes}m {seconds:02d}s."
        )
        return

    with st.form("login"):
        candidate = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Enter")

    if not submitted:
        return

    role = _check_password(candidate)
    if role is None:
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

    st.session_state[_SESSION_ROLE] = role
    st.session_state[_SESSION_ATTEMPTS] = 0
    st.rerun()


def require_access(min_role: str = ROLE_VIEW) -> Access:
    """Gate a page. Call this before rendering anything else.

    Renders the login form and calls `st.stop()` when access is insufficient, so a page body
    after this call only ever runs for an authorized session.
    """
    role = current_role()

    if role is None:
        _render_login()
        st.stop()

    if _RANK.get(role, 0) < _RANK.get(min_role, 99):
        st.title("Not available")
        st.warning(
            "This page needs the upload password. You are signed in with view access, which can "
            "browse the graph but cannot run anything that spends API credits."
        )
        render_sidebar(Access(role))
        st.stop()

    access = Access(role)
    render_sidebar(access)
    return access


def render_sidebar(access: Access) -> None:
    """Role badge, usage, and log out."""
    with st.sidebar:
        if access.role == ROLE_OPEN:
            st.warning(
                "No password is configured, so this app is OPEN. Set VIEW_PASSWORD and "
                "UPLOAD_PASSWORD before deploying."
            )
        else:
            label = "Upload access" if access.can_upload else "View access"
            st.caption(label)
            if not access.can_upload:
                st.caption("Read-only: features that spend API credits are hidden.")

        render_usage_widget()

        if access.role != ROLE_OPEN:
            if st.button("Log out"):
                for key in (_SESSION_ROLE, _SESSION_ATTEMPTS, _SESSION_LOCKED_UNTIL):
                    st.session_state.pop(key, None)
                st.rerun()


def render_usage_widget() -> None:
    """Today's usage against the daily caps. Only meaningful on the Supabase backend."""
    from config import get_settings
    from storage.factory import get_store
    from usage import today_key, usage_summary

    settings = get_settings()
    try:
        store = get_store(settings)
        summary = usage_summary(store, settings)
    except Exception:
        return
    if summary is None:
        return

    st.caption(f"Today ({today_key(settings)})")
    st.text(
        f"reports    {summary['reports']}/{settings.daily_report_limit}\n"
        f"agent runs {summary['agent_runs']}/{settings.daily_agent_limit}\n"
        f"spend      ${float(summary['spend_usd']):.2f}/${settings.daily_spend_limit_usd:.2f}"
    )

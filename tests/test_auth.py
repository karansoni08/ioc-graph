"""Behavioural tests for the access gate.

`auth.py` decides who can spend the owner's API credits, so it needs real tests rather than only
the source-text assertions in `test_concurrency.py`. Streamlit is replaced with a stub exposing a
dict `session_state` and no-op widgets, which is enough to drive every branch: the interesting
logic is password comparison, role ranking and lockout, none of which needs a browser.
"""

from __future__ import annotations

import time
import types

import pytest

import auth
from auth import ROLE_OPEN, ROLE_UPLOAD, ROLE_VIEW, Access

VIEW_PASSWORD = "view-password-for-tests"
UPLOAD_PASSWORD = "upload-password-for-tests"


class StopCalled(Exception):
    """Raised by the stub's `st.stop()` so gating can be observed."""


class RerunCalled(Exception):
    """Raised by the stub's `st.rerun()`."""


class _Sidebar:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_streamlit_stub(submitted: bool = False, password: str = "") -> types.SimpleNamespace:
    """A Streamlit stand-in with just enough surface for auth.py."""
    state: dict = {}

    def noop(*args, **kwargs):
        return None

    def stop():
        raise StopCalled()

    def rerun():
        raise RerunCalled()

    class _Form:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return types.SimpleNamespace(
        session_state=state,
        sidebar=_Sidebar(),
        form=lambda *a, **k: _Form(),
        text_input=lambda *a, **k: password,
        form_submit_button=lambda *a, **k: submitted,
        button=lambda *a, **k: False,
        title=noop,
        caption=noop,
        error=noop,
        warning=noop,
        info=noop,
        success=noop,
        text=noop,
        stop=stop,
        rerun=rerun,
    )


@pytest.fixture
def passwords(monkeypatch):
    monkeypatch.setenv("VIEW_PASSWORD", VIEW_PASSWORD)
    monkeypatch.setenv("UPLOAD_PASSWORD", UPLOAD_PASSWORD)
    return VIEW_PASSWORD, UPLOAD_PASSWORD


@pytest.fixture
def no_passwords(monkeypatch):
    monkeypatch.delenv("VIEW_PASSWORD", raising=False)
    monkeypatch.delenv("UPLOAD_PASSWORD", raising=False)


@pytest.fixture
def st_stub(monkeypatch):
    stub = make_streamlit_stub()
    monkeypatch.setattr(auth, "st", stub)
    return stub


class TestPasswordCheck:
    def test_upload_password_grants_upload(self, passwords) -> None:
        assert auth._check_password(UPLOAD_PASSWORD) == ROLE_UPLOAD

    def test_view_password_grants_view(self, passwords) -> None:
        assert auth._check_password(VIEW_PASSWORD) == ROLE_VIEW

    def test_wrong_password_grants_nothing(self, passwords) -> None:
        assert auth._check_password("not-the-password") is None

    def test_empty_password_grants_nothing(self, passwords) -> None:
        assert auth._check_password("") is None

    def test_prefix_of_a_real_password_is_rejected(self, passwords) -> None:
        """Guards against any accidental startswith/prefix comparison."""
        assert auth._check_password(UPLOAD_PASSWORD[:-1]) is None
        assert auth._check_password(UPLOAD_PASSWORD + "x") is None

    def test_case_differences_are_rejected(self, passwords) -> None:
        assert auth._check_password(UPLOAD_PASSWORD.upper()) is None

    def test_unset_password_cannot_be_matched_by_empty_input(self, monkeypatch) -> None:
        """A missing password must not become a blank password that anything matches."""
        monkeypatch.delenv("UPLOAD_PASSWORD", raising=False)
        monkeypatch.setenv("VIEW_PASSWORD", VIEW_PASSWORD)
        assert auth._check_password("") is None
        assert auth._check_password(VIEW_PASSWORD) == ROLE_VIEW

    def test_upload_wins_when_both_passwords_are_identical(self, monkeypatch) -> None:
        """A misconfiguration, but it must resolve to one role deterministically."""
        monkeypatch.setenv("VIEW_PASSWORD", "same")
        monkeypatch.setenv("UPLOAD_PASSWORD", "same")
        assert auth._check_password("same") == ROLE_UPLOAD


class TestAccessRoles:
    def test_upload_can_upload_and_spend(self) -> None:
        access = Access(ROLE_UPLOAD)
        assert access.can_upload is True
        assert access.can_spend is True

    def test_view_cannot_upload_or_spend(self) -> None:
        access = Access(ROLE_VIEW)
        assert access.can_upload is False
        assert access.can_spend is False

    def test_open_mode_can_do_everything(self) -> None:
        access = Access(ROLE_OPEN)
        assert access.can_upload is True
        assert access.can_spend is True


class TestCurrentRole:
    def test_no_password_configured_is_refused_by_default(self, no_passwords, st_stub, monkeypatch) -> None:
        """Fail CLOSED. A deployment that forgets its secrets must not open to the internet."""
        monkeypatch.delenv("ALLOW_OPEN_ACCESS", raising=False)
        import config

        config.get_settings.cache_clear()
        try:
            assert auth.current_role() is None
        finally:
            config.get_settings.cache_clear()

    def test_open_access_requires_an_explicit_opt_in(self, no_passwords, st_stub, monkeypatch) -> None:
        monkeypatch.setenv("ALLOW_OPEN_ACCESS", "true")
        import config

        config.get_settings.cache_clear()
        try:
            assert auth.current_role() == ROLE_OPEN
        finally:
            config.get_settings.cache_clear()

    def test_configured_but_not_signed_in_means_none(self, passwords, st_stub) -> None:
        assert auth.current_role() is None

    def test_signed_in_role_is_returned(self, passwords, st_stub) -> None:
        st_stub.session_state[auth._SESSION_ROLE] = ROLE_VIEW
        assert auth.current_role() == ROLE_VIEW


class TestGating:
    def test_unauthenticated_access_is_stopped(self, passwords, monkeypatch) -> None:
        monkeypatch.setattr(auth, "st", make_streamlit_stub())
        with pytest.raises(StopCalled):
            auth.require_access(ROLE_VIEW)

    def test_view_role_is_stopped_on_an_upload_page(self, passwords, monkeypatch) -> None:
        """The central authorization check: view must not reach an upload-only page."""
        stub = make_streamlit_stub()
        stub.session_state[auth._SESSION_ROLE] = ROLE_VIEW
        monkeypatch.setattr(auth, "st", stub)
        with pytest.raises(StopCalled):
            auth.require_access(ROLE_UPLOAD)

    def test_view_role_passes_a_view_page(self, passwords, monkeypatch) -> None:
        stub = make_streamlit_stub()
        stub.session_state[auth._SESSION_ROLE] = ROLE_VIEW
        monkeypatch.setattr(auth, "st", stub)
        access = auth.require_access(ROLE_VIEW)
        assert access.role == ROLE_VIEW
        assert access.can_spend is False

    def test_upload_role_passes_both_page_kinds(self, passwords, monkeypatch) -> None:
        for minimum in (ROLE_VIEW, ROLE_UPLOAD):
            stub = make_streamlit_stub()
            stub.session_state[auth._SESSION_ROLE] = ROLE_UPLOAD
            monkeypatch.setattr(auth, "st", stub)
            assert auth.require_access(minimum).can_upload is True

    def test_unconfigured_app_refuses_to_serve(self, no_passwords, monkeypatch) -> None:
        """The regression that matters: this app was once deployed publicly with no gate."""
        monkeypatch.delenv("ALLOW_OPEN_ACCESS", raising=False)
        import config

        config.get_settings.cache_clear()
        monkeypatch.setattr(auth, "st", make_streamlit_stub())
        try:
            with pytest.raises(StopCalled):
                auth.require_access(ROLE_VIEW)
        finally:
            config.get_settings.cache_clear()

    def test_unconfigured_app_shows_no_login_form(self, no_passwords, monkeypatch) -> None:
        """It must not present a form that would accept an empty password."""
        monkeypatch.delenv("ALLOW_OPEN_ACCESS", raising=False)
        import config

        config.get_settings.cache_clear()
        stub = make_streamlit_stub(submitted=True, password="")
        monkeypatch.setattr(auth, "st", stub)
        try:
            with pytest.raises(StopCalled):
                auth.require_access(ROLE_VIEW)
            assert auth._SESSION_ROLE not in stub.session_state
        finally:
            config.get_settings.cache_clear()

    def test_open_mode_passes_with_the_explicit_opt_in(self, no_passwords, monkeypatch) -> None:
        monkeypatch.setenv("ALLOW_OPEN_ACCESS", "true")
        import config

        config.get_settings.cache_clear()
        monkeypatch.setattr(auth, "st", make_streamlit_stub())
        try:
            assert auth.require_access(ROLE_UPLOAD).role == ROLE_OPEN
        finally:
            config.get_settings.cache_clear()


class TestLoginFlow:
    def _login(self, monkeypatch, password: str):
        stub = make_streamlit_stub(submitted=True, password=password)
        monkeypatch.setattr(auth, "st", stub)
        # A successful login ends in st.rerun(); a failure returns normally.
        try:
            auth._render_login()
        except RerunCalled:
            pass
        return stub

    def test_correct_password_sets_the_role(self, passwords, monkeypatch) -> None:
        stub = self._login(monkeypatch, UPLOAD_PASSWORD)
        assert stub.session_state[auth._SESSION_ROLE] == ROLE_UPLOAD

    def test_wrong_password_sets_no_role_and_counts_the_attempt(
        self, passwords, monkeypatch
    ) -> None:
        stub = self._login(monkeypatch, "wrong")
        assert auth._SESSION_ROLE not in stub.session_state
        assert stub.session_state[auth._SESSION_ATTEMPTS] == 1

    def test_lockout_after_five_failures(self, passwords, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password="wrong")
        monkeypatch.setattr(auth, "st", stub)
        # Remove the per-failure sleep so the test does not take five seconds.
        monkeypatch.setattr(auth, "FAILED_ATTEMPT_DELAY_SECONDS", 0)

        for _ in range(auth.MAX_ATTEMPTS):
            auth._render_login()

        locked_until = stub.session_state.get(auth._SESSION_LOCKED_UNTIL, 0)
        assert locked_until > time.time()
        assert auth._SESSION_ROLE not in stub.session_state

    def test_correct_password_is_refused_while_locked(self, passwords, monkeypatch) -> None:
        """The lockout must hold even against the right password."""
        stub = make_streamlit_stub(submitted=True, password=UPLOAD_PASSWORD)
        stub.session_state[auth._SESSION_LOCKED_UNTIL] = time.time() + 300
        monkeypatch.setattr(auth, "st", stub)

        auth._render_login()
        assert auth._SESSION_ROLE not in stub.session_state

    def test_lockout_expires(self, passwords, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password=UPLOAD_PASSWORD)
        stub.session_state[auth._SESSION_LOCKED_UNTIL] = time.time() - 1
        monkeypatch.setattr(auth, "st", stub)
        try:
            auth._render_login()
        except RerunCalled:
            pass
        assert stub.session_state[auth._SESSION_ROLE] == ROLE_UPLOAD

    def test_successful_login_resets_the_attempt_counter(self, passwords, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password=UPLOAD_PASSWORD)
        stub.session_state[auth._SESSION_ATTEMPTS] = 3
        monkeypatch.setattr(auth, "st", stub)
        try:
            auth._render_login()
        except RerunCalled:
            pass
        assert stub.session_state[auth._SESSION_ATTEMPTS] == 0

    def test_nothing_happens_until_the_form_is_submitted(self, passwords, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=False, password=UPLOAD_PASSWORD)
        monkeypatch.setattr(auth, "st", stub)
        auth._render_login()
        assert auth._SESSION_ROLE not in stub.session_state


class TestConfiguredPasswords:
    """Checks against the passwords actually configured for this project."""

    def test_both_roles_are_configured(self) -> None:
        from config import get_upload_password, get_view_password

        assert get_view_password(), "VIEW_PASSWORD is not set"
        assert get_upload_password(), "UPLOAD_PASSWORD is not set"

    def test_the_two_passwords_are_different(self) -> None:
        """Identical passwords would collapse the two roles into one."""
        from config import get_upload_password, get_view_password

        assert get_view_password() != get_upload_password()

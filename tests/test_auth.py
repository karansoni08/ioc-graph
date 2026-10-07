"""Behavioural tests for the single-password access gate.

`auth.py` is the only thing standing between a public URL and an API key that spends real money,
so it is tested directly rather than by inspection. Streamlit is replaced with a stub exposing a
dict `session_state` and no-op widgets: the logic that matters is password comparison, the
fail-closed path and lockout, none of which needs a browser.
"""

from __future__ import annotations

import time
import types
from pathlib import Path

import pytest

import auth
import config

PASSWORD = "a-twenty-char-test-pw"


class StopCalled(Exception):
    """Raised by the stub's `st.stop()` so gating can be observed."""


class RerunCalled(Exception):
    """Raised by the stub's `st.rerun()`."""


class _Ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_streamlit_stub(submitted: bool = False, password: str = "") -> types.SimpleNamespace:
    state: dict = {}

    def noop(*args, **kwargs):
        return None

    def stop():
        raise StopCalled()

    def rerun():
        raise RerunCalled()

    return types.SimpleNamespace(
        session_state=state,
        sidebar=_Ctx(),
        form=lambda *a, **k: _Ctx(),
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
def configured(monkeypatch):
    monkeypatch.setenv("APP_PASSWORD", PASSWORD)
    return PASSWORD


@pytest.fixture
def unconfigured(monkeypatch):
    monkeypatch.delenv("APP_PASSWORD", raising=False)


@pytest.fixture
def st_stub(monkeypatch):
    stub = make_streamlit_stub()
    monkeypatch.setattr(auth, "st", stub)
    return stub


class TestPasswordCheck:
    def test_correct_password_is_accepted(self, configured) -> None:
        assert auth.check_password(PASSWORD) is True

    def test_wrong_password_is_rejected(self, configured) -> None:
        assert auth.check_password("not-the-password") is False

    def test_empty_input_is_rejected(self, configured) -> None:
        assert auth.check_password("") is False

    def test_prefix_and_suffix_are_rejected(self, configured) -> None:
        """Guards against any accidental startswith or substring comparison."""
        assert auth.check_password(PASSWORD[:-1]) is False
        assert auth.check_password(PASSWORD + "x") is False

    def test_case_differences_are_rejected(self, configured) -> None:
        assert auth.check_password(PASSWORD.upper()) is False

    def test_unset_password_cannot_be_matched(self, unconfigured) -> None:
        """A missing password must not become a blank one that anything matches."""
        assert auth.check_password("") is False
        assert auth.check_password("anything") is False

    def test_comparison_is_timing_safe(self) -> None:
        """Asserted by reading the source, so a later simplification to `==` fails the build."""
        source = Path("auth.py").read_text(encoding="utf-8")
        assert "hmac.compare_digest" in source
        assert "candidate ==" not in source
        assert "== expected" not in source


class TestFailClosed:
    """The regression that matters: this app was once deployed publicly with no gate."""

    def test_unconfigured_app_refuses_to_serve(self, unconfigured, monkeypatch) -> None:
        monkeypatch.setattr(auth, "st", make_streamlit_stub())
        with pytest.raises(StopCalled):
            auth.require_access()

    def test_unconfigured_app_offers_no_password_form(self, unconfigured, monkeypatch) -> None:
        """Offering a form when nothing is configured invites an empty password to pass."""
        stub = make_streamlit_stub(submitted=True, password="")
        monkeypatch.setattr(auth, "st", stub)
        with pytest.raises(StopCalled):
            auth.require_access()
        assert auth._SESSION_AUTHED not in stub.session_state

    def test_there_is_no_open_mode(self) -> None:
        """An escape hatch would eventually be set in a deployment by accident."""
        source = Path("auth.py").read_text(encoding="utf-8")
        assert "ALLOW_OPEN_ACCESS" not in source
        assert not hasattr(config.Settings(), "allow_open_access")


class TestGating:
    def test_unauthenticated_session_is_stopped(self, configured, monkeypatch) -> None:
        monkeypatch.setattr(auth, "st", make_streamlit_stub())
        with pytest.raises(StopCalled):
            auth.require_access()

    def test_authenticated_session_passes(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub()
        stub.session_state[auth._SESSION_AUTHED] = True
        monkeypatch.setattr(auth, "st", stub)
        access = auth.require_access()
        assert access.can_upload is True
        assert access.can_spend is True

    def test_a_truthy_session_value_is_required(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub()
        stub.session_state[auth._SESSION_AUTHED] = False
        monkeypatch.setattr(auth, "st", stub)
        with pytest.raises(StopCalled):
            auth.require_access()


class TestLoginFlow:
    def _login(self, monkeypatch, password: str):
        stub = make_streamlit_stub(submitted=True, password=password)
        monkeypatch.setattr(auth, "st", stub)
        try:
            auth._render_login()
        except RerunCalled:
            pass
        return stub

    def test_correct_password_authenticates(self, configured, monkeypatch) -> None:
        stub = self._login(monkeypatch, PASSWORD)
        assert stub.session_state[auth._SESSION_AUTHED] is True

    def test_wrong_password_does_not_authenticate(self, configured, monkeypatch) -> None:
        stub = self._login(monkeypatch, "wrong")
        assert auth._SESSION_AUTHED not in stub.session_state
        assert stub.session_state[auth._SESSION_ATTEMPTS] == 1

    def test_nothing_happens_until_submitted(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=False, password=PASSWORD)
        monkeypatch.setattr(auth, "st", stub)
        auth._render_login()
        assert auth._SESSION_AUTHED not in stub.session_state

    def test_lockout_after_five_failures(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password="wrong")
        monkeypatch.setattr(auth, "st", stub)
        monkeypatch.setattr(auth, "FAILED_ATTEMPT_DELAY_SECONDS", 0)
        for _ in range(auth.MAX_ATTEMPTS):
            auth._render_login()
        assert stub.session_state.get(auth._SESSION_LOCKED_UNTIL, 0) > time.time()
        assert auth._SESSION_AUTHED not in stub.session_state

    def test_correct_password_is_refused_while_locked(self, configured, monkeypatch) -> None:
        """The lockout must hold even against the right password."""
        stub = make_streamlit_stub(submitted=True, password=PASSWORD)
        stub.session_state[auth._SESSION_LOCKED_UNTIL] = time.time() + 300
        monkeypatch.setattr(auth, "st", stub)
        auth._render_login()
        assert auth._SESSION_AUTHED not in stub.session_state

    def test_lockout_expires(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password=PASSWORD)
        stub.session_state[auth._SESSION_LOCKED_UNTIL] = time.time() - 1
        monkeypatch.setattr(auth, "st", stub)
        try:
            auth._render_login()
        except RerunCalled:
            pass
        assert stub.session_state[auth._SESSION_AUTHED] is True

    def test_successful_login_resets_the_attempt_counter(self, configured, monkeypatch) -> None:
        stub = make_streamlit_stub(submitted=True, password=PASSWORD)
        stub.session_state[auth._SESSION_ATTEMPTS] = 3
        monkeypatch.setattr(auth, "st", stub)
        try:
            auth._render_login()
        except RerunCalled:
            pass
        assert stub.session_state[auth._SESSION_ATTEMPTS] == 0


class TestConfiguredPassword:
    """Checks against the password actually configured for this project."""

    def test_a_password_is_configured(self) -> None:
        assert config.access_control_configured(), "APP_PASSWORD is not set"

    def test_it_is_at_least_twenty_characters(self) -> None:
        password = config.get_app_password()
        assert password is not None
        assert len(password) >= 20, "the app password is shorter than 20 characters"

    def test_it_is_not_one_of_the_known_weak_ones(self) -> None:
        """These leaked into a chat transcript or were dictionary-based."""
        weak = {"forensics@regex", "forensics@llm", "password", "changeme"}
        assert config.get_app_password() not in weak

"""Shared test fixtures.

The important one is `isolate_streamlit_secrets`, which is autouse.

`config._lookup` reads the environment first and `st.secrets` second. Tests that simulate a
missing setting only ever cleared the environment, so once a real `.streamlit/secrets.toml`
existed on the machine, eight of them began failing: the value they had deleted was still being
supplied by the second source. The suite's result depended on whether the developer running it
happened to have a local secrets file, which makes it untrustworthy — it passed during
development purely because no such file existed yet.

So the second source is neutralized for every test by default. A test then reads only what it
explicitly sets, and behaves identically on a laptop with secrets configured, a laptop without,
and CI. The tests that exist to verify the layering itself opt back in with
`use_real_streamlit_secrets`.
"""

from __future__ import annotations

import pytest

import config


@pytest.fixture(autouse=True)
def isolate_streamlit_secrets(request, monkeypatch):
    """Make `st.secrets` invisible unless a test opts in."""
    if "use_real_streamlit_secrets" in request.keywords:
        return
    monkeypatch.setattr(config, "_from_streamlit_secrets", lambda name: None)


@pytest.fixture
def streamlit_secrets(monkeypatch):
    """Simulate specific values in `st.secrets` without touching any real file."""

    def _install(values: dict[str, str]) -> None:
        monkeypatch.setattr(
            config, "_from_streamlit_secrets", lambda name: values.get(name)
        )

    return _install

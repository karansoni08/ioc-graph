"""Concurrency, usage caps and secret-hiding tests. No API calls, no Supabase connection.

A fake store stands in for Supabase so the atomic-reservation contract and the version-conflict
retry can be exercised without a network or a database.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from config import SECRET_VARS, Settings
from extract.iocs import extract_iocs
from extract.llm_extract import MergedEntity, ReportAnalysis
from graph.merge import merge_report
from graph.normalize import report_node_id
from graph.persist import merge_and_save
from ingest.models import Document, join_pages
from storage.base import VersionConflict
from storage.local import LocalGraphStore
from usage import KIND_AGENT, KIND_REPORT, reserve, settle, today_key, usage_summary

TEXT_A = "Indicators of Compromise\n\nAPT21 deployed the Akira ransomware. C2 at 45.66.77.88."
TEXT_B = "Indicators of Compromise\n\nAPT21 returned using Mimikatz. Traffic to 91.92.93.94."


def make_doc(text: str, sha: str, name: str) -> Document:
    pages = [text]
    return Document(
        filename=name,
        file_type="pdf",
        sha256=sha,
        size_bytes=len(text),
        page_count=1,
        pages=pages,
        tables=[],
        text=join_pages(pages),
    )


def analysis_for(entity: str, etype: str, evidence: str) -> ReportAnalysis:
    return ReportAnalysis(
        document_sha256="x",
        model="claude-haiku-4-5",
        prompt_version="v1",
        entities=[MergedEntity(name=entity, type=etype, evidence=[evidence])],
    )


@pytest.fixture
def doc_a():
    return make_doc(TEXT_A, "a" * 64, "a.pdf")


@pytest.fixture
def doc_b():
    return make_doc(TEXT_B, "b" * 64, "b.pdf")


class FakeUsageStore(LocalGraphStore):
    """Local storage plus an in-memory version of the Supabase usage functions.

    Mirrors the SQL contract: `reserve_usage` checks and increments in one step and returns False
    when a limit would be exceeded.
    """

    def __init__(self, path):
        super().__init__(path)
        self.usage: dict[str, dict] = {}
        self.reserve_calls = 0
        self.settle_calls = 0

    def _row(self, day: str) -> dict:
        return self.usage.setdefault(
            day, {"day": day, "reports": 0, "agent_runs": 0, "spend_usd": 0.0}
        )

    def reserve_usage(
        self, day, kind, estimated_cost, report_limit, agent_limit, spend_limit
    ) -> bool:
        self.reserve_calls += 1
        row = self._row(day)
        if kind == KIND_REPORT and row["reports"] + 1 > report_limit:
            return False
        if kind == KIND_AGENT and row["agent_runs"] + 1 > agent_limit:
            return False
        if row["spend_usd"] + estimated_cost > spend_limit:
            return False
        if kind == KIND_REPORT:
            row["reports"] += 1
        if kind == KIND_AGENT:
            row["agent_runs"] += 1
        row["spend_usd"] += estimated_cost
        return True

    def settle_usage(self, day, delta) -> None:
        self.settle_calls += 1
        row = self._row(day)
        row["spend_usd"] = max(0.0, row["spend_usd"] + delta)

    def get_usage(self, day) -> dict:
        return dict(self._row(day))


class TestVersionConflictRetry:
    def test_two_sessions_both_land_in_the_graph(self, tmp_path, doc_a, doc_b) -> None:
        """The core concurrency guarantee: a conflict must not lose anyone's upload."""
        iocs_a, iocs_b = extract_iocs(doc_a), extract_iocs(doc_b)
        analysis_a = analysis_for("APT21", "threat-actor", "APT21 deployed the Akira ransomware.")
        analysis_b = analysis_for("Mimikatz", "tool", "APT21 returned using Mimikatz.")

        shared = LocalGraphStore(tmp_path)

        class SessionOne(LocalGraphStore):
            """Session two commits in between session one's load and save, exactly once."""

            def __init__(self, path):
                super().__init__(path)
                self.tripped = False

            def save(self, graph, expected_version):
                if not self.tripped:
                    self.tripped = True
                    other, other_version = LocalGraphStore.load(self)
                    merge_report(other, doc_b, iocs_b, analysis_b)
                    LocalGraphStore.save(self, other, other_version)
                return super().save(graph, expected_version)

        merge_and_save(SessionOne(tmp_path), doc_a, iocs_a, analysis_a)

        final, _ = shared.load()
        assert report_node_id(doc_a.sha256) in final, "session one's report was lost"
        assert report_node_id(doc_b.sha256) in final, "session two's report was lost"
        assert "tool--mimikatz" in final
        assert "threat-actor--apt21" in final

    def test_shared_entity_keeps_both_report_ids(self, tmp_path, doc_a, doc_b) -> None:
        iocs_a, iocs_b = extract_iocs(doc_a), extract_iocs(doc_b)
        both = analysis_for("APT21", "threat-actor", "APT21 deployed the Akira ransomware.")
        both_b = analysis_for("APT21", "threat-actor", "APT21 returned using Mimikatz.")

        store = LocalGraphStore(tmp_path)
        merge_and_save(store, doc_a, iocs_a, both)
        merge_and_save(store, doc_b, iocs_b, both_b)

        graph, _ = store.load()
        assert len(graph.nodes["threat-actor--apt21"]["reports"]) == 2

    def test_retry_gives_up_after_three_attempts(self, tmp_path, doc_a) -> None:
        class AlwaysConflict(LocalGraphStore):
            def save(self, graph, expected_version):
                raise VersionConflict(expected_version, expected_version + 1)

        with pytest.raises(VersionConflict):
            merge_and_save(
                AlwaysConflict(tmp_path),
                doc_a,
                extract_iocs(doc_a),
                analysis_for("APT21", "threat-actor", "APT21 deployed the Akira ransomware."),
            )

    def test_version_increments_on_each_save(self, tmp_path, doc_a, doc_b) -> None:
        store = LocalGraphStore(tmp_path)
        _, first = merge_and_save(
            store, doc_a, extract_iocs(doc_a), analysis_for("APT21", "threat-actor", "APT21 deployed the Akira ransomware.")
        )
        _, second = merge_and_save(
            store, doc_b, extract_iocs(doc_b), analysis_for("Mimikatz", "tool", "APT21 returned using Mimikatz.")
        )
        assert second == first + 1


class TestUsageCaps:
    def test_local_backend_enforces_caps_too(self, tmp_path) -> None:
        """The local backend used to leave caps unenforced.

        That meant a deployment on it had no spend ceiling at all, which is the one control that
        actually protects the owner's API credits on a shared link. It now implements the same
        interface as Supabase.
        """
        store = LocalGraphStore(tmp_path)
        settings = Settings(daily_report_limit=1, daily_spend_limit_usd=100.0)

        first = reserve(store, settings, KIND_REPORT, 0.01)
        assert first.allowed is True
        assert first.enforced is True

        second = reserve(store, settings, KIND_REPORT, 0.01)
        assert second.allowed is False, "the local backend did not enforce the report cap"

    def test_local_spend_cap_is_enforced(self, tmp_path) -> None:
        store = LocalGraphStore(tmp_path)
        settings = Settings(daily_report_limit=99, daily_spend_limit_usd=0.50)
        assert reserve(store, settings, KIND_REPORT, 0.40).allowed is True
        assert reserve(store, settings, KIND_REPORT, 0.40).allowed is False

    def test_local_usage_survives_a_new_store_instance(self, tmp_path) -> None:
        """Counts must persist to disk: Streamlit rebuilds objects on every rerun."""
        settings = Settings(daily_report_limit=1, daily_spend_limit_usd=100.0)
        assert reserve(LocalGraphStore(tmp_path), settings, KIND_REPORT, 0.01).allowed is True
        assert reserve(LocalGraphStore(tmp_path), settings, KIND_REPORT, 0.01).allowed is False

    def test_local_caps_are_per_day(self, tmp_path) -> None:
        store = LocalGraphStore(tmp_path)
        assert store.reserve_usage("2026-10-06", "report", 0.01, 1, 5, 100.0) is True
        assert store.reserve_usage("2026-10-06", "report", 0.01, 1, 5, 100.0) is False
        # A new day starts fresh.
        assert store.reserve_usage("2026-10-07", "report", 0.01, 1, 5, 100.0) is True

    def test_report_limit_blocks_the_next_upload(self, tmp_path) -> None:
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_report_limit=2, daily_spend_limit_usd=100.0)

        assert reserve(store, settings, KIND_REPORT, 0.01).allowed is True
        assert reserve(store, settings, KIND_REPORT, 0.01).allowed is True
        third = reserve(store, settings, KIND_REPORT, 0.01)
        assert third.allowed is False
        assert "daily limit" in third.reason

    def test_agent_limit_is_separate_and_smaller(self, tmp_path) -> None:
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_report_limit=20, daily_agent_limit=1, daily_spend_limit_usd=100.0)

        assert reserve(store, settings, KIND_AGENT, 0.01).allowed is True
        assert reserve(store, settings, KIND_AGENT, 0.01).allowed is False
        # Reports are still allowed; the caps are independent.
        assert reserve(store, settings, KIND_REPORT, 0.01).allowed is True

    def test_spend_limit_blocks_even_under_the_count_limit(self, tmp_path) -> None:
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_report_limit=100, daily_spend_limit_usd=0.50)

        assert reserve(store, settings, KIND_REPORT, 0.40).allowed is True
        blocked = reserve(store, settings, KIND_REPORT, 0.40)
        assert blocked.allowed is False

    def test_estimate_is_reserved_before_the_call(self, tmp_path) -> None:
        """Reserving the worst case first is what stops a burst from overshooting the cap."""
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_spend_limit_usd=1.00)
        reserve(store, settings, KIND_REPORT, 0.90)
        assert store.get_usage(today_key(settings))["spend_usd"] == pytest.approx(0.90)

    def test_settle_brings_spend_down_to_actual(self, tmp_path) -> None:
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_spend_limit_usd=10.0)
        reservation = reserve(store, settings, KIND_REPORT, 0.50)
        settle(store, reservation, 0.03)
        assert store.get_usage(today_key(settings))["spend_usd"] == pytest.approx(0.03)

    def test_settle_cannot_make_spend_negative(self, tmp_path) -> None:
        store = FakeUsageStore(tmp_path)
        settings = Settings(daily_spend_limit_usd=10.0)
        reservation = reserve(store, settings, KIND_REPORT, 0.10)
        settle(store, reservation, -5.0)
        assert store.get_usage(today_key(settings))["spend_usd"] >= 0

    def test_reservation_fails_closed_when_the_check_errors(self, tmp_path) -> None:
        """If the cap cannot be checked, the request must be blocked, not allowed."""

        class BrokenStore(FakeUsageStore):
            def reserve_usage(self, *args, **kwargs):
                raise RuntimeError("database unreachable")

        reservation = reserve(BrokenStore(tmp_path), Settings(), KIND_REPORT, 0.10)
        assert reservation.allowed is False
        assert "could not be checked" in reservation.reason

    def test_settle_is_a_noop_for_a_store_without_usage_support(self, tmp_path) -> None:
        """A backend that does not implement the usage interface must not be called."""

        class NoUsageStore:
            name = "none"

        reservation = reserve(NoUsageStore(), Settings(), KIND_REPORT, 0.10)
        assert reservation.enforced is False
        # Must not raise, and must not attempt to settle.
        settle(NoUsageStore(), reservation, 0.05)

    def test_local_settle_adjusts_to_actual_spend(self, tmp_path) -> None:
        store = LocalGraphStore(tmp_path)
        settings = Settings(daily_spend_limit_usd=10.0)
        reservation = reserve(store, settings, KIND_REPORT, 0.50)
        settle(store, reservation, 0.03)
        assert store.get_usage(today_key(settings))["spend_usd"] == pytest.approx(0.03)

    def test_usage_summary_is_available_on_local(self, tmp_path) -> None:
        summary = usage_summary(LocalGraphStore(tmp_path), Settings())
        assert summary is not None
        assert summary["reports"] == 0

    def test_usage_summary_is_none_without_usage_support(self) -> None:
        class NoUsageStore:
            name = "none"

        assert usage_summary(NoUsageStore(), Settings()) is None

    def test_today_key_uses_the_configured_timezone(self) -> None:
        key = today_key(Settings(app_timezone="America/Toronto"))
        assert len(key) == 10 and key.count("-") == 2

    def test_unknown_timezone_falls_back_rather_than_raising(self) -> None:
        key = today_key(Settings(app_timezone="Not/AZone"))
        assert key == date.today().isoformat()


class TestSecretsAreHidden:
    def test_settings_repr_contains_no_secret_values(self, monkeypatch) -> None:
        for variable in SECRET_VARS:
            monkeypatch.setenv(variable, f"SECRET-VALUE-FOR-{variable}")
        settings = Settings()
        rendered = repr(settings) + str(settings)
        for variable in SECRET_VARS:
            assert f"SECRET-VALUE-FOR-{variable}" not in rendered

    def test_settings_has_no_secret_fields(self) -> None:
        """`token` is deliberately not in this list: `max_output_tokens` is a count, not a secret."""
        field_names = set(Settings().__dataclass_fields__)
        for forbidden in ("api_key", "apikey", "service_key", "password", "secret", "credential"):
            offenders = [name for name in field_names if forbidden in name]
            assert offenders == [], f"{forbidden!r} appears in Settings fields: {offenders}"

    def test_auth_token_fields_are_not_credentials(self) -> None:
        """Guard the exemption above: any `token` field must be a numeric budget."""
        settings = Settings()
        for name in settings.__dataclass_fields__:
            if "token" in name:
                assert isinstance(getattr(settings, name), int), name

    def test_secret_accessors_raise_clear_errors_without_values(self, monkeypatch) -> None:
        from config import ConfigError, get_supabase_service_key, get_supabase_url

        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)

        for accessor in (get_supabase_url, get_supabase_service_key):
            with pytest.raises(ConfigError) as caught:
                accessor()
            # Names the variable, never a value.
            assert "SUPABASE" in str(caught.value)

    def test_access_control_detects_configuration(self, monkeypatch) -> None:
        from config import access_control_configured

        monkeypatch.delenv("VIEW_PASSWORD", raising=False)
        monkeypatch.delenv("UPLOAD_PASSWORD", raising=False)
        assert access_control_configured() is False

        monkeypatch.setenv("VIEW_PASSWORD", "something")
        assert access_control_configured() is True


class TestPasswordComparison:
    def test_passwords_are_compared_with_compare_digest(self) -> None:
        """Timing-safe comparison, asserted by reading the source.

        A plain `==` leaks the length of the matching prefix through timing, which over many
        attempts is enough to recover the password. This test fails if someone simplifies it.
        """
        source = Path("auth.py").read_text(encoding="utf-8")
        assert "hmac.compare_digest" in source
        # No bare equality against a password value.
        assert "candidate ==" not in source
        assert "== upload_password" not in source
        assert "== view_password" not in source

    def test_both_passwords_are_always_compared(self) -> None:
        """Short-circuiting after the first match would leak which password was correct."""
        source = Path("auth.py").read_text(encoding="utf-8")
        check = source.split("def _check_password")[1].split("def ")[0]
        assert check.index("upload_match") < check.index("if upload_match")
        assert "view_match = " in check.split("if upload_match")[0]


class TestSchemaFile:
    """The schema is committed SQL, so its security properties are checkable as text."""

    def _schema(self) -> str:
        return Path("supabase/schema.sql").read_text(encoding="utf-8")

    def test_rls_is_enabled_on_every_table(self) -> None:
        schema = self._schema()
        for table in (
            "workspace",
            "workspace_backups",
            "reports",
            "llm_cache",
            "agent_runs",
            "usage_daily",
        ):
            assert f"alter table {table}" in schema.replace("  ", " ")
            assert "enable row level security" in schema

    def test_no_policies_are_granted_to_public_roles(self) -> None:
        schema = self._schema().lower()
        # A `create policy` for anon/authenticated would defeat the whole model.
        assert "create policy" not in schema

    def test_functions_are_revoked_from_public_roles(self) -> None:
        schema = self._schema().lower()
        assert "revoke all on function save_graph" in schema
        assert "revoke all on function reserve_usage" in schema

    def test_save_graph_returns_minus_one_on_conflict(self) -> None:
        assert "return -1" in self._schema()

    def test_reserve_usage_locks_the_row(self) -> None:
        schema = self._schema()
        reserve_body = schema.split("function reserve_usage")[1]
        assert "for update" in reserve_body

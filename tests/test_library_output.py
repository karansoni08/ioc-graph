"""Tests for the report library and the output folder.

Network tests are marked `live` and skipped by default: the manifest points at a third-party
site, and a unit suite that fails when someone else's CDN is slow is not a useful unit suite.
Everything that does not need the network is tested unconditionally.
"""

from __future__ import annotations

import csv
import json
import os
import zipfile
from pathlib import Path

import pytest

from config import Settings
from extract.iocs import extract_iocs
from extract.llm_extract import MergedEntity, MergedRelationship, ReportAnalysis
from ingest.errors import IngestError
from ingest.library import (
    MANIFEST_PATH,
    LibraryReport,
    cached_count,
    cached_path,
    categories,
    fetch_report,
    get_report,
    is_cached,
    load_manifest,
)
from ingest.models import Document, join_pages
from storage.output import (
    build_zip,
    delete_output,
    list_outputs,
    output_root,
    save_results,
)

live_only = pytest.mark.skipif(
    os.environ.get("RUN_LIVE") != "1",
    reason="downloads from cisa.gov; set RUN_LIVE=1 to enable",
)

TEXT = (
    "Indicators of Compromise\n\n"
    "APT21 deployed the Akira ransomware against healthcare targets. "
    "The C2 server was 45.66.77.88 and the actor exploited CVE-2024-3400."
)


def make_doc(name: str = "report.pdf") -> Document:
    pages = [TEXT]
    return Document(
        filename=name,
        file_type="pdf",
        sha256="a1b2c3d4e5f6" + "0" * 52,
        size_bytes=len(TEXT),
        page_count=1,
        pages=pages,
        tables=[],
        text=join_pages(pages),
    )


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(data_dir=str(tmp_path))


class TestManifest:
    def test_manifest_is_committed_and_parses(self) -> None:
        assert MANIFEST_PATH.exists(), "library/manifest.json is missing"
        json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_there_are_ten_reports(self) -> None:
        assert len(load_manifest()) == 10

    def test_every_entry_is_complete(self) -> None:
        for report in load_manifest():
            assert report.id and report.title and report.description
            assert report.pdf_url.startswith("https://")
            assert report.source_page.startswith("https://")
            assert report.filename.endswith(".pdf")

    def test_ids_and_filenames_are_unique(self) -> None:
        reports = load_manifest()
        assert len({r.id for r in reports}) == len(reports)
        assert len({r.filename for r in reports}) == len(reports)

    def test_filenames_cannot_escape_the_cache_directory(self) -> None:
        """A manifest is data; a crafted filename must not write outside the cache."""
        for report in load_manifest():
            assert "/" not in report.filename
            assert ".." not in report.filename

    def test_categories_are_discovered(self) -> None:
        assert set(categories()) == {"ransomware", "nation-state"}

    def test_get_report_by_id(self) -> None:
        assert get_report("aa24-109a") is not None
        assert get_report("does-not-exist") is None

    def test_nothing_is_cached_in_a_fresh_data_dir(self, settings) -> None:
        assert cached_count(settings) == 0

    def test_pdfs_are_not_committed(self) -> None:
        """The whole point of the manifest: 8 MB of third-party PDFs stay out of the repo."""
        committed = list((MANIFEST_PATH.parent).glob("*.pdf"))
        assert committed == [], f"PDFs committed to library/: {committed}"


class TestFetchErrors:
    def _entry(self, url: str) -> LibraryReport:
        return LibraryReport(
            id="bogus",
            title="Bogus",
            category="test",
            publisher="Nowhere",
            advisory_id="X",
            description="",
            source_page="https://example.invalid/page",
            pdf_url=url,
            filename="bogus.pdf",
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.invalid/missing.pdf",
            "https://evil.test/payload.pdf",
            "http://www.cisa.gov/report.pdf",          # wrong scheme
            "https://169.254.169.254/latest/meta-data",  # cloud metadata
            "https://localhost/admin",
            "https://cisa.gov.evil.test/x.pdf",        # suffix trick
        ],
    )
    def test_urls_outside_the_allowlist_are_refused(self, settings, url) -> None:
        """The manifest lives in a PUBLIC repo, so a pull request could propose any URL.

        Host restriction means an accepted malicious edit still cannot make the app fetch
        arbitrary addresses, including cloud metadata or internal hosts.
        """
        with pytest.raises(IngestError):
            fetch_report(self._entry(url), settings)

    def test_the_check_happens_before_any_request(self, settings, monkeypatch) -> None:
        import ingest.library as library

        def fail(*args, **kwargs):
            raise AssertionError("a disallowed host was actually contacted")

        monkeypatch.setattr(library.requests, "get", fail)
        with pytest.raises(IngestError):
            fetch_report(self._entry("https://evil.test/x.pdf"), settings)

    def test_an_allowed_host_that_fails_gives_a_user_facing_error(
        self, settings, monkeypatch
    ) -> None:
        import ingest.library as library

        def boom(*args, **kwargs):
            raise library.requests.ConnectionError("network down")

        monkeypatch.setattr(library.requests, "get", boom)
        entry = self._entry("https://www.cisa.gov/some-report.pdf")
        with pytest.raises(IngestError) as caught:
            fetch_report(entry, settings)
        # Names the report, not a stack trace.
        assert "Bogus" in str(caught.value)

    def test_every_manifest_url_is_on_the_allowlist(self) -> None:
        from urllib.parse import urlsplit

        from ingest.library import ALLOWED_HOSTS

        for report in load_manifest():
            host = urlsplit(report.pdf_url).hostname
            assert host in ALLOWED_HOSTS, f"{report.advisory_id} points at {host}"

    def test_a_non_pdf_response_is_rejected_and_not_cached(self, settings, monkeypatch) -> None:
        """A CDN error page returns 200 with HTML; caching it would poison the library."""
        import ingest.library as library

        class FakeResponse:
            content = b"<html>error</html>"

            def raise_for_status(self):
                return None

        monkeypatch.setattr(library.requests, "get", lambda *a, **k: FakeResponse())
        report = load_manifest()[0]
        with pytest.raises(IngestError):
            fetch_report(report, settings)
        assert not cached_path(report, settings).exists()

    def test_a_cached_file_is_not_refetched(self, settings, monkeypatch) -> None:
        import ingest.library as library

        report = load_manifest()[0]
        path = cached_path(report, settings)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"%PDF-1.7 cached")

        def fail(*args, **kwargs):
            raise AssertionError("a cached report was downloaded again")

        monkeypatch.setattr(library.requests, "get", fail)
        assert fetch_report(report, settings) == b"%PDF-1.7 cached"
        assert is_cached(report, settings)


class TestOutput:
    def _analysis(self) -> ReportAnalysis:
        return ReportAnalysis(
            document_sha256="a" * 64,
            model="claude-haiku-4-5",
            prompt_version="v1",
            entities=[
                MergedEntity(
                    name="APT21",
                    type="threat-actor",
                    aliases=["Group 21"],
                    descriptions=["A group."],
                    evidence=["APT21 deployed the Akira ransomware against healthcare targets"],
                )
            ],
            relationships=[
                MergedRelationship(
                    source="APT21",
                    relation="uses",
                    target="Akira",
                    evidence=["APT21 deployed the Akira ransomware against healthcare targets"],
                )
            ],
        )

    def test_saving_writes_every_expected_file(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), self._analysis(), settings)
        names = {path.name for path in saved.files}
        assert names == {
            "README.txt",
            "analysis.json",
            "entities.csv",
            "iocs.csv",
            "relationships.csv",
            "summary.txt",
        }

    def test_indicators_are_written_in_real_form_not_defanged(self, settings) -> None:
        """These files feed other tools, so they carry real values — the opposite of the UI."""
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        body = (saved.path / "iocs.csv").read_text(encoding="utf-8")
        assert "45.66.77.88" in body
        assert "45[.]66[.]77[.]88" not in body

    def test_the_readme_warns_about_real_values(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        warning = (saved.path / "README.txt").read_text(encoding="utf-8")
        assert "REAL indicator values" in warning

    def test_iocs_csv_is_valid_and_has_a_header(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        with (saved.path / "iocs.csv").open(encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
        assert rows[0] == [
            "type", "value", "occurrences", "pages", "in_ioc_section", "flags", "original_forms"
        ]
        assert len(rows) > 1

    def test_analysis_json_round_trips(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), self._analysis(), settings)
        payload = json.loads((saved.path / "analysis.json").read_text(encoding="utf-8"))
        assert payload["report"]["sha256"] == doc.sha256
        assert payload["analysis"]["entities"][0]["name"] == "APT21"

    def test_saving_without_an_analysis_still_works(self, settings) -> None:
        """Indicators are useful on their own; the LLM step is optional."""
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        assert saved.entity_count == 0
        assert "No LLM analysis" in (saved.path / "summary.txt").read_text(encoding="utf-8")

    def test_resaving_overwrites_rather_than_duplicating(self, settings) -> None:
        doc = make_doc()
        save_results(doc, extract_iocs(doc), None, settings)
        save_results(doc, extract_iocs(doc), None, settings)
        assert len(list_outputs(settings)) == 1

    def test_folder_name_is_safe_and_identifiable(self, settings) -> None:
        doc = make_doc("../../etc/passwd.pdf")
        saved = save_results(doc, extract_iocs(doc), None, settings)
        assert ".." not in saved.name
        assert "/" not in saved.name
        assert saved.path.parent == output_root(settings)

    def test_listing_is_newest_first(self, settings) -> None:
        import time

        first = make_doc("first.pdf")
        save_results(first, extract_iocs(first), None, settings)
        time.sleep(1.1)  # the timestamp has one-second resolution
        second = make_doc("second.pdf")
        object.__setattr__(second, "sha256", "b" * 64)
        save_results(second, extract_iocs(second), None, settings)

        names = [item.filename for item in list_outputs(settings)]
        assert names[0] == "second.pdf"

    def test_zip_contains_every_file(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        with zipfile.ZipFile(__import__("io").BytesIO(build_zip(saved))) as archive:
            inside = {Path(n).name for n in archive.namelist()}
        assert "iocs.csv" in inside
        assert "analysis.json" in inside

    def test_delete_removes_the_folder(self, settings) -> None:
        doc = make_doc()
        saved = save_results(doc, extract_iocs(doc), None, settings)
        delete_output(saved)
        assert list_outputs(settings) == []

    def test_listing_an_absent_directory_is_empty_not_an_error(self, settings) -> None:
        assert list_outputs(settings) == []


@live_only
class TestLibraryDownloads:
    """Confirms every manifest URL still resolves. Third-party; run deliberately."""

    def test_every_pdf_url_is_reachable(self) -> None:
        import requests

        broken = []
        for report in load_manifest():
            try:
                response = requests.get(report.pdf_url, timeout=90)
                if response.status_code != 200 or not response.content.startswith(b"%PDF-"):
                    broken.append(f"{report.advisory_id} -> {response.status_code}")
            except requests.RequestException as exc:
                broken.append(f"{report.advisory_id} -> {type(exc).__name__}")
        assert broken == [], f"library URLs no longer resolve: {broken}"

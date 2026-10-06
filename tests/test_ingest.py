"""Ingestion and configuration tests.

All fixtures are generated in memory so the suite needs no external files and costs nothing.
Real reports arrive as fixtures in Phase 2.
"""

from __future__ import annotations

import re

import pymupdf
import pytest

import config
from config import ConfigError, Settings, get_api_key
from ingest.errors import IngestError
from ingest.loader import detect_file_type, load_document, sha256_bytes
from ingest.pdf import clean_pdf_text

SMALL_LIMITS = Settings(max_file_mb=5, max_pages=50)


def make_pdf(pages: list[str]) -> bytes:
    """Build a PDF in memory with one text block per page."""
    doc = pymupdf.open()
    for body in pages:
        page = doc.new_page()
        page.insert_text((72, 100), body, fontsize=11)
    data = doc.tobytes()
    doc.close()
    return data


HTML_WITH_SCRIPT = """<!DOCTYPE html>
<html>
  <head>
    <style>.secret { color: red; }</style>
    <script>var exfiltrate = "SCRIPT_SHOULD_NOT_APPEAR";</script>
  </head>
  <body>
    <h1>Threat Report</h1>
    <p>APT21 exploited CVE-2024-3400.</p>
    <noscript>NOSCRIPT_SHOULD_NOT_APPEAR</noscript>
  </body>
</html>
"""


class TestPdf:
    def test_text_and_page_count(self) -> None:
        data = make_pdf(["First page about APT21.", "Second page about malware."])
        document = load_document("report.pdf", data, SMALL_LIMITS)

        assert document.file_type == "pdf"
        assert document.page_count == 2
        assert len(document.pages) == 2
        assert "APT21" in document.pages[0]
        assert "malware" in document.pages[1]

    def test_text_includes_page_markers(self) -> None:
        data = make_pdf(["Page one body.", "Page two body."])
        document = load_document("report.pdf", data, SMALL_LIMITS)

        assert "[[PAGE 1]]" in document.text
        assert "[[PAGE 2]]" in document.text

    def test_page_limit_is_enforced(self) -> None:
        data = make_pdf(["a", "b", "c"])
        with pytest.raises(IngestError, match="over the 2-page limit"):
            load_document("report.pdf", data, Settings(max_pages=2))

    def test_image_only_pdf_is_rejected_with_ocr_hint(self) -> None:
        doc = pymupdf.open()
        doc.new_page()  # a page with no text at all
        data = doc.tobytes()
        doc.close()

        with pytest.raises(IngestError, match="OCR"):
            load_document("scan.pdf", data, SMALL_LIMITS)

    def test_corrupt_pdf_is_rejected(self) -> None:
        with pytest.raises(IngestError):
            load_document("broken.pdf", b"%PDF-1.7\nnot actually a pdf body", SMALL_LIMITS)


class TestPdfTextCleanup:
    def test_soft_hyphens_removed(self) -> None:
        assert clean_pdf_text("compro­mised") == "compromised"

    def test_hyphenated_line_break_joined_when_continuation_is_lowercase(self) -> None:
        assert clean_pdf_text("compro-\nmised host") == "compromised host"

    def test_hyphenated_line_break_kept_when_continuation_is_uppercase(self) -> None:
        # "Windows-\nBased" is a real hyphenated compound, not a split word.
        assert clean_pdf_text("Windows-\nBased") == "Windows-\nBased"


class TestHtml:
    def test_script_and_style_content_is_removed(self) -> None:
        document = load_document("report.html", HTML_WITH_SCRIPT.encode(), SMALL_LIMITS)

        assert "SCRIPT_SHOULD_NOT_APPEAR" not in document.text
        assert "NOSCRIPT_SHOULD_NOT_APPEAR" not in document.text
        assert "color: red" not in document.text
        assert "APT21 exploited CVE-2024-3400." in document.text

    def test_html_is_a_single_page(self) -> None:
        document = load_document("report.html", HTML_WITH_SCRIPT.encode(), SMALL_LIMITS)

        assert document.file_type == "html"
        assert document.page_count == 1
        assert document.tables == []

    def test_htm_extension_accepted(self) -> None:
        document = load_document("report.htm", HTML_WITH_SCRIPT.encode(), SMALL_LIMITS)
        assert document.file_type == "html"

    def test_latin1_fallback(self) -> None:
        markup = "<html><body><p>caf\xe9 server</p></body></html>".encode("latin-1")
        document = load_document("report.html", markup, SMALL_LIMITS)
        assert "caf" in document.text


class TestValidation:
    def test_oversized_file_is_rejected(self) -> None:
        oversized = b"%PDF-" + b"0" * (2 * 1024 * 1024)
        with pytest.raises(IngestError, match="over the 1 MB limit"):
            load_document("big.pdf", oversized, Settings(max_file_mb=1))

    def test_html_bytes_renamed_as_pdf_are_rejected(self) -> None:
        with pytest.raises(IngestError, match="named as a PDF"):
            load_document("disguised.pdf", HTML_WITH_SCRIPT.encode(), SMALL_LIMITS)

    def test_pdf_bytes_renamed_as_html_are_rejected(self) -> None:
        data = make_pdf(["Real PDF content."])
        with pytest.raises(IngestError, match="named as HTML"):
            load_document("disguised.html", data, SMALL_LIMITS)

    def test_empty_file_is_rejected(self) -> None:
        with pytest.raises(IngestError, match="empty"):
            load_document("nothing.pdf", b"", SMALL_LIMITS)

    def test_unsupported_content_is_rejected(self) -> None:
        with pytest.raises(IngestError, match="not a supported file"):
            load_document("notes.txt", b"\x00\x01\x02 plain junk", SMALL_LIMITS)

    def test_detect_file_type_uses_magic_bytes(self) -> None:
        assert detect_file_type("x.pdf", b"%PDF-1.4 ...") == "pdf"
        assert detect_file_type("x.html", b"<html><body>hi</body></html>") == "html"


class TestHashing:
    def test_sha256_is_stable_for_identical_bytes(self) -> None:
        data = make_pdf(["Deterministic content."])
        assert sha256_bytes(data) == sha256_bytes(bytes(data))

    def test_sha256_matches_document_field(self) -> None:
        data = HTML_WITH_SCRIPT.encode()
        document = load_document("report.html", data, SMALL_LIMITS)
        assert document.sha256 == sha256_bytes(data)
        assert len(document.sha256) == 64

    def test_different_bytes_give_different_hashes(self) -> None:
        assert sha256_bytes(b"<html><body>a</body></html>") != sha256_bytes(
            b"<html><body>b</body></html>"
        )


class TestApiKeyHandling:
    def test_get_api_key_raises_clear_error_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv(config.API_KEY_VAR, raising=False)

        with pytest.raises(ConfigError) as caught:
            get_api_key()

        message = str(caught.value)
        assert config.API_KEY_VAR in message
        assert ".env" in message

    def test_error_message_contains_no_key_like_string(self, monkeypatch) -> None:
        monkeypatch.delenv(config.API_KEY_VAR, raising=False)

        with pytest.raises(ConfigError) as caught:
            get_api_key()

        message = str(caught.value)
        assert "sk-ant" not in message
        # No long unbroken token that could be a leaked credential.
        assert not re.search(r"[A-Za-z0-9_\-]{25,}", message)

    def test_get_api_key_returns_value_when_set(self, monkeypatch) -> None:
        monkeypatch.setenv(config.API_KEY_VAR, "test-value")
        assert get_api_key() == "test-value"

    def test_blank_key_is_treated_as_missing(self, monkeypatch) -> None:
        monkeypatch.setenv(config.API_KEY_VAR, "   ")
        assert config.has_api_key() is False
        with pytest.raises(ConfigError):
            get_api_key()

    def test_settings_repr_has_no_api_key(self, monkeypatch) -> None:
        monkeypatch.setenv(config.API_KEY_VAR, "sk-ant-should-not-appear")
        settings = Settings()
        assert "sk-ant" not in repr(settings)
        assert not hasattr(settings, "anthropic_api_key")


class TestSettings:
    def test_defaults(self) -> None:
        settings = Settings()
        assert settings.anthropic_model == config.DEFAULT_MODEL
        assert settings.storage_backend == "local"
        assert settings.max_file_mb == 5
        assert settings.max_pages == 50
        assert settings.max_file_bytes == 5 * 1024 * 1024

    def test_agent_model_defaults_to_main_model(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_MODEL", "some-model")
        monkeypatch.delenv("ANTHROPIC_AGENT_MODEL", raising=False)
        config.get_settings.cache_clear()
        try:
            settings = config.get_settings()
            assert settings.anthropic_agent_model == "some-model"
        finally:
            config.get_settings.cache_clear()

    def test_non_numeric_limit_raises_without_echoing_value(self, monkeypatch) -> None:
        monkeypatch.setenv("MAX_PAGES", "not-a-number")
        config.get_settings.cache_clear()
        try:
            with pytest.raises(ConfigError) as caught:
                config.get_settings()
            assert "not-a-number" not in str(caught.value)
        finally:
            config.get_settings.cache_clear()

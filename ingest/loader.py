"""Upload validation and dispatch to the PDF or HTML extractor."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from config import Settings, get_settings

from .errors import IngestError
from .html import extract_html
from .models import Document, FileType, join_pages

PDF_MAGIC = b"%PDF-"

_PDF_EXTENSIONS = {".pdf"}
_HTML_EXTENSIONS = {".html", ".htm"}

# A real HTML document contains at least one of these structural tags.
_HTML_TAG = re.compile(r"<\s*(html|body|div)\b", re.IGNORECASE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_text(data: bytes) -> str | None:
    """Decode bytes as text, or None if they are not text in either encoding we accept."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _looks_like_pdf(data: bytes) -> bool:
    # Tolerate a UTF-8 BOM or leading whitespace, which some tools prepend.
    return data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(PDF_MAGIC)


def detect_file_type(filename: str, data: bytes) -> FileType:
    """Determine the real file type from its content, checked against the extension.

    The extension alone is not trusted: an attacker (or a confused browser) can rename a file.
    A mismatch between the claimed extension and the actual bytes is rejected rather than
    silently resolved, because it usually means the upload is not what the user thinks.
    """
    extension = Path(filename).suffix.lower()

    if _looks_like_pdf(data):
        detected: FileType | None = "pdf"
    else:
        text = decode_text(data)
        detected = "html" if text is not None and _HTML_TAG.search(text) else None

    if extension in _PDF_EXTENSIONS:
        if detected != "pdf":
            raise IngestError(
                f"'{filename}' is named as a PDF but its contents are not a PDF "
                "(it does not begin with the PDF file signature). Please upload a real PDF."
            )
        return "pdf"

    if extension in _HTML_EXTENSIONS:
        if detected != "html":
            raise IngestError(
                f"'{filename}' is named as HTML but its contents are not HTML "
                "(no <html>, <body> or <div> tag was found). Please upload a real HTML file."
            )
        return "html"

    if detected is not None:
        return detected

    raise IngestError(
        f"'{filename}' is not a supported file. Please upload a PDF or an HTML report."
    )


def load_document(filename: str, data: bytes, settings: Settings | None = None) -> Document:
    """Validate an upload and extract its text.

    Raises IngestError with a message suitable for display to the user.
    """
    settings = settings or get_settings()

    if not data:
        raise IngestError(f"'{filename}' is empty.")

    if len(data) > settings.max_file_bytes:
        actual_mb = len(data) / (1024 * 1024)
        raise IngestError(
            f"'{filename}' is {actual_mb:.1f} MB, which is over the "
            f"{settings.max_file_mb} MB limit. Please upload a smaller file."
        )

    file_type = detect_file_type(filename, data)

    if file_type == "pdf":
        # Imported here so that HTML-only use does not pay the PyMuPDF import cost.
        from .pdf import extract_pdf

        pages, tables = extract_pdf(data, settings.max_pages)
    else:
        markup = decode_text(data)
        if markup is None:  # pragma: no cover - detect_file_type already decoded it
            raise IngestError(f"'{filename}' could not be read as text.")
        pages, tables = [extract_html(markup)], []

    return Document(
        filename=filename,
        file_type=file_type,
        sha256=sha256_bytes(data),
        size_bytes=len(data),
        page_count=len(pages),
        pages=pages,
        tables=tables,
        text=join_pages(pages),
    )

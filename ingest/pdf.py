"""PDF text and table extraction."""

from __future__ import annotations

import io
import re

import pdfplumber
import pymupdf  # PyMuPDF; the legacy `fitz` import name is deprecated

from .errors import IngestError

SOFT_HYPHEN = "­"

# A word broken across lines: "compro-\nmised". Only joined when the continuation starts
# lowercase, so genuine hyphenated line ends like "Windows-\nBased" are left alone.
_LINE_BREAK_HYPHEN = re.compile(r"(\w)-\n([a-z])")


def clean_pdf_text(text: str) -> str:
    """Repair artifacts that PDF text extraction leaves behind."""
    text = text.replace(SOFT_HYPHEN, "")
    text = _LINE_BREAK_HYPHEN.sub(r"\1\2", text)
    return text


def extract_tables(data: bytes) -> list[list[list[str]]]:
    """Extract tables with pdfplumber.

    Table extraction is best-effort: pdfplumber fails on some real-world PDFs, and a table
    failure must never cost us the text, so everything is caught here.
    """
    tables: list[list[list[str]]] = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for page in pdf.pages:
                try:
                    found = page.extract_tables() or []
                except Exception:
                    continue
                for raw_table in found:
                    rows = [
                        [("" if cell is None else str(cell).strip()) for cell in row]
                        for row in raw_table
                    ]
                    # Drop tables that are entirely empty cells.
                    if any(cell for row in rows for cell in row):
                        tables.append(rows)
    except Exception:
        return tables
    return tables


def extract_pdf(data: bytes, max_pages: int) -> tuple[list[str], list[list[list[str]]]]:
    """Return (page texts, tables) for a PDF.

    Raises IngestError for encrypted PDFs, unreadable files and page-count overruns.
    """
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        raise IngestError("This PDF could not be opened. It may be corrupted.") from exc

    try:
        if doc.needs_pass:
            raise IngestError(
                "This PDF is password protected. Please remove the password and upload again."
            )

        if doc.page_count > max_pages:
            raise IngestError(
                f"This PDF has {doc.page_count} pages, which is over the {max_pages}-page limit. "
                "Please upload a shorter report or split it."
            )

        if doc.page_count == 0:
            raise IngestError("This PDF has no pages.")

        pages = [clean_pdf_text(page.get_text("text")) for page in doc]
    finally:
        doc.close()

    if not any(page.strip() for page in pages):
        raise IngestError(
            "No text could be extracted from this PDF. It may be a scan of images, which "
            "needs OCR and is not supported."
        )

    return pages, extract_tables(data)

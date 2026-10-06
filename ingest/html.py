"""HTML text extraction."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .errors import IngestError

# Elements whose text is never report content.
_DROP_TAGS = ("script", "style", "noscript", "template")

_BLANK_RUN = re.compile(r"\n{3,}")


def extract_html(markup: str) -> str:
    """Return visible text from an HTML document.

    Phase 5 replaced the simple version of this with `guards.sanitize_html`, which also removes
    content hidden by CSS, comments, aria-hidden and hiding classes. This wrapper keeps the
    original signature for callers that do not need the sanitization report.
    """
    text, _ = extract_html_with_report(markup)
    return text


def extract_html_with_report(markup: str):
    """Return (visible text, SanitizationReport).

    Hidden content is quarantined rather than merely dropped, so the UI can show what was
    removed and the injection scanner can look at it.
    """
    # Imported here to keep `ingest` free of a hard dependency on `guards` at import time.
    from guards.sanitize_html import sanitize_html

    try:
        text, report = sanitize_html(markup)
    except Exception as exc:
        raise IngestError("This HTML file could not be parsed.") from exc

    if not text:
        raise IngestError("No readable text could be extracted from this HTML file.")

    return text, report


def extract_html_basic(markup: str) -> str:
    """The Phase 1 extractor: structural tags only, no hidden-content handling.

    Kept so tests can demonstrate the difference the Phase 5 sanitizer makes.
    """
    try:
        soup = BeautifulSoup(markup, "lxml")
    except Exception as exc:
        raise IngestError("This HTML file could not be parsed.") from exc

    for tag_name in _DROP_TAGS:
        for element in soup.find_all(tag_name):
            element.decompose()

    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.split("\n")]
    text = "\n".join(lines)
    text = _BLANK_RUN.sub("\n\n", text).strip()

    if not text:
        raise IngestError("No readable text could be extracted from this HTML file.")

    return text

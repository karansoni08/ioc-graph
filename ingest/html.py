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

    TODO Phase 5: full hidden-content sanitization — elements hidden with CSS
    (display:none, visibility:hidden, zero size, off-screen positioning, color matching the
    background), HTML comments, and aria-hidden content are all prompt-injection carriers and
    are not handled here yet.
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

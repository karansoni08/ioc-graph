"""Locate the IOC section of a report.

Knowing which pages hold the IOC list matters for two later phases: it tells Phase 3 which
chunks to send to the LLM (the IOC section plus nearby context, not the whole report), and it
raises confidence in an indicator, since a hash printed in an "Indicators of Compromise" table
is more certainly an indicator than one mentioned in passing.

Two strategies, in order:
1. Heading matching. A heading that names indicators opens a section; the next heading that is
   not IOC-related closes it.
2. Density fallback, used only when no heading matches: pages whose IOC density is more than
   three times the document average.
"""

from __future__ import annotations

import re

from ingest.models import Document

# Headings that open an IOC section. Anchored at line start, case-insensitive.
_IOC_HEADING_PATTERNS = [
    r"indicators?\s+of\s+compromise",
    r"io[cC]s?\b",
    r"\bindicators?\b",
    r"network\s+(based\s+)?indicators?",
    r"host[\s-]*based\s+indicators?",
    r"file\s+indicators?",
    r"email\s+indicators?",
    r"malware\s+(hashes|samples|indicators)",
    r"file\s+hashes",
    r"hashes\b",
    r"observed\s+(iocs?|indicators?|infrastructure)",
    r"(appendix[\s:.\w]*?)(indicators?|iocs?|hashes)",
    r"technical\s+details[\s:.\w]*?indicators?",
]

_IOC_HEADING = re.compile(
    r"^\s*(?:appendix\s+[a-z0-9]+[.:]?\s*|[0-9ivx]+[.)]\s*)?(?:"
    + "|".join(_IOC_HEADING_PATTERNS)
    + r")\s*[:.]?\s*$",
    re.IGNORECASE,
)

# A looser test used to decide whether a heading inside a section is still IOC-related, so a
# subheading like "Network Indicators" does not close the section.
_IOC_RELATED = re.compile(
    r"(indicator|ioc|hash|md5|sha-?\d|domain|ip\s+address|url|email\s+address|"
    r"infrastructure|signature|yara|snort|detection)",
    re.IGNORECASE,
)

# Headings that reliably close an IOC section even though they mention IOC-ish words, because
# they introduce guidance rather than more indicators.
_CLOSING_HEADINGS = re.compile(
    r"^\s*(mitigations?|recommendations?|validate\s+security\s+controls|references?|"
    r"disclaimer|acknowledge?ments?|contact|reporting|resources|about|revisions?|"
    r"version\s+history|works\s+cited|mitre\s+att&ck|conclusion)\b",
    re.IGNORECASE,
)

_MAX_HEADING_WORDS = 12
_MAX_HEADING_CHARS = 90


def is_heading_like(line: str) -> bool:
    """Heuristic test for a heading in text extracted from a PDF.

    PDF text extraction loses font information, so a heading has to be recognized by shape:
    short, few words, no sentence punctuation at the end.
    """
    stripped = line.strip()
    if not (3 <= len(stripped) <= _MAX_HEADING_CHARS):
        return False
    if stripped.endswith((".", ",", ";", ":")) and not stripped.endswith("..."):
        # A trailing colon is common on real headings, so allow it explicitly.
        if not stripped.endswith(":"):
            return False
    words = stripped.split()
    if len(words) > _MAX_HEADING_WORDS:
        return False
    # Reject prose: sentences contain lowercase function words in the middle.
    letters = [c for c in stripped if c.isalpha()]
    if not letters:
        return False
    uppercase_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    if stripped.isupper():
        return True
    # Title Case: most words start with a capital.
    capitalized = sum(1 for word in words if word[:1].isupper())
    return capitalized >= max(1, len(words) - 1) or uppercase_ratio > 0.6


def _heading_pages_from_headings(doc: Document) -> list[int]:
    """Pages covered by an IOC section found via headings."""
    pages: set[int] = set()
    in_section = False

    for page_number, page_text in enumerate(doc.pages, start=1):
        page_has_section = False
        for raw_line in page_text.split("\n"):
            line = raw_line.strip()
            if not line:
                continue

            if _IOC_HEADING.match(line):
                in_section = True
                page_has_section = True
                continue

            if in_section and is_heading_like(line):
                if _CLOSING_HEADINGS.match(line) or not _IOC_RELATED.search(line):
                    in_section = False
                    continue

            if in_section:
                page_has_section = True

        if in_section or page_has_section:
            pages.add(page_number)

    return sorted(pages)


def _density_pages(doc: Document) -> list[int]:
    """Fallback: pages whose IOC density exceeds 3x the document average.

    Density is measured with a cheap inline regex rather than the full extractor, because the
    full extractor calls this module and importing it here would be circular.
    """
    counts: list[int] = []
    lengths: list[int] = []
    for page_text in doc.pages:
        counts.append(len(_CHEAP_IOC.findall(page_text)))
        lengths.append(max(len(page_text), 1))

    total_count = sum(counts)
    total_length = sum(lengths)
    if total_count == 0 or total_length == 0:
        return []

    average = total_count / total_length * 1000
    if average <= 0:
        return []

    pages: list[int] = []
    for index, (count, length) in enumerate(zip(counts, lengths), start=1):
        density = count / length * 1000
        if density > 3 * average:
            pages.append(index)
    return pages


# Rough IOC shapes, used only for the density fallback: hashes, dotted quads, defanged dots
# and CVE ids.
_CHEAP_IOC = re.compile(
    r"\b[a-fA-F0-9]{32,128}\b"
    r"|\b\d{1,3}(?:\[?\.\]?\d{1,3}){3}\b"
    r"|\bCVE-\d{4}-\d{4,7}\b"
    r"|\b[\w-]+(?:\[\.\]|\(\.\)|\[dot\])[\w.-]+\b"
    r"|\bhxxps?://",
    re.IGNORECASE,
)


def find_ioc_section(doc: Document) -> list[int]:
    """Return the 1-based page numbers that make up the report's IOC section."""
    pages = _heading_pages_from_headings(doc)
    if pages:
        return pages
    return _density_pages(doc)

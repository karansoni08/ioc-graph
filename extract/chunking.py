"""Split a report into chunks worth sending to the model.

Two goals, both about cost. Send the parts of the report that actually contain threat
intelligence, and send as few of them as possible: a 31-page advisory is mostly mitigation
advice and boilerplate, and paying to analyse all of it would be waste.

Priority order is therefore IOC-section pages first, then pages holding regex IOCs or ATT&CK
technique ids, then everything else. Only the first `max_chunks` are processed and the rest are
reported as skipped, so the UI can say what was left out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ingest.models import Document

from .models import IOCExtraction

# Characters per token, used as a cheap estimate so no tokenizer call is needed just to plan
# chunks. Deliberately conservative: over-estimating tokens makes chunks smaller and safer.
CHARS_PER_TOKEN = 4

TARGET_CHUNK_TOKENS = 6000
OVERLAP_TOKENS = 300

TARGET_CHUNK_CHARS = TARGET_CHUNK_TOKENS * CHARS_PER_TOKEN
OVERLAP_CHARS = OVERLAP_TOKENS * CHARS_PER_TOKEN

# MITRE ATT&CK technique ids, e.g. T1059 or T1059.001.
ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

PRIORITY_IOC_SECTION = 0
PRIORITY_HAS_SIGNAL = 1
PRIORITY_OTHER = 2


def estimate_tokens(text: str) -> int:
    """Rough token count. Used for planning and cost estimates, never for billing."""
    return max(1, len(text) // CHARS_PER_TOKEN)


@dataclass
class Chunk:
    """A contiguous piece of a report, with the pages it came from."""

    text: str
    pages: list[int] = field(default_factory=list)
    priority: int = PRIORITY_OTHER
    index: int = 0

    @property
    def estimated_tokens(self) -> int:
        return estimate_tokens(self.text)

    @property
    def page_label(self) -> str:
        if not self.pages:
            return "tables"
        if len(self.pages) == 1:
            return f"page {self.pages[0]}"
        return f"pages {self.pages[0]}-{self.pages[-1]}"


def _split_paragraphs(text: str) -> list[str]:
    """Split on blank lines, keeping paragraphs intact.

    Paragraph boundaries are preferred over a fixed character cut so a chunk rarely ends
    mid-sentence, which matters because the model must quote evidence verbatim.
    """
    parts = re.split(r"\n\s*\n", text)
    return [part for part in parts if part.strip()]


def _pack(paragraphs: list[str], pages: list[int], priority: int) -> list[Chunk]:
    """Pack paragraphs into chunks of roughly the target size, with overlap."""
    chunks: list[Chunk] = []
    current: list[str] = []
    current_len = 0

    for paragraph in paragraphs:
        paragraph_len = len(paragraph)

        # A single paragraph larger than the target is split on sentence boundaries.
        if paragraph_len > TARGET_CHUNK_CHARS:
            if current:
                chunks.append(Chunk("\n\n".join(current), list(pages), priority))
                current, current_len = [], 0
            for piece in _split_oversized(paragraph):
                chunks.append(Chunk(piece, list(pages), priority))
            continue

        if current_len + paragraph_len > TARGET_CHUNK_CHARS and current:
            chunks.append(Chunk("\n\n".join(current), list(pages), priority))
            # Carry the tail forward so an entity introduced at a boundary keeps its context.
            tail = "\n\n".join(current)[-OVERLAP_CHARS:]
            current = [tail] if tail.strip() else []
            current_len = len(tail)

        current.append(paragraph)
        current_len += paragraph_len

    if current and "\n\n".join(current).strip():
        chunks.append(Chunk("\n\n".join(current), list(pages), priority))

    return chunks


def _split_oversized(paragraph: str) -> list[str]:
    """Split a very long paragraph, preferring sentence ends."""
    sentences = re.split(r"(?<=[.!?])\s+", paragraph)
    pieces: list[str] = []
    current = ""
    for sentence in sentences:
        if len(current) + len(sentence) > TARGET_CHUNK_CHARS and current:
            pieces.append(current)
            current = ""
        if len(sentence) > TARGET_CHUNK_CHARS:
            # No sentence boundary available: hard cut as a last resort.
            for start in range(0, len(sentence), TARGET_CHUNK_CHARS):
                pieces.append(sentence[start : start + TARGET_CHUNK_CHARS])
            continue
        current = f"{current} {sentence}".strip()
    if current:
        pieces.append(current)
    return pieces


def _page_priority(
    page_number: int, page_text: str, section_pages: set[int], ioc_pages: set[int]
) -> int:
    if page_number in section_pages:
        return PRIORITY_IOC_SECTION
    if page_number in ioc_pages or ATTACK_ID.search(page_text):
        return PRIORITY_HAS_SIGNAL
    return PRIORITY_OTHER


def chunk_document(
    doc: Document, ioc_extraction: IOCExtraction, max_chunks: int = 6
) -> tuple[list[Chunk], int]:
    """Return (chunks to process, number skipped).

    Chunks are ordered by priority and then by page, so the most valuable pages are analysed
    first and truncation only ever drops the least relevant material.
    """
    section_pages = set(ioc_extraction.ioc_section_pages)
    ioc_pages = {page for ioc in ioc_extraction.iocs for page in ioc.pages}

    grouped: dict[int, list[tuple[int, str]]] = {
        PRIORITY_IOC_SECTION: [],
        PRIORITY_HAS_SIGNAL: [],
        PRIORITY_OTHER: [],
    }
    for page_number, page_text in enumerate(doc.pages, start=1):
        if not page_text.strip():
            continue
        priority = _page_priority(page_number, page_text, section_pages, ioc_pages)
        grouped[priority].append((page_number, page_text))

    all_chunks: list[Chunk] = []
    for priority in (PRIORITY_IOC_SECTION, PRIORITY_HAS_SIGNAL, PRIORITY_OTHER):
        pages = grouped[priority]
        if not pages:
            continue
        # Pages of the same priority are packed together so a chunk can span pages, which
        # keeps the IOC section whole rather than one chunk per page.
        combined = "\n\n".join(text for _, text in pages)
        page_numbers = [number for number, _ in pages]
        all_chunks.extend(_pack(_split_paragraphs(combined), page_numbers, priority))

    # Table text is appended as its own chunk when there is room: advisory IOC tables are
    # where the indicators live, and PyMuPDF page text does not always keep their structure.
    table_text = "\n\n".join(
        "\n".join(" | ".join(cell for cell in row if cell) for row in table)
        for table in doc.tables
    )
    if table_text.strip():
        all_chunks.extend(_pack(_split_paragraphs(table_text), [], PRIORITY_HAS_SIGNAL))

    all_chunks.sort(key=lambda chunk: (chunk.priority, chunk.pages[:1] or [0]))

    selected = all_chunks[:max_chunks]
    for position, chunk in enumerate(selected):
        chunk.index = position

    return selected, max(0, len(all_chunks) - len(selected))

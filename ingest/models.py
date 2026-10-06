"""Data model for an ingested report."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FileType = Literal["pdf", "html"]

# Page markers let later phases map an extracted IOC or quote back to a page number.
PAGE_MARKER = "[[PAGE {n}]]"


class Document(BaseModel):
    """An ingested report, after text extraction but before any IOC or LLM work."""

    filename: str
    file_type: FileType
    sha256: str = Field(description="SHA-256 of the raw uploaded bytes, used for caching.")
    size_bytes: int
    page_count: int = Field(description="1 for HTML.")
    pages: list[str] = Field(default_factory=list, description="Extracted text per page.")
    tables: list[list[list[str]]] = Field(
        default_factory=list, description="Each table is a list of rows; each row a list of cells."
    )
    text: str = Field(default="", description="All pages joined with page markers.")

    @property
    def char_count(self) -> int:
        return len(self.text)

    @property
    def table_count(self) -> int:
        return len(self.tables)


def join_pages(pages: list[str]) -> str:
    """Join page texts with page markers.

    The marker precedes each page so a quote's position in `text` can be traced to a page.
    """
    parts: list[str] = []
    for index, page_text in enumerate(pages, start=1):
        parts.append(f"\n\n{PAGE_MARKER.format(n=index)}\n\n")
        parts.append(page_text)
    return "".join(parts).strip()

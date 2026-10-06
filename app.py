"""IOC Graph — Streamlit entry point.

Phase 1 scope: upload a PDF or HTML threat report and show the extracted text.

Display rule for the whole app: report-derived text is UNTRUSTED and is only ever rendered
with `st.text`, `st.code` or `st.dataframe`. Never `st.markdown`/`st.write`/`st.html` and never
`unsafe_allow_html`, so a report can never inject markup or links into the page.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config import get_settings
from ingest.errors import IngestError
from ingest.loader import load_document
from ingest.models import Document

st.set_page_config(page_title="IOC Graph", layout="wide")

settings = get_settings()


@st.cache_data(show_spinner="Extracting text…")
def parse_upload(sha_or_name: str, filename: str, data: bytes) -> Document:
    """Parse an upload, cached so Streamlit reruns do not re-parse the same file.

    `sha_or_name` is part of the cache key; `data` is hashed by Streamlit anyway, but keying on
    the file identity makes the cache behaviour explicit.
    """
    return load_document(filename, data)


def render_pages(document: Document) -> None:
    with st.expander(f"Extracted text ({document.page_count} page(s))"):
        for index, page_text in enumerate(document.pages, start=1):
            label = "Document" if document.file_type == "html" else f"Page {index}"
            st.caption(label)
            # st.text, never st.markdown: report content must not be rendered as markup.
            st.text(page_text if page_text.strip() else "(no text on this page)")


def render_tables(document: Document) -> None:
    if not document.tables:
        return
    with st.expander(f"Tables ({document.table_count})"):
        for index, table in enumerate(document.tables, start=1):
            st.caption(f"Table {index}")
            if len(table) > 1:
                # First row is treated as the header; cells stay strings so nothing is coerced.
                frame = pd.DataFrame(table[1:], columns=_unique_headers(table[0]))
            else:
                frame = pd.DataFrame(table)
            st.dataframe(frame, use_container_width=True)


def _unique_headers(row: list[str]) -> list[str]:
    """pandas rejects duplicate column names, which scanned tables often have."""
    seen: dict[str, int] = {}
    headers: list[str] = []
    for position, cell in enumerate(row):
        name = cell.strip() or f"column_{position + 1}"
        if name in seen:
            seen[name] += 1
            name = f"{name}_{seen[name]}"
        else:
            seen[name] = 0
        headers.append(name)
    return headers


def main() -> None:
    with st.sidebar:
        st.header("IOC Graph")
        st.write(
            "Upload a threat intelligence report. The app extracts indicators of compromise "
            "and threat entities and merges them into a knowledge graph you can explore."
        )
        st.info("Phase 1: ingestion")
        st.caption(
            f"Limits: {settings.max_file_mb} MB per file, {settings.max_pages} pages per PDF."
        )

    st.title("Upload a report")

    upload = st.file_uploader(
        "PDF or HTML threat report",
        type=["pdf", "html", "htm"],
        accept_multiple_files=False,
    )

    if upload is None:
        st.caption("Waiting for a file.")
        return

    data = upload.getvalue()

    try:
        document = parse_upload(f"{upload.name}:{len(data)}", upload.name, data)
    except IngestError as exc:
        st.error(str(exc))
        return

    columns = st.columns(4)
    columns[0].metric("Type", document.file_type.upper())
    columns[1].metric("Pages", document.page_count)
    columns[2].metric("Characters", f"{document.char_count:,}")
    columns[3].metric("Tables", document.table_count)

    st.caption("SHA-256 of the uploaded file")
    st.code(document.sha256, language=None)

    render_pages(document)
    render_tables(document)


main()

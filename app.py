"""IOC Graph — Streamlit entry point.

Phase 2 scope: upload a PDF or HTML threat report, show the extracted text, and extract
indicators of compromise with regular expressions. No LLM is involved yet.

Display rules for the whole app, both of which matter for safety:

1. Report-derived text is UNTRUSTED and is only ever rendered with `st.text`, `st.code` or
   `st.dataframe`. Never `st.markdown`/`st.write`/`st.html` and never `unsafe_allow_html`, so a
   report can never inject markup or links into the page.
2. IOC values are shown DEFANGED (`evil[.]com`, `hxxp://`), so nothing in the table is a live
   clickable link and a value copied out of the page is not immediately dangerous. The real
   refanged values are available only through the explicitly labelled download buttons.
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from config import get_settings, has_api_key
from extract.chunking import chunk_document
from extract.display import defang, format_pages
from extract.iocs import extract_iocs
from extract.llm_extract import (
    ReportAnalysis,
    estimate_max_cost,
    load_cached,
    run_llm_extraction,
)
from extract.models import IOC_TYPES, IOCExtraction
from ingest.errors import IngestError
from ingest.loader import load_document
from ingest.models import Document
from llm.base import LLMError
from llm.factory import get_provider
from llm.pricing import format_cost, is_known_model

st.set_page_config(page_title="IOC Graph", layout="wide")

settings = get_settings()


@st.cache_data(show_spinner="Extracting text…")
def parse_upload(sha_or_name: str, filename: str, data: bytes) -> Document:
    """Parse an upload, cached so Streamlit reruns do not re-parse the same file.

    `sha_or_name` is part of the cache key; `data` is hashed by Streamlit anyway, but keying on
    the file identity makes the cache behaviour explicit.
    """
    return load_document(filename, data)


@st.cache_data(show_spinner="Extracting indicators…")
def extract_indicators(sha256: str, document: Document) -> IOCExtraction:
    """Run regex extraction, cached by document hash.

    Extraction is deterministic and costs nothing but CPU, so the cache is purely about keeping
    the UI responsive across Streamlit reruns.
    """
    return extract_iocs(document)


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


def _ioc_rows(iocs: list) -> pd.DataFrame:
    """Build the display table. Values are defanged here and nowhere else."""
    return pd.DataFrame(
        [
            {
                "type": ioc.type,
                "value (defanged)": defang(ioc.value, ioc.type),
                "occurrences": ioc.occurrences,
                "pages": format_pages(ioc.pages),
                "in IOC section": ioc.in_ioc_section,
                "flags": ", ".join(ioc.flags),
            }
            for ioc in iocs
        ]
    )


def _export_frame(iocs: list) -> pd.DataFrame:
    """Export table with real refanged values, for the download buttons only."""
    return pd.DataFrame(
        [
            {
                "type": ioc.type,
                "value": ioc.value,
                "occurrences": ioc.occurrences,
                "pages": " ".join(str(page) for page in ioc.pages),
                "in_ioc_section": ioc.in_ioc_section,
                "flags": " ".join(ioc.flags),
                "original_forms": " ".join(ioc.original_forms),
            }
            for ioc in iocs
        ]
    )


def render_iocs(document: Document, extraction: IOCExtraction) -> None:
    st.subheader("Indicators of compromise")

    if extraction.total == 0:
        st.info("No indicators were found in this report.")
        return

    present_types = [t for t in IOC_TYPES if extraction.counts_by_type.get(t)]
    metric_columns = st.columns(max(len(present_types), 1))
    for column, ioc_type in zip(metric_columns, present_types):
        column.metric(ioc_type, extraction.counts_by_type[ioc_type])

    if extraction.ioc_section_found:
        pages = ", ".join(str(page) for page in extraction.ioc_section_pages)
        st.caption(f"IOC section detected on page(s) {pages}.")
    else:
        st.caption("No IOC section heading was detected; indicators come from the whole report.")

    st.caption(
        f"{extraction.total} unique indicators, of which {extraction.flagged_count} are flagged "
        "as likely false positives. Nothing is ever dropped — flags only separate them."
    )

    filter_column, toggle_column = st.columns([3, 1])
    selected_types = filter_column.multiselect(
        "Filter by type", options=present_types, default=present_types
    )
    show_flagged = toggle_column.toggle("Show flagged items", value=False)

    visible = [
        ioc
        for ioc in extraction.iocs
        if ioc.type in selected_types and (show_flagged or not ioc.flags)
    ]

    if not visible:
        st.info("No indicators match the current filters.")
    else:
        st.caption("Values are shown defanged so nothing here is a working link.")
        st.dataframe(_ioc_rows(visible), use_container_width=True, hide_index=True)

        labels = [f"{ioc.type}: {defang(ioc.value, ioc.type)}" for ioc in visible]
        chosen = st.selectbox(
            "Show source evidence for", options=range(len(visible)), format_func=labels.__getitem__
        )
        selected = visible[chosen]
        with st.expander("Evidence from the report", expanded=True):
            st.caption(
                f"Seen {selected.occurrences} time(s) on page(s) "
                f"{format_pages(selected.pages)}."
            )
            if selected.original_forms:
                st.caption("Exactly as written in the report:")
                for form in selected.original_forms:
                    st.text(form)
            if selected.flags:
                st.caption("Flags: " + ", ".join(selected.flags))
            st.caption("Context:")
            for snippet in selected.contexts:
                # st.text: these snippets are raw report content.
                st.text(snippet)

    st.caption(
        "Downloads contain the real refanged values, not the defanged display form. "
        "Treat them as live indicators."
    )
    download_columns = st.columns(2)
    download_columns[0].download_button(
        "Download JSON (real values)",
        data=json.dumps(extraction.model_dump(), indent=2),
        file_name=f"iocs-{document.sha256[:12]}.json",
        mime="application/json",
    )
    download_columns[1].download_button(
        "Download CSV (real values)",
        data=_export_frame(extraction.iocs).to_csv(index=False),
        file_name=f"iocs-{document.sha256[:12]}.csv",
        mime="text/csv",
    )


def render_analysis(analysis: ReportAnalysis) -> None:
    """Show LLM results. All model-derived text goes through st.dataframe or st.text."""
    columns = st.columns(5)
    columns[0].metric("Entities", len(analysis.entities))
    columns[1].metric("Relationships", len(analysis.relationships))
    columns[2].metric("Tokens", f"{analysis.total_tokens:,}")
    columns[3].metric("Cost", "cached" if analysis.from_cache else format_cost(analysis.cost_usd))
    columns[4].metric("Dropped", analysis.validation.dropped_count)

    if analysis.from_cache:
        st.success("Loaded from cache — no API call was made and this cost nothing.")
    if analysis.chunks_skipped:
        st.caption(
            f"{analysis.chunks_processed} chunk(s) analysed, {analysis.chunks_skipped} skipped "
            "to control cost. The highest-priority pages were analysed first."
        )
    if analysis.validation.suspicious:
        st.warning(
            "More than half of this report's proposed items were rejected. The text may be "
            "adversarial, or the model behaved unusually. Review the validation panel."
        )

    if analysis.entities:
        st.caption("Entities (model output, validated against the report)")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "type": entity.type,
                        "name": entity.name,
                        "aliases": ", ".join(entity.aliases),
                        "description": " ".join(entity.descriptions)[:300],
                        "quotes": len(entity.evidence),
                    }
                    for entity in analysis.entities
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No entities survived validation for this report.")

    if analysis.relationships:
        st.caption("Relationships")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "source": rel.source,
                        "relation": rel.relation,
                        "target": rel.target,
                        "quotes": len(rel.evidence),
                    }
                    for rel in analysis.relationships
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    with st.expander(f"Validation — {analysis.validation.dropped_count} item(s) dropped"):
        st.caption(
            "Every claim the model made had to quote the report verbatim, name something that "
            "appears in the text, and use only indicators found by regex. Anything else was "
            "dropped. This panel is the audit trail."
        )
        kept = analysis.validation.kept_total
        proposed = analysis.validation.proposed_total
        st.text(
            f"proposed: {proposed}\n"
            f"kept:     {kept}\n"
            f"dropped:  {analysis.validation.dropped_count}"
        )
        counts = analysis.validation.counts_by_reason()
        if counts:
            st.caption("Dropped by reason")
            st.dataframe(
                pd.DataFrame(
                    [{"reason": reason, "count": count} for reason, count in counts.items()]
                ),
                use_container_width=True,
                hide_index=True,
            )
            st.caption("Dropped items")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "kind": item.kind,
                            "reason": item.reason,
                            "value": item.value,
                            "detail": item.detail,
                        }
                        for item in analysis.validation.dropped
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.text("Nothing was dropped.")

    with st.expander("Evidence quotes"):
        for entity in analysis.entities:
            st.caption(f"{entity.type}: {entity.name}")
            for quote in entity.evidence:
                # st.text: this is report-derived content echoed by the model.
                st.text(quote)


def render_llm_section(document: Document, extraction: IOCExtraction) -> None:
    st.subheader("Entity and relationship extraction")

    settings = get_settings()
    model = settings.anthropic_model

    cached = load_cached(document.sha256, model)
    if cached is not None:
        st.caption("A cached analysis exists for this report and model.")
        render_analysis(cached)
        return

    if not has_api_key():
        st.warning(
            "No ANTHROPIC_API_KEY is configured, so analysis is unavailable. "
            "Copy .env.example to .env and add your key."
        )
        return

    chunks, skipped = chunk_document(document, extraction, max_chunks=settings.max_chunks_per_report)
    worst_case = estimate_max_cost(chunks, model, settings.max_output_tokens)

    st.caption(
        f"{len(chunks)} chunk(s) would be sent to {model}"
        + (f", {skipped} skipped to control cost" if skipped else "")
        + f". Estimated maximum cost: {format_cost(worst_case)} "
        "(worst case: every chunk uses its full output budget)."
    )
    if not is_known_model(model):
        st.warning(
            f"'{model}' is not in the price table, so the estimate uses the most expensive "
            "current rate. Check llm/pricing.py."
        )

    # No API call happens without this click.
    if not st.button("Analyze with Claude", type="primary"):
        st.caption("Analysis runs only when you click. Nothing has been sent yet.")
        return

    status = st.status("Analyzing…", expanded=True)

    def progress(index: int, total: int, label: str) -> None:
        status.update(label=f"Analyzing chunk {index + 1} of {total} ({label})…")

    try:
        analysis = run_llm_extraction(
            document,
            extraction,
            get_provider("anthropic"),
            settings=settings,
            model=model,
            max_tokens=settings.max_output_tokens,
            progress=progress,
        )
    except LLMError as exc:
        status.update(label="Analysis failed", state="error")
        st.error(str(exc))
        return

    status.update(label="Analysis complete", state="complete")
    render_analysis(analysis)


def main() -> None:
    with st.sidebar:
        st.header("IOC Graph")
        st.write(
            "Upload a threat intelligence report. The app extracts indicators of compromise "
            "and threat entities and merges them into a knowledge graph you can explore."
        )
        st.info("Phase 3: LLM entity extraction")
        st.caption(
            f"Limits: {settings.max_file_mb} MB per file, {settings.max_pages} pages per PDF."
        )
        st.caption(
            "Indicators come from regular expressions. Entities and relationships come "
            "from Claude, and every claim is checked against the report before it is kept."
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

    st.divider()
    extraction = extract_indicators(document.sha256, document)
    render_iocs(document, extraction)

    st.divider()
    render_llm_section(document, extraction)


main()

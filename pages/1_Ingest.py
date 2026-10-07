"""Ingest page: upload a report, extract indicators, analyse with Claude, add to the graph.

Display rules (unchanged from Phase 1-3): report-derived and model-derived text is UNTRUSTED
and only ever reaches the page through `st.text`, `st.code` or `st.dataframe`. IOC values are
shown defanged.
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from auth import require_access
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
from agent.attack_data import ensure_available as ensure_attack_available
from agent.loop import run_agent
from graph.persist import merge_and_save
from ingest.errors import IngestError
from ingest.loader import load_document
from ingest.models import Document
from llm.base import LLMError
from llm.factory import get_provider
from llm.pricing import estimate_cost, format_cost, is_known_model
from storage.base import StorageError, VersionConflict
from usage import KIND_AGENT, KIND_REPORT, limit_message, reserve, settle
from storage.factory import get_store
from storage.local import LocalGraphStore

st.set_page_config(page_title="Ingest — IOC Graph", layout="wide")


@st.cache_resource(show_spinner="Fetching MITRE ATT&CK data (first run only)…")
def _attack_ready() -> bool:
    """Fetch the ATT&CK bundle once per container; the deployed disk is wiped on restart."""
    return ensure_attack_available()

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


def render_security(document: Document) -> None:
    """Guardrail findings for this upload: what was removed and what looked hostile."""
    security = getattr(document, "security", None)
    if security is None:
        return

    st.subheader("Security checks")

    status = security.status
    if status == "suspicious":
        st.error(
            "This report contains content that looks like a prompt-injection attempt. "
            "Affected chunks are excluded from the model."
        )
    elif status == "warnings":
        st.warning("Content was removed from this report before processing. Details below.")
    else:
        st.success("No hidden content or injection patterns were found.")

    columns = st.columns(3)
    columns[0].metric("Quarantined", security.quarantined_count)
    columns[1].metric("Injection findings", len(security.injection_findings))
    columns[2].metric("Document risks", len(security.document_risks))

    if security.quarantine_counts:
        st.caption("Removed before extraction, by reason")
        st.dataframe(
            pd.DataFrame(
                [
                    {"reason": reason, "count": count}
                    for reason, count in sorted(security.quarantine_counts.items())
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.caption(
            "Quarantined content is excluded from BOTH indicator extraction and the model: "
            "hidden text can plant a fake indicator as easily as a fake instruction."
        )

    if security.document_risks:
        st.caption("Document-level risks (reported, never opened or executed)")
        st.dataframe(
            pd.DataFrame(
                [
                    {"risk": risk, "count": count}
                    for risk, count in sorted(security.document_risks.items())
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    if security.quarantined_items:
        with st.expander(f"View quarantined content ({len(security.quarantined_items)} item(s))"):
            st.warning(
                "This is untrusted content that was removed. It is shown as plain text and is "
                "never sent to the model."
            )
            for item in security.quarantined_items:
                st.caption(f"{item['reason']} — {item.get('where', '')}")
                # st.text: quarantined content is the most hostile text in the app.
                st.text(item["preview"])


def render_injection_findings(document: Document) -> None:
    security = getattr(document, "security", None)
    if security is None or not security.injection_findings:
        return
    with st.expander(f"Injection findings ({len(security.injection_findings)})"):
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "severity": f["severity"],
                        "pattern": f["pattern"],
                        "chunk": f.get("chunk", ""),
                        "pages": f.get("pages", ""),
                        "snippet": f["snippet"],
                    }
                    for f in security.injection_findings
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.caption(
            "HIGH findings exclude the chunk from the model. MEDIUM findings are shown but the "
            "chunk is still sent, because those patterns also match legitimate advisory prose."
        )
    if security.excluded_chunks:
        st.warning(
            f"{len(security.excluded_chunks)} chunk(s) were excluded from the model: "
            + ", ".join(
                f"{c['pages']} ({', '.join(c['reasons'])})" for c in security.excluded_chunks
            )
        )


def render_add_to_graph(
    document: Document, extraction: IOCExtraction, analysis: ReportAnalysis
) -> None:
    """Merge this report into the shared graph.

    Separate from analysis on purpose: analysing is reversible and local, whereas merging
    changes the shared graph everyone sees.
    """
    st.divider()
    st.subheader("Add to the knowledge graph")

    name = st.text_input(
        "Your name (recorded as who ingested this report)",
        max_chars=50,
        help="Free text. There are no accounts; this is just a note on the report.",
    )
    st.caption(
        "Merging is idempotent: adding the same report twice replaces its previous "
        "contribution rather than duplicating it."
    )

    if not st.button("Add to graph", type="primary"):
        return

    store = get_store(settings)
    try:
        stats, version = merge_and_save(
            store, document, extraction, analysis, ingested_by=name.strip()
        )
    except VersionConflict as exc:
        st.error(str(exc))
        return

    st.success(f"Merged into the graph (version {version}).")
    columns = st.columns(4)
    columns[0].metric("New nodes", stats.new_nodes)
    columns[1].metric("Updated nodes", stats.updated_nodes)
    columns[2].metric("New edges", stats.new_edges)
    columns[3].metric("Removed", stats.removed_nodes)
    if stats.by_type:
        st.caption("New nodes by type")
        st.dataframe(
            pd.DataFrame(
                [{"type": key, "count": value} for key, value in sorted(stats.by_type.items())]
            ),
            use_container_width=True,
            hide_index=True,
        )
    st.page_link("pages/2_Graph.py", label="Explore the graph", icon=":material/hub:")


def render_llm_section(document: Document, extraction: IOCExtraction) -> None:
    st.subheader("Entity and relationship extraction")

    settings = get_settings()
    model = settings.anthropic_model

    cached = load_cached(document.sha256, model)
    if cached is not None:
        st.caption("A cached analysis exists for this report and model.")
        render_analysis(cached)
        render_add_to_graph(document, extraction, cached)
        render_agent_section(document, extraction, cached)
        return

    if not has_api_key():
        st.warning(
            "No ANTHROPIC_API_KEY is configured, so analysis is unavailable. "
            "Copy .env.example to .env and add your key."
        )
        return

    render_injection_findings(document)

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

    store = get_store(settings)
    reservation = reserve(store, settings, KIND_REPORT, worst_case)
    if not reservation.allowed:
        st.error(reservation.reason or limit_message(settings, KIND_REPORT))
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
            security_report=getattr(document, "security", None),
            store=store,
        )
    except LLMError as exc:
        status.update(label="Analysis failed", state="error")
        # The reservation stands at the estimate, which over-counts. Safe direction to fail.
        settle(store, reservation, 0.0)
        st.error(str(exc))
        return

    # Bring the reserved worst case down to what was actually spent.
    settle(store, reservation, analysis.cost_usd)

    status.update(label="Analysis complete", state="complete")
    render_analysis(analysis)
    render_add_to_graph(document, extraction, analysis)
    render_agent_section(document, extraction, analysis)


def render_agent_section(
    document: Document, extraction: IOCExtraction, analysis: ReportAnalysis
) -> None:
    """Optional deep analysis. The pipeline stays the default; this is strictly on top."""
    st.divider()
    st.subheader("Deep analysis (agent mode)")
    st.caption(
        "An optional bounded agent that can search the report, look up MITRE ATT&CK techniques "
        "and query the existing graph, then submit findings. The pipeline result above is the "
        "default; this only adds to it."
    )

    if not has_api_key():
        st.caption("Set ANTHROPIC_API_KEY to enable agent mode.")
        return

    if not _attack_ready():
        st.warning(
            "MITRE ATT&CK data is missing, so technique mapping would be unavailable. "
            "Run `python scripts/fetch_attack.py` first."
        )
        return

    model = settings.anthropic_agent_model
    # Worst case: every tool call uses the full input budget and the full output budget.
    worst_case = estimate_cost(
        model,
        settings.agent_max_input_tokens,
        settings.max_output_tokens * (settings.agent_max_tool_calls + 1),
    )
    st.caption(
        f"Budgets: {settings.agent_max_tool_calls} tool calls, "
        f"{settings.agent_max_input_tokens:,} input tokens, {settings.agent_max_seconds}s. "
        f"Maximum possible cost on {model}: {format_cost(worst_case)}."
    )

    if not st.button("Run deep analysis", key="agent_run"):
        st.caption("Agent mode runs only when you click. Nothing has been sent yet.")
        return

    store = get_store(settings)
    reservation = reserve(store, settings, KIND_AGENT, worst_case)
    if not reservation.allowed:
        st.error(reservation.reason or limit_message(settings, KIND_AGENT))
        return

    try:
        snapshot, _ = store.load()
    except StorageError:
        snapshot = None
    if snapshot is None:
        from graph.model import new_graph

        snapshot = new_graph()

    status = st.status("Running agent…", expanded=True)
    try:
        import anthropic

        from config import get_api_key

        client = anthropic.Anthropic(api_key=get_api_key(), timeout=120.0, max_retries=3)
        run = run_agent(
            document, extraction, analysis, snapshot, client, settings, model=model
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the user, never a stack trace
        status.update(label="Agent run failed", state="error")
        settle(store, reservation, 0.0)
        st.error(f"The agent run could not complete: {exc}")
        return

    settle(store, reservation, run.cost_usd)

    status.update(label=f"Agent finished ({run.status})", state="complete")

    # Save the trace whatever the outcome: a run that produced nothing is still evidence.
    if isinstance(store, LocalGraphStore):
        store.save_run(run.run_id, run.to_dict())

    columns = st.columns(5)
    columns[0].metric("Status", run.status)
    columns[1].metric("Tool calls", run.tool_calls)
    columns[2].metric("New items", run.diff.total_new)
    columns[3].metric("Tokens", f"{run.input_tokens + run.output_tokens:,}")
    columns[4].metric("Cost", format_cost(run.cost_usd))

    if run.status != "submitted":
        st.warning(
            f"{run.stop_note or 'The agent did not submit findings.'} "
            "The pipeline result above is unchanged."
        )
        st.page_link("pages/5_Agent_Runs.py", label="See the full trace", icon=":material/timeline:")
        return

    st.caption("Steps")
    for step in run.steps:
        label = f"{step.index + 1}. {step.tool}"
        if step.withheld:
            label += " (result withheld)"
        with st.expander(label):
            st.text(step.result_preview or "(empty)")

    if run.diff.new_entities or run.diff.new_relationships or run.diff.new_attack_patterns:
        st.caption("Added over the pipeline")
        for item in run.diff.new_entities + run.diff.new_relationships + run.diff.new_attack_patterns:
            st.text(f"+ {item}")
    else:
        st.caption("The agent did not add anything the pipeline had missed.")

    if run.attack_patterns:
        st.caption("Validated ATT&CK mappings")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "technique": pattern["technique_id"],
                        "name": pattern["name"],
                        "entity": pattern.get("entity", ""),
                    }
                    for pattern in run.attack_patterns
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    name = st.text_input("Your name", max_chars=50, key="agent_name")
    if st.button("Add agent findings to graph", type="primary", key="agent_merge"):
        try:
            stats, version = merge_and_save(
                store,
                document,
                extraction,
                run.analysis,
                ingested_by=name.strip(),
                mode="agent",
            )
        except VersionConflict as exc:
            st.error(str(exc))
            return
        st.success(
            f"Merged agent findings (version {version}): +{stats.new_nodes} nodes, "
            f"+{stats.new_edges} edges."
        )
        st.page_link("pages/2_Graph.py", label="Explore the graph", icon=":material/hub:")


def main() -> None:
    require_access()

    st.title("Ingest a report")
    st.warning(
        "Public reports only. Do not upload internal, confidential or client documents. "
        "Uploaded files are processed in memory and discarded — only the extracted results are "
        "stored."
    )
    st.caption(
        f"Limits: {settings.max_file_mb} MB per file, {settings.max_pages} pages per PDF. "
        "Indicators come from regular expressions; entities and relationships come from Claude, "
        "and every claim is checked against the report before it is kept."
    )

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

    st.divider()
    render_security(document)

    render_pages(document)
    render_tables(document)

    st.divider()
    extraction = extract_indicators(document.sha256, document)
    render_iocs(document, extraction)

    st.divider()
    render_llm_section(document, extraction)


main()

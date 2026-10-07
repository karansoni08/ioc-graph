"""IOC Graph — home page and app entry point.

Streamlit's multipage convention: this file is the landing page, and `pages/*.py` are the rest.

Display rule for every page: report-derived and model-derived text is UNTRUSTED and only ever
reaches the page through `st.text`, `st.code`, `st.dataframe` or a graph node label. Never
`st.markdown`, `st.write`, `st.html` or `unsafe_allow_html`.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from auth import require_access
from config import access_control_configured, get_settings, has_api_key
from graph.model import graph_stats, list_reports
from llm.pricing import format_cost
from storage.base import StorageError
from storage.factory import get_store

st.set_page_config(page_title="IOC Graph", layout="wide")

settings = get_settings()


def main() -> None:
    require_access()

    st.title("IOC Graph")
    st.caption(
        "Upload threat intelligence reports; the app extracts indicators and entities and "
        "merges them into one knowledge graph you can explore."
    )

    store = get_store(settings)
    try:
        graph, version = store.load()
    except StorageError as exc:
        st.error(f"The stored graph could not be loaded: {exc}")
        st.caption("Restore a backup with: python scripts/maintain.py restore --version N --apply")
        return

    stats = graph_stats(graph)

    columns = st.columns(4)
    columns[0].metric("Reports", stats["reports"])
    columns[1].metric("Nodes", stats["nodes"])
    columns[2].metric("Edges", stats["edges"])
    columns[3].metric("Graph version", version)

    if stats["nodes"] == 0:
        st.info("The graph is empty. Ingest a report to get started.")
        st.page_link("pages/1_Ingest.py", label="Ingest a report", icon=":material/upload:")
        return

    left, right = st.columns([1, 1])

    with left:
        st.subheader("Nodes by type")
        rows = [
            {"type": node_type, "count": count}
            for node_type, count in sorted(stats["by_type"].items())
            if node_type != "report"
        ]
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with right:
        st.subheader("Recent reports")
        reports = list_reports(graph)[:5]
        if reports:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "filename": report.get("filename", ""),
                            "ingested": report.get("ingested_at", "")[:10],
                            "by": report.get("ingested_by", "") or "—",
                            "cost": format_cost(report.get("cost_usd", 0.0)),
                        }
                        for report in reports
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

    st.divider()
    links = st.columns(4)
    with links[0]:
        st.page_link("pages/1_Ingest.py", label="Ingest", icon=":material/upload:")
    with links[1]:
        st.page_link("pages/2_Graph.py", label="Explore the graph", icon=":material/hub:")
    with links[2]:
        st.page_link("pages/3_Reports.py", label="Reports", icon=":material/description:")
    with links[3]:
        st.page_link("pages/4_Output.py", label="Output", icon=":material/folder:")

    if not has_api_key():
        st.warning(
            "No ANTHROPIC_API_KEY is configured. Ingestion and indicator extraction work, "
            "but entity extraction and summaries are unavailable."
        )


main()

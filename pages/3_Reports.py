"""Reports page: what has been ingested, and removing a report from the graph."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config import get_settings
from graph.model import list_reports
from graph.persist import remove_and_save
from llm.pricing import format_cost
from storage.base import StorageError, VersionConflict
from storage.factory import get_store

st.set_page_config(page_title="Reports — IOC Graph", layout="wide")

settings = get_settings()


def _entity_count(graph, report_id: str) -> int:
    return sum(
        1
        for _, attributes in graph.nodes(data=True)
        if attributes.get("type") != "report" and report_id in attributes.get("reports", [])
    )


def main() -> None:
    st.title("Ingested reports")

    store = get_store(settings)
    try:
        graph, version = store.load()
    except StorageError as exc:
        st.error(f"The stored graph could not be loaded: {exc}")
        return

    reports = list_reports(graph)
    if not reports:
        st.info("No reports have been ingested yet.")
        st.page_link("pages/1_Ingest.py", label="Ingest a report", icon=":material/upload:")
        return

    st.caption(f"Graph version {version}")
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "filename": report.get("filename", ""),
                    "ingested": report.get("ingested_at", "")[:19].replace("T", " "),
                    "by": report.get("ingested_by", "") or "—",
                    "mode": report.get("mode", "pipeline"),
                    "entities": _entity_count(graph, report["id"]),
                    "cost": format_cost(report.get("cost_usd", 0.0)),
                    "sha256": report.get("sha256", "")[:12],
                }
                for report in reports
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    st.subheader("Remove a report from the graph")
    st.caption(
        "Removing a report strips its contributions. Nodes that no other report mentions are "
        "deleted; shared nodes are kept and lose only this report's evidence."
    )

    labels = {
        f"{report.get('filename','')} ({report.get('sha256','')[:12]})": report["id"]
        for report in reports
    }
    chosen = st.selectbox("Report", options=["(none)"] + list(labels))
    if chosen == "(none)":
        return

    report_id = labels[chosen]

    # Two-step confirmation: this mutates the shared graph for everyone.
    confirmed = st.checkbox(f"Yes, remove '{chosen}' from the graph", key="confirm_remove")
    if st.button("Remove from graph", type="primary", disabled=not confirmed):
        try:
            stats, new_version = remove_and_save(store, report_id)
        except VersionConflict as exc:
            st.error(str(exc))
            return
        st.success(
            f"Removed. {stats.removed_nodes} node(s) deleted. Graph is now version {new_version}."
        )
        st.rerun()


main()

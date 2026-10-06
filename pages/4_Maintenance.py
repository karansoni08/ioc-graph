"""Maintenance: possible duplicates, graph download, backup restore."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from config import get_settings
from graph.model import to_json
from graph.normalize import ALIASES_PATH, find_possible_duplicates
from storage.base import StorageError
from storage.factory import get_store
from storage.local import LocalGraphStore

st.set_page_config(page_title="Maintenance — IOC Graph", layout="wide")

settings = get_settings()


def main() -> None:
    st.title("Maintenance")

    store = get_store(settings)
    try:
        graph, version = store.load()
    except StorageError as exc:
        st.error(f"The stored graph could not be loaded: {exc}")
        graph, version = None, -1

    st.subheader("Possible duplicates")
    st.caption(
        "Same-type nodes with similar names. Nothing is merged automatically: fuzzy matching "
        "would eventually merge two genuinely different threat actors, which is worse than a "
        f"duplicate node. To record a real merge, add the alias to {ALIASES_PATH.name}."
    )

    if graph is not None and graph.number_of_nodes() > 0:
        threshold = st.slider("Similarity threshold", 80, 100, 90)
        pairs = find_possible_duplicates(graph, threshold=threshold)
        if pairs:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "type": graph.nodes[left].get("type", ""),
                            "name A": graph.nodes[left].get("name", ""),
                            "name B": graph.nodes[right].get("name", ""),
                            "similarity": score,
                            "id A": left,
                            "id B": right,
                        }
                        for left, right, score in pairs
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
            st.caption(
                "To merge: add {\"name b key\": \"name a key\"} to graph/aliases.json, then "
                "re-ingest the affected reports."
            )
        else:
            st.success("No likely duplicates at this threshold.")

        with st.expander("Current alias map"):
            try:
                st.text(ALIASES_PATH.read_text(encoding="utf-8"))
            except OSError:
                st.caption("No alias map file yet.")

    st.divider()
    st.subheader("Download the graph")
    if graph is not None:
        st.download_button(
            "Download graph JSON",
            data=json.dumps({"version": version, "graph": to_json(graph)}, indent=2),
            file_name=f"ioc-graph-v{version}.json",
            mime="application/json",
        )
        st.caption(
            "Contains indicator values in their real (refanged) form and report-derived quotes."
        )

    st.divider()
    st.subheader("Restore a backup")

    if not isinstance(store, LocalGraphStore):
        st.caption("Backup restore is only available on the local storage backend.")
        return

    backups = store.list_backups()
    if not backups:
        st.caption("No backups yet. One is written before every save.")
        return

    st.caption(
        "Restoring writes the backup as a NEW version rather than rewinding the counter, so "
        "anyone holding the old version still gets a conflict instead of overwriting the restore."
    )
    chosen = st.selectbox("Backup version", options=backups)
    confirmed = st.checkbox(f"Yes, restore version {chosen} over the current graph")
    if st.button("Restore backup", type="primary", disabled=not confirmed):
        try:
            new_version = store.restore_backup(int(chosen))
        except (OSError, StorageError) as exc:
            st.error(f"Restore failed: {exc}")
            return
        st.success(f"Restored version {chosen} as version {new_version}.")
        st.rerun()


main()

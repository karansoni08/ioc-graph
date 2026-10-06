"""Graph explorer: pick a node, see its neighborhood and its evidence.

The view is always a neighborhood, never the whole graph: past a few hundred nodes a full
graph is an unreadable hairball, and the question being asked is almost always "what is this
one thing connected to".

`streamlit-agraph` is used rather than pyvis because it returns the clicked node back to
Python, which is what makes click-to-navigate possible.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph

from config import get_settings, has_api_key
from extract.display import defang
from graph.model import (
    REPORTED_IN,
    entity_nodes,
    neighborhood,
    node_relationships,
    related_indicators,
    top_nodes_by_degree,
)
from graph.persist import save_graph_with_retry
from graph.summaries import generate_summary, summary_is_current
from llm.base import LLMError
from llm.factory import get_provider
from llm.pricing import format_cost
from storage.base import StorageError, VersionConflict
from storage.factory import get_store

st.set_page_config(page_title="Graph — IOC Graph", layout="wide")

settings = get_settings()

# Colour and shape per type, with a legend. Consistent across the app so a shape means one
# thing everywhere.
TYPE_STYLE: dict[str, tuple[str, str]] = {
    "threat-actor": ("#d94f4f", "diamond"),
    "malware": ("#e07b39", "dot"),
    "tool": ("#e0c339", "dot"),
    "vulnerability": ("#9b59b6", "triangle"),
    "indicator": ("#3d8bcd", "square"),
    "attack-pattern": ("#2fa98c", "triangleDown"),
    "campaign": ("#c2578f", "star"),
    "infrastructure": ("#7d8a99", "hexagon"),
    "report": ("#5a6472", "square"),
}
DEFAULT_STYLE = ("#8a8a8a", "dot")

BREADCRUMB_LIMIT = 8


def _style(node_type: str) -> tuple[str, str]:
    return TYPE_STYLE.get(node_type, DEFAULT_STYLE)


def _label(attributes: dict) -> str:
    """Node label. Indicators are defanged so the canvas holds no live value."""
    name = attributes.get("name", "")
    if attributes.get("type") == "indicator":
        return defang(name, attributes.get("ioc_type"))
    return name


def _push_breadcrumb(node_id: str) -> None:
    trail: list[str] = st.session_state.setdefault("graph_trail", [])
    if trail and trail[-1] == node_id:
        return
    trail.append(node_id)
    del trail[:-BREADCRUMB_LIMIT]


def _select(node_id: str) -> None:
    st.session_state["graph_selected"] = node_id
    _push_breadcrumb(node_id)


def render_detail(graph, node_id: str) -> None:
    """The right-hand detail panel for one node."""
    attributes = graph.nodes[node_id]
    node_type = attributes.get("type", "")

    st.subheader(_label(attributes))
    st.caption(node_type)

    if attributes.get("aliases"):
        st.caption("Also called")
        st.text(", ".join(attributes["aliases"]))

    if node_type == "indicator":
        if attributes.get("flags"):
            st.warning("Flagged: " + ", ".join(attributes["flags"]))
        st.caption(f"Indicator type: {attributes.get('ioc_type', 'unknown')}")

    # Appears in
    report_names = []
    for report_id in attributes.get("reports", []):
        if report_id in graph:
            report_names.append(graph.nodes[report_id].get("filename", report_id))
    if report_names:
        st.caption(f"Appears in {len(report_names)} report(s)")
        for filename in report_names:
            st.text(filename)

    # Summary
    st.divider()
    st.caption("Summary")
    summary = attributes.get("summary", "")
    current = summary_is_current(attributes)
    if summary:
        st.text(summary)
        if not current:
            st.warning("The evidence has changed since this summary was written.")
    else:
        st.caption("No summary yet.")

    if has_api_key():
        label = "Regenerate summary" if summary else "Generate summary"
        st.caption("Generated once from this node's evidence quotes only, then cached.")
        if st.button(label, key=f"summary_{node_id}"):
            provider = get_provider("anthropic")
            try:
                with st.spinner("Summarizing…"):
                    text, cost = generate_summary(
                        graph, node_id, provider, settings.anthropic_model
                    )
                    written = dict(graph.nodes[node_id])

                    def mutate(fresh_graph, node=node_id, payload=written):
                        if node in fresh_graph:
                            fresh_graph.nodes[node]["summary"] = payload["summary"]
                            fresh_graph.nodes[node]["summary_evidence_hash"] = payload[
                                "summary_evidence_hash"
                            ]

                    save_graph_with_retry(get_store(settings), mutate)
            except (LLMError, VersionConflict) as exc:
                st.error(str(exc))
            else:
                st.success(f"Summary generated ({format_cost(cost)}).")
                st.text(text)
                st.rerun()
    else:
        st.caption("Set ANTHROPIC_API_KEY to generate summaries.")

    # Relationships, grouped, each clickable.
    st.divider()
    grouped = node_relationships(graph, node_id)
    if grouped:
        st.caption("Relationships")
        for relation, items in sorted(grouped.items()):
            arrow = {"out": "→", "in": "←"}
            st.caption(relation)
            for item in items:
                direction = arrow.get(item["direction"], "")
                button_label = f"{direction} {item['name']} ({item['type']})"
                if st.button(button_label, key=f"nav_{node_id}_{relation}_{item['id']}"):
                    _select(item["id"])
                    st.rerun()
    else:
        st.caption("No relationships recorded.")

    # Related indicators
    indicators = related_indicators(graph, node_id)
    if indicators:
        st.divider()
        st.caption("Related indicators (shown defanged)")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "type": item["ioc_type"],
                        "value": defang(item["name"], item["ioc_type"]),
                        "flags": ", ".join(item["flags"]),
                    }
                    for item in indicators
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    # Evidence
    st.divider()
    st.caption("Evidence from the reports")
    evidence = attributes.get("evidence", [])
    if evidence:
        for entry in evidence:
            report_id = entry.get("report_id", "")
            filename = (
                graph.nodes[report_id].get("filename", report_id)
                if report_id in graph
                else report_id
            )
            page = entry.get("page")
            location = f"{filename}" + (f", page {page}" if page else "")
            st.caption(location)
            # st.text: quotes are raw report content.
            st.text(entry.get("quote", ""))
    else:
        st.caption("No evidence quotes recorded.")


def main() -> None:
    st.title("Explore the graph")

    store = get_store(settings)
    try:
        graph, version = store.load()
    except StorageError as exc:
        st.error(f"The stored graph could not be loaded: {exc}")
        return

    if graph.number_of_nodes() == 0:
        st.info("The graph is empty. Ingest a report first.")
        st.page_link("pages/1_Ingest.py", label="Ingest a report", icon=":material/upload:")
        return

    controls, canvas, detail = st.columns([1, 2, 1.4])

    with controls:
        st.caption(f"Loaded version {version}")
        if st.button("Refresh", icon=":material/refresh:"):
            st.rerun()

        nodes = entity_nodes(graph)
        # Search over names and aliases, which is why aliases are stored on the node.
        options: dict[str, str] = {}
        for identifier, attributes in nodes:
            label = f"{_label(attributes)}  [{attributes.get('type','')}]"
            options[label] = identifier
            for alias in attributes.get("aliases", []):
                options[f"{alias} → {_label(attributes)}  [{attributes.get('type','')}]"] = identifier

        chosen_label = st.selectbox(
            "Search nodes",
            options=["(none)"] + sorted(options),
            index=0,
        )
        if chosen_label != "(none)":
            candidate = options[chosen_label]
            if st.session_state.get("graph_selected") != candidate:
                _select(candidate)

        present_types = sorted({attributes.get("type", "") for _, attributes in nodes})
        type_filter = st.multiselect("Entity types", present_types, default=present_types)
        show_reports = st.toggle("Show report nodes", value=False)
        found_by = st.radio(
            "Found by",
            options=["both", "pipeline", "agent"],
            horizontal=True,
            help="Filter edges by which mode produced them.",
        )
        depth = st.slider("Neighborhood depth", 1, 2, 1)
        max_nodes = st.slider("Max nodes", 20, 300, 150, step=10)

        st.caption("Legend")
        for node_type in present_types:
            colour, shape = _style(node_type)
            st.caption(f"{node_type} — {shape}")

        trail = st.session_state.get("graph_trail", [])
        if len(trail) > 1:
            st.divider()
            st.caption("Recently visited")
            for identifier in reversed(trail[:-1][-5:]):
                if identifier not in graph:
                    continue
                if st.button(
                    _label(graph.nodes[identifier]), key=f"trail_{identifier}"
                ):
                    _select(identifier)
                    st.rerun()

    selected = st.session_state.get("graph_selected")
    if selected is not None and selected not in graph:
        selected = None
        st.session_state.pop("graph_selected", None)

    if selected:
        view = neighborhood(
            graph, selected, depth=depth, max_nodes=max_nodes, include_reports=show_reports
        )
    else:
        keep = top_nodes_by_degree(graph, limit=min(50, max_nodes), include_reports=show_reports)
        view = graph.subgraph(keep).copy()

    with canvas:
        if selected:
            st.caption(
                f"Neighborhood of {_label(graph.nodes[selected])} "
                f"({view.number_of_nodes()} nodes)"
            )
        else:
            st.caption(f"Most connected nodes ({view.number_of_nodes()}). Select one to explore.")

        agraph_nodes = []
        for identifier, attributes in view.nodes(data=True):
            node_type = attributes.get("type", "")
            if node_type != "report" and type_filter and node_type not in type_filter:
                continue
            colour, shape = _style(node_type)
            is_selected = identifier == selected
            agraph_nodes.append(
                Node(
                    id=identifier,
                    # Labels carry report-derived names; agraph renders them as plain text.
                    label=_label(attributes),
                    size=26 if is_selected else 16,
                    color="#ffffff" if is_selected else colour,
                    borderWidth=4 if is_selected else 1,
                    shape=shape,
                    title=node_type,
                )
            )

        visible = {node.id for node in agraph_nodes}
        agraph_edges = [
            Edge(source=source, target=target, label="" if key == REPORTED_IN else str(key))
            for source, target, key, data in view.edges(keys=True, data=True)
            if source in visible
            and target in visible
            and (found_by == "both" or data.get("source", "pipeline") == found_by)
        ]

        clicked = agraph(
            nodes=agraph_nodes,
            edges=agraph_edges,
            config=Config(
                width=720,
                height=560,
                directed=True,
                physics=True,
                hierarchical=False,
                nodeHighlightBehavior=True,
                highlightColor="#f6c344",
                collapsible=False,
            ),
        )

        if clicked and clicked != selected and clicked in graph:
            _select(clicked)
            st.rerun()

    with detail:
        if selected:
            render_detail(graph, selected)
        else:
            st.caption("Click a node, or search on the left, to see its details.")


main()

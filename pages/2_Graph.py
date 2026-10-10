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

from auth import render_usage_strip, require_access
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
# Colour families, not one hue per type.
#
# A node-link canvas is an ALL-PAIRS surface: any two nodes can end up side by side, unlike a bar
# chart where only neighbours need separating. Validating the eight-hue categorical palette under
# all-pairs FAILED — worst normal-vision ΔE 7.1 (red vs orange, hard to tell apart even with full
# colour vision) and worst CVD ΔE 1.6 (magenta vs aqua under deuteranopia, effectively identical).
# No five-hue subset passes either; exactly two four-hue subsets do.
#
# So the nine node types are grouped into four validated families plus a neutral for provenance.
# The chosen four pass every check against this surface, with one CVD warn (green↔yellow, ΔE 6.9)
# which is permitted only alongside a secondary encoding — here every node is directly labelled on
# the canvas and hovering shows its exact type.
FAMILY_COLOR = {
    "adversary": "#d55181",    # who is doing it
    "capability": "#c98500",   # what they deploy
    "technique": "#008300",    # how, and the weakness used
    "observable": "#3987e5",   # what you can detect — the large majority of nodes
    "provenance": "#6b7280",   # report nodes; neutral grey, deliberately not a series colour
}

TYPE_FAMILY = {
    "threat-actor": "adversary",
    "campaign": "adversary",
    "malware": "capability",
    "tool": "capability",
    "attack-pattern": "technique",
    "vulnerability": "technique",
    "indicator": "observable",
    "infrastructure": "observable",
    "report": "provenance",
}

# Kept short on purpose: the legend sits in a narrow column, and a long label is clipped rather
# than wrapped. The full membership is spelled out in a caption underneath.
FAMILY_LABEL = {
    "adversary": "Adversary",
    "capability": "Capability",
    "technique": "Technique",
    "observable": "Observable",
    "provenance": "Report",
}

FAMILY_MEMBERS = {
    "adversary": "threat actors, campaigns",
    "capability": "malware, tools",
    "technique": "attack patterns, vulnerabilities",
    "observable": "indicators, infrastructure",
    "provenance": "source reports",
}

SURFACE = "#0E1117"
EDGE_COLOR = "#3f4654"
EDGE_HIGHLIGHT = "#8ea2c6"
LABEL_COLOR = "#d6dae2"
SELECTED_RING = "#f5f7fa"

BREADCRUMB_LIMIT = 8

MIN_NODE_SIZE = 11
MAX_NODE_SIZE = 34


def filter_key(attributes: dict) -> str:
    """The value the type filter matches on.

    Indicators are split by their IOC type. Lumping all of them under one "indicator" entry made
    the filter almost useless on a real graph: indicators are the overwhelming majority of nodes
    (429 of 486 here), so the only choice it offered was "nearly everything" or "nearly nothing".
    Splitting them lets you ask for just the CVEs, or just the hashes.
    """
    if attributes.get("type") == "indicator":
        return f"indicator:{attributes.get('ioc_type') or 'unknown'}"
    return attributes.get("type", "")


def filter_label(key: str) -> str:
    """How a filter key reads in the picker."""
    if key.startswith("indicator:"):
        return f"indicator · {key.split(':', 1)[1]}"
    return key


def family_of(node_type: str) -> str:
    return TYPE_FAMILY.get(node_type, "observable")


def color_of(node_type: str) -> str:
    return FAMILY_COLOR[family_of(node_type)]


def _node_size(degree: int, max_degree: int, selected: bool) -> int:
    """Size by connectedness, so hubs read as hubs.

    Square root rather than linear: degree is long-tailed, and a linear scale would make one hub
    enormous and flatten everything else into identical dots.
    """
    if selected:
        return MAX_NODE_SIZE + 6
    if max_degree <= 1:
        return MIN_NODE_SIZE
    share = (degree / max_degree) ** 0.5
    return int(MIN_NODE_SIZE + share * (MAX_NODE_SIZE - MIN_NODE_SIZE))


def _node_color(node_type: str, selected: bool) -> dict:
    """vis.js colour object: fill, border, and the hover/selected states."""
    base = color_of(node_type)
    return {
        "background": base,
        "border": SELECTED_RING if selected else base,
        "highlight": {"background": base, "border": SELECTED_RING},
        "hover": {"background": base, "border": EDGE_HIGHLIGHT},
    }


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
    require_access()

    # First thing on the page, above the title: the daily caps are the only ceiling on what a
    # shared link costs, so they belong where they are seen rather than in the sidebar.
    render_usage_strip()

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

    # The canvas spans the full width at the top; controls and details sit underneath.
    #
    # Streamlit executes top to bottom, and the graph depends on every control value, so the
    # controls must RUN before it. st.container reserves a slot that can be written to later:
    # the controls execute first and render below, while the graph executes afterwards and
    # renders into the slot above them. Without this the widgets would have to be read from
    # session_state a run behind, and every filter change would lag by one interaction.
    canvas = st.container()
    st.divider()
    controls, detail = st.columns([1, 1.25])

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

        # Counted from the whole graph, not the current view, so the option list does not
        # reshuffle every time the neighbourhood changes under you.
        counts: dict[str, int] = {}
        for _, attributes in nodes:
            key = filter_key(attributes)
            counts[key] = counts.get(key, 0) + 1

        # Named entities first, then indicator sub-types; each group alphabetical.
        ordered_keys = sorted(
            counts, key=lambda k: (k.startswith("indicator:"), filter_label(k))
        )
        option_labels = {f"{filter_label(k)}  ({counts[k]})": k for k in ordered_keys}

        chosen_labels = st.multiselect(
            "Entity and indicator types",
            options=list(option_labels),
            default=list(option_labels),
            help=(
                "Indicators are split by IOC type — CVEs, hashes, domains, URLs and so on — "
                "because they outnumber everything else combined."
            ),
        )
        type_filter = {option_labels[label] for label in chosen_labels}
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
        families = []
        for node_type in present_types:
            family = family_of(node_type)
            if family not in families:
                families.append(family)
        if show_reports and "provenance" not in families:
            families.append("provenance")

        legend = pd.DataFrame(
            {"": ["" for _ in families], "group": [FAMILY_LABEL[f] for f in families]}
        )
        # Styler, not markdown: this paints the exact node colours without any HTML of our own.
        st.dataframe(
            legend.style.apply(
                lambda _col: [f"background-color: {FAMILY_COLOR[f]}" for f in families], subset=[""]
            ),
            use_container_width=True,
            hide_index=True,
            height=min(42 + 35 * len(families), 260),
        )
        # One caption per family: st.caption collapses newlines, so a joined string ran the
        # four groups together into a single unreadable line.
        for family in families:
            st.caption(f"{FAMILY_LABEL[family]}: {FAMILY_MEMBERS[family]}")
        st.caption(
            "Types are grouped rather than each getting its own hue: on a canvas where any two "
            "nodes can sit side by side, eight hues are not reliably distinguishable. Node size "
            "reflects how connected it is; hover a node for its exact type."
        )

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
            st.caption(f"Most connected nodes ({view.number_of_nodes()}). Click one, or search below.")

        # Degree in the WHOLE graph, not in the view. The view is an induced subgraph, so a node
        # whose edges run to anything outside it — most often the report node, which is hidden by
        # default — measured zero, and the overview captioned "most connected nodes" then showed
        # "0 connection(s)". Degree is a property of the entity, so it must not change with the
        # viewport; this also stops nodes resizing as you filter.
        degrees = {identifier: graph.degree(identifier) for identifier in view.nodes()}
        max_degree = max(degrees.values()) if degrees else 1

        agraph_nodes = []
        for identifier, attributes in view.nodes(data=True):
            node_type = attributes.get("type", "")
            if (
                node_type != "report"
                and type_filter
                and filter_key(attributes) not in type_filter
            ):
                continue
            is_selected = identifier == selected
            agraph_nodes.append(
                Node(
                    id=identifier,
                    # Labels carry report-derived names; agraph renders them as plain text.
                    label=_label(attributes),
                    # Round for every type, as requested. Type is carried by colour family, the
                    # hover title and the detail panel rather than by shape.
                    shape="dot",
                    size=_node_size(degrees.get(identifier, 1), max_degree, is_selected),
                    color=_node_color(node_type, is_selected),
                    borderWidth=3 if is_selected else 0,
                    borderWidthSelected=3,
                    # Shows the IOC type for indicators, since colour only carries the family.
                    title=(
                        f"{filter_label(filter_key(attributes))} · "
                        f"{degrees.get(identifier, 0)} connection(s)"
                    ),
                    font={
                        "color": SELECTED_RING if is_selected else LABEL_COLOR,
                        "size": 15 if is_selected else 12,
                        "face": "Inter, Helvetica, Arial, sans-serif",
                        # A halo in the surface colour keeps labels readable where edges cross.
                        "strokeWidth": 3,
                        "strokeColor": SURFACE,
                        "vadjust": -2,
                    },
                )
            )

        visible = {node.id for node in agraph_nodes}
        agraph_edges = [
            Edge(
                source=source,
                target=target,
                label="" if key == REPORTED_IN else str(key),
                color={"color": EDGE_COLOR, "highlight": EDGE_HIGHLIGHT, "hover": EDGE_HIGHLIGHT},
                width=1,
                selectionWidth=2,
                # Curved edges separate the several relations two nodes can have, which a
                # MultiDiGraph produces routinely and straight lines would draw on top of itself.
                smooth={"type": "continuous", "roundness": 0.18},
                arrows={"to": {"enabled": True, "scaleFactor": 0.45}},
                font={
                    "color": "#9aa3b2",
                    "size": 10,
                    "face": "Inter, Helvetica, Arial, sans-serif",
                    "strokeWidth": 3,
                    "strokeColor": SURFACE,
                    "align": "middle",
                },
            )
            for source, target, key, data in view.edges(keys=True, data=True)
            if source in visible
            and target in visible
            and (found_by == "both" or data.get("source", "pipeline") == found_by)
        ]

        clicked = agraph(
            nodes=agraph_nodes,
            edges=agraph_edges,
            config=Config(
                # The canvas is now full width rather than one column of three, so it can be
                # far larger. Still a fixed pixel size, so it is set to fit the content area of
                # a ~1280px laptop; wider than that and narrow screens crop it.
                width=1000,
                height=760,
                directed=True,
                physics=True,
                hierarchical=False,
                nodeHighlightBehavior=True,
                highlightColor=EDGE_HIGHLIGHT,
                collapsible=False,
                # Config passes unknown kwargs straight through to vis.js options.
                backgroundColor=SURFACE,
                # Repulsion over the default barnesHut: it spaces a small, dense neighbourhood
                # evenly instead of flinging low-degree nodes to the rim, which is the shape this
                # graph actually has — one hub with many single-edge indicators hanging off it.
                solver="repulsion",
                repulsion={
                    # Spacing is a legibility trade: pulling nodes closer lets vis fit more on
                    # screen, but it then zooms out until the labels are unreadable, which defeats
                    # the point. These values keep labels legible and rely on the canvas width
                    # being set to fit its column so nothing is cropped.
                    "nodeDistance": 180,
                    "centralGravity": 0.15,
                    "springLength": 165,
                    "springConstant": 0.04,
                    "damping": 0.22,
                },
                stabilization={"enabled": True, "iterations": 220, "fit": True},
                nodes={
                    "shape": "dot",
                    "borderWidthSelected": 3,
                    "shadow": {
                        "enabled": True,
                        "color": "rgba(0,0,0,0.45)",
                        "size": 12,
                        "x": 0,
                        "y": 2,
                    },
                    "scaling": {"label": {"enabled": False}},
                },
                edges={
                    "selectionWidth": 2,
                    "hoverWidth": 1.5,
                    "smooth": {"type": "continuous", "roundness": 0.18},
                },
                interaction={
                    "hover": True,
                    "tooltipDelay": 120,
                    "navigationButtons": False,
                    "keyboard": False,
                    "multiselect": False,
                    "hideEdgesOnDrag": True,
                },
            ),
        )

        if clicked and clicked != selected and clicked in graph:
            _select(clicked)
            st.rerun()

    with detail:
        if selected:
            render_detail(graph, selected)
        else:
            st.caption("Click a node in the graph, or use the search below, to see its details.")


main()

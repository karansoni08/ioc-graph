"""The knowledge graph: node and edge shapes, and helpers for reading it.

A `networkx.MultiDiGraph`, serialized to JSON. MultiDiGraph because two entities can be
related in more than one way ("APT21 uses Akira" and "APT21 communicates-with Akira"), and
direction matters for relations like `attributed-to`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import networkx as nx

# Edge key for the internal entity -> report edge. Not an LLM-proposed relation: application
# code adds it so provenance is always present even when the model said nothing about it.
REPORTED_IN = "reported-in"

MAX_EVIDENCE_PER_NODE = 10

NODE_TYPES = (
    "threat-actor",
    "malware",
    "tool",
    "vulnerability",
    "indicator",
    "attack-pattern",
    "campaign",
    "infrastructure",
    "report",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_graph() -> nx.MultiDiGraph:
    return nx.MultiDiGraph()


@dataclass
class MergeStats:
    """What one merge changed, for display after ingesting a report."""

    new_nodes: int = 0
    updated_nodes: int = 0
    new_edges: int = 0
    removed_nodes: int = 0
    by_type: dict[str, int] = field(default_factory=dict)

    def count_type(self, node_type: str) -> None:
        self.by_type[node_type] = self.by_type.get(node_type, 0) + 1


def graph_stats(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """Counts for the home page."""
    by_type: dict[str, int] = {}
    for _, attributes in graph.nodes(data=True):
        node_type = attributes.get("type", "unknown")
        by_type[node_type] = by_type.get(node_type, 0) + 1
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "reports": by_type.get("report", 0),
        "by_type": by_type,
    }


def list_reports(graph: nx.MultiDiGraph) -> list[dict[str, Any]]:
    """Report nodes, newest first."""
    reports = [
        {"id": identifier, **attributes}
        for identifier, attributes in graph.nodes(data=True)
        if attributes.get("type") == "report"
    ]
    reports.sort(key=lambda report: report.get("ingested_at", ""), reverse=True)
    return reports


def entity_nodes(graph: nx.MultiDiGraph) -> list[tuple[str, dict[str, Any]]]:
    return [
        (identifier, attributes)
        for identifier, attributes in graph.nodes(data=True)
        if attributes.get("type") != "report"
    ]


def neighborhood(
    graph: nx.MultiDiGraph,
    center: str,
    depth: int = 1,
    max_nodes: int = 150,
    include_reports: bool = False,
) -> nx.MultiDiGraph:
    """The subgraph around one node.

    Showing the whole graph is useless past a few hundred nodes, so the explorer always works
    on a neighborhood. Breadth-first so that the closest nodes survive the `max_nodes` cut.
    """
    if center not in graph:
        return new_graph()

    def walk(with_reports: bool) -> list[str]:
        keep: list[str] = [center]
        seen = {center}
        frontier = [center]
        for _ in range(max(1, depth)):
            next_frontier: list[str] = []
            for node in frontier:
                for neighbour in list(graph.successors(node)) + list(graph.predecessors(node)):
                    if neighbour in seen:
                        continue
                    if not with_reports and graph.nodes[neighbour].get("type") == "report":
                        continue
                    seen.add(neighbour)
                    keep.append(neighbour)
                    next_frontier.append(neighbour)
                    if len(keep) >= max_nodes:
                        return keep
            frontier = next_frontier
            if not frontier:
                break
        return keep

    keep = walk(include_reports)

    # Most indicator nodes come from regex extraction and are never mentioned by the model, so
    # their only edge is `reported-in`. Hiding report nodes would render them as a lone dot with
    # nothing to explore. When that happens, show the reports anyway: "this came from report X"
    # is useful, an isolated dot is not.
    if len(keep) == 1 and not include_reports:
        keep = walk(True)

    return graph.subgraph(keep).copy()


def top_nodes_by_degree(
    graph: nx.MultiDiGraph, limit: int = 50, include_reports: bool = False
) -> list[str]:
    """The most connected nodes, used as the default view when nothing is selected."""
    candidates = [
        identifier
        for identifier, attributes in graph.nodes(data=True)
        if include_reports or attributes.get("type") != "report"
    ]
    candidates.sort(key=lambda identifier: graph.degree(identifier), reverse=True)
    return candidates[:limit]


def node_relationships(graph: nx.MultiDiGraph, node_id: str) -> dict[str, list[dict[str, Any]]]:
    """Relationships grouped by relation name, for the detail panel.

    Both directions are reported, with `direction` saying which, so the panel can render
    "uses: X" and "used by: Y" distinctly.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    if node_id not in graph:
        return grouped

    for _, target, key, data in graph.out_edges(node_id, keys=True, data=True):
        if key == REPORTED_IN:
            continue
        relation = data.get("relation", key)
        grouped.setdefault(relation, []).append(
            {
                "id": target,
                "name": graph.nodes[target].get("name", target),
                "type": graph.nodes[target].get("type", ""),
                "direction": "out",
                "evidence": data.get("evidence", ""),
                "report_id": data.get("report_id", ""),
                "source_mode": data.get("source", "pipeline"),
            }
        )

    for source, _, key, data in graph.in_edges(node_id, keys=True, data=True):
        if key == REPORTED_IN:
            continue
        relation = data.get("relation", key)
        grouped.setdefault(relation, []).append(
            {
                "id": source,
                "name": graph.nodes[source].get("name", source),
                "type": graph.nodes[source].get("type", ""),
                "direction": "in",
                "evidence": data.get("evidence", ""),
                "report_id": data.get("report_id", ""),
                "source_mode": data.get("source", "pipeline"),
            }
        )

    return grouped


def related_indicators(graph: nx.MultiDiGraph, node_id: str) -> list[dict[str, Any]]:
    """Indicator nodes adjacent to this node, for the detail panel."""
    if node_id not in graph:
        return []
    found: dict[str, dict[str, Any]] = {}
    for neighbour in list(graph.successors(node_id)) + list(graph.predecessors(node_id)):
        attributes = graph.nodes[neighbour]
        if attributes.get("type") == "indicator":
            found[neighbour] = {
                "id": neighbour,
                "name": attributes.get("name", ""),
                "ioc_type": attributes.get("ioc_type", ""),
                "flags": attributes.get("flags", []),
            }
    return sorted(found.values(), key=lambda item: (item["ioc_type"], item["name"]))


def to_json(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """Serialize for storage. `edges="links"` is passed explicitly for forward compatibility."""
    return nx.node_link_data(graph, edges="links")


def from_json(payload: dict[str, Any]) -> nx.MultiDiGraph:
    graph = nx.node_link_graph(payload, directed=True, multigraph=True, edges="links")
    if not isinstance(graph, nx.MultiDiGraph):  # pragma: no cover - defensive
        graph = nx.MultiDiGraph(graph)
    return graph

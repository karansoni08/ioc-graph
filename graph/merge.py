"""Merging a report's findings into the shared graph.

The hard requirement is idempotence: re-ingesting the same report must not duplicate nodes,
edges or evidence. That matters because re-analysing a report is cheap (it is cached) and will
happen by accident. The approach is to remove the report's previous contributions first, then
add them fresh, so a re-merge converges on the same graph rather than accumulating.

Removal is the subtle part. A node can be referenced by several reports, so removing one report
must strip only that report's evidence, descriptions and edges, and delete the node only if no
report still references it.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from extract.llm_extract import ReportAnalysis
from extract.models import IOCExtraction
from ingest.models import Document

from .model import (
    MAX_EVIDENCE_PER_NODE,
    REPORTED_IN,
    MergeStats,
    now_iso,
)
from .normalize import node_id, normalize_key, report_node_id


def _resolve_entity(name: str, analysis: ReportAnalysis, ioc_extraction: IOCExtraction) -> tuple[str, str] | None:
    """Map a relationship endpoint to (entity_type, node id).

    Relationship endpoints are names, not ids. They may refer to an LLM entity or to a regex
    indicator, and both must resolve to the same node the entity pass created.
    """
    folded = name.casefold()

    for entity in analysis.entities:
        if entity.name.casefold() == folded:
            key = normalize_key(entity.type, entity.name)
            return entity.type, node_id(entity.type, key)
        if any(alias.casefold() == folded for alias in entity.aliases):
            key = normalize_key(entity.type, entity.name)
            return entity.type, node_id(entity.type, key)

    for ioc in ioc_extraction.iocs:
        if ioc.value.casefold() == folded:
            key = normalize_key("indicator", ioc.value, ioc.type)
            return "indicator", node_id("indicator", key)

    return None


def _add_evidence(attributes: dict[str, Any], report_id: str, quote: str, page: int | None) -> None:
    """Append an evidence entry, newest first, without duplicating it."""
    entries: list[dict[str, Any]] = attributes.setdefault("evidence", [])
    for entry in entries:
        if entry.get("report_id") == report_id and entry.get("quote") == quote:
            return
    entries.insert(0, {"report_id": report_id, "quote": quote, "page": page})
    del entries[MAX_EVIDENCE_PER_NODE:]


def _touch_node(
    graph: nx.MultiDiGraph,
    identifier: str,
    node_type: str,
    name: str,
    report_id: str,
    stats: MergeStats,
    **extra: Any,
) -> dict[str, Any]:
    """Create or update a node, returning its attribute dict."""
    if identifier in graph:
        attributes = graph.nodes[identifier]
        stats.updated_nodes += 1
    else:
        graph.add_node(
            identifier,
            type=node_type,
            # First-seen spelling becomes the display name; later spellings become aliases.
            name=name,
            aliases=[],
            reports=[],
            evidence=[],
            descriptions=[],
            first_seen=now_iso(),
            summary="",
            summary_evidence_hash="",
        )
        attributes = graph.nodes[identifier]
        stats.new_nodes += 1
        stats.count_type(node_type)

    attributes["last_seen"] = now_iso()
    if report_id not in attributes["reports"]:
        attributes["reports"].append(report_id)

    # A different spelling of a node we already have becomes an alias rather than a new node.
    if name and name != attributes.get("name"):
        aliases = attributes.setdefault("aliases", [])
        if name not in aliases:
            aliases.append(name)

    for key, value in extra.items():
        if value not in (None, "", [], {}):
            attributes[key] = value

    return attributes


def merge_report(
    graph: nx.MultiDiGraph,
    doc: Document,
    ioc_extraction: IOCExtraction,
    analysis: ReportAnalysis,
    ingested_by: str = "",
    mode: str = "pipeline",
) -> MergeStats:
    """Merge one analysed report into the graph. Idempotent."""
    stats = MergeStats()
    report_id = report_node_id(doc.sha256)

    # Remove any previous contribution from this report so a re-merge cannot accumulate.
    if report_id in graph:
        removal = remove_report(graph, report_id)
        stats.removed_nodes += removal.removed_nodes

    graph.add_node(
        report_id,
        type="report",
        name=doc.filename,
        filename=doc.filename,
        sha256=doc.sha256,
        ingested_at=now_iso(),
        model=analysis.model,
        prompt_version=analysis.prompt_version,
        ingested_by=ingested_by,
        cost_usd=round(analysis.cost_usd, 6),
        mode=mode,
        reports=[],
        evidence=[],
        descriptions=[],
        aliases=[],
    )
    stats.new_nodes += 1
    stats.count_type("report")

    # Every regex indicator becomes a node, whether or not the LLM mentioned it. The regex
    # pass is the authoritative source of indicators, so the graph should not lose one just
    # because the model did not pick it up.
    for ioc in ioc_extraction.iocs:
        key = normalize_key("indicator", ioc.value, ioc.type)
        identifier = node_id("indicator", key)
        attributes = _touch_node(
            graph,
            identifier,
            "indicator",
            ioc.value,
            report_id,
            stats,
            ioc_type=ioc.type,
            flags=list(ioc.flags),
        )
        page = ioc.pages[0] if ioc.pages else None
        for context in ioc.contexts[:2]:
            _add_evidence(attributes, report_id, context, page)
        graph.add_edge(identifier, report_id, key=REPORTED_IN, relation=REPORTED_IN,
                       report_id=report_id, source=mode)
        stats.new_edges += 1

    # LLM entities.
    for entity in analysis.entities:
        key = normalize_key(entity.type, entity.name)
        if not key:
            continue
        identifier = node_id(entity.type, key)
        attributes = _touch_node(
            graph, identifier, entity.type, entity.name, report_id, stats
        )
        for alias in entity.aliases:
            aliases = attributes.setdefault("aliases", [])
            if alias and alias not in aliases and alias != attributes.get("name"):
                aliases.append(alias)
        for description in entity.descriptions:
            descriptions = attributes.setdefault("descriptions", [])
            if not any(
                item.get("report_id") == report_id and item.get("text") == description
                for item in descriptions
            ):
                descriptions.append({"report_id": report_id, "text": description})
        for quote in entity.evidence:
            _add_evidence(attributes, report_id, quote, None)

        graph.add_edge(identifier, report_id, key=REPORTED_IN, relation=REPORTED_IN,
                       report_id=report_id, source=mode)
        stats.new_edges += 1

    # LLM relationships.
    for relationship in analysis.relationships:
        source = _resolve_entity(relationship.source, analysis, ioc_extraction)
        target = _resolve_entity(relationship.target, analysis, ioc_extraction)
        if source is None or target is None:
            # Validation should already have dropped these; skip rather than invent a node.
            continue
        _, source_id = source
        _, target_id = target
        if source_id not in graph or target_id not in graph:
            continue
        evidence = relationship.evidence[0] if relationship.evidence else ""
        graph.add_edge(
            source_id,
            target_id,
            key=relationship.relation,
            relation=relationship.relation,
            report_id=report_id,
            evidence=evidence,
            source=mode,
        )
        stats.new_edges += 1

    return stats


def remove_report(graph: nx.MultiDiGraph, report_id: str) -> MergeStats:
    """Remove one report's contributions, deleting nodes that no report references any more."""
    stats = MergeStats()
    if report_id not in graph:
        return stats

    # Drop every edge attributed to this report.
    doomed_edges = [
        (source, target, key)
        for source, target, key, data in graph.edges(keys=True, data=True)
        if data.get("report_id") == report_id
    ]
    for source, target, key in doomed_edges:
        if graph.has_edge(source, target, key):
            graph.remove_edge(source, target, key)

    orphans: list[str] = []
    for identifier, attributes in list(graph.nodes(data=True)):
        if attributes.get("type") == "report":
            continue
        reports: list[str] = attributes.get("reports", [])
        if report_id in reports:
            reports.remove(report_id)
        attributes["evidence"] = [
            entry for entry in attributes.get("evidence", []) if entry.get("report_id") != report_id
        ]
        attributes["descriptions"] = [
            entry
            for entry in attributes.get("descriptions", [])
            if entry.get("report_id") != report_id
        ]
        if not reports:
            orphans.append(identifier)
        elif attributes.get("summary"):
            # The evidence a summary was written from has changed, so mark it stale rather
            # than silently presenting a summary of material that is no longer there.
            attributes["summary_evidence_hash"] = "stale"

    for identifier in orphans:
        graph.remove_node(identifier)
        stats.removed_nodes += 1

    graph.remove_node(report_id)
    stats.removed_nodes += 1
    return stats

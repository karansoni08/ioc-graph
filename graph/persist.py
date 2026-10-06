"""Merge-and-save with conflict retry.

The concurrency story in one function. Two peers can upload at the same time; whoever saves
second gets a `VersionConflict`, and the right response is not to overwrite but to reload the
other person's graph and re-merge onto it. Merging is idempotent, so replaying it on a fresh
graph is safe and produces the union of both uploads.
"""

from __future__ import annotations

import networkx as nx

from extract.llm_extract import ReportAnalysis
from extract.models import IOCExtraction
from ingest.models import Document
from storage.base import GraphStore, VersionConflict

from .merge import MergeStats, merge_report, remove_report

MAX_SAVE_ATTEMPTS = 3


def merge_and_save(
    store: GraphStore,
    doc: Document,
    ioc_extraction: IOCExtraction,
    analysis: ReportAnalysis,
    ingested_by: str = "",
    mode: str = "pipeline",
    max_attempts: int = MAX_SAVE_ATTEMPTS,
) -> tuple[MergeStats, int]:
    """Merge a report into the stored graph and save it. Returns (stats, new version)."""
    last_error: VersionConflict | None = None

    for _ in range(max_attempts):
        graph, version = store.load()
        stats = merge_report(graph, doc, ioc_extraction, analysis, ingested_by, mode)
        try:
            new_version = store.save(graph, version)
        except VersionConflict as conflict:
            # Someone else saved between our load and our save. Start over on their graph.
            last_error = conflict
            continue
        return stats, new_version

    raise last_error or VersionConflict(0, 0)


def remove_and_save(
    store: GraphStore, report_id: str, max_attempts: int = MAX_SAVE_ATTEMPTS
) -> tuple[MergeStats, int]:
    """Remove a report from the stored graph and save, with the same retry policy."""
    last_error: VersionConflict | None = None

    for _ in range(max_attempts):
        graph, version = store.load()
        stats = remove_report(graph, report_id)
        try:
            new_version = store.save(graph, version)
        except VersionConflict as conflict:
            last_error = conflict
            continue
        return stats, new_version

    raise last_error or VersionConflict(0, 0)


def save_graph_with_retry(
    store: GraphStore, mutate, max_attempts: int = MAX_SAVE_ATTEMPTS
) -> int:
    """Apply `mutate(graph)` to the stored graph and save it, retrying on conflict.

    Used for in-place changes that are not a report merge, such as writing a generated
    summary onto a node.
    """
    last_error: VersionConflict | None = None

    for _ in range(max_attempts):
        graph, version = store.load()
        mutate(graph)
        try:
            return store.save(graph, version)
        except VersionConflict as conflict:
            last_error = conflict
            continue

    raise last_error or VersionConflict(0, 0)

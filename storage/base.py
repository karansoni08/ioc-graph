"""The storage interface.

One interface so Phase 7 can swap local JSON files for Supabase without the app noticing. The
version number is the concurrency mechanism: `save` only succeeds if the stored version is
still the one the caller loaded, which is what stops two people's uploads from overwriting each
other.
"""

from __future__ import annotations

from typing import Any, Protocol

import networkx as nx


class StorageError(RuntimeError):
    """Storage could not complete an operation."""


class VersionConflict(StorageError):
    """The stored graph changed since it was loaded.

    The caller should reload, re-merge its report onto the fresh graph, and retry. Overwriting
    would silently discard whatever the other writer added.
    """

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"The graph was updated by someone else (expected version {expected}, "
            f"found {actual}). Reload and merge again."
        )
        self.expected = expected
        self.actual = actual


class GraphStore(Protocol):
    """What the app needs from storage."""

    name: str

    def load(self) -> tuple[nx.MultiDiGraph, int]:
        """Return the graph and its version. A missing graph is an empty graph at version 0."""
        ...

    def save(self, graph: nx.MultiDiGraph, expected_version: int) -> int:
        """Persist the graph, returning the new version. Raises `VersionConflict`."""
        ...

    def list_reports(self) -> list[dict[str, Any]]:
        ...

    def cache_get(self, key: str) -> dict[str, Any] | None:
        """LLM result cache. Moved behind this interface in Phase 4 so Phase 7 can share it."""
        ...

    def cache_set(self, key: str, value: dict[str, Any]) -> None:
        ...

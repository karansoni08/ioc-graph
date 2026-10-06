"""Supabase backend for `GraphStore`.

Used in the deployed app because Streamlit Community Cloud wipes the container disk on restart
and redeploy, so local JSON would lose every ingested report.

Only extraction results and metadata are stored. **The original uploaded file is never stored
anywhere** — not on disk, not in Supabase, not in object storage. It is parsed in memory and
discarded. That is stated in the UI and the README because it is a promise to whoever uploads.

Concurrency lives in the `save_graph` SQL function rather than here: comparing versions in Python
would be a race between two sessions.
"""

from __future__ import annotations

from functools import cached_property
from typing import Any

import networkx as nx

from config import get_supabase_service_key, get_supabase_url
from graph.model import from_json, new_graph, to_json

from .base import GraphStore, StorageError, VersionConflict

WORKSPACE_ID = "main"


class SupabaseGraphStore(GraphStore):
    """One shared workspace row, plus cache, runs, reports and usage tables."""

    name = "supabase"

    def __init__(self) -> None:
        self._client: Any = None

    @cached_property
    def client(self) -> Any:
        """Created on first use, with the service-role key.

        The service-role key bypasses Row Level Security, which is exactly why it is only ever
        used here, server-side. It is never passed to the browser.
        """
        if self._client is None:
            try:
                from supabase import create_client
            except ImportError as exc:  # pragma: no cover
                raise StorageError(
                    "The `supabase` package is not installed. "
                    "Install it or set STORAGE_BACKEND=local."
                ) from exc
            self._client = create_client(get_supabase_url(), get_supabase_service_key())
        return self._client

    # ------------------------------------------------------------------ graph

    def load(self) -> tuple[nx.MultiDiGraph, int]:
        try:
            response = (
                self.client.table("workspace")
                .select("graph, version")
                .eq("id", WORKSPACE_ID)
                .limit(1)
                .execute()
            )
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not read the graph from Supabase: {exc}") from exc

        rows = response.data or []
        if not rows:
            # No workspace row yet: an empty graph at version 0, which `save_graph` accepts.
            return new_graph(), 0

        row = rows[0]
        return from_json(row["graph"]), int(row["version"])

    def save(self, graph: nx.MultiDiGraph, expected_version: int) -> int:
        try:
            response = self.client.rpc(
                "save_graph",
                {"p_graph": to_json(graph), "p_expected": expected_version},
            ).execute()
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not save the graph to Supabase: {exc}") from exc

        new_version = response.data
        if new_version is None:
            raise StorageError("save_graph returned no version.")
        new_version = int(new_version)

        if new_version == -1:
            # The function detected a version mismatch under a row lock.
            raise VersionConflict(expected_version, -1)

        return new_version

    def list_backups(self) -> list[dict[str, Any]]:
        try:
            response = (
                self.client.table("workspace_backups")
                .select("id, version, created_at")
                .eq("workspace_id", WORKSPACE_ID)
                .order("created_at", desc=True)
                .limit(10)
                .execute()
            )
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not list backups: {exc}") from exc
        return response.data or []

    # ---------------------------------------------------------------- reports

    def list_reports(self) -> list[dict[str, Any]]:
        try:
            response = (
                self.client.table("reports")
                .select("*")
                .order("ingested_at", desc=True)
                .execute()
            )
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not list reports: {exc}") from exc
        return response.data or []

    def record_report(
        self,
        sha256: str,
        filename: str,
        ingested_by: str,
        mode: str,
        tokens: int,
        cost_usd: float,
        security_status: str,
    ) -> None:
        try:
            self.client.table("reports").upsert(
                {
                    "sha256": sha256,
                    "filename": filename,
                    "ingested_by": ingested_by,
                    "mode": mode,
                    "tokens": tokens,
                    "cost_usd": cost_usd,
                    "security_status": security_status,
                }
            ).execute()
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not record the report: {exc}") from exc

    # ------------------------------------------------------------------ cache

    def cache_get(self, key: str) -> dict[str, Any] | None:
        try:
            response = (
                self.client.table("llm_cache").select("value").eq("key", key).limit(1).execute()
            )
        except Exception:
            # A cache miss is always safe; a cache failure must not break analysis.
            return None
        rows = response.data or []
        return rows[0]["value"] if rows else None

    def cache_set(self, key: str, value: dict[str, Any]) -> None:
        try:
            self.client.table("llm_cache").upsert({"key": key, "value": value}).execute()
        except Exception:
            # Failing to cache costs money later but breaks nothing now.
            return

    # ------------------------------------------------------------------- runs

    def save_run(self, run_id: str, payload: dict[str, Any]) -> None:
        try:
            self.client.table("agent_runs").upsert(
                {
                    "id": run_id,
                    "sha256": payload.get("document_sha256", ""),
                    "data": payload,
                }
            ).execute()
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not save the agent run: {exc}") from exc

    def list_runs(self) -> list[dict[str, Any]]:
        try:
            response = (
                self.client.table("agent_runs")
                .select("data")
                .order("created_at", desc=True)
                .limit(50)
                .execute()
            )
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not list agent runs: {exc}") from exc
        return [row["data"] for row in (response.data or []) if row.get("data")]

    # ------------------------------------------------------------------ usage

    def reserve_usage(
        self,
        day: str,
        kind: str,
        estimated_cost: float,
        report_limit: int,
        agent_limit: int,
        spend_limit: float,
    ) -> bool:
        """Atomically check and reserve today's usage. False means a limit would be exceeded."""
        try:
            response = self.client.rpc(
                "reserve_usage",
                {
                    "p_day": day,
                    "p_kind": kind,
                    "p_est_cost": estimated_cost,
                    "p_report_limit": report_limit,
                    "p_agent_limit": agent_limit,
                    "p_spend_limit": spend_limit,
                },
            ).execute()
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Could not reserve usage: {exc}") from exc
        return bool(response.data)

    def settle_usage(self, day: str, delta: float) -> None:
        """Adjust the reserved estimate to the actual spend."""
        try:
            self.client.rpc("settle_usage", {"p_day": day, "p_delta": delta}).execute()
        except Exception:
            # The estimate stays reserved, which over-counts spend. Safe direction to fail.
            return

    def get_usage(self, day: str) -> dict[str, Any]:
        try:
            response = (
                self.client.table("usage_daily").select("*").eq("day", day).limit(1).execute()
            )
        except Exception:
            return {"day": day, "reports": 0, "agent_runs": 0, "spend_usd": 0}
        rows = response.data or []
        return rows[0] if rows else {"day": day, "reports": 0, "agent_runs": 0, "spend_usd": 0}

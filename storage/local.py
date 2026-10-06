"""Local JSON storage, used in development.

Writes are atomic: content goes to a temp file in the same directory, is flushed and fsynced,
then `os.replace`d over the target. `os.replace` is atomic on POSIX and Windows, so a crash
mid-write leaves the previous file intact rather than a truncated graph. Without this, an
interrupted save loses every report ever ingested.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

import networkx as nx

from graph.model import from_json, new_graph, to_json
from graph.model import list_reports as _list_reports

from .base import GraphStore, VersionConflict

BACKUP_COUNT = 5

_BACKUP_NAME = re.compile(r"^graph\.v(\d+)\.json$")


class LocalGraphStore(GraphStore):
    """`data/graph.json` plus rotating backups in `data/backups/`."""

    name = "local"

    def __init__(self, data_dir: str | Path = "data") -> None:
        self.data_dir = Path(data_dir)
        self.graph_path = self.data_dir / "graph.json"
        self.backup_dir = self.data_dir / "backups"
        self.cache_dir = self.data_dir / "cache"
        self.runs_dir = self.data_dir / "runs"
        self.usage_path = self.data_dir / "usage.json"

    # ------------------------------------------------------------------ graph

    def load(self) -> tuple[nx.MultiDiGraph, int]:
        if not self.graph_path.exists():
            return new_graph(), 0
        try:
            payload = json.loads(self.graph_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # A corrupt graph is recoverable from a backup through the Maintenance page; do not
            # silently start from empty, which would look like data loss.
            raise VersionConflict(0, -1) from None
        return from_json(payload["graph"]), int(payload.get("version", 0))

    def stored_version(self) -> int:
        if not self.graph_path.exists():
            return 0
        try:
            payload = json.loads(self.graph_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return -1
        return int(payload.get("version", 0))

    def save(self, graph: nx.MultiDiGraph, expected_version: int) -> int:
        current = self.stored_version()
        if current != expected_version:
            raise VersionConflict(expected_version, current)

        new_version = current + 1
        payload = {"version": new_version, "graph": to_json(graph)}

        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.graph_path.exists():
            self._backup(current)

        self._atomic_write(self.graph_path, json.dumps(payload, indent=2))
        return new_version

    def _atomic_write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Temp file in the same directory so os.replace stays on one filesystem.
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        )
        try:
            with handle as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(handle.name, path)
        except BaseException:
            Path(handle.name).unlink(missing_ok=True)
            raise

    def _backup(self, version: int) -> None:
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        target = self.backup_dir / f"graph.v{version}.json"
        target.write_bytes(self.graph_path.read_bytes())
        self._rotate_backups()

    def _rotate_backups(self) -> None:
        backups = sorted(
            (
                (int(match.group(1)), path)
                for path in self.backup_dir.glob("graph.v*.json")
                if (match := _BACKUP_NAME.match(path.name))
            ),
            key=lambda item: item[0],
        )
        for _, path in backups[:-BACKUP_COUNT]:
            path.unlink(missing_ok=True)

    def list_backups(self) -> list[int]:
        if not self.backup_dir.exists():
            return []
        versions = [
            int(match.group(1))
            for path in self.backup_dir.glob("graph.v*.json")
            if (match := _BACKUP_NAME.match(path.name))
        ]
        return sorted(versions, reverse=True)

    def restore_backup(self, version: int) -> int:
        """Restore a backup as a new version, rather than rewinding the counter.

        Moving the version forward means anyone holding the old version still gets a conflict
        instead of silently writing over the restore.
        """
        source = self.backup_dir / f"graph.v{version}.json"
        if not source.exists():
            raise FileNotFoundError(f"No backup for version {version}.")
        payload = json.loads(source.read_text(encoding="utf-8"))
        graph = from_json(payload["graph"])
        return self.save(graph, self.stored_version())

    def list_reports(self) -> list[dict[str, Any]]:
        graph, _ = self.load()
        return _list_reports(graph)

    # ------------------------------------------------------------------ cache

    def cache_get(self, key: str) -> dict[str, Any] | None:
        path = self.cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def cache_set(self, key: str, value: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.cache_dir / f"{key}.json", json.dumps(value, indent=2))


    # ------------------------------------------------------------------ usage

    # Streamlit serves every session of one deployment from a single process, so a process-level
    # lock plus an atomic file write is enough to make the daily caps race-free here. Supabase does
    # this in SQL because there the writers are separate connections; the guarantee needed is the
    # same, which is why this backend implements the identical interface rather than leaving the
    # caps unenforced. Without it, a deployment on this backend would have no spend ceiling at all.
    _usage_lock = threading.Lock()

    def _read_usage(self) -> dict[str, dict]:
        if not self.usage_path.exists():
            return {}
        try:
            data = json.loads(self.usage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write_usage(self, data: dict[str, dict]) -> None:
        self._atomic_write(self.usage_path, json.dumps(data, indent=2))

    def _row(self, data: dict[str, dict], day: str) -> dict:
        return data.setdefault(
            day, {"day": day, "reports": 0, "agent_runs": 0, "spend_usd": 0.0}
        )

    def reserve_usage(
        self,
        day: str,
        kind: str,
        estimated_cost: float,
        report_limit: int,
        agent_limit: int,
        spend_limit: float,
    ) -> bool:
        """Check every daily cap and reserve the usage, atomically. False means blocked."""
        with self._usage_lock:
            data = self._read_usage()
            row = self._row(data, day)

            if kind == "report" and row["reports"] + 1 > report_limit:
                return False
            if kind == "agent" and row["agent_runs"] + 1 > agent_limit:
                return False
            if row["spend_usd"] + estimated_cost > spend_limit:
                return False

            if kind == "report":
                row["reports"] += 1
            if kind == "agent":
                row["agent_runs"] += 1
            row["spend_usd"] = round(row["spend_usd"] + estimated_cost, 6)

            # Keep only the recent days; this file should never grow without bound.
            for stale in sorted(data)[:-30]:
                del data[stale]

            self._write_usage(data)
            return True

    def settle_usage(self, day: str, delta: float) -> None:
        """Adjust the reserved estimate to the actual spend, never below zero."""
        with self._usage_lock:
            data = self._read_usage()
            row = self._row(data, day)
            row["spend_usd"] = round(max(0.0, row["spend_usd"] + delta), 6)
            self._write_usage(data)

    def get_usage(self, day: str) -> dict[str, Any]:
        return dict(self._row(self._read_usage(), day))

    # ------------------------------------------------------------------- runs

    def save_run(self, run_id: str, payload: dict[str, Any]) -> None:
        """Agent run traces (Phase 6)."""
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.runs_dir / f"{run_id}.json", json.dumps(payload, indent=2))

    def list_runs(self) -> list[dict[str, Any]]:
        if not self.runs_dir.exists():
            return []
        runs: list[dict[str, Any]] = []
        for path in sorted(self.runs_dir.glob("*.json"), reverse=True):
            try:
                runs.append(json.loads(path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return runs

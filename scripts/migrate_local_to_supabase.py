"""Copy local development data into Supabase.

Dry-run by default: it reports exactly what it would write and writes nothing. `--apply` is
required to make changes, because the graph in Supabase is the shared one and overwriting it would
destroy other people's uploads.

Run from the project root:

    python scripts/migrate_local_to_supabase.py            # dry run
    python scripts/migrate_local_to_supabase.py --apply    # actually write
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import get_settings  # noqa: E402
from graph.model import graph_stats  # noqa: E402
from storage.base import VersionConflict  # noqa: E402
from storage.local import LocalGraphStore  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write to Supabase (default: dry run)")
    parser.add_argument(
        "--force-graph",
        action="store_true",
        help="overwrite the remote graph even if it is not empty (destructive)",
    )
    args = parser.parse_args()

    settings = get_settings()
    local = LocalGraphStore(settings.data_dir)

    try:
        from storage.supabase_store import SupabaseGraphStore

        remote = SupabaseGraphStore()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not create the Supabase client: {exc}", file=sys.stderr)
        return 1

    local_graph, local_version = local.load()
    stats = graph_stats(local_graph)
    print(
        f"local graph: version {local_version}, {stats['nodes']} nodes, "
        f"{stats['edges']} edges, {stats['reports']} reports"
    )

    cache_files = sorted((Path(settings.data_dir) / "cache").glob("*.json"))
    run_files = sorted((Path(settings.data_dir) / "runs").glob("*.json"))
    print(f"local cache entries: {len(cache_files)}")
    print(f"local agent runs:    {len(run_files)}")

    try:
        remote_graph, remote_version = remote.load()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not read the remote graph: {exc}", file=sys.stderr)
        return 1

    remote_stats = graph_stats(remote_graph)
    print(
        f"remote graph: version {remote_version}, {remote_stats['nodes']} nodes, "
        f"{remote_stats['reports']} reports"
    )

    if remote_stats["nodes"] > 0 and not args.force_graph:
        print(
            "\nThe remote graph is NOT empty. Refusing to overwrite it: that would destroy "
            "whatever is already there. Re-run with --force-graph only if you are certain."
        )
        graph_action = "skip graph"
    else:
        graph_action = "upload graph"

    if not args.apply:
        print(f"\nDRY RUN. Would: {graph_action}, upload {len(cache_files)} cache entries, "
              f"upload {len(run_files)} runs.")
        print("Nothing was written. Re-run with --apply to make these changes.")
        return 0

    if graph_action == "upload graph":
        try:
            new_version = remote.save(local_graph, remote_version)
            print(f"uploaded graph as remote version {new_version}")
        except VersionConflict:
            print("the remote graph changed while uploading; re-run the migration", file=sys.stderr)
            return 1

    import json

    uploaded_cache = 0
    for path in cache_files:
        try:
            remote.cache_set(path.stem, json.loads(path.read_text(encoding="utf-8")))
            uploaded_cache += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  cache {path.name} failed: {exc}", file=sys.stderr)
    print(f"uploaded {uploaded_cache} cache entries")

    uploaded_runs = 0
    for path in run_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            remote.save_run(payload.get("run_id", path.stem), payload)
            uploaded_runs += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  run {path.name} failed: {exc}", file=sys.stderr)
    print(f"uploaded {uploaded_runs} agent runs")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

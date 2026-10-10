"""Maintenance and agent-run inspection from the command line.

These were Streamlit pages. They were removed from the app because they are operator tasks, not
things a reader of the graph does: reviewing possible duplicates, restoring a backup and reading
an agent trace are all occasional, deliberate actions. Keeping them in the UI meant every visitor
saw two pages they had no use for, and one of them could overwrite the graph.

The capability is unchanged — it simply lives here now, where it is scriptable and where a
destructive action requires typing a flag rather than clicking a button.

    python scripts/maintain.py stats
    python scripts/maintain.py usage
    python scripts/maintain.py duplicates --threshold 90
    python scripts/maintain.py export --out graph.json
    python scripts/maintain.py backups
    python scripts/maintain.py restore --version 3 --apply
    python scripts/maintain.py runs
    python scripts/maintain.py run --id 20261007_120000_abcdef123456
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import get_settings  # noqa: E402
from graph.model import graph_stats, list_reports, to_json  # noqa: E402
from graph.normalize import ALIASES_PATH, find_possible_duplicates  # noqa: E402
from llm.pricing import format_cost  # noqa: E402
from storage.base import StorageError  # noqa: E402
from storage.factory import get_store  # noqa: E402
from storage.local import LocalGraphStore  # noqa: E402


def _load():
    settings = get_settings()
    store = get_store(settings)
    try:
        graph, version = store.load()
    except StorageError as exc:
        print(f"Could not load the graph: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return settings, store, graph, version


def cmd_stats(args) -> int:
    _, _, graph, version = _load()
    stats = graph_stats(graph)
    print(f"graph version {version}")
    print(f"  {stats['nodes']} nodes, {stats['edges']} edges, {stats['reports']} report(s)")
    for node_type, count in sorted(stats["by_type"].items()):
        print(f"    {node_type:16} {count}")
    print("\nreports:")
    for report in list_reports(graph):
        print(
            f"  {report.get('filename', '?'):40} {report.get('ingested_at', '')[:19]}  "
            f"mode={report.get('mode', '?')}  {format_cost(report.get('cost_usd', 0.0))}"
        )
    return 0


def cmd_usage(args) -> int:
    """Today's usage against the daily caps.

    This was a sidebar widget. It was removed from the app because it showed every visitor a
    budget that is the owner's business; the caps are still enforced before every spend.
    """
    settings, store, _, _ = _load()
    from usage import today_key, usage_summary  # noqa: PLC0415 — keeps CLI startup cheap

    summary = usage_summary(store, settings)
    if summary is None:
        print("This storage backend does not track usage.", file=sys.stderr)
        return 1

    print(f"today ({today_key(settings)}, timezone {settings.app_timezone}):")
    print(f"  reports     {summary['reports']}/{settings.daily_report_limit}")
    print(f"  agent runs  {summary['agent_runs']}/{settings.daily_agent_limit}")
    print(
        f"  spend       ${float(summary['spend_usd']):.2f}/"
        f"${settings.daily_spend_limit_usd:.2f}"
    )
    return 0


def cmd_duplicates(args) -> int:
    """Surface likely duplicates. Never merges: a human decides, via graph/aliases.json."""
    _, _, graph, _ = _load()
    pairs = find_possible_duplicates(graph, threshold=args.threshold)
    if not pairs:
        print(f"No candidate duplicates at similarity >= {args.threshold}.")
    else:
        print(f"{len(pairs)} candidate pair(s) at similarity >= {args.threshold}:\n")
        for left, right, score in pairs:
            left_name = graph.nodes[left].get("name", left)
            right_name = graph.nodes[right].get("name", right)
            print(
                f"  {score:5.1f}  [{graph.nodes[left].get('type','')}]  "
                f"{left_name!r}  ~  {right_name!r}"
            )

    # Runs whether or not the fuzzy scan found anything: it is a different question.
    _report_same_name_pairs(graph)
    print(
        f"\nNothing was merged. To record a real merge, add an entry to {ALIASES_PATH} mapping "
        "the alias key to the canonical key, then re-ingest the affected reports.\n"
        "Fuzzy matching is never applied automatically: merging two genuinely different threat "
        "actors is worse than keeping a duplicate node."
    )
    return 0


def _report_same_name_pairs(graph) -> None:
    """Nodes sharing a name across different types.

    The fuzzy scan deliberately never pairs different types — "Akira" the group and "Akira" the
    ransomware are genuinely two things, and merging them would be wrong. But the case is still
    worth seeing: an advisory that names the group and its malware identically often yields one
    well-connected node and one near-empty stub, and the stub is easy to select by accident.
    Listed, never merged.
    """
    by_name: dict[str, list[tuple[str, str, int]]] = {}
    for identifier, attributes in graph.nodes(data=True):
        if attributes.get("type") == "report":
            continue
        name = (attributes.get("name") or "").strip().casefold()
        if name:
            by_name.setdefault(name, []).append(
                (identifier, attributes.get("type", ""), graph.degree(identifier))
            )

    shared = {n: v for n, v in by_name.items() if len({t for _, t, _ in v}) > 1}
    if not shared:
        return

    print(f"\n{len(shared)} name(s) used by more than one type (listed, not merged):")
    for name, entries in sorted(shared.items()):
        parts = ", ".join(f"{t} (degree {d})" for _, t, d in sorted(entries, key=lambda e: -e[2]))
        print(f"  {name!r}: {parts}")
    print(
        "  These are usually legitimate — a group and its malware sharing a name — but the "
        "low-degree one is easy to select by mistake in the explorer."
    )


def cmd_export(args) -> int:
    _, _, graph, version = _load()
    payload = {"version": version, "graph": to_json(graph)}
    destination = Path(args.out)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    size_kb = destination.stat().st_size / 1024
    print(f"wrote {destination} ({size_kb:,.0f} KB, graph version {version})")
    print(
        "This file contains REAL indicator values and report-derived quotes. Treat it as live "
        "threat data."
    )
    return 0


def cmd_backups(args) -> int:
    _, store, _, version = _load()
    if not isinstance(store, LocalGraphStore):
        print("Backups are only listable on the local storage backend.", file=sys.stderr)
        return 1
    versions = store.list_backups()
    print(f"current version: {version}")
    if not versions:
        print("no backups yet (one is written before every save)")
        return 0
    print("available backups:", ", ".join(str(v) for v in versions))
    return 0


def cmd_restore(args) -> int:
    """Restore a backup. Requires --apply, because it overwrites the shared graph."""
    _, store, _, version = _load()
    if not isinstance(store, LocalGraphStore):
        print("Restore is only available on the local storage backend.", file=sys.stderr)
        return 1

    available = store.list_backups()
    if args.version not in available:
        print(
            f"No backup for version {args.version}. Available: "
            f"{', '.join(str(v) for v in available) or 'none'}",
            file=sys.stderr,
        )
        return 1

    if not args.apply:
        print(
            f"DRY RUN: would restore backup v{args.version} over the current graph (v{version}).\n"
            "Nothing was written. Re-run with --apply to do it."
        )
        return 0

    new_version = store.restore_backup(args.version)
    # Restoring moves the version FORWARD rather than rewinding it, so anyone holding the old
    # version still gets a conflict instead of silently overwriting the restore.
    print(f"restored backup v{args.version} as version {new_version}")
    return 0


def cmd_runs(args) -> int:
    _, store, _, _ = _load()
    if not hasattr(store, "list_runs"):
        print("This storage backend does not keep agent runs.", file=sys.stderr)
        return 1
    runs = store.list_runs()
    if not runs:
        print("No agent runs recorded.")
        return 0
    print(f"{len(runs)} agent run(s), newest first:\n")
    for run in runs:
        diff = run.get("diff", {}) or {}
        new_items = (
            len(diff.get("new_entities", []))
            + len(diff.get("new_relationships", []))
            + len(diff.get("new_attack_patterns", []))
        )
        print(
            f"  {run.get('run_id','?'):32} {run.get('status','?'):16} "
            f"{run.get('tool_calls',0)} calls  +{new_items} items  "
            f"{format_cost(run.get('cost_usd', 0.0))}"
        )
    print("\nInspect one with: python scripts/maintain.py run --id <run_id>")
    return 0


def cmd_run(args) -> int:
    """Print a full agent trace: every tool call, its arguments and what came back."""
    _, store, _, _ = _load()
    runs = store.list_runs() if hasattr(store, "list_runs") else []
    match = next((r for r in runs if r.get("run_id") == args.id), None)
    if match is None:
        print(f"No run with id {args.id}.", file=sys.stderr)
        return 1

    print(f"run:      {match.get('run_id')}")
    print(f"status:   {match.get('status')}  {match.get('stop_note', '')}")
    print(f"model:    {match.get('model')}   ATT&CK {match.get('attack_version','?')}")
    print(
        f"budget:   {match.get('tool_calls', 0)} tool calls, "
        f"{match.get('input_tokens',0):,} in / {match.get('output_tokens',0):,} out, "
        f"{format_cost(match.get('cost_usd', 0.0))}, "
        f"{match.get('duration_ms',0)/1000:.1f}s"
    )

    print("\nsteps:")
    for step in match.get("steps", []):
        flags = []
        if step.get("withheld"):
            flags.append("RESULT WITHHELD (injection detected)")
        if step.get("error"):
            flags.append("error")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        print(f"\n  {step.get('index', 0) + 1}. {step.get('tool')}{suffix}")
        for key, value in (step.get("arguments") or {}).items():
            print(f"       {key}: {value}")
        preview = (step.get("result_preview") or "").replace("\n", "\n       ")
        print(f"       -> {preview[:400]}")

    patterns = match.get("attack_patterns", [])
    if patterns:
        print("\nvalidated ATT&CK mappings:")
        for pattern in patterns:
            print(f"  {pattern['technique_id']:12} {pattern['name']}  (entity: {pattern.get('entity','')})")

    dropped = (match.get("validation", {}) or {}).get("dropped", [])
    print(f"\nvalidation dropped {len(dropped)} item(s)")
    for item in dropped[:10]:
        print(f"  [{item.get('reason')}] {item.get('value','')}: {item.get('detail','')[:80]}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("stats", help="graph size, node types and ingested reports").set_defaults(
        func=cmd_stats
    )

    sub.add_parser("usage", help="today's reports / agent runs / spend against the caps").set_defaults(
        func=cmd_usage
    )

    duplicates = sub.add_parser("duplicates", help="candidate duplicate nodes for human review")
    duplicates.add_argument("--threshold", type=int, default=90, help="similarity 80-100")
    duplicates.set_defaults(func=cmd_duplicates)

    export = sub.add_parser("export", help="write the whole graph to a JSON file")
    export.add_argument("--out", default="graph-export.json")
    export.set_defaults(func=cmd_export)

    sub.add_parser("backups", help="list restorable graph backups").set_defaults(func=cmd_backups)

    restore = sub.add_parser("restore", help="restore a backup (dry run unless --apply)")
    restore.add_argument("--version", type=int, required=True)
    restore.add_argument("--apply", action="store_true", help="actually overwrite the graph")
    restore.set_defaults(func=cmd_restore)

    sub.add_parser("runs", help="list agent runs").set_defaults(func=cmd_runs)

    run = sub.add_parser("run", help="print one agent run's full trace")
    run.add_argument("--id", required=True)
    run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

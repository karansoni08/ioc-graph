"""Measure agent-mode run-to-run variance.

The Phase 6 comparison used one agent run per fixture, which is too few to say anything about a
non-deterministic loop. This runs it N times per fixture and reports the spread, so the evaluation
can state variance as a measurement rather than an impression.

Costs money: prints an estimate and requires --yes.

    python scripts/agent_variance.py --dry-run
    python scripts/agent_variance.py --runs 3 --yes
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.loop import run_agent  # noqa: E402
from config import Settings, get_api_key, get_settings  # noqa: E402
from extract.iocs import extract_iocs  # noqa: E402
from extract.llm_extract import run_llm_extraction  # noqa: E402
from graph.model import new_graph  # noqa: E402
from ingest.loader import load_document  # noqa: E402
from llm.factory import get_provider  # noqa: E402
from llm.pricing import estimate_cost, format_cost  # noqa: E402
from storage.local import LocalGraphStore  # noqa: E402

KEYS = ("aa24-109a-akira", "aa23-158a-cl0p-moveit", "aa24-242a-ransomhub")
REPORTS = Path("tests/fixtures/reports")
EXPECTED = Path("tests/fixtures/expected")
EVAL = Settings(max_file_mb=25, max_pages=200, data_dir="data")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    per_run = estimate_cost(
        settings.anthropic_agent_model,
        settings.agent_max_input_tokens,
        settings.max_output_tokens * (settings.agent_max_tool_calls + 1),
    )
    total = per_run * args.runs * len(KEYS)
    print(f"{args.runs} runs x {len(KEYS)} fixtures, worst case {format_cost(total)}")
    print("(observed actual is far lower, around $0.05-0.16 per run)")
    if args.dry_run:
        return 0
    if not args.yes:
        if input("proceed? [y/N] ").strip().lower() != "y":
            return 0

    import anthropic

    client = anthropic.Anthropic(api_key=get_api_key(), timeout=180.0, max_retries=3)
    provider = get_provider("anthropic")
    store = LocalGraphStore("data")

    results: dict[str, list[dict]] = {}

    for key in KEYS:
        truth = set(
            json.loads((EXPECTED / f"{key}.json").read_text()).get("attack_techniques", [])
        )
        pdf = REPORTS / f"{key}.pdf"
        doc = load_document(pdf.name, pdf.read_bytes(), EVAL)
        iocs = extract_iocs(doc)
        pipeline = run_llm_extraction(doc, iocs, provider, settings=EVAL, use_cache=True)

        rows = []
        for n in range(args.runs):
            run = run_agent(doc, iocs, pipeline, new_graph(), client, EVAL)
            store.save_run(run.run_id, run.to_dict())
            found = {p["technique_id"].upper() for p in run.attack_patterns}
            tp = len(found & truth)
            rows.append(
                {
                    "status": run.status,
                    "tool_calls": run.tool_calls,
                    "entities": len(run.analysis.entities) if run.analysis else 0,
                    "relationships": len(run.analysis.relationships) if run.analysis else 0,
                    "attack_found": len(found),
                    "attack_tp": tp,
                    "attack_recall": round(tp / len(truth), 3) if truth else 0.0,
                    "cost": round(run.cost_usd, 4),
                    "seconds": round(run.duration_ms / 1000, 1),
                }
            )
            print(
                f"  {key} run {n+1}/{args.runs}: {run.status}, {run.tool_calls} calls, "
                f"{rows[-1]['attack_tp']}/{len(truth)} ATT&CK, {format_cost(run.cost_usd)}"
            )
        results[key] = rows

    print("\n=== VARIANCE ===")
    for key, rows in results.items():
        statuses = [r["status"] for r in rows]
        recalls = [r["attack_recall"] for r in rows]
        costs = [r["cost"] for r in rows]
        print(f"\n{key}")
        print(f"  statuses: {statuses}")
        print(f"  ATT&CK recall: min={min(recalls)} max={max(recalls)} mean={statistics.mean(recalls):.3f}")
        print(f"  entities: {[r['entities'] for r in rows]}")
        print(f"  relationships: {[r['relationships'] for r in rows]}")
        print(f"  cost: min={min(costs)} max={max(costs)} total={sum(costs):.3f}")

    out = Path("docs/results/agent_variance.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {out}")
    grand = sum(r["cost"] for rows in results.values() for r in rows)
    print(f"total spent: {format_cost(grand)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Compare pipeline mode against agent mode on the evaluation fixtures.

**This script spends money.** It prints the estimated cost and requires explicit confirmation
before making any call. The pipeline side can come from cache (free); the agent side is always a
fresh run, because an agent run is not deterministic and caching it would make the comparison
meaningless.

Run from the project root:

    python scripts/compare_modes.py --dry-run     # show what it would cost, call nothing
    python scripts/compare_modes.py               # ask for confirmation, then run
    python scripts/compare_modes.py --yes         # skip the prompt (for non-interactive use)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.attack_data import attack_version, is_available  # noqa: E402
from agent.loop import run_agent  # noqa: E402
from config import Settings, get_api_key, get_settings, has_api_key  # noqa: E402
from extract.chunking import chunk_document  # noqa: E402
from extract.iocs import extract_iocs  # noqa: E402
from extract.llm_extract import (  # noqa: E402
    estimate_max_cost,
    load_cached,
    run_llm_extraction,
)
from graph.model import new_graph  # noqa: E402
from ingest.loader import load_document  # noqa: E402
from llm.factory import get_provider  # noqa: E402
from llm.pricing import estimate_cost, format_cost  # noqa: E402

REPORTS_DIR = Path("tests/fixtures/reports")
EXPECTED_DIR = Path("tests/fixtures/expected")
DOCS_PATH = Path("docs/EVALUATION.md")
RESULTS_DIR = Path("docs/results")

EVAL_SETTINGS = Settings(max_file_mb=25, max_pages=200)

KEYS = ("aa24-109a-akira", "aa23-158a-cl0p-moveit", "aa24-242a-ransomhub")


@dataclass
class ModeResult:
    mode: str
    entities_kept: int = 0
    relationships_kept: int = 0
    proposed: int = 0
    dropped: int = 0
    attack_found: list[str] = field(default_factory=list)
    tokens: int = 0
    cost_usd: float = 0.0
    duration_ms: int = 0
    tool_calls: int = 0
    status: str = ""
    from_cache: bool = False

    # Items the VALIDATOR kept, excluding entities synthesized from ATT&CK mappings. Those are
    # created by application code after validation, so counting them made the rate exceed 1.0.
    validated_kept: int = 0

    @property
    def grounded_rate(self) -> float:
        """Validator-kept / proposed: how much of what the model said survived validation."""
        if self.proposed == 0:
            return 0.0
        return self.validated_kept / self.proposed


def _attack_metrics(found: list[str], truth: list[str]) -> tuple[int, int, int, float, float]:
    found_set = {value.upper() for value in found}
    truth_set = {value.upper() for value in truth}
    true_positives = len(found_set & truth_set)
    false_positives = len(found_set - truth_set)
    false_negatives = len(truth_set - found_set)
    precision = true_positives / len(found_set) if found_set else 0.0
    recall = true_positives / len(truth_set) if truth_set else 0.0
    return true_positives, false_positives, false_negatives, precision, recall


def _pipeline_attack_ids(analysis) -> list[str]:
    """Technique ids the pipeline captured, from its attack-pattern entities."""
    import re

    pattern = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    found: set[str] = set()
    for entity in analysis.entities:
        if entity.type == "attack-pattern":
            for match in pattern.finditer(entity.name):
                found.add(match.group(0).upper())
            for alias in entity.aliases:
                for match in pattern.finditer(alias):
                    found.add(match.group(0).upper())
    return sorted(found)


def estimate_total_cost(settings: Settings) -> tuple[float, list[str]]:
    """Worst-case cost of the whole comparison, plus notes about what is cached."""
    total = 0.0
    notes: list[str] = []

    for key in KEYS:
        pdf = REPORTS_DIR / f"{key}.pdf"
        if not pdf.exists():
            notes.append(f"{key}: PDF missing, will be skipped")
            continue
        document = load_document(pdf.name, pdf.read_bytes(), EVAL_SETTINGS)
        iocs = extract_iocs(document)

        cached = load_cached(document.sha256, settings.anthropic_model, settings)
        if cached is not None:
            notes.append(f"{key}: pipeline is cached (free)")
        else:
            chunks, _ = chunk_document(document, iocs, max_chunks=settings.max_chunks_per_report)
            pipeline_cost = estimate_max_cost(
                chunks, settings.anthropic_model, settings.max_output_tokens
            )
            total += pipeline_cost
            notes.append(f"{key}: pipeline up to {format_cost(pipeline_cost)}")

        agent_cost = estimate_cost(
            settings.anthropic_agent_model,
            settings.agent_max_input_tokens,
            settings.max_output_tokens * (settings.agent_max_tool_calls + 1),
        )
        total += agent_cost
        notes.append(f"{key}: agent up to {format_cost(agent_cost)}")

    return total, notes


def run_comparison(settings: Settings) -> list[dict]:
    import anthropic

    provider = get_provider("anthropic")
    client = anthropic.Anthropic(api_key=get_api_key(), timeout=120.0, max_retries=3)

    rows: list[dict] = []

    for key in KEYS:
        pdf = REPORTS_DIR / f"{key}.pdf"
        expected_path = EXPECTED_DIR / f"{key}.json"
        if not pdf.exists() or not expected_path.exists():
            print(f"skipping {key}: fixture missing", file=sys.stderr)
            continue

        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        truth = expected.get("attack_techniques", [])

        document = load_document(pdf.name, pdf.read_bytes(), EVAL_SETTINGS)
        iocs = extract_iocs(document)

        print(f"\n=== {key} — pipeline ===")
        pipeline_analysis = run_llm_extraction(
            document, iocs, provider, settings=settings, use_cache=True
        )
        pipeline = ModeResult(
            mode="pipeline",
            entities_kept=len(pipeline_analysis.entities),
            relationships_kept=len(pipeline_analysis.relationships),
            proposed=pipeline_analysis.validation.proposed_total,
            dropped=pipeline_analysis.validation.dropped_count,
            attack_found=_pipeline_attack_ids(pipeline_analysis),
            validated_kept=pipeline_analysis.validation.kept_total,
            tokens=pipeline_analysis.total_tokens,
            cost_usd=pipeline_analysis.cost_usd,
            duration_ms=pipeline_analysis.duration_ms,
            from_cache=pipeline_analysis.from_cache,
            status="cached" if pipeline_analysis.from_cache else "ran",
        )
        print(
            f"  {pipeline.entities_kept} entities, {pipeline.relationships_kept} relationships, "
            f"{len(pipeline.attack_found)} ATT&CK ids, {format_cost(pipeline.cost_usd)}"
        )

        print(f"=== {key} — agent ===")
        run = run_agent(document, iocs, pipeline_analysis, new_graph(), client, settings)
        agent_analysis = run.analysis
        agent = ModeResult(
            mode="agent",
            entities_kept=len(agent_analysis.entities) if agent_analysis else 0,
            relationships_kept=len(agent_analysis.relationships) if agent_analysis else 0,
            proposed=run.validation.proposed_total,
            dropped=run.validation.dropped_count,
            attack_found=[pattern["technique_id"] for pattern in run.attack_patterns],
            validated_kept=run.validation.kept_total,
            tokens=run.input_tokens + run.output_tokens,
            cost_usd=run.cost_usd,
            duration_ms=run.duration_ms,
            tool_calls=run.tool_calls,
            status=run.status,
        )
        print(
            f"  status={run.status}, {run.tool_calls} tool calls, "
            f"{len(agent.attack_found)} ATT&CK ids, {format_cost(agent.cost_usd)}"
        )

        for result in (pipeline, agent):
            tp, fp, fn, precision, recall = _attack_metrics(result.attack_found, truth)
            rows.append(
                {
                    "fixture": key,
                    "mode": result.mode,
                    "status": result.status,
                    "entities": result.entities_kept,
                    "relationships": result.relationships_kept,
                    "proposed": result.proposed,
                    "dropped": result.dropped,
                    "grounded_rate": round(result.grounded_rate, 3),
                    "attack_truth": len(truth),
                    "attack_found": len(result.attack_found),
                    "attack_tp": tp,
                    "attack_fp": fp,
                    "attack_fn": fn,
                    "attack_precision": round(precision, 3),
                    "attack_recall": round(recall, 3),
                    "tokens": result.tokens,
                    "cost_usd": round(result.cost_usd, 6),
                    "seconds": round(result.duration_ms / 1000, 1),
                    "tool_calls": result.tool_calls,
                }
            )

    return rows


def write_outputs(rows: list[dict]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "pipeline_vs_agent.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nwrote {csv_path}")

    lines = [
        "",
        "## Pipeline vs agent (Phase 6)",
        "",
        f"Date: {date.today().isoformat()}  ",
        f"ATT&CK dataset: {attack_version()}",
        "",
        "Agent runs are fresh (never cached), because an agent run is not deterministic and a",
        "cached one would make the comparison meaningless. Pipeline runs may be cached, which is",
        "why their cost can read as $0.00.",
        "",
        "| Fixture | Mode | Entities | Rels | Grounded | ATT&CK P | ATT&CK R | Tokens | Cost | Tool calls |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['fixture']} | {row['mode']} | {row['entities']} | {row['relationships']} | "
            f"{row['grounded_rate']:.3f} | {row['attack_precision']:.3f} | "
            f"{row['attack_recall']:.3f} | {row['tokens']:,} | "
            f"{format_cost(row['cost_usd'])} | {row['tool_calls'] or '-'} |"
        )

    pipeline_cost = sum(r["cost_usd"] for r in rows if r["mode"] == "pipeline")
    agent_cost = sum(r["cost_usd"] for r in rows if r["mode"] == "agent")
    ratio = (agent_cost / pipeline_cost) if pipeline_cost else float("inf")

    lines += [
        "",
        f"Total pipeline cost {format_cost(pipeline_cost)}, total agent cost "
        f"{format_cost(agent_cost)}"
        + (f", ratio {ratio:.1f}x." if pipeline_cost else " (pipeline was cached, so no ratio)."),
        "",
        "Raw numbers: `docs/results/pipeline_vs_agent.csv`.",
        "",
        "**Note on ATT&CK ground truth.** The scored truth is the technique ids printed in each",
        "advisory's own ATT&CK table, filtered to ids that still exist in the current dataset.",
        "Several ids from these 2023-2024 advisories were REVOKED or renumbered by MITRE since",
        "publication (T1562.001, T1562.004, T1574.002, and T1604 which never existed). They are",
        "excluded from scoring and listed in each fixture's",
        "`attack_techniques_unavailable`, because no correct mapping to them is possible against",
        "the current dataset — scoring them would penalise correct behaviour.",
        "",
    ]

    existing = DOCS_PATH.read_text(encoding="utf-8") if DOCS_PATH.exists() else "# Evaluation\n"
    marker = "\n## Pipeline vs agent (Phase 6)\n"
    if marker in existing:
        existing = existing.split(marker)[0]
    DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOCS_PATH.write_text(existing.rstrip("\n") + "\n" + "\n".join(lines), encoding="utf-8")
    print(f"wrote {DOCS_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="estimate cost and make no calls")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = parser.parse_args()

    settings = get_settings()

    if not is_available():
        print(
            "MITRE ATT&CK data is missing. Run `python scripts/fetch_attack.py` first.",
            file=sys.stderr,
        )
        return 1

    total, notes = estimate_total_cost(settings)
    print("Estimated maximum cost of this comparison:")
    for note in notes:
        print(f"  {note}")
    print(f"\n  TOTAL (worst case): {format_cost(total)}")
    print(
        "\nThis is a worst case: it assumes every chunk and every agent turn uses its full "
        "output budget. Actual cost is usually far lower."
    )

    if args.dry_run:
        print("\n--dry-run: nothing was called.")
        return 0

    if not has_api_key():
        print("\nANTHROPIC_API_KEY is not set, so no calls can be made.", file=sys.stderr)
        return 1

    if not args.yes:
        answer = input("\nProceed and spend this? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted. Nothing was called.")
            return 0

    rows = run_comparison(settings)
    if not rows:
        print("No fixtures were evaluated.", file=sys.stderr)
        return 1

    write_outputs(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

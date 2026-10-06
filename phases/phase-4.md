# Phase 4 — Knowledge Graph, Storage, and Interactive Exploration

Read `CLAUDE.md` first. This file adds detail for Phase 4 only.

## Goal
Merge every analyzed report into one deduplicated knowledge graph, store it safely on
disk, and let me explore it in Streamlit: click a node and see what it is, its relations,
related IOCs, source quotes and a grounded summary.

## Before you start
Phase 3 complete: tests pass, git clean, pushed. Install `networkx` and
`streamlit-agraph` (it returns the clicked node to Python, which pyvis cannot do).
Pin both.

## Out of scope
Agent mode, Supabase, passwords. Storage is local JSON only, behind an interface.

## 1. Graph model (`graph/model.py`)
Use `networkx.MultiDiGraph`.
Node id: `"{type}--{normalized_key}"` (STIX-like), e.g. `threat-actor--apt21`,
`indicator--ipv4--203.0.113.5`, `report--{sha256[:12]}`.
Node attributes:
- `name` (display name: first seen form), `type`, `aliases` (set -> list),
- `ioc_type` (for indicators), `flags` (from Phase 2, for indicators),
- `reports` (list of report ids where it appears),
- `evidence`: list of `{report_id, quote, page}` (max 10 kept, newest first),
- `descriptions`: list of `{report_id, text}`,
- `first_seen`, `last_seen` (ISO timestamps of ingestion),
- `summary`, `summary_evidence_hash` (filled lazily, section 5).
Report nodes: `filename`, `sha256`, `ingested_at`, `model`, `prompt_version`,
`ingested_by` (empty string for now), `cost_usd`.
Edges: key = relation; attributes `relation`, `report_id`, `evidence`.
Internal edge `reported-in` from each entity to the report node (not from the LLM).
All regex IOCs become `indicator` nodes even if the LLM did not mention them.

## 2. Normalization (`graph/normalize.py`)
`normalize_key(type, name) -> str`:
- Trim, collapse whitespace, NFKC, casefold.
- `threat-actor`: `APT 21`, `APT-21`, `apt21` -> `apt21`. Same pattern for `UNC`, `TA`,
  `FIN`, `G` + digits.
- `vulnerability`: uppercase CVE id when present.
- `attack-pattern`: if a technique id like `T1059.001` is present, key by the id.
- `indicator`: use the Phase 2 normalized value with its IOC type.
- Manual alias map `graph/aliases.json` (committed, starts empty `{}`) mapping alias keys
  to canonical keys. Only I edit it; never auto-merge by fuzzy matching.
- `find_possible_duplicates(graph)`: use `rapidfuzz` (add + pin) to list same-type node
  pairs with similarity above 90, shown in the UI for me to review. No auto-merge.

## 3. Merge (`graph/merge.py`)
`merge_report(graph, doc, ioc_extraction, analysis) -> MergeStats`
- Idempotent: if the report id already exists, first remove that report's contributions
  (its edges, its evidence entries, its id from node `reports`), then re-add. Delete
  nodes left with no reports.
- `MergeStats`: new nodes, updated nodes, new edges, by type.
`remove_report(graph, report_id)` uses the same removal logic.

## 4. Storage (`storage/`)
- `storage/base.py`: `Protocol` `GraphStore` with
  `load() -> tuple[MultiDiGraph, int]` (graph, version),
  `save(graph, expected_version) -> int` (raises `VersionConflict` if the stored version
  differs), `list_reports()`, `cache_get(key)`, `cache_set(key, value)`.
  (Move the Phase 3 cache behind this interface so Phase 7 can swap backends.)
- `storage/local.py`: `data/graph.json` = `{"version": int, "graph": node_link_data}`.
  Atomic writes: write to a temp file in the same folder, `fsync`, then `os.replace`.
  Keep the last 5 versions as `data/backups/graph.v{n}.json`.
- `storage/factory.py` picks the backend from `STORAGE_BACKEND`.
- On `VersionConflict`: reload, re-merge the report, retry up to 3 times.

## 5. Node summaries (`graph/summaries.py`)
- Generated only when I click "Generate summary" on a node.
- Input: the node's evidence quotes and descriptions only (inside random-nonce delimiters,
  treated as untrusted). Output: plain text, max 120 words, covering what it is, how it is
  used in the reports, and what it relates to. Instruct: no outside knowledge.
- Use the Phase 3 provider with a small schema `{summary: str}`; strip markdown/HTML.
- Cache on the node with `summary_evidence_hash` (hash of the inputs). If evidence changes,
  show "summary outdated" with a regenerate button.

## 6. UI (multipage Streamlit)
Restructure into:
- `app.py`: home page with graph stats (nodes by type, edges, reports) and quick links.
- `pages/1_Ingest.py`: the Phase 1-3 flow, plus a "Add to graph" button after analysis
  that runs `merge_report` + save and shows `MergeStats`.
- `pages/2_Graph.py`:
  - Left: controls: search box (autocomplete over node names and aliases), entity-type
    filter, "show report nodes" toggle, neighborhood depth slider (1-2), max nodes
    (default 150).
  - Center: `streamlit-agraph` view of the selected node's neighborhood (the mind-map
    view). With no selection, show the top 50 nodes by degree. Colors and shapes per type
    with a legend; selected node highlighted.
  - Right: detail panel for the clicked/selected node:
    name, type, aliases, flags; "Appears in" (report filenames);
    relationships grouped by relation (`uses: X, Y`), each clickable to navigate;
    related indicators (defanged display);
    evidence quotes with report name and page (`st.text`);
    summary with Generate/Regenerate button and cost shown.
  - Breadcrumb of recently visited nodes.
- `pages/3_Reports.py`: table of ingested reports (filename, date, entities, cost);
  "Remove from graph" with a confirmation step.
- `pages/4_Maintenance.py`: possible duplicates list (from section 2), download graph
  JSON, restore from a backup version (with confirmation).
All model-derived or report-derived text is rendered with `st.text`/`st.dataframe`/agraph
labels, never `st.markdown` or `unsafe_allow_html`.

## 7. Tests (`tests/test_graph.py`)
- Normalization: APT variants, CVE case, technique ids, alias map.
- Merging two reports that both mention APT21 yields ONE APT21 node with both report ids.
- Re-merging the same report does not duplicate nodes, edges or evidence.
- `remove_report` deletes orphaned nodes and keeps shared ones.
- Atomic save produces a valid file; `VersionConflict` raised on stale version.
- Backups rotate to 5.
- Summary cache invalidates when evidence changes (fake provider).

## 8. Manual end-to-end check (ask before spending)
With my permission, analyze the 3 Phase 2 fixtures (cached ones cost nothing), merge them,
and confirm: shared entities merged, clicking works, navigation via relationship links
works. Take 2 screenshots if your tools allow and save them to `docs/images/` for the
README; otherwise tell me which views to capture.

## 9. Finish
README status "Phase 4 of 7", add "Exploring the graph" section.
`pytest -q`, `git status` (no `data/`), commit
`Phase 4: knowledge graph, dedup, local versioned storage, interactive explorer`. Push.

## Acceptance criteria
- [ ] One node per real-world entity across reports; duplicates surfaced, not auto-merged.
- [ ] Clicking a node shows details; relationship links navigate.
- [ ] Graph survives app restart; re-ingesting a report is idempotent.
- [ ] Summaries only on click, grounded, cached.
- [ ] Tests pass, pushed.

## Ask me before
Live API calls, adding dependencies not named here, changing node id format.

## When finished, report
Graph stats after the 3 fixtures, duplicates found, UI performance with 150 nodes, and
any UX issues you noticed.

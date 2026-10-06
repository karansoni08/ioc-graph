# IOC Graph

A web app for exploring threat intelligence. Upload a threat report as a PDF or HTML file and
the app extracts indicators of compromise (IPs, domains, URLs, hashes, emails, CVE IDs) with
regular expressions, uses an LLM to identify the threat entities and the relationships between
them, and merges the result into a knowledge graph that spans every report ingested so far.
Clicking a node shows what the entity is, how it is used, which indicators relate to it, and
the exact quotes from the source reports that support each claim. It is a portfolio project
built to demonstrate a practical LLM use case with security taken seriously: report text is
treated as untrusted input throughout, the model is never allowed to invent an indicator, and
every claim it makes is checked against the source text before it reaches the graph.

## Status

**Phase 4 of 7 — knowledge graph and explorer.** The app accepts a PDF or HTML report, extracts
indicators with regular expressions, asks Claude for the threat entities and relationships
(validating every claim against the source text), and merges the result into one deduplicated
knowledge graph stored on disk. A multipage Streamlit UI lets you explore it: click a node to
see what it is, what it relates to, which indicators it touches and the exact source quotes.
Guardrail hardening, agent mode and deployment are the subject of later phases.

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Repo setup, secret scanning, Streamlit skeleton, PDF/HTML ingestion | Done |
| 2 | Regex IOC extraction, refanging, false-positive flags, evaluation | Done |
| 3 | Claude extraction with schema, grounding validation, caching, cost tracking | Done |
| 4 | Knowledge graph, normalization, dedup, versioned storage, explorer | Done |
| 5 | Layered guardrails, poisoned test corpus, threat model | Not started |
| 6 | Bounded agent mode with ATT&CK mapping, run traces, evaluation | Not started |
| 7 | Supabase storage, passwords, daily caps, deployment, v1.0 | Not started |

## Tech stack

- **UI:** Streamlit (Python only; no React and no hand-written frontend JavaScript)
- **PDF parsing:** PyMuPDF for text, pdfplumber for tables
- **HTML parsing:** BeautifulSoup with lxml
- **Validation:** Pydantic v2
- **Config:** python-dotenv
- **Tests:** pytest
- **Secret scanning:** pre-commit with gitleaks
- **IOC extraction:** `ioc-finder` (primary), `iocextract` (SHA-512 only)
- **LLM:** the official `anthropic` SDK with native structured outputs, behind a provider
  interface so another provider can be added
- **Graph:** NetworkX `MultiDiGraph`, `streamlit-agraph` for the interactive view, `rapidfuzz`
  for duplicate detection
- **Planned:** Supabase for deployed storage

## Local setup

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then edit .env and add your Anthropic API key
pre-commit install          # installs the gitleaks secret-scanning hook

streamlit run app.py        # start the app
pytest                      # run the test suite
```

The tests generate their own PDF and HTML fixtures in memory and never call the API, so running
them costs nothing. The real-advisory evaluation is separate, because it needs PDFs that are
deliberately not committed — see [Accuracy](#accuracy).

## Configuration

All settings live in `.env`, which is never committed. See `.env.example` for the full list.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | none | API key; required from Phase 3 onward |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Model used for extraction |
| `ANTHROPIC_AGENT_MODEL` | same as `ANTHROPIC_MODEL` | Model used by agent mode (Phase 6) |
| `STORAGE_BACKEND` | `local` | `local` for JSON files in `data/`, `supabase` when deployed |
| `MAX_FILE_MB` | `5` | Largest accepted upload |
| `MAX_PAGES` | `50` | Largest accepted PDF |
| `MAX_CHUNKS_PER_REPORT` | `6` | Chunks of one report sent to the model; the main cost control |
| `MAX_OUTPUT_TOKENS` | `4000` | Output budget per chunk |

## Project layout

```text
app.py              Streamlit entry point
config.py           Settings and API key access
ingest/             PDF and HTML text extraction
  models.py         The Document model
  loader.py         Upload validation and dispatch
  pdf.py            PyMuPDF text, pdfplumber tables
  html.py           BeautifulSoup text extraction
extract/            IOC extraction and LLM extraction
  models.py         The IOC and IOCExtraction models
  iocs.py           Regex extraction, normalization, dedup, false-positive flags
  sections.py       IOC section detection
  text_repair.py    Rejoins hashes wrapped across lines by PDF layout
  display.py        Defanging for display
  allowlist.txt     Domains flagged as benign
  schema.py         The schema the LLM must return (single source of truth)
  chunking.py       Priority-ordered chunking with a per-report chunk cap
  prompts.py        Nonce delimiters and the untrusted-data instructions
  validate.py       Grounding, indicator and integrity checks on model output
  llm_extract.py    Orchestration, merging, caching, cost tracking
llm/                Provider interface, Anthropic provider, price table
graph/              Knowledge graph
  model.py          Node/edge shapes, neighborhood and detail queries
  normalize.py      Name normalization, alias map, duplicate detection
  merge.py          Idempotent merge and report removal
  persist.py        Merge-and-save with version-conflict retry
  summaries.py      Grounded node summaries, cached by evidence hash
storage/            GraphStore interface, local JSON backend, factory
pages/              Streamlit pages: Ingest, Graph, Reports, Maintenance
scripts/            fetch_fixtures.py, build_expected.py, eval_regex.py
llm/                LLM provider interface (Phase 3)
graph/              Knowledge graph (Phase 4)
guards/             Guardrail layers (Phase 5)
agent/              Bounded agent mode (Phase 6)
storage/            Local and Supabase backends (Phase 4 and 7)
tests/              pytest suite with generated fixtures
```

## How IOC extraction works

Extraction is entirely deterministic: regular expressions, no model, no network. The same
report always yields the same indicators.

1. **Collect sources.** Each page's text and each table's cells are searched separately, so an
   indicator can be attributed to a page. IOC lists in advisories are almost always tables.
2. **Repair the text.** Advisories print hashes in narrow columns, which wraps a 64-character
   SHA-256 across two or three lines. `extract/text_repair.py` rejoins the fragments, but only
   when they divide cleanly into whole hashes, so two stacked SHA-256 hashes are never merged
   into a SHA-512 that was never in the report. On one advisory this recovered 28 of 29 hashes
   that were otherwise invisible.
3. **Refang.** `hxxp://evil[.]com`, `bad(.)org`, `evil[dot]net` and `user[at]evil[.]com` are
   turned back into real indicators before matching.
4. **Extract.** `ioc-finder` handles IPs, domains, URLs, emails, CVEs, MD5, SHA-1 and SHA-256.
   `iocextract` is used for SHA-512 only, which `ioc-finder` does not support.
5. **Normalize.** Domains and hashes lowercased, CVE IDs uppercased, IPs canonicalized through
   Python's `ipaddress` module (which also rejects invalid ones), URL scheme and host lowercased
   while the path keeps its case.
6. **Deduplicate** by type and value, merging page numbers, occurrence counts and every original
   spelling. A domain that only ever appears as the host of an extracted URL is not reported
   separately, so one URL does not become two indicators.
7. **Flag likely false positives** without ever dropping them: private, loopback, reserved and
   documentation IP ranges; dotted quads next to version wording; allowlisted and
   publisher-owned domains; domains whose TLD is also a file extension; and hashes with no
   context nearby. The UI hides flagged items behind a toggle.

Indicators are displayed **defanged** so that nothing in the table is a working link and a value
copied from the page is not immediately dangerous. The real values are available only through
the download buttons, which say so.

### Accuracy

Measured against three CISA advisories using their own published STIX IOC lists as ground
truth. Full numbers, methodology and known limitations are in
[docs/EVALUATION.md](docs/EVALUATION.md).

| Advisory | Precision (flagged excluded) | Recall | Attainable recall |
| --- | --- | --- | --- |
| Akira (AA24-109A) | 0.967 | 0.513 | 1.000 |
| CL0P / MOVEit (AA23-158A) | 0.845 | 0.617 | 0.922 |
| RansomHub (AA24-242A) | 0.935 | 0.967 | 0.967 |

Plain recall looks low for a reason worth stating: a CISA STIX bundle lists every hash of a file
while the advisory PDF prints only one hash column, so many ground-truth hashes are not in the
document at all. *Attainable recall* measures only the entries actually present in the text, and
is the number that reflects the extractor. The IOC section was detected in all three advisories.

Reproduce it with:

```bash
python scripts/fetch_fixtures.py      # downloads the advisories (gitignored)
python scripts/build_expected.py      # rebuilds the committed ground truth
python scripts/eval_regex.py          # prints the metrics
```

## How LLM extraction is validated

The model is treated as an untrusted component that *proposes* claims. Application code decides
which claims survive. Nothing it says reaches the graph unchecked.

**Before the call.** Report text is wrapped in `<report-{nonce}>` tags where the nonce is eight
random hex characters generated per request, so a document cannot close a delimiter it cannot
predict. Any literal `<report` or `</report` in the text is neutralized first. The
untrusted-data rule appears at the top of the system prompt and again immediately after the
report block. In pipeline mode the model is given **no tools at all** — output format is
constrained with native structured outputs (`output_config`), not a forced tool — so there is
nothing to execute.

**After the call**, in `extract/validate.py`, every item must pass:

1. **Schema** — Pydantic. Entity and relationship types outside the STIX allowlists never get
   further. A malformed response is retried exactly once with the error described, then dropped.
2. **Text safety** — HTML tags and markdown link/image syntax are stripped from every string.
3. **Grounding** — the `evidence` quote must appear verbatim in the chunk. Comparison normalizes
   the things PDFs break (line breaks mid-sentence, curly quotes, en dashes, soft hyphens,
   hyphenation across lines, case) but not wording, so a paraphrase still fails.
4. **Indicator check** — an `indicator` entity must match a value regex extraction already
   found. This is what enforces the rule that the model never invents an IOC.
5. **Name presence** — the entity name or one of its aliases must appear in the text.
6. **Relationship integrity** — both endpoints must resolve to a kept entity or a known
   indicator. Dangling relationships are dropped.

Every drop is recorded with a reason code (`schema`, `not_grounded`, `unknown_indicator`,
`name_not_in_text`, `dangling`, `limit`) and shown in the app's validation panel, so the
guardrails are visible rather than implied. If more than half a chunk's items are dropped, the
report is flagged as suspicious.

**Cost control.** No API call happens without a button click, and the worst-case cost is shown
first. Only the highest-priority chunks are sent — IOC-section pages, then pages with indicators
or ATT&CK technique ids — capped at `MAX_CHUNKS_PER_REPORT` (default 6), with the number skipped
reported. Results are cached by file hash, model and prompt version, so re-analysing the same
report makes no call and costs nothing.

## Exploring the graph

Every analysed report merges into one graph, so an entity named in three advisories is **one
node with three sources**, not three nodes.

**Deduplication** happens on a normalized key. `APT 21`, `APT-21` and `apt21` all key to
`apt21`; CVE ids are case-normalized; an ATT&CK technique is keyed by its id, so `T1053.005` and
"Scheduled Task/Job: Cron" are the same node. Normalization only collapses *mechanical*
differences — spacing, punctuation, case. It never merges two names because they look similar:
similar pairs are listed on the Maintenance page for a human to judge, and a real merge is
recorded by editing `graph/aliases.json`. Automatic fuzzy merging would eventually merge two
genuinely different threat actors, which is a worse failure than a duplicate node.

**The view is always a neighborhood**, never the whole graph — past a few hundred nodes a full
graph is an unreadable hairball, and the real question is "what is this one thing connected to".
Select a node and the explorer shows its neighbors to a depth you choose, capped at a node limit.
Clicking a node in the canvas, or a relationship in the detail panel, navigates to it, and a
breadcrumb tracks where you have been.

The detail panel shows the node's type and aliases, which reports it appears in, its
relationships grouped by relation, its related indicators (defanged), the exact evidence quotes
with their source report, and an optional summary. **Summaries are generated only on click**,
from that node's evidence quotes alone, and cached against a hash of those quotes — if a later
report adds evidence, the summary is marked outdated rather than silently presented as current.

**Storage** is `data/graph.json` behind a `GraphStore` interface, with a Supabase backend coming
in Phase 7. Writes are atomic (temp file, fsync, `os.replace`) so an interrupted save cannot
truncate the graph, and the last five versions are kept as backups restorable from the
Maintenance page. Saves use an optimistic version number: if the stored version changed since
load, the save is rejected, and the app reloads and re-merges onto the newer graph rather than
overwriting someone else's upload. Merging is idempotent, which is what makes that retry safe.

## Security

Secrets live only in `.env`, which is listed in `.gitignore` and has never been committed.
`.env.example` holds placeholder values only. The Anthropic API key is deliberately not a
field on the settings object: it is read on demand by `config.get_api_key()` so it cannot be
captured in a `repr`, a log line, an exception message or Streamlit session state.

A `pre-commit` hook runs [gitleaks](https://github.com/gitleaks/gitleaks) on every commit, so
a commit containing an API key is blocked before it can reach GitHub. This was verified against
a generated fake key in the real Anthropic key format, which gitleaks correctly rejected. The
same hook set also blocks committed private keys and files over 1 MB.

Uploaded reports are untrusted input. Two consequences are already in force in Phase 1:

- **File type is determined from content, not the filename.** A PDF must begin with the `%PDF-`
  signature and HTML must decode as text and contain a structural tag. A file whose extension
  disagrees with its bytes is rejected rather than silently reinterpreted.
- **Report text is never rendered as markup.** Extracted text reaches the page only through
  `st.text`, `st.code` and `st.dataframe`, never `st.markdown`, `st.write`, `st.html` or
  `unsafe_allow_html`, so a report cannot inject HTML or links into the app.
- **Indicators are displayed defanged.** Values are shown as `evil[.]com` and `hxxp://`, so the
  UI contains no live link to a malicious host and a value copied out of the page does not
  resolve. Real values leave the app only through the download buttons, which are labelled as
  containing them.

Uploads are capped at 5 MB and PDFs at 50 pages. Encrypted PDFs and image-only scans are
rejected with a clear message. `data/` and `uploads/` are gitignored so no ingested report
or extracted content is ever committed.

Prompt-injection defence, hidden-content sanitization and the full threat model
(`docs/SECURITY.md`) are the subject of Phase 5.

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

**Phase 2 of 7 — deterministic IOC extraction.** The app accepts a PDF or HTML report, extracts
the text and tables, and pulls out indicators of compromise with regular expressions: IPs,
domains, URLs, hashes, emails and CVE IDs, refanged, deduplicated, and flagged where they look
like false positives. No LLM is involved yet. The graph, storage and access control are the
subject of later phases.

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Repo setup, secret scanning, Streamlit skeleton, PDF/HTML ingestion | Done |
| 2 | Regex IOC extraction, refanging, false-positive flags, evaluation | Done |
| 3 | Claude extraction with schema, grounding validation, caching, cost tracking | Not started |
| 4 | Knowledge graph, normalization, dedup, versioned storage, explorer | Not started |
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
- **Planned:** the Anthropic Python SDK for entity extraction, NetworkX for the graph,
  Supabase for deployed storage

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

## Project layout

```text
app.py              Streamlit entry point
config.py           Settings and API key access
ingest/             PDF and HTML text extraction
  models.py         The Document model
  loader.py         Upload validation and dispatch
  pdf.py            PyMuPDF text, pdfplumber tables
  html.py           BeautifulSoup text extraction
extract/            IOC extraction (Phase 2); entity extraction follows in Phase 3
  models.py         The IOC and IOCExtraction models
  iocs.py           Extraction, normalization, dedup, false-positive flags
  sections.py       IOC section detection
  text_repair.py    Rejoins hashes wrapped across lines by PDF layout
  display.py        Defanging for display
  allowlist.txt     Domains flagged as benign
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

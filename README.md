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

**Phase 1 of 7 — ingestion.** The app accepts a PDF or HTML report, validates it, extracts the
text and tables, and displays them. IOC extraction, LLM calls, the graph, storage and access
control are the subject of later phases and are not implemented yet.

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Repo setup, secret scanning, Streamlit skeleton, PDF/HTML ingestion | Done |
| 2 | Regex IOC extraction, refanging, false-positive flags, evaluation | Not started |
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
- **Planned:** iocextract/ioc-finder for indicators, the Anthropic Python SDK for extraction,
  NetworkX for the graph, Supabase for deployed storage

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

The tests generate their own PDF and HTML fixtures in memory, mock the Anthropic client, and
never call the API, so running them costs nothing.

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

```
app.py              Streamlit entry point
config.py           Settings and API key access
ingest/             PDF and HTML text extraction
  models.py         The Document model
  loader.py         Upload validation and dispatch
  pdf.py            PyMuPDF text, pdfplumber tables
  html.py           BeautifulSoup text extraction
extract/            IOC and entity extraction (Phase 2 and 3)
llm/                LLM provider interface (Phase 3)
graph/              Knowledge graph (Phase 4)
guards/             Guardrail layers (Phase 5)
agent/              Bounded agent mode (Phase 6)
storage/            Local and Supabase backends (Phase 4 and 7)
tests/              pytest suite with generated fixtures
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

Uploads are capped at 5 MB and PDFs at 50 pages. Encrypted PDFs and image-only scans are
rejected with a clear message. `data/` and `uploads/` are gitignored so no ingested report
or extracted content is ever committed.

Prompt-injection defence, hidden-content sanitization and the full threat model
(`docs/SECURITY.md`) are the subject of Phase 5.

# Phase 1 — Repository Setup, Secrets Safety, and App Skeleton

Read `CLAUDE.md` first. This file adds detail for Phase 1 only. If anything here conflicts
with `CLAUDE.md`, stop and ask me.

## Goal
A private GitHub repo with safe secrets handling from the very first commit, and a running
Streamlit app that accepts a PDF or HTML threat report and shows its extracted text.

## Out of scope for this phase
IOC extraction, LLM calls, graphs, storage, passwords. Do not start them.

## 0. Preflight checks (do these before writing any file)
Run and report the result of each. Stop and tell me if any fails.
1. `pwd` shows the project folder and `CLAUDE.md` exists in it.
2. `.env` exists and contains `ANTHROPIC_API_KEY`. Check with
   `grep -q '^ANTHROPIC_API_KEY=' .env && echo present`.
   NEVER print, cat, echo or log the contents of `.env`.
3. `gh auth status` shows I am logged in.
4. `python3 --version` is 3.11 or newer. If it is older, stop and ask me before installing
   anything (suggest `brew install python@3.12`).
5. `git --version` works.

## 1. Git and .gitignore FIRST
1. `git init -b main`
2. Create `.gitignore` before any other file, containing at least:
   ```
   .env
   .env.*
   !.env.example
   .venv/
   __pycache__/
   *.pyc
   .DS_Store
   .streamlit/secrets.toml
   data/
   uploads/
   .pytest_cache/
   tests/fixtures/reports/
   ```
3. Verify: `git check-ignore -v .env` must print a matching rule. If not, fix and re-check.

## 2. Python environment
1. `python3 -m venv .venv` and activate it for all later commands.
2. Create `requirements.txt` with:
   streamlit, pymupdf, pdfplumber, beautifulsoup4, lxml, python-dotenv, pydantic>=2,
   pytest, pre-commit.
   Install, then pin the installed versions with `==` in `requirements.txt`.

## 3. Secret scanning with pre-commit + gitleaks
1. Create `.pre-commit-config.yaml` with:
   - the gitleaks hook from `https://github.com/gitleaks/gitleaks` (use the latest release
     tag; run `pre-commit autoupdate` to set it),
   - from `https://github.com/pre-commit/pre-commit-hooks`: `check-added-large-files`
     (args: `--maxkb=1000`), `end-of-file-fixer`, `trailing-whitespace`,
     `check-merge-conflict`, `detect-private-key`.
2. `pre-commit install`
3. Prove it works: create `tmp_secret_test.txt` containing a FAKE Anthropic-style key
   (e.g. `sk-ant-api03-` followed by 90 random letters/digits you generate, never my real
   key), `git add` it, run `git commit -m test` and confirm gitleaks BLOCKS it.
   Then `git restore --staged tmp_secret_test.txt && rm tmp_secret_test.txt`.
   Report that the block worked.

## 4. Configuration
Create `config.py`:
- Loads `.env` with python-dotenv.
- Exposes a `Settings` object (Pydantic `BaseModel` or dataclass) with:
  `anthropic_model` (default `claude-haiku-4-5-20251001`), `anthropic_agent_model`
  (default: same as `anthropic_model`), `storage_backend` (default `local`),
  `max_file_mb` (default 5), `max_pages` (default 50), `data_dir` (default `data`).
- Reads the API key only when needed via a function `get_api_key()` that raises a clear
  error if missing. The key must never be included in `repr`/`str` of any object,
  logs, exceptions or Streamlit output.
- Later phases will also read from `st.secrets`; design `config.py` so a second source
  can be added easily (env first for now).

Create `.env.example` with placeholder values only:
```
ANTHROPIC_API_KEY=your-key-here
ANTHROPIC_MODEL=claude-haiku-4-5-20251001
ANTHROPIC_AGENT_MODEL=claude-haiku-4-5-20251001
STORAGE_BACKEND=local
MAX_FILE_MB=5
MAX_PAGES=50
```

## 5. Project structure
```
app.py                  # Streamlit entry point
config.py
ingest/
  __init__.py
  models.py             # Document model
  pdf.py                # PDF text + table extraction
  html.py               # HTML text extraction
  loader.py             # validates the upload, dispatches to pdf/html
tests/
  __init__.py
  test_ingest.py
  fixtures/             # small generated fixtures only; real reports come in Phase 2
README.md
```
Create empty package folders now for later phases with only an `__init__.py` and a one-line
docstring: `extract/`, `llm/`, `agent/`, `graph/`, `storage/`, `guards/`.

## 6. Ingestion
`ingest/models.py`: Pydantic model `Document` with:
- `filename: str`
- `file_type: Literal["pdf", "html"]`
- `sha256: str` (hash of the raw bytes, used later for caching and dedup)
- `size_bytes: int`
- `page_count: int` (1 for HTML)
- `pages: list[str]` (text per page; HTML is a single page)
- `tables: list[list[list[str]]]` (rows of cells; empty for HTML for now)
- `text: str` (all pages joined with page markers like `\n\n[[PAGE 3]]\n\n`)

`ingest/loader.py`: `load_document(filename: str, data: bytes) -> Document`
- Reject files larger than `max_file_mb` with a clear message.
- Detect type from content, not only the extension:
  PDF must start with `%PDF-`; HTML must decode as UTF-8 (fallback latin-1) and contain
  an `<html` or `<body` or `<div` tag (case-insensitive). Mismatch -> clear error.
- Compute SHA-256 of the raw bytes.
- Raise a custom `IngestError` with user-friendly messages; never a raw stack trace in UI.

`ingest/pdf.py`:
- Open from bytes with PyMuPDF. Reject encrypted PDFs with a clear message.
- Reject if `page_count > max_pages`.
- Extract text per page with `page.get_text("text")`.
- Extract tables with pdfplumber (`page.extract_tables()`), wrapped in try/except so a
  table failure never breaks text extraction. Normalize cells: None -> "", strip whitespace.
- Fix common PDF artifacts in the joined text: remove soft hyphens, join words split
  across lines with a trailing hyphen only when the next line starts lowercase.

`ingest/html.py`:
- Parse with BeautifulSoup + lxml.
- Remove `script`, `style`, `noscript`, `template` elements.
  (Full hidden-content sanitization is Phase 5; leave a `# TODO Phase 5` comment.)
- `get_text(separator="\n")`, collapse 3+ blank lines into 2, strip each line.

## 7. Streamlit skeleton (`app.py`)
- Page config: title "IOC Graph", wide layout.
- Sidebar: short description of the project and the current phase ("Phase 1: ingestion").
- `st.file_uploader` accepting `pdf`, `html`, `htm`, single file.
- On upload: call `load_document`, then show:
  - metrics: file type, pages, characters, number of tables
  - SHA-256 (in `st.code`)
  - an expander with the text of each page (use `st.text`, NOT `st.markdown`, so report
    content is never rendered as markdown/HTML)
  - an expander showing tables with `st.dataframe`
- On `IngestError`: `st.error(message)`.
- Cache parsing per file hash with `st.cache_data` so reruns do not re-parse.

## 8. Tests (`tests/test_ingest.py`)
Generate fixtures inside the tests (PyMuPDF can create a PDF in memory; HTML as a string)
so no external files are needed. Cover:
- PDF text extraction returns expected text and correct page count.
- HTML extraction removes `<script>` and `<style>` content.
- Oversized file is rejected.
- A `.pdf` file whose bytes are actually HTML is rejected (magic-byte check).
- SHA-256 is stable for identical bytes.
- `get_api_key()` raises a clear error when the variable is unset (use monkeypatch),
  and the error message does not contain any key-like string.
All tests must pass with `pytest -q`.

## 9. README.md
Include: project name and one-paragraph description, status ("Phase 1 of 7"), tech stack,
local setup steps (venv, `pip install -r requirements.txt`, copy `.env.example` to `.env`,
`pre-commit install`, `streamlit run app.py`, `pytest`), and a short "Security" section
stating that secrets live only in `.env` and gitleaks blocks committed secrets.

## 10. Create the GitHub repo and push
1. Run `git status` and show it to me.
2. Verify nothing sensitive is tracked:
   `git ls-files | grep -E '(^|/)\.env$|secrets\.toml|^data/'` must print nothing.
3. Commit: `Phase 1: repo setup, secret scanning, Streamlit ingestion skeleton`.
4. `gh repo create ioc-graph --private --source=. --remote=origin --push`
5. `gh repo view --json visibility` must show `PRIVATE`. Report it.

## Acceptance criteria (all must be true)
- [ ] `.env` is ignored and NOT on GitHub.
- [ ] gitleaks blocked the fake-key test commit.
- [ ] `pytest -q` passes.
- [ ] `streamlit run app.py` starts; uploading a PDF and an HTML file shows text, pages,
      tables and hash; a non-PDF renamed to `.pdf` shows a friendly error.
- [ ] Repo `ioc-graph` exists on GitHub and is PRIVATE.

## Ask me before
- Installing anything with Homebrew or system-wide.
- Making the repo public, or changing any GitHub settings.
- Anything not listed in this file.

## When finished, report
What you built (files created), test results, the preflight results, confirmation of the
gitleaks test, the repo URL, and anything I should check manually.

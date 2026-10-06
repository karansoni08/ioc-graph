# Phase 7 — Shared Deployment and Final Polish

Read `CLAUDE.md` first. This file adds detail for Phase 7 only.

## Goal
Deploy the app so a few trusted peers can use it through a link: one shared workspace,
my API key, persistent storage in Supabase, a view/upload password gate, daily caps, and
safe handling of concurrent uploads. Then polish the README and prepare a v1.0 release.

## Before you start
- Phase 6 complete: tests pass, git clean, pushed.
- Install `supabase` (official Python client) and pin it.
- Several steps need ME (accounts, dashboards, secrets). When you reach one, stop, give
  me exact step-by-step instructions, and wait until I confirm.

## Out of scope
Per-user accounts, public sign-up, storing original uploaded files.

## 1. Config from Streamlit secrets (`config.py`)
- Read settings from `st.secrets` when available, else environment/`.env`.
- New settings: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `VIEW_PASSWORD`,
  `UPLOAD_PASSWORD`, `DAILY_REPORT_LIMIT` (default 20), `DAILY_AGENT_LIMIT` (default 5),
  `DAILY_SPEND_LIMIT_USD` (default 2.00), `APP_TIMEZONE` (default `America/Toronto`).
- Create `.streamlit/secrets.toml.example` (placeholders only; real file is gitignored).
- Secrets never shown in UI, logs or errors. Add a test that `Settings` repr hides them.

## 2. Supabase schema (`supabase/schema.sql`, committed)
Tables:
- `workspace(id text primary key default 'main', graph jsonb not null,
  version int not null, updated_at timestamptz default now())`
- `reports(sha256 text primary key, filename text, ingested_at timestamptz,
  ingested_by text, mode text, tokens int, cost_usd numeric, security_status text)`
- `llm_cache(key text primary key, value jsonb, created_at timestamptz default now())`
- `agent_runs(id text primary key, sha256 text, data jsonb, created_at timestamptz)`
- `usage_daily(day date primary key, reports int default 0, agent_runs int default 0,
  spend_usd numeric default 0)`
Functions:
- `save_graph(p_graph jsonb, p_expected int) returns int`: updates `workspace` only if
  `version = p_expected`, increments version, returns new version or -1 on conflict.
- `reserve_usage(p_day date, p_kind text, p_est_cost numeric, p_report_limit int,
  p_agent_limit int, p_spend_limit numeric) returns boolean`: atomically checks limits
  and increments counts/spend (row lock); returns false if any limit would be exceeded.
- `settle_usage(p_day date, p_delta numeric)`: adjusts spend from estimate to actual.
Security: enable Row Level Security on every table with NO policies for `anon` or
`authenticated`, so only the service-role key (used server-side by Streamlit, never sent
to the browser) can access data. Add a comment explaining this.

## 3. Supabase backend (`storage/supabase_store.py`)
Implement the `GraphStore` interface from Phase 4 on top of the schema:
`load`, `save` (via `save_graph` RPC, raise `VersionConflict` on -1), `list_reports`,
`cache_get/set`, run storage for agent traces.
- Only extraction results and metadata are stored. Original uploaded files are never
  stored anywhere (state this in the UI and README).
- Keep graph backups: before each save, copy the current row into a
  `workspace_backups` table (add it to the schema; keep the last 10).
- `scripts/migrate_local_to_supabase.py`: uploads local `data/graph.json`, cache and runs.
  Dry-run by default; `--apply` to write. Ask me before running with `--apply`.

## 4. Access control (`auth.py`)
- On every page, before rendering anything else, call `require_access(min_role)`.
- Login form with one password field. Compare against both passwords with
  `hmac.compare_digest`; role is `upload` or `view`. Store role in `st.session_state`.
- Lockout: after 5 failed attempts in a session, refuse attempts for 5 minutes, and add
  a 1-second delay to every failed attempt. Document in `docs/SECURITY.md` that
  session-level lockout can be bypassed by opening new sessions, and why that is
  acceptable for a link shared with a few trusted people (plus the daily caps).
- `view` role: Home, Graph, Reports (read-only), Agent Runs. No buttons that call the LLM,
  including "Generate summary" (show cached summaries only).
- `upload` role: everything, including Ingest, summaries, remove-report and maintenance.
- "Log out" button in the sidebar.

## 5. Cost and abuse controls
- Before ANY LLM call (analysis, agent, summary): compute the estimated maximum cost and
  call `reserve_usage`. If it returns false, block the action with a message showing
  which daily limit was reached and when it resets (midnight `APP_TIMEZONE`).
- After the call, `settle_usage` with the actual cost.
- Sidebar widget: today's reports / agent runs / spend vs limits.
- Ingest page banner (always visible): "Public reports only. Do not upload internal,
  confidential or client documents. Uploaded files are processed and discarded; only
  extracted results are stored."
- "Your name" free-text field on Ingest (required for upload role), saved as
  `ingested_by`. Strip to 50 chars, plain text.

## 6. Concurrency
- On save, use the version from load. On `VersionConflict`: reload, re-run `merge_report`
  on the fresh graph, retry up to 3 times, then show a friendly "someone else just
  updated the graph, please retry" message.
- Graph page: "Refresh" button and a note showing the loaded version and time.
- Test with two simulated sessions in `tests/test_concurrency.py` using a fake store.

## 7. Deployment preparation
- Verify the app runs with `STORAGE_BACKEND=supabase` locally (after I create the project,
  section 8).
- `scripts/fetch_attack.py`: make the app call it automatically on first start if the
  ATT&CK data is missing, cached with `st.cache_resource`.
- Confirm `requirements.txt` has no unused or heavy packages; app cold start under 60 s.
- Add `.streamlit/config.toml` (committed): theme, `maxUploadSize` matching
  `MAX_FILE_MB`, `toolbarMode = "minimal"`.
- Confirm the Python version the app needs and tell me which one to select on
  Streamlit Community Cloud.

## 8. Steps for ME (give me exact instructions and wait)
1. Create a free Supabase project; copy the project URL and the service-role key.
2. Run `supabase/schema.sql` in the Supabase SQL editor.
3. Put the values in local `.streamlit/secrets.toml` for the local test.
4. Choose the two passwords (suggest using a password manager to generate them).
5. On share.streamlit.io: sign in with GitHub, grant access to the private `ioc-graph`
   repo, create the app from `main` / `app.py`, choose the Python version, and paste all
   secrets into the app's Secrets settings. If the platform offers app-level viewer
   restrictions, tell me about them as an optional extra layer.
6. Send me (Claude Code) the deployed URL so you can give me a smoke-test checklist.

## 9. Smoke test checklist (write it to `docs/DEPLOY.md` and walk me through it)
- Wrong password rejected; lockout after 5 tries.
- View password: can browse graph, cannot see Ingest or any LLM button.
- Upload password: ingest a CISA fixture, analyze, add to graph; data still there after
  rebooting the app from the Streamlit dashboard (persistence check).
- Daily cap: temporarily set `DAILY_REPORT_LIMIT=1` in secrets and confirm the second
  upload is blocked; then restore.
- Two browsers uploading near-simultaneously: both reports end up in the graph.
- Secrets not visible anywhere in the UI or page source.

## 10. Final polish
- README rewrite: overview with a screenshot/GIF placeholder, live demo note ("access by
  invitation"), features, architecture diagram (Mermaid: ingest -> sanitize -> regex ->
  LLM/agent -> validate -> graph -> Supabase -> Streamlit), security design summary
  (link `docs/SECURITY.md`), evaluation highlights (link `docs/EVALUATION.md`), local setup,
  deployment (link `docs/DEPLOY.md`), limitations, roadmap (per-user accounts, enrichment
  APIs, STIX export).
- Ask me which license to use (suggest MIT) and add `LICENSE`.
- Update `CLAUDE.md` "Current scope" if anything changed during the build.
- Full-history secret scan with gitleaks (use the history-scan command of the installed
  version) and report the result. It must be clean before the repo can ever go public.
- `pytest -q` passes.
- Commit `Phase 7: Supabase storage, access control, usage caps, deployment, docs`, push,
  then tag `v1.0.0` and create a GitHub release with a short changelog (ask me first).

## Acceptance criteria
- [ ] Deployed app reachable by link; nothing visible without a password.
- [ ] View and upload roles behave as specified.
- [ ] Data persists across app restarts and redeploys.
- [ ] Daily caps enforced atomically; spend tracked.
- [ ] Concurrent uploads do not lose data.
- [ ] Full-history gitleaks scan clean; README, SECURITY, EVALUATION, DEPLOY docs complete.
- [ ] Repo still PRIVATE (making it public is my decision, later).

## Ask me before
Every step in section 8, running the migration with `--apply`, tagging the release,
changing repo visibility.

## When finished, report
Deployed URL, smoke test results, cold-start time, today's usage numbers, gitleaks
history result, and a short list of what you would build next.

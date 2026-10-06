# Deployment

## Fastest path to a live link (about 3 minutes, no Supabase)

**You do not need Supabase to get a working public link.** The app runs on the `local` storage
backend anywhere, including Streamlit Community Cloud. The only thing you give up is persistence:
Streamlit wipes the container disk on restart and redeploy, so ingested reports disappear when the
app sleeps or is rebooted. For showing the project to someone, that is usually fine — and you can
add Supabase later without changing any code, just one secret.

Everything else in this document is the durable setup. Start here if you want the link now.

1. Go to **<https://share.streamlit.io>** and sign in **with GitHub** (the account that owns this
   repo). Authorize access to private repositories when prompted.
2. Click **Create app** → **Deploy a public app from a template**? No — choose **Deploy now** /
   "I have an app", then select:
   - Repository: `karansoni08/ioc-graph`
   - Branch: `main`
   - Main file path: `app.py`
   - Python version: **3.11** or newer
3. Open **Advanced settings** → **Secrets**, and paste the block below, replacing the two
   placeholder values with your real ones.
4. Click **Deploy**. First boot takes a few minutes while it installs dependencies.

```toml
ANTHROPIC_API_KEY = "sk-ant-api03-PASTE-YOUR-REAL-KEY-HERE"
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
ANTHROPIC_AGENT_MODEL = "claude-haiku-4-5-20251001"

# No Supabase needed for this path. Data does NOT survive an app restart.
STORAGE_BACKEND = "local"

# Change BOTH of these. See the warning below.
VIEW_PASSWORD = "PASTE-A-LONG-RANDOM-PASSPHRASE"
UPLOAD_PASSWORD = "PASTE-A-DIFFERENT-LONG-RANDOM-PASSPHRASE"

DAILY_REPORT_LIMIT = 20
DAILY_AGENT_LIMIT = 5
DAILY_SPEND_LIMIT_USD = 2.00
APP_TIMEZONE = "America/Toronto"

MAX_FILE_MB = 5
MAX_PAGES = 50
MAX_CHUNKS_PER_REPORT = 6
```

> **The daily caps work on this path too.** They are enforced on both backends — in SQL under a row
> lock on Supabase, and under a process lock with an atomic file write on the local backend, which
> is sufficient because Streamlit serves every session of one deployment from a single process. The
> counts live in `data/usage.json`, so they reset whenever the container is wiped. Combined with the
> per-report chunk cap, the file size and page limits, the result cache, and the fact that nothing
> calls the API without a click, that bounds what a shared link can cost you.

> **Choose strong passwords.** Anything short, dictionary-based, or thematically related to the
> project ("regex", "llm", "ioc", "graph") is guessable by exactly the audience you are sharing this
> with. The upload password is what protects your API credits. Generate both with a password
> manager, 20+ characters, and never reuse them.

### Adding persistence afterwards

When you want reports to survive restarts, do Part 1 below, then change one secret:
`STORAGE_BACKEND = "supabase"` plus `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`. No code changes.

---

## The durable setup

One shared workspace on Streamlit Community Cloud, with Supabase for storage and two shared
passwords. Deployed from the private GitHub repo.

**Why Supabase and not the local files?** Streamlit Community Cloud wipes the container disk on
every restart and redeploy. `data/graph.json` would survive until the first reboot and then be
gone, taking every ingested report with it.

Python version to select: **3.11** or newer (the code is developed against 3.13).

---

## Part 1 — things only you can do

These need accounts and dashboards. Work through them in order.

### 1. Create the Supabase project

1. Go to <https://supabase.com> and sign in.
2. **New project**. Any name; pick the region closest to you. The free tier is enough.
3. Set a database password when prompted and save it in your password manager. (The app does not
   use it — it connects with the service-role key — but you will need it if you ever use the SQL
   console as a superuser or connect directly.)
4. Wait for provisioning to finish (a minute or two).

### 2. Create the tables

1. In the project, open **SQL Editor** → **New query**.
2. Paste the entire contents of [`supabase/schema.sql`](../supabase/schema.sql) and click **Run**.
3. Confirm it reports success. The script is idempotent, so you can re-run it safely after an edit.
4. Open **Table Editor** and check six tables exist: `workspace`, `workspace_backups`, `reports`,
   `llm_cache`, `agent_runs`, `usage_daily`.

### 3. Copy the credentials

1. **Project Settings** → **API**.
2. Copy the **Project URL** → this is `SUPABASE_URL`.
3. Under Project API keys, copy the **`service_role`** key → this is `SUPABASE_SERVICE_KEY`.

> **Use the `service_role` key, not `anon`.** Row Level Security is enabled on every table with
> **no policies**, so the `anon` key can read and write nothing — that is the point, and it means
> a leaked anon key is harmless. The `service_role` key bypasses RLS and is used only server-side
> by Streamlit. Never paste it into client-side code, a browser, or a public issue.

### 4. Choose the two passwords

Generate two different long passphrases with a password manager (20+ characters each). Do not
reuse anything.

- `VIEW_PASSWORD` — browse the graph, read reports and agent traces. Spends nothing.
- `UPLOAD_PASSWORD` — also ingest, analyse, run the agent and generate summaries. **Spends your
  API credits**, so share this one with fewer people.

### 5. Test locally against Supabase first

Before deploying, confirm the backend works from your machine:

```bash
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# edit .streamlit/secrets.toml: fill in SUPABASE_URL, SUPABASE_SERVICE_KEY,
# the two passwords, and your real ANTHROPIC_API_KEY. Set STORAGE_BACKEND = "supabase".

streamlit run app.py
```

`.streamlit/secrets.toml` is gitignored. Verify before committing anything:

```bash
git check-ignore -v .streamlit/secrets.toml   # must print a matching rule
git status --short                            # must not list secrets.toml
```

If you already have a local graph you want to keep, migrate it (dry run first):

```bash
python scripts/migrate_local_to_supabase.py            # shows what it would do
python scripts/migrate_local_to_supabase.py --apply    # actually writes
```

### 6. Deploy on Streamlit Community Cloud

1. Go to <https://share.streamlit.io> and sign in **with GitHub**.
2. Grant access to the private `ioc-graph` repository when prompted.
3. **New app** → choose the repo, branch `main`, main file `app.py`.
4. Under **Advanced settings**, select Python **3.11+** and paste all secrets into the **Secrets**
   box, in the same TOML format as `.streamlit/secrets.toml.example`.
5. Deploy. First boot takes a couple of minutes: it installs dependencies and downloads the
   MITRE ATT&CK bundle (~38 MB, fetched automatically on first use of agent mode).

**Optional extra layer.** Streamlit Community Cloud can restrict an app to a list of allowed
Google accounts (app settings → Sharing → "Only specific people can view this app"). That is a
stronger gate than a shared password because it authenticates individuals. If it fits how you want
to share the link, use it *in addition to* the passwords, not instead: the passwords are also what
separates view from upload.

### 7. Send me the URL

Once it is live, give me the deployed URL and I will walk you through the smoke test below.

---

## Part 2 — smoke test

Run through this after the first deploy and after any redeploy that changes secrets or storage.

| # | Check | How | Expected |
|---|---|---|---|
| 1 | Nothing is visible without a password | Open the URL in a private window | Login form only. No graph, no stats, no page content |
| 2 | Wrong password is rejected | Enter anything incorrect | "Incorrect password", with a remaining-attempts count |
| 3 | Lockout works | Get it wrong 5 times | Session locked for 5 minutes, with a countdown |
| 4 | View role is read-only | Log in with `VIEW_PASSWORD` | Home, Graph, Reports, Agent Runs all work. Ingest and Maintenance are refused. No "Generate summary" button, no "Analyze with Claude", no "Remove from graph" |
| 5 | Upload role can ingest | Log in with `UPLOAD_PASSWORD`, upload a CISA advisory PDF | Text, indicators, security panel all shown. "Analyze with Claude" appears with a cost estimate |
| 6 | Analysis and merge work | Click Analyze, then Add to graph | Entities and relationships shown with a validation panel; merge reports node and edge counts |
| 7 | **Persistence** | Streamlit dashboard → **Reboot app**, then reopen | The report and graph are still there. This is the check that proves Supabase is actually being used |
| 8 | Daily cap is enforced | Temporarily set `DAILY_REPORT_LIMIT = 1` in Secrets, save, then try a second report | Second attempt is blocked with a message naming the limit and the reset time. **Restore the real value afterwards** |
| 9 | Concurrency | Two browsers, each upload a different report, click "Add to graph" within a few seconds of each other | Both reports appear in the graph; neither is lost |
| 10 | Secrets are not exposed | View page source; check the Streamlit logs | No API key, no service-role key, no passwords anywhere |
| 11 | Agent mode is bounded | Run a deep analysis | Finishes within the budgets; Agent Runs shows every step and a defined status |

If check 7 fails, the app is still on the local backend: confirm `STORAGE_BACKEND = "supabase"`
is in the deployed Secrets, not just in your local file.

---

## Operating notes

**Rotating a secret.** Change it in the Streamlit Secrets box and save; the app restarts
automatically. For the Anthropic key, create the new key first, deploy it, then revoke the old one
so there is no window where the app is broken.

**Watching spend.** The sidebar shows today's reports, agent runs and spend against the caps. The
authoritative figure is in the Anthropic console; the app's number is an estimate from its own
price table (`llm/pricing.py`), which needs updating if Anthropic changes prices.

**Raising the caps.** `DAILY_REPORT_LIMIT`, `DAILY_AGENT_LIMIT` and `DAILY_SPEND_LIMIT_USD` in
Secrets. They are enforced atomically in Postgres, so raising them takes effect on the next request.

**Restoring the graph.** Every save keeps a backup; `workspace_backups` holds the last 10. There
is no restore button for the Supabase backend yet — restore by hand in the SQL editor, copying the
`graph` column of the chosen backup row into `workspace` and bumping `version`.

**What is stored.** Only extracted results and metadata: the graph, LLM result cache, agent run
traces, report metadata and usage counters. **The uploaded file itself is never stored** anywhere —
it is parsed in memory and discarded. Keep it that way; it is a promise made in the UI.

**Known limitation worth repeating.** The 5-attempt lockout is per session, so someone can bypass
it by opening a new one. That is accepted for a link shared with a few trusted people, and the
daily caps bound what an attacker who guesses the password can actually cost you. See
[docs/SECURITY.md](SECURITY.md).

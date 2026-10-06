# Deploying to Hugging Face Spaces

An alternative to Streamlit Community Cloud. CLAUDE.md allows either. Use this if you would rather
not connect Streamlit Cloud to your GitHub account, or if you want someone else to run the deploy
for you from a scoped token.

Spaces are their own git repository, so the code is pushed there rather than linked from GitHub.
`README.md` in the Space root must carry the YAML frontmatter in `deploy/huggingface/README.md` —
that is what tells Spaces to run Streamlit and which file to run.

## One-time setup

1. Create a free account at <https://huggingface.co/join>.
2. Create a **write** access token: Settings → Access Tokens → New token → type **Write**.
3. Log the CLI in:

   ```bash
   hf auth login        # paste the write token when prompted
   ```

## Create and push the Space

```bash
# 1. Create a PRIVATE Space. Private matters: the app holds a live API key.
hf repo create ioc-graph --repo-type space --space_sdk streamlit --private

# 2. Clone it somewhere outside this repo
cd ..
git clone https://huggingface.co/spaces/<your-username>/ioc-graph hf-ioc-graph
cd hf-ioc-graph

# 3. Copy the application across, excluding everything that must not ship
rsync -a --delete \
  --exclude '.git' --exclude '.venv' --exclude 'data' --exclude '.env' \
  --exclude '.streamlit/secrets.toml' --exclude 'tests/fixtures/reports' \
  --exclude '__pycache__' --exclude '.pytest_cache' \
  ../ioc-graph/ ./

# 4. The Space's README must be the one with the Spaces frontmatter
cp deploy/huggingface/README.md README.md

# 5. Push
git add -A && git commit -m "Deploy IOC Graph" && git push
```

## Add the secrets

In the Space: **Settings → Variables and secrets**. Add each as a **Secret** (not a Variable, which
is public):

| Name | Value |
| --- | --- |
| `ANTHROPIC_API_KEY` | your real key |
| `VIEW_PASSWORD` | a long random passphrase |
| `UPLOAD_PASSWORD` | a different long random passphrase |
| `STORAGE_BACKEND` | `local`, or `supabase` with the two Supabase secrets |
| `DAILY_SPEND_LIMIT_USD` | `2.00` |

Spaces exposes secrets as environment variables, which `config.py` reads first, so nothing else
needs changing.

## Caveats

- **Make the Space private.** A public Space with these secrets would let anyone who finds it spend
  your API credits, and the password gate is the only thing in front of that.
- Free Spaces sleep after inactivity and the disk is ephemeral, so on `STORAGE_BACKEND=local` the
  graph resets when the Space restarts — same trade as Streamlit Community Cloud.
- The MITRE ATT&CK bundle (~38 MB) downloads on first use of agent mode.

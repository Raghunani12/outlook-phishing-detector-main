# Phish Raksha — Admin Dashboard Upgrade

This adds persistence (MongoDB Atlas), structured logging, per-user
attribution, and a server-rendered admin dashboard on top of your existing
Outlook add-in. Your taskpane's own UI and analysis logic are unchanged —
this is additive.

## 1. What's in this drop, and where it goes in your repo

Your repo (from the screenshot) looks like:

```
outlook-phishing-detect.../
├── backend/
│   └── app/
│       └── main.py          <-- REPLACE this file
├── frontend/
│   └── src/
│       └── taskpane/
│           └── taskpane.ts  <-- REPLACE this file
```

This drop is structured to match exactly:

```
phish-raksha/
├── backend/
│   ├── requirements.txt      <-- REPLACE backend/requirements.txt
│   ├── .env.example          <-- copy to backend/.env and fill in
│   └── app/
│       ├── __init__.py       <-- new, empty file, needed for the package
│       ├── main.py           <-- REPLACE backend/app/main.py
│       ├── database.py       <-- NEW: backend/app/database.py
│       ├── logger.py         <-- NEW: backend/app/logger.py
│       ├── admin/            <-- NEW: backend/app/admin/
│       │   ├── __init__.py
│       │   ├── auth.py
│       │   ├── queries.py
│       │   └── routes.py
│       ├── templates/        <-- NEW: backend/app/templates/
│       │   └── (7 .html files)
│       └── static/
│           └── admin.css     <-- NEW: backend/app/static/admin.css
└── frontend/
    └── taskpane.ts           <-- REPLACE frontend/src/taskpane/taskpane.ts
```

**Copy everything under `phish-raksha/backend/` into your `backend/`
folder** (merging, not overwriting your venv), and **copy
`phish-raksha/frontend/taskpane.ts` over your
`frontend/src/taskpane/taskpane.ts`**.

## 2. Set up MongoDB Atlas (free tier, no local install)

1. Go to https://www.mongodb.com/cloud/atlas/register and create a free account.
2. Create a new **free (M0) cluster** — takes a couple of minutes to provision.
3. **Database Access** (left sidebar) → Add a database user. Give it a
   username/password (not your Atlas login — a separate DB user) and
   "Read and write to any database" permission.
4. **Network Access** (left sidebar) → Add IP Address → for the prototype,
   "Allow Access from Anywhere" (`0.0.0.0/0`) is fine since it's localhost-only
   and password-protected at the DB user level. Tighten this later.
5. **Database → Connect → Drivers → Python** → copy the connection string.
   It looks like:
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```
6. You do **not** need to manually create the database or collections —
   `connect_to_mongo()` in `database.py` creates the `phish_raksha` database
   and its two collections (`scans`, `raw_scan_data`) automatically the
   first time a scan is written.

## 3. Configure environment variables

```bash
cd backend
cp .env.example .env
```

Edit `.env`:
- `MONGODB_URI` — paste your Atlas connection string, with your actual username/password swapped in
- `MONGODB_DB_NAME` — leave as `phish_raksha` unless you want a different name
- `VT_API_KEY`, `GEMINI_API_KEY` — same values you already had working
- `ADMIN_PASSWORD` — pick a real password for `/admin`
- `SESSION_SECRET_KEY` — generate one:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- `ALLOWED_ORIGINS` — leave as `https://localhost:3000` to match your taskpane's origin

## 4. Install dependencies and run

```bash
cd backend
source venv/bin/activate    # your existing venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Watch the startup logs — you should see JSON lines like:
```json
{"timestamp": "...", "level": "INFO", "message": "Connecting to MongoDB Atlas", "event": "startup.mongo_connect"}
{"timestamp": "...", "level": "INFO", "message": "MongoDB connected", "event": "startup.mongo_connected"}
```
If it errors out here instead, it's almost always the Atlas connection
string, DB user password, or the Network Access IP allowlist — not your code.

## 5. Run a scan, then check the dashboard

1. Open Outlook, open an email, click "Analyze Email" like before — this
   should work exactly as it did, but now every scan also gets written to
   Mongo (and logs go to structured JSON instead of plain `print()`).
2. Visit **http://127.0.0.1:8000/admin** in a browser.
3. Log in with the `ADMIN_PASSWORD` you set.
4. You should see:
   - **Overview** — tiles, verdict breakdown, volume trend, auth pass-rate trend, top targeted users, repeat offender domains, API latency
   - **Users** — click a user to see everything they've scanned
   - **Scan detail** — click any scan row to see the full breakdown
   - **"View raw source data"** link on scan detail — the unprocessed
     headers, email body, full VirusTotal JSON, full DNS answers, and the
     exact Gemini prompt/response for that scan

If Overview looks empty, that's expected until a few scans have run — some
panels (like the 14-day trend charts) need at least one scan in the last 14
days to render anything.

## 6. What to expect the first time

- The very first scan after switching this on will have no `scanned_by`
  showing anything meaningful unless Outlook has a signed-in user profile
  available — this is normal in most Outlook desktop/web sessions, but if
  you test in an environment without a mailbox identity, it'll show
  `unknown_user`. That's a legitimate fallback, not a bug.
- Raw email bodies are now stored in Mongo. For a scoped prototype test
  group this is fine — just be aware the DB now holds real email content,
  which is a different risk profile than the summary-only version from
  before. Don't point this at your full 1000+ user base without revisiting
  that.

## 7. Known gaps, deliberately left out of this pass

These came up earlier in our conversation and are still valid — just not
part of this drop:
- No CORS lockdown beyond the `ALLOWED_ORIGINS` env var (still permissive
  by default)
- No retry/backoff around VirusTotal (still a single attempt) or its
  4-req/min free-tier rate limit
- No caching of repeat VT/DNS lookups
- No attachment scanning
- No alerting (Slack/Teams/email) on PHISHING_DETECTED verdicts
- No Jira integration for high-risk verdicts
- No analyst feedback loop ("mark this verdict correct/incorrect")

Say the word on any of these and we'll scope the next pass the same way we
did this one.

# Phishing Shield Outlook Add-in

This repository contains a cross-platform Outlook add-in for detecting phishing risks in email messages. The add-in uses a frontend task pane for Outlook, and a backend FastAPI service to analyze email authentication, DNS policy, VirusTotal URL reputation, and Gemini AI-generated verdicts.

## Repository structure

- `frontend/`
  - Outlook add-in UI and manifest
  - `src/taskpane/` - main taskpane HTML/CSS/TypeScript
  - `src/commands/` - add-in command registration
  - `webpack.config.js` - build and dev server configuration
  - `package.json` - npm scripts and dependencies

- `backend/`
  - `app/main.py` - FastAPI application with analysis logic
  - `venv/` - local Python virtual environment (should not be committed)
  - `.env` - local environment variables with API keys (must remain local)
  - `requirements.txt` - Python dependencies

## What it does

The add-in performs the following actions:

- reads the currently opened Outlook message
- fetches raw email headers and body text
- extracts URLs from the message body
- sends sender, headers, and URLs to the backend
- backend verifies SPF/DKIM/DMARC from headers
- backend checks DNS SPF/DMARC records for sender domain
- backend checks URLs against VirusTotal
- backend generates a short Gemini AI verdict
- frontend displays a risk score, verdict, reasons, and details

## Prerequisites

- macOS
- Node.js and npm
- Python 3.9+ with pip
- Outlook local or Microsoft 365 account for add-in testing

## Setup

### 1. Clone this repository

```bash
cd /path/to/parent/folder
git clone <your-repo-url> outlook-phishing-detector
cd outlook-phishing-detector
```

### 2. Install frontend dependencies

```bash
cd frontend
npm install
```

### 3. Install backend dependencies

```bash
cd ../backend
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

### 4. Configure API keys

Create a local `backend/.env` file with your API keys from the repository root.

```bash
cp .env.example backend/.env
```

Then edit `backend/.env` to add:

```text
VT_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
```

> Do not commit `backend/.env` to Git. It contains sensitive credentials.

## Running locally

### Start the backend

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload
```

The backend is expected to run on `http://127.0.0.1:8000`.

### Start the frontend

```bash
cd ../frontend
npm run dev-server
```

The frontend dev server runs on `https://localhost:3000` using local development certificates.

### Load the add-in in Outlook

Use the Office Add-in debugging tools or sideload the manifest from `frontend/manifest.xml`. The task pane is loaded from:

- `https://localhost:3000/taskpane.html`
- `https://localhost:3000/commands.html`

## Project files worth knowing

- `frontend/src/taskpane/taskpane.ts`
  - entry point for scan behavior, Office.js integration, URL extraction, result rendering
- `frontend/manifest.xml`
  - Outlook add-in manifest, taskpane and command configuration
- `frontend/webpack.config.js`
  - build and development server setup
- `backend/app/main.py`
  - analysis engine, FastAPI endpoints, VirusTotal/Gemini integration
- `backend/requirements.txt`
  - Python dependency list

## Security and deployment notes

- Keep `backend/.env` private
- `frontend/manifest.xml` is configured for localhost development
- Update production URLs in `frontend/webpack.config.js` before deploying
- Remove or rotate API keys if they were accidentally exposed

## Git preparation

The repository already includes a `.gitignore` to exclude:

- `frontend/node_modules/`
- `backend/venv/`
- `.env` files
- OS/editor artifacts such as `.DS_Store`

## Recommended commands

- `npm run build` — build frontend for production
- `npm run dev-server` — launch frontend dev server
- `npm run watch` — watch frontend source files
- `python app/main.py` — run backend service

## Notes

- The backend uses FastAPI and a simple analyzer for SPF/DKIM/DMARC and URL reputation.
- Gemini AI is used to generate an end-user friendly verdict, but the technical risk score is the main signal.
- This repository does not currently include a remote Git origin or existing `.git` metadata.

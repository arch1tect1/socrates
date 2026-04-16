# SOCrates — AI-Powered IOC Triage Platform

A web-based threat intelligence triage tool. Paste an IOC (IP, domain, URL, or file hash), and SOCrates enriches it across multiple threat intel sources in real-time, then delivers an AI-powered verdict with cross-referenced reasoning.

## Architecture

```
Frontend (React + Vite + Tailwind CSS)
   │  SSE stream
   ▼
Backend (FastAPI)
   ├── VirusTotal API
   ├── Shodan API
   ├── AbuseIPDB API
   ├── OTX AlienVault API
   ├── URLScan.io API
   └── Claude AI (OpenAI fallback)
```

## Quick Start

### 1. Configure API Keys

Copy the example env file and add your API keys:

```bash
cp .env.example .env
# Edit .env with your actual keys
```

### 2. Start the Backend

```bash
cd backend
pip install -r ../requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Run from the `socrates-web/` directory:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

### 3. Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend dev server proxies `/api` requests to `localhost:8000`.

Open **http://localhost:5173** in your browser.

## Features

- **Auto-detection** of IOC type (IPv4/IPv6, domain, URL, MD5/SHA1/SHA256)
- **Real-time progress** via Server-Sent Events — watch each source query live
- **Parallel enrichment** across 5 threat intelligence sources
- **AI triage verdict** with cross-referenced reasoning, MITRE ATT&CK mapping, and recommended actions
- **Dark/light mode** with smooth transitions
- **Query history** persisted in localStorage

## Supported IOC Types

| Type | Sources Queried |
|------|----------------|
| IP Address | VirusTotal, Shodan, AbuseIPDB, OTX AlienVault |
| Domain | VirusTotal, Shodan, OTX AlienVault, URLScan.io |
| URL | VirusTotal, OTX AlienVault, URLScan.io |
| File Hash | VirusTotal, OTX AlienVault |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze` | Submit IOC for analysis (returns SSE stream) |
| GET | `/api/detect?ioc=...` | Detect IOC type without analysis |
| GET | `/api/health` | Health check |

## Tech Stack

- **Frontend**: React 18, Vite 5, Tailwind CSS 3, Lucide Icons
- **Backend**: Python, FastAPI, httpx (async HTTP), Pydantic
- **AI**: Anthropic Claude (primary), OpenAI GPT-4o (fallback)

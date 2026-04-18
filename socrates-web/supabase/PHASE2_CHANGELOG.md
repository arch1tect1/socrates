# Phase 2 — Webhook + parser + IOC extractor (changelog)

## What shipped

- **`backend/models/alerts.py`** — Pydantic models: `ExtractedIOC`, `AlertCreate`, `AlertResponse`, `VerdictResponse`, `ManualSubmitRequest`, `StatusPatchRequest`.
- **`backend/services/ioc_extractor.py`** — `IOCExtractor`: IPv4/IPv6, URL, email, MD5/SHA1/SHA256, domains; defang; private/reserved IP filtering (`ipaddress`); configurable domain whitelist (`SOCrates_DOMAIN_WHITELIST` CSV + defaults); dedupe.
- **`backend/services/alert_parser.py`** — `WazuhParser`, `ManualInputParser`, `ParserRegistry` (hint: `wazuh` / `manual`).
- **`backend/services/alert_ingestion.py`** — `ingest`, `fetch_alert`, `list_alerts`, `update_alert_status` (Supabase via `get_supabase_client()` from `cache.py`).
- **`backend/api/alerts.py`** — Router mounted at **`/api/v1/alerts`**.
- **`backend/agents/triage_agent.py`** — `investigate(alert_id)` **stub** (Phase 3); invoked via `BackgroundTasks` after ingest.
- **`backend/cache.py`** — `get_supabase_client()` for shared DB access.
- **`tests/test_ioc_extractor.py`** + **`tests/fixtures/wazuh_ssh_bruteforce.json`**
- **`requirements.txt`** — `pytest` added.

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/alerts/webhook/wazuh` | Wazuh JSON body |
| POST | `/api/v1/alerts/manual` | JSON `{ "raw_text", "source_label"?, "title"?, "severity"? }` |
| GET | `/api/v1/alerts/` | List (optional `status`, `severity`, `limit`, `offset`) |
| GET | `/api/v1/alerts/{alert_id}` | Detail + IOCs + latest verdict |
| PATCH | `/api/v1/alerts/{alert_id}/status` | `{ "status": "..." }` |

## Acceptance criteria

- [ ] `curl` to Wazuh webhook creates `alerts` + `alert_iocs` (needs Supabase env on server).
- [ ] Public IOCs extracted; private IPs skipped; defang works.
- [ ] `pytest tests/test_ioc_extractor.py` passes.

---

## Manual testing

**1. Env** — `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (recommended). Phase 1 migration applied (`alerts`, `alert_iocs`, `verdicts`).

**2. Run API** (from `socrates-web/`):

```bash
uvicorn backend.main:app --reload --port 8000
```

**3. Wazuh webhook** (Git Bash / WSL paths):

```bash
curl -sS -X POST "http://localhost:8000/api/v1/alerts/webhook/wazuh" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/wazuh_ssh_bruteforce.json
```

Expect JSON `AlertResponse` with `iocs` containing `185.234.217.42` (public); agent IP `10.0.1.5` must **not** appear as an IOC.

**4. Supabase** — New row in `alerts`; related rows in `alert_iocs`.

**5. Unit tests**

```bash
cd socrates-web
python -m pytest tests/test_ioc_extractor.py -v
```

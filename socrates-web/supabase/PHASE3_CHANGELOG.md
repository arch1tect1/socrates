# Phase 3 — Triage agent tool loop (changelog)

## What shipped

- **`backend/agents/tools.py`** — `TRIAGE_TOOLS`: Anthropic-compatible tool definitions for VT, Shodan, AbuseIPDB, OTX, URLScan, RDAP/WHOIS-style domain metadata, similar alerts search.
- **`backend/agents/tool_executor.py`** — `ToolExecutor`: maps tool names to existing `backend/enrichment/*` modules; **cache-first** via `ioc_queries` + `enrichment_results` (24h TTL on new cache rows).
- **`backend/agents/triage_agent.py`** — `async def investigate(alert_id)`: loads alert + IOCs, sets `alerts.status` → `investigating`, runs Anthropic **Messages** API with tools (httpx), persists **`verdicts`** (`tools_used`, `agent_trace`). Exposed as **`async`** so `BackgroundTasks` awaits completion (important on Vercel serverless).
- **`backend/cache.py`** — `get_cached_enrichment_for_source`, `save_tool_enrichment_to_cache` for per-source tool caching.
- **`tests/test_phase3.py`** — verdict JSON parsing + IOC type mapping tests.

## Env

- **`ANTHROPIC_API_KEY`** — required for triage.
- **`ANTHROPIC_TRIAGE_MODEL`** — optional (default `claude-sonnet-4-20250514`).
- Existing enrichment API keys (`VIRUSTOTAL_API_KEY`, etc.) — used when cache misses.
- **`SUPABASE_*`** — required for alerts + verdict persistence + tool cache.

## Manual checks

1. Ingest an alert (`POST /api/v1/alerts/manual` or Wazuh webhook) with a public IOC.
2. Wait for background triage (Vercel: check function logs).
3. `GET /api/v1/alerts/{id}` — expect `verdict` populated; `agent_trace` non-empty.
4. Repeat ingest with same IOC — tool steps should show `cache_hit` / `cached: true` in trace when reading from `enrichment_results`.

## Notes

- **`get_whois`** uses public **RDAP** (`https://rdap.org/domain/...`) — no extra API key.
- **`search_similar_alerts`** queries `alert_iocs` + `alerts` (last 30 days); does not use external APIs.

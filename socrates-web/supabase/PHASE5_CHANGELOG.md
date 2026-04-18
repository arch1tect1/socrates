# Phase 5 — Hardening (Part A changelog)

## A.1 Alert status after verdict

After each successful `verdicts` insert, `alerts.status` is updated via `_status_for_verdict()`:

- `malicious` + confidence ≥ 0.75 → `escalated`
- `benign` + confidence ≥ 0.85 → `resolved`
- `suspicious` → `investigating`
- Otherwise (incl. `inconclusive`) → `investigating`

Triage sets `investigating` at the **start** of `_investigate_async` (before loading alert for the main loop). Ingest still creates alerts as `open`.

## A.2 Early exits

- **No IOCs:** `inconclusive` verdict + reasoning (no Anthropic loop).
- **All IOCs whitelist-only (IP/domain):** `benign` / `close_fp` without external API calls.

Whitelist defaults + env extensions: `backend/agents/whitelist_config.py`  
(`SOCrates_IOC_WHITELIST_DOMAINS`, `SOCrates_IOC_WHITELIST_IPS`).

## A.3 Reprocess stuck

- **SQL:** `supabase/migrations/20260418_find_alerts_without_verdict.sql` — function `find_alerts_without_verdict(cutoff timestamptz)`.
- **API:** `POST /api/v1/alerts/admin/reprocess-stuck?older_than_minutes=10`  
  If `SOCRATES_ADMIN_SECRET` is set, send header `X-SOCrates-Admin-Secret: <same value>`.

## A.4 Agent trace UI

Collapsed iteration rows show a one-line preview (reasoning snippet + tool + IOC target) in `AgentTraceViewer.jsx`.

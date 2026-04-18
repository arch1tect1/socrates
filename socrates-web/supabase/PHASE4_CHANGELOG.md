# Phase 4 — Alerts dashboard (changelog)

## What shipped

- **Routes:** `/` (IOC analyzer), `/alerts` (dashboard), `/alerts/:id` (detail + agent trace).
- **`frontend/src/lib/supabase.js`** — browser Supabase client (`VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`).
- **`useAlerts` / `useAlertDetail`** — `select` with `alert_iocs`, `verdicts`; Realtime subscriptions for `alerts` + `verdicts`.
- **UI:** `AlertFilters` (URL-synced via `useSearchParams`), `AlertsTable`, badges, `AgentTraceViewer`, `IOCList`.
- **Vercel:** SPA fallback rewrite to `index.html` (after `/api/*`).

## Env (Vercel + local)

The Vite build resolves the browser client from (first match wins):

- URL: `SUPABASE_URL` or `VITE_SUPABASE_URL` or `NEXT_PUBLIC_SUPABASE_URL`
- Anon: `NEXT_PUBLIC_SUPABASE_ANON_KEY` or `VITE_SUPABASE_ANON_KEY`

So existing Vercel vars like **`SUPABASE_URL`** + **`NEXT_PUBLIC_SUPABASE_ANON_KEY`** work with no duplicates. Use the **anon** key only in the frontend (not the service role). RLS must allow `SELECT` on `alerts`, `alert_iocs`, `verdicts` for anon (or use authenticated users later).

## Manual checks

1. Open `/alerts` with env set — table loads.
2. POST a new alert — row appears without full refresh (Realtime).
3. When triage finishes — verdict column updates without refresh.
4. Open `/alerts/<uuid>` — reasoning + expandable trace.
5. Change filters — URL query string updates; link is shareable.

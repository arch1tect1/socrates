# Phase 1 — Supabase schema (changelog)

## What shipped

- New migration: `supabase/migrations/20260415_alerts_schema.sql`
- **Tables**
  - `alerts` — ingested events (source, severity, status, title, `raw_payload`, timestamps + `updated_at` trigger).
  - `alert_iocs` — IOCs per alert (`ioc_type` / `ioc_value`; no FK to existing cache tables).
  - `verdicts` — agent verdicts per alert (verdict, confidence, reasoning, `tools_used`, `agent_trace`, etc.).
- **Indexes** — as specified for status, severity, created_at, source, alert_id, ioc_value.
- **Realtime** — `alerts` and `verdicts` added to `supabase_realtime` publication; `REPLICA IDENTITY FULL` on both for reliable change payloads.
- **RLS** — enabled on all three tables; permissive policies with `USING (true) WITH CHECK (true)` so inserts work under RLS.

## Not changed

- Existing enrichment cache tables (e.g. `ioc_queries`, `enrichment_results`, `ai_verdicts`) — **not modified**.

## Acceptance criteria mapping

| Criterion | Notes |
|-----------|--------|
| Migration applies cleanly | Run via SQL Editor or `supabase db push` (CLI). |
| Realtime on `alerts` / `verdicts` | Check **Database → Replication** (or publication `supabase_realtime`). |
| `ioc_cache` / existing cache untouched | No DDL on those objects in this file. |

---

## Manual testing instructions

1. **Apply migration**
   - **Supabase Dashboard** → **SQL Editor** → paste `20260415_alerts_schema.sql` → **Run**.
   - Or from repo root (if CLI linked): `supabase db push` / `supabase migration up`.

2. **Verify tables**
   - **Table Editor**: confirm `alerts`, `alert_iocs`, `verdicts` exist with expected columns.

3. **Verify Realtime**
   - **Database → Publications** (or **Replication**): confirm `alerts` and `verdicts` are in `supabase_realtime`.
   - Optional: **Realtime** settings → confirm tables can broadcast (project-dependent UI).

4. **Smoke insert (RLS)**
   - In **SQL Editor**, run **only** the lines below — do **not** paste Markdown code fences (no `` ``` `` or `` ```sql ``). Those cause `syntax error at or near "```"`.
   - Statement to run (type or paste these three lines only):

        insert into public.alerts (source, severity, title, raw_payload)
        values ('test', 'low', 'Phase 1 smoke', '{}'::jsonb)
        returning id;

   - Expect: one row with a new `id` (RLS policy allows insert).

5. **Confirm existing cache**
   - Confirm `ioc_queries` (or your legacy cache table) row counts / schema unchanged from before migration.

6. **Re-run safety**
   - This migration is **not** idempotent (re-run will error on “already exists”). Use fresh DB or adjust for dev resets only.

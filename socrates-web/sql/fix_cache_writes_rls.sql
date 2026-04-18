-- SOCrates: fixes when new rows never appear in ioc_queries / enrichment_results / ai_verdicts
--
-- =============================================================================
-- 1) REQUIRED SCHEMA: session_id (if INSERT errors mention missing column)
-- =============================================================================
ALTER TABLE public.ioc_queries ADD COLUMN IF NOT EXISTS session_id TEXT;
CREATE INDEX IF NOT EXISTS idx_ioc_queries_session_id ON public.ioc_queries (session_id);

-- =============================================================================
-- 2) RECOMMENDED: use the service role from your Python API (Vercel env)
--    SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY
--    Service role bypasses RLS — no policy changes needed.
-- =============================================================================

-- =============================================================================
-- 3) OPTIONAL: permissive RLS (only if you insist on using the anon key from
--    the server — weaker; prefer service_role instead.)
--    Run: SELECT * FROM pg_policies WHERE tablename IN ('ioc_queries', ...);
-- =============================================================================

-- Example: allow all operations for anon/authenticated (adjust to your security model)
-- DROP POLICY IF EXISTS "socreates_allow_all_ioc_queries" ON public.ioc_queries;
-- CREATE POLICY "socreates_allow_all_ioc_queries" ON public.ioc_queries
--   FOR ALL USING (true) WITH CHECK (true);

-- DROP POLICY IF EXISTS "socreates_allow_all_enrichment_results" ON public.enrichment_results;
-- CREATE POLICY "socreates_allow_all_enrichment_results" ON public.enrichment_results
--   FOR ALL USING (true) WITH CHECK (true);

-- DROP POLICY IF EXISTS "socreates_allow_all_ai_verdicts" ON public.ai_verdicts;
-- CREATE POLICY "socreates_allow_all_ai_verdicts" ON public.ai_verdicts
--   FOR ALL USING (true) WITH CHECK (true);

-- =============================================================================
-- 4) NUCLEAR (private/dev only): disable RLS on cache tables
-- =============================================================================
-- ALTER TABLE public.ioc_queries DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE public.enrichment_results DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE public.ai_verdicts DISABLE ROW LEVEL SECURITY;

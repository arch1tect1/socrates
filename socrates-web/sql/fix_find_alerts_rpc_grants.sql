-- Run in Supabase SQL Editor if POST /api/v1/alerts/admin/reprocess-stuck returns PGRST202
-- (function exists but PostgREST cannot execute it for your API role).

GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO anon;
GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO authenticated;
GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO service_role;

-- If RPC still 404s, wait ~1 min or restart the project / run a schema reload from Supabase support docs.

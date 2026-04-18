-- Maintenance: find alerts with no verdict row older than a cutoff (reprocess-stuck endpoint)

CREATE OR REPLACE FUNCTION public.find_alerts_without_verdict(cutoff timestamptz)
RETURNS TABLE (id uuid, created_at timestamptz, source text)
LANGUAGE sql
STABLE
AS $$
  SELECT a.id, a.created_at, a.source
  FROM public.alerts a
  LEFT JOIN public.verdicts v ON v.alert_id = a.id
  WHERE v.id IS NULL
    AND a.created_at < cutoff
  ORDER BY a.created_at ASC;
$$;

COMMENT ON FUNCTION public.find_alerts_without_verdict(timestamptz) IS
  'Used by API admin/reprocess-stuck to backfill triage for stuck alerts.';

-- PostgREST exposes RPC only if the role used by the API can EXECUTE:
GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO anon;
GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO authenticated;
GRANT EXECUTE ON FUNCTION public.find_alerts_without_verdict(timestamptz) TO service_role;

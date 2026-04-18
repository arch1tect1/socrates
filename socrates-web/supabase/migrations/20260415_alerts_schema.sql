-- Phase 1: Alert dashboard schema (alerts, alert_iocs, verdicts)
-- Does NOT alter existing enrichment cache tables (e.g. ioc_queries, enrichment_results).
-- alert_iocs stores IOCs extracted from alerts; optional linkage to cache is application-level.

-- ── alerts: incoming events from SIEM/EDR/manual input ─────────────────────
CREATE TABLE public.alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source text NOT NULL,
    source_alert_id text,
    rule_name text,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive', 'escalated')),
    title text NOT NULL,
    description text,
    raw_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_status ON public.alerts (status);
CREATE INDEX idx_alerts_severity ON public.alerts (severity);
CREATE INDEX idx_alerts_created_at ON public.alerts (created_at DESC);
CREATE INDEX idx_alerts_source ON public.alerts (source);

-- ── alert_iocs: IOCs tied to an alert (no FK to ioc_queries — existing cache untouched) ──
CREATE TABLE public.alert_iocs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id uuid NOT NULL REFERENCES public.alerts (id) ON DELETE CASCADE,
    ioc_type text NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email')),
    ioc_value text NOT NULL,
    extracted_from text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_iocs_alert_id ON public.alert_iocs (alert_id);
CREATE INDEX idx_alert_iocs_ioc_value ON public.alert_iocs (ioc_value);

-- ── verdicts: AI agent investigation results ───────────────────────────────
CREATE TABLE public.verdicts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id uuid NOT NULL REFERENCES public.alerts (id) ON DELETE CASCADE,
    verdict text NOT NULL CHECK (verdict IN ('malicious', 'suspicious', 'benign', 'inconclusive')),
    confidence numeric(3, 2) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    reasoning text NOT NULL,
    tools_used jsonb NOT NULL DEFAULT '[]'::jsonb,
    recommended_action text,
    agent_trace jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_verdicts_alert_id ON public.verdicts (alert_id);

-- ── updated_at trigger for alerts ───────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS update_alerts_updated_at ON public.alerts;
CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON public.alerts
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- Realtime: replica identity recommended for Postgres changes / full row payloads
ALTER TABLE public.alerts REPLICA IDENTITY FULL;
ALTER TABLE public.verdicts REPLICA IDENTITY FULL;

-- Enable Realtime (requires supabase_realtime publication — standard on Supabase Cloud)
ALTER PUBLICATION supabase_realtime ADD TABLE public.alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE public.verdicts;

-- RLS (permissive until auth is wired)
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alert_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verdicts ENABLE ROW LEVEL SECURITY;

-- USING + WITH CHECK so INSERT/UPDATE work under RLS with anon/service clients
CREATE POLICY alerts_allow_all_for_now ON public.alerts
    FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY alert_iocs_allow_all_for_now ON public.alert_iocs
    FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY verdicts_allow_all_for_now ON public.verdicts
    FOR ALL USING (true) WITH CHECK (true);

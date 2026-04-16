-- Run in Supabase SQL Editor (private Recent Queries per browser session)
ALTER TABLE ioc_queries ADD COLUMN IF NOT EXISTS session_id TEXT;
CREATE INDEX IF NOT EXISTS idx_ioc_queries_session_id ON ioc_queries(session_id);

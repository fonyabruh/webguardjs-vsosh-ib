CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS incidents (
  id uuid PRIMARY KEY,
  ts timestamptz NOT NULL,
  session_id text NOT NULL,
  page_id text NOT NULL,
  risk real NOT NULL,
  top_signals jsonb NOT NULL,
  features jsonb NOT NULL,
  counters jsonb NOT NULL,
  user_agent text,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS incidents_ts_idx ON incidents (ts);
CREATE INDEX IF NOT EXISTS incidents_session_id_idx ON incidents (session_id);
CREATE INDEX IF NOT EXISTS incidents_page_id_idx ON incidents (page_id);
CREATE INDEX IF NOT EXISTS incidents_risk_idx ON incidents (risk);

CREATE TABLE IF NOT EXISTS dead_letter_log (
  id            SERIAL PRIMARY KEY,
  routing_key   TEXT NOT NULL,
  source        TEXT,
  payload       JSONB,
  death_reason  TEXT,
  received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dl_log_routing_key ON dead_letter_log(routing_key);
CREATE INDEX IF NOT EXISTS idx_dl_log_received_at ON dead_letter_log(received_at);

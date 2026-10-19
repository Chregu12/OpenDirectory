CREATE TABLE IF NOT EXISTS replication_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_dc VARCHAR(255) NOT NULL,
  target_dc VARCHAR(255) NOT NULL,
  naming_context VARCHAR(255) NOT NULL,
  attempt_time TIMESTAMPTZ DEFAULT NOW(),
  success BOOLEAN NOT NULL,
  error_code VARCHAR(50),
  objects_replicated INTEGER DEFAULT 0,
  duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS replication_state (
  dc_name VARCHAR(255) NOT NULL,
  naming_context VARCHAR(255) NOT NULL,
  last_usn BIGINT DEFAULT 0,
  last_success TIMESTAMPTZ,
  last_attempt TIMESTAMPTZ,
  consecutive_failures INTEGER DEFAULT 0,
  PRIMARY KEY (dc_name, naming_context)
);
CREATE INDEX IF NOT EXISTS idx_repl_log_time ON replication_log(attempt_time DESC);

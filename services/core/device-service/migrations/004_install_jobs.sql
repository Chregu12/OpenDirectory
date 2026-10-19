CREATE TABLE IF NOT EXISTS install_jobs (
  job_id        TEXT PRIMARY KEY,
  device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  app_id        TEXT NOT NULL,
  app_name      TEXT,
  package_id    TEXT,
  format        TEXT,
  version       TEXT,
  status        TEXT NOT NULL DEFAULT 'queued',
  queued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ,
  error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_install_jobs_device ON install_jobs(device_id);
CREATE INDEX IF NOT EXISTS idx_install_jobs_status ON install_jobs(status);

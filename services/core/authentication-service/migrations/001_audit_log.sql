CREATE TABLE IF NOT EXISTS audit_events (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  actor VARCHAR(255),
  target VARCHAR(255),
  message TEXT NOT NULL,
  severity VARCHAR(20) DEFAULT 'info',
  ip_address VARCHAR(45),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor);

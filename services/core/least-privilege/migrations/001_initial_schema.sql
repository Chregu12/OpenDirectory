-- Permission assignments
CREATE TABLE IF NOT EXISTS permission_assignments (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  level VARCHAR(50) NOT NULL,
  override VARCHAR(50),
  source VARCHAR(50) DEFAULT 'role',
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used TIMESTAMPTZ,
  days_idle INTEGER DEFAULT 0,
  UNIQUE(user_id, resource)
);

-- PIM requests
CREATE TABLE IF NOT EXISTS pim_requests (
  id VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  level VARCHAR(50) NOT NULL,
  justification TEXT,
  duration_hours INTEGER NOT NULL DEFAULT 4,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  approved_by VARCHAR(255),
  expires_at TIMESTAMPTZ
);

-- Active PIM elevations
CREATE TABLE IF NOT EXISTS pim_active (
  id VARCHAR(255) PRIMARY KEY,
  request_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  level VARCHAR(50) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Escalation alerts
CREATE TABLE IF NOT EXISTS escalation_alerts (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  admin_count INTEGER,
  resources JSONB,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved BOOLEAN DEFAULT FALSE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_perm_user ON permission_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_pim_user ON pim_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_pim_active_expires ON pim_active(expires_at);
CREATE INDEX IF NOT EXISTS idx_escalation_user ON escalation_alerts(user_id);

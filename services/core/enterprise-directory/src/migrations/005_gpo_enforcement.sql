-- Migration 005: GPO Enforcement tables
-- Tracks which OUs/objects a GPO has been applied to, and caches RSoP results.

CREATE TABLE IF NOT EXISTS gpo_application_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gpo_id UUID NOT NULL,
  target_dn VARCHAR(500) NOT NULL,
  target_type VARCHAR(50) NOT NULL, -- 'ou', 'user', 'computer'
  applied_at TIMESTAMPTZ DEFAULT NOW(),
  settings_applied JSONB,
  status VARCHAR(50) DEFAULT 'success',
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_gpo_app_gpo_id ON gpo_application_log(gpo_id);
CREATE INDEX IF NOT EXISTS idx_gpo_app_target ON gpo_application_log(target_dn);
CREATE INDEX IF NOT EXISTS idx_gpo_app_applied_at ON gpo_application_log(applied_at DESC);

CREATE TABLE IF NOT EXISTS resultant_set_of_policy (
  target_dn VARCHAR(500) PRIMARY KEY,
  computer_config JSONB,
  user_config JSONB,
  applied_gpos JSONB,
  computed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Fine-grained password policies (Fine-Grained Password Policy / FGPP)
CREATE TABLE IF NOT EXISTS password_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL UNIQUE,
  precedence INTEGER NOT NULL DEFAULT 0,
  applies_to VARCHAR(500) DEFAULT 'domain',
  min_length INTEGER DEFAULT 8,
  complexity JSONB DEFAULT '{"minCategories": 3}'::jsonb,
  max_age_days INTEGER DEFAULT 90,
  min_age_days INTEGER DEFAULT 1,
  history_count INTEGER DEFAULT 10,
  lockout_threshold INTEGER DEFAULT 5,
  lockout_duration_minutes INTEGER DEFAULT 30,
  lockout_observation_window_minutes INTEGER DEFAULT 30,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed domain default policy
INSERT INTO password_policies (
  name, precedence, applies_to, min_length, complexity,
  max_age_days, min_age_days, history_count,
  lockout_threshold, lockout_duration_minutes, lockout_observation_window_minutes
) VALUES (
  'Default Domain Policy', 0, 'domain', 8,
  '{"minCategories": 3, "upperCase": true, "lowerCase": true, "digit": true, "special": false}'::jsonb,
  90, 1, 10, 5, 30, 30
) ON CONFLICT (name) DO NOTHING;

-- Track per-user authentication failures for lockout enforcement
CREATE TABLE IF NOT EXISTS auth_failure_tracking (
  user_id VARCHAR(255) PRIMARY KEY,
  failure_count INTEGER DEFAULT 0,
  last_failure TIMESTAMPTZ,
  locked_until TIMESTAMPTZ,
  last_ip INET
);

-- Extended password history table (may already exist from 002_password_history.sql)
-- Only add if not present (CREATE TABLE IF NOT EXISTS is idempotent)
CREATE TABLE IF NOT EXISTS password_history (
  user_id VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  changed_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, password_hash)
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_time ON password_history(user_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username            VARCHAR(256) UNIQUE NOT NULL,
  email               VARCHAR(512) UNIQUE,
  password_hash       TEXT,
  first_name          VARCHAR(256),
  last_name           VARCHAR(256),
  roles               JSONB        NOT NULL DEFAULT '["user"]',
  permissions         JSONB        NOT NULL DEFAULT '[]',
  provider            VARCHAR(64)  NOT NULL DEFAULT 'local',
  mfa_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
  mfa_secret          TEXT,
  is_locked           BOOLEAN      NOT NULL DEFAULT FALSE,
  lock_reason         TEXT,
  locked_until        TIMESTAMPTZ,
  password_changed_at TIMESTAMPTZ  DEFAULT NOW(),
  last_login          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider);

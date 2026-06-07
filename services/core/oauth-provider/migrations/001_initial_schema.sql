-- OAuth2 clients
CREATE TABLE IF NOT EXISTS oauth_clients (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  secret VARCHAR(255),
  redirect_uris JSONB NOT NULL DEFAULT '[]',
  grants JSONB NOT NULL DEFAULT '[]',
  scopes JSONB NOT NULL DEFAULT '[]',
  token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auth codes (short-lived, TTL ~10min)
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  code VARCHAR(512) PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  redirect_uri TEXT,
  scope TEXT,
  code_challenge TEXT,
  code_challenge_method VARCHAR(10),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Access tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token VARCHAR(512) PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255),
  scope TEXT,
  token_type VARCHAR(50) DEFAULT 'Bearer',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Refresh tokens
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token VARCHAR(512) PRIMARY KEY,
  access_token VARCHAR(512),
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255),
  scope TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Device authorization codes (RFC 8628)
CREATE TABLE IF NOT EXISTS oauth_device_codes (
  device_code VARCHAR(512) PRIMARY KEY,
  user_code VARCHAR(20) NOT NULL UNIQUE,
  client_id VARCHAR(255) NOT NULL,
  scope TEXT,
  verification_uri TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  approved BOOLEAN DEFAULT FALSE,
  user_id VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SCIM Users
CREATE TABLE IF NOT EXISTS scim_users (
  id VARCHAR(255) PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SCIM Groups
CREATE TABLE IF NOT EXISTS scim_groups (
  id VARCHAR(255) PRIMARY KEY,
  display_name VARCHAR(255) NOT NULL,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enrollment tokens
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token VARCHAR(512) PRIMARY KEY,
  platform VARCHAR(50) NOT NULL,
  label VARCHAR(255),
  max_uses INTEGER NOT NULL DEFAULT 50,
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enrolled devices
CREATE TABLE IF NOT EXISTS enrolled_devices (
  id VARCHAR(255) PRIMARY KEY,
  token VARCHAR(512),
  hostname VARCHAR(255),
  platform VARCHAR(50),
  os_version VARCHAR(255),
  ip_address VARCHAR(45),
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ,
  status VARCHAR(50) DEFAULT 'active',
  compliance_status VARCHAR(50) DEFAULT 'unknown',
  data JSONB DEFAULT '{}'
);

-- SCIM push log
CREATE TABLE IF NOT EXISTS scim_push_log (
  id SERIAL PRIMARY KEY,
  app_id VARCHAR(255),
  action VARCHAR(50),
  user_id VARCHAR(255),
  group_name VARCHAR(255),
  success BOOLEAN,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Update rings
CREATE TABLE IF NOT EXISTS update_rings (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  delay_days INTEGER NOT NULL DEFAULT 0,
  rollout_percent INTEGER NOT NULL DEFAULT 100,
  data JSONB DEFAULT '{}'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires ON oauth_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_expires ON oauth_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON oauth_device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_enrolled_devices_platform ON enrolled_devices(platform);
CREATE INDEX IF NOT EXISTS idx_scim_push_log_created ON scim_push_log(created_at);

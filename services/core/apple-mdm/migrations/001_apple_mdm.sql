-- Apple MDM Service Schema
-- Run against the 'auth' database (or a dedicated mdm database)

CREATE TABLE IF NOT EXISTS mdm_devices (
  udid VARCHAR(255) PRIMARY KEY,
  push_token TEXT,
  device_name VARCHAR(255),
  model VARCHAR(255),
  os_version VARCHAR(50),
  enrolled_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS mdm_commands (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  udid VARCHAR(255) REFERENCES mdm_devices(udid) ON DELETE CASCADE,
  command_uuid UUID DEFAULT gen_random_uuid(),
  request_type VARCHAR(100) NOT NULL,
  payload JSONB DEFAULT '{}',
  status VARCHAR(50) DEFAULT 'pending',
  issued_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mdm_commands_udid_status ON mdm_commands(udid, status);
CREATE INDEX IF NOT EXISTS idx_mdm_devices_status ON mdm_devices(status);

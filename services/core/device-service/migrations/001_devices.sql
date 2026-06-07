CREATE TABLE IF NOT EXISTS devices (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255),
  platform VARCHAR(50),
  os_version VARCHAR(100),
  status VARCHAR(50) DEFAULT 'active',
  enrolled_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ,
  assigned_user VARCHAR(255),
  serial_number VARCHAR(255),
  model VARCHAR(255),
  agent_version VARCHAR(50),
  compliance_status VARCHAR(50) DEFAULT 'unknown',
  metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS device_compliance (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id VARCHAR(255) REFERENCES devices(id) ON DELETE CASCADE,
  checked_at TIMESTAMPTZ DEFAULT NOW(),
  platform VARCHAR(50),
  settings JSONB DEFAULT '{}',
  compliant BOOLEAN DEFAULT false,
  failed_checks TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

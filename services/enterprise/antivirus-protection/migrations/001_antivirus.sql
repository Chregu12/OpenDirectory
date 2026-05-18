CREATE TABLE IF NOT EXISTS av_devices (
  device_id VARCHAR(255) PRIMARY KEY,
  platform VARCHAR(50),
  clamav_version VARCHAR(100),
  signature_version VARCHAR(100),
  signature_date DATE,
  realtime_enabled BOOLEAN DEFAULT false,
  last_scan TIMESTAMPTZ,
  last_scan_type VARCHAR(50),
  threats_found INTEGER DEFAULT 0,
  quarantined_files INTEGER DEFAULT 0,
  status VARCHAR(50) DEFAULT 'unknown',
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS av_threats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id VARCHAR(255) REFERENCES av_devices(device_id) ON DELETE CASCADE,
  scan_id UUID,
  threat_name VARCHAR(500) NOT NULL,
  threat_path TEXT,
  threat_type VARCHAR(100) DEFAULT 'malware',
  severity VARCHAR(50) DEFAULT 'high',
  status VARCHAR(50) DEFAULT 'active',
  quarantined BOOLEAN DEFAULT false,
  detected_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS av_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id VARCHAR(255) REFERENCES av_devices(device_id) ON DELETE CASCADE,
  scan_type VARCHAR(50) DEFAULT 'quick',
  status VARCHAR(50) DEFAULT 'completed',
  started_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ DEFAULT NOW(),
  files_scanned INTEGER DEFAULT 0,
  threats_found INTEGER DEFAULT 0,
  raw_output TEXT,
  platform VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS av_quarantine (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id VARCHAR(255),
  threat_id UUID REFERENCES av_threats(id),
  file_path TEXT NOT NULL,
  threat_name VARCHAR(500),
  quarantined_at TIMESTAMPTZ DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'quarantined',
  file_size BIGINT
);

CREATE INDEX IF NOT EXISTS idx_av_threats_device ON av_threats(device_id);
CREATE INDEX IF NOT EXISTS idx_av_scans_device ON av_scans(device_id);
CREATE INDEX IF NOT EXISTS idx_av_threats_status ON av_threats(status);

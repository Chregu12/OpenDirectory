CREATE TABLE IF NOT EXISTS dns_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(10) NOT NULL,
  value TEXT NOT NULL,
  zone VARCHAR(255) DEFAULT 'opendirectory.local',
  ttl INTEGER DEFAULT 300,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(name, type, zone)
);

CREATE TABLE IF NOT EXISTS dhcp_leases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mac_address VARCHAR(17) UNIQUE NOT NULL,
  ip_address VARCHAR(15),
  hostname VARCHAR(255),
  lease_start TIMESTAMPTZ DEFAULT NOW(),
  lease_end TIMESTAMPTZ,
  status VARCHAR(50) DEFAULT 'active',
  vlan_id INTEGER
);

CREATE TABLE IF NOT EXISTS vlans (
  id INTEGER PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  subnet VARCHAR(18),
  gateway VARCHAR(15),
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed default DNS records
INSERT INTO dns_records (name, type, value, zone) VALUES
  ('opendirectory.local', 'A', '127.0.0.1', 'opendirectory.local'),
  ('ldap.opendirectory.local', 'A', '127.0.0.1', 'opendirectory.local'),
  ('kdc.opendirectory.local', 'A', '127.0.0.1', 'opendirectory.local')
ON CONFLICT DO NOTHING;

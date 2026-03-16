CREATE TABLE IF NOT EXISTS policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  type VARCHAR(50) NOT NULL, -- security, software, registry, network, firewall, encryption, password, compliance
  platform VARCHAR(50), -- windows, macos, linux, all
  rules JSONB DEFAULT '[]',
  settings JSONB DEFAULT '{}',
  priority INTEGER DEFAULT 100,
  status VARCHAR(20) DEFAULT 'draft', -- draft, active, inactive, archived
  version INTEGER DEFAULT 1,
  enforce BOOLEAN DEFAULT false, -- GPO enforce flag
  block_inheritance BOOLEAN DEFAULT false,
  wmi_filter JSONB, -- WMI filter conditions
  security_filter JSONB, -- security group filter
  created_by VARCHAR(255),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  activated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS policy_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
  target_type VARCHAR(50) NOT NULL, -- ou, site, domain, group, device
  target_id VARCHAR(255) NOT NULL,
  target_name VARCHAR(255),
  enabled BOOLEAN DEFAULT true,
  enforce BOOLEAN DEFAULT false,
  link_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(255) NOT NULL,
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  assigned_by VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID,
  action VARCHAR(50) NOT NULL,
  actor VARCHAR(255),
  changes JSONB,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);
CREATE INDEX IF NOT EXISTS idx_policy_links_target ON policy_links(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_timestamp ON policy_audit_log(timestamp);

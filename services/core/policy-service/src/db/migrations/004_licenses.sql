CREATE TABLE IF NOT EXISTS license_catalog (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  vendor VARCHAR(255),
  category VARCHAR(100) DEFAULT 'Software',
  license_type VARCHAR(50) DEFAULT 'per_user',
  total_seats INTEGER DEFAULT 0,
  used_seats INTEGER DEFAULT 0,
  cost_per_seat DECIMAL(10,2),
  currency VARCHAR(10) DEFAULT 'CHF',
  renewal_date DATE,
  auto_approve BOOLEAN DEFAULT false,
  description TEXT,
  icon_url TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS license_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id UUID REFERENCES license_catalog(id) ON DELETE CASCADE,
  assignee_type VARCHAR(50) NOT NULL,
  assignee_id VARCHAR(255) NOT NULL,
  assignee_name VARCHAR(255),
  assigned_at TIMESTAMPTZ DEFAULT NOW(),
  assigned_by VARCHAR(255),
  expires_at TIMESTAMPTZ,
  UNIQUE(license_id, assignee_type, assignee_id)
);

CREATE TABLE IF NOT EXISTS license_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id UUID REFERENCES license_catalog(id) ON DELETE CASCADE,
  license_name VARCHAR(255),
  requester_id VARCHAR(255) NOT NULL,
  requester_name VARCHAR(255),
  assignee_type VARCHAR(50) DEFAULT 'user',
  assignee_id VARCHAR(255),
  assignee_name VARCHAR(255),
  justification TEXT,
  status VARCHAR(50) DEFAULT 'pending',
  requested_at TIMESTAMPTZ DEFAULT NOW(),
  decided_at TIMESTAMPTZ,
  decided_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_license_requests_status ON license_requests(status);
CREATE INDEX IF NOT EXISTS idx_license_assignments_license ON license_assignments(license_id);

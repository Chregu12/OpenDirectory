CREATE TABLE IF NOT EXISTS pim_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  target_group_id VARCHAR(255) NOT NULL,
  target_group_name VARCHAR(255),
  max_duration_hours INTEGER DEFAULT 8,
  requires_approval BOOLEAN DEFAULT true,
  approver_group_id VARCHAR(255),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pim_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id VARCHAR(255) NOT NULL,
  user_name VARCHAR(255),
  user_email VARCHAR(255),
  role_id UUID REFERENCES pim_roles(id) ON DELETE CASCADE,
  role_name VARCHAR(255),
  justification TEXT,
  requested_duration_hours INTEGER DEFAULT 4,
  status VARCHAR(50) DEFAULT 'pending',
  requested_at TIMESTAMPTZ DEFAULT NOW(),
  decided_at TIMESTAMPTZ,
  decided_by VARCHAR(255),
  activated_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_pim_requests_status ON pim_requests(status);
CREATE INDEX IF NOT EXISTS idx_pim_requests_user ON pim_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_pim_requests_expires ON pim_requests(expires_at) WHERE status = 'active';

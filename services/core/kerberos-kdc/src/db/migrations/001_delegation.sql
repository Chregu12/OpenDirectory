-- Delegation configuration for constrained and unconstrained delegation
CREATE TABLE IF NOT EXISTS delegation_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service_principal VARCHAR(255) NOT NULL,
  delegation_type VARCHAR(50) NOT NULL, -- 'constrained' | 'rbcd' | 'unconstrained'
  allowed_targets JSONB DEFAULT '[]'::jsonb,
  protocol VARCHAR(50) DEFAULT 'kerberos-only',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(service_principal, delegation_type)
);

-- Resource-Based Constrained Delegation: target resource controls who can delegate to it
CREATE TABLE IF NOT EXISTS rbcd_config (
  resource_principal VARCHAR(255) PRIMARY KEY,
  allowed_delegators JSONB DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log for delegation attempts
CREATE TABLE IF NOT EXISTS delegation_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_time TIMESTAMPTZ DEFAULT NOW(),
  service_principal VARCHAR(255),
  target_spn VARCHAR(255),
  user_principal VARCHAR(255),
  delegation_type VARCHAR(50),
  allowed BOOLEAN,
  reason TEXT
);

-- Indexes for efficient audit queries
CREATE INDEX IF NOT EXISTS idx_delegation_audit_time ON delegation_audit(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_service ON delegation_audit(service_principal);

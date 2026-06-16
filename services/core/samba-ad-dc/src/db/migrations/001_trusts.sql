CREATE TABLE IF NOT EXISTS domain_trusts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trusted_domain VARCHAR(255) NOT NULL UNIQUE,
  trust_type VARCHAR(50) NOT NULL,
  trust_direction VARCHAR(50) NOT NULL,
  transitivity VARCHAR(50) DEFAULT 'non-transitive',
  trust_attributes JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_verified TIMESTAMPTZ,
  last_verification_status BOOLEAN,
  verification_errors JSONB DEFAULT '[]'::jsonb
);

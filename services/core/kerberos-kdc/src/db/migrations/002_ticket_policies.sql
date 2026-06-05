-- Ticket policies: realm-wide default (principal = 'REALM_DEFAULT') or per-principal overrides
CREATE TABLE IF NOT EXISTS ticket_policies (
  principal VARCHAR(255) PRIMARY KEY, -- 'REALM_DEFAULT' for realm-wide default
  max_ticket_life INTEGER DEFAULT 36000,   -- 10 hours in seconds
  max_renew_life INTEGER DEFAULT 604800,   -- 7 days in seconds
  forwardable BOOLEAN DEFAULT true,
  proxiable BOOLEAN DEFAULT false,
  renewable BOOLEAN DEFAULT true,
  no_address BOOLEAN DEFAULT true,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed realm default if not present
INSERT INTO ticket_policies (principal, max_ticket_life, max_renew_life, forwardable, proxiable, renewable, no_address)
VALUES ('REALM_DEFAULT', 36000, 604800, true, false, true, true)
ON CONFLICT (principal) DO NOTHING;

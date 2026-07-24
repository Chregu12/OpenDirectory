-- Service accounts (see src/routes/serviceAccounts.js).
--
-- Previously this route group was in-memory only (a plain Map) — a service
-- restart lost every service account except the hardcoded 'sa-ci-runner'
-- seed. This table gives it real persistence, following the same DB-first /
-- in-memory-fallback pattern already used by PIM (004_pim.sql) and OUs
-- (003_groups_ous.sql).
--
-- Deliberately NOT stored here: the signed JWT itself. Service-account
-- tokens are always re-derived from (id, name, scopes) + JWT_SECRET at
-- read/rotation time — storing a live bearer credential in the database
-- would be an unnecessary secret-at-rest exposure, and it isn't needed: the
-- token is fully reconstructible from the row plus the service's own
-- signing key.
CREATE TABLE IF NOT EXISTS service_accounts (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  scopes JSONB DEFAULT '[]'::jsonb,
  created_by VARCHAR(255),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  rotated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_service_accounts_name ON service_accounts(name);

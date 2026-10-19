-- identity-service core schema: users, groups, group_members, ous.
--
-- identity-service is the platform's identity store (users/groups/OUs
-- reachable via the API-gateway's /api/users, /api/groups, /api/ous
-- proxies — see api-gateway/src/index.js). This is a separate database
-- ("identity", per docker-compose.yml's DATABASE_URL) from
-- authentication-service's own "auth" database, which happens to also
-- define a `groups` table (migrations/003_groups_ous.sql there) but only
-- for OIDC token group-claims — it exposes no /api/groups CRUD routes, so
-- there is no route or data overlap with the tables below.
--
-- ids are generated application-side (crypto.randomUUID()) rather than via
-- a column DEFAULT, matching the pre-existing in-memory behavior this
-- migration replaces (the id is already known before the INSERT runs, so
-- it can be echoed back in the response without a second round-trip).

-- No UNIQUE constraint on username/name: the pre-existing in-memory
-- implementation never validated uniqueness (only presence), and this
-- migration is persistence-only — it must not introduce a new 500/failure
-- mode (duplicate-key violation) that the golden-master behavior never had.

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  display_name VARCHAR(255),
  department VARCHAR(255),
  title VARCHAR(255),
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS groups (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  -- No FK to users(id): the pre-existing in-memory implementation accepted
  -- any userId in POST /api/groups/:id/members without validating it
  -- referenced a real user, and this migration preserves that behavior
  -- rather than silently turning it into a 500.
  user_id VARCHAR(255) NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members(group_id);

CREATE TABLE IF NOT EXISTS ous (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  parent_id UUID REFERENCES ous(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ous_parent_id ON ous(parent_id);

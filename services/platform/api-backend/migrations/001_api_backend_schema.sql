-- api-backend persistence: users, devices, enrollment_tokens, setup_config.
--
-- api-backend has historically kept these four stores purely in-memory
-- (userStore array, deviceStore object, enrollmentTokens object,
-- setupConfig variable) even though docker-compose already wires it with a
-- DATABASE_URL (postgres://.../api). This migration adds the tables that
-- back them, following the identity-service migration pattern
-- (services/core/identity-service/migrations/001_identity_schema.sql):
-- ids are generated application-side (matching the pre-existing in-memory
-- id formats — 'admin', 'user_<timestamp>', 'DEV-XXXXXXXX', the raw
-- enrollment token hex string) rather than via a DEFAULT, and no new
-- UNIQUE/NOT NULL constraints are added beyond what the in-memory
-- implementation already enforced at the application layer, so this stays
-- persistence-only and does not introduce a new failure mode (e.g. a
-- duplicate-key 500) that the golden-master behavior never had.

-- users: mirrors the userStore array shape exactly (see server.js
-- validateUserBody / the POST /api/users handler). No UNIQUE constraint on
-- username: the app already checks for an existing username and returns a
-- 409 before inserting, and the pre-existing in-memory store never enforced
-- uniqueness at a "storage" layer either.
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  name VARCHAR(128),
  email VARCHAR(254),
  role VARCHAR(128),
  active BOOLEAN NOT NULL DEFAULT true,
  groups TEXT[] NOT NULL DEFAULT '{}',
  password_hash TEXT NOT NULL,
  last_login TIMESTAMPTZ,
  created TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- devices: the in-memory deviceStore holds heterogeneous, ad hoc-mutated
-- objects (enroll sets id/name/platform/os/osVersion/status/enrolledAt/
-- lastSeen; refresh adds lastSeen/status/installedAppsCount; apps
-- install/uninstall push/filter an installedApps array — all via direct
-- property mutation, not a fixed set of columns). Modeling every field as
-- its own column would risk silently dropping or reshaping fields the
-- golden-master tests never exercise. A JSONB blob for everything but the
-- id keeps the persisted shape byte-for-byte identical to what server.js
-- already reads/writes in memory.
CREATE TABLE IF NOT EXISTS devices (
  id VARCHAR(64) PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- enrollment_tokens: token is the natural key (it's already a random
-- 32-byte hex string — see POST /api/devices/enroll/token).
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token VARCHAR(64) PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT false,
  created_by VARCHAR(64)
);

-- setup_config: a single-row singleton (the in-memory version is a lone
-- `let setupConfig = null` variable, not a collection).
CREATE TABLE IF NOT EXISTS setup_config (
  id SMALLINT PRIMARY KEY DEFAULT 1,
  data JSONB NOT NULL,
  CONSTRAINT setup_config_singleton CHECK (id = 1)
);

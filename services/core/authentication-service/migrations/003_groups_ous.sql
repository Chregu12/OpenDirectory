CREATE TABLE IF NOT EXISTS groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT,
  lldap_id INTEGER,
  ou_id UUID,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
  user_id VARCHAR(255) NOT NULL,
  added_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (group_id, user_id)
);

-- NOTE: this table is no longer used by any route in this service.
-- src/routes/directory.js used to serve GET/POST/PUT/DELETE /api/ous
-- against it, but that duplicated identity-service's own (separately
-- persisted) OU store, so /api/ous was consolidated onto identity-service
-- (see the NOTE in src/routes/directory.js for the full rationale). The
-- CREATE TABLE is left in place rather than dropped: migrations here have
-- no up/down tracking (src/db.js just re-runs every .sql file on every
-- boot — see runMigrations()), so removing it wouldn't affect any
-- already-provisioned database anyway, and dropping a table that some
-- environment might still have data in is exactly the kind of hard-to-undo
-- change this consolidation pass was told to avoid. Safe to drop via a
-- proper follow-up migration once confirmed empty everywhere.
CREATE TABLE IF NOT EXISTS organizational_units (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  parent_id UUID REFERENCES organizational_units(id),
  path TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

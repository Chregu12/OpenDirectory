-- Domain configuration (see src/routes/directory.js).
--
-- Previously stored only in a process-global (global.__od_domain_config) —
-- a service restart silently reverted the configured domain/issuer back to
-- unset. This is a singleton table (id is pinned to 1 via the CHECK
-- constraint) so a write is a plain upsert; global.__od_domain_config is
-- kept as the in-memory mirror/fallback used whenever the DB is
-- unavailable, consistent with the PIM/OU DB-first pattern.
CREATE TABLE IF NOT EXISTS domain_config (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  domain VARCHAR(255) NOT NULL,
  issuer VARCHAR(255),
  configured_at TIMESTAMPTZ DEFAULT NOW()
);

-- monitoring-service alert persistence.
--
-- Backs src/database/alertStore.js, which previously held alerts purely
-- in-memory (a Map) despite src/config/index.js already defining a
-- `database` config block for exactly this purpose. See
-- src/db/client.js for the connection/migration-runner wiring.
--
-- Numbered 001 (this migrations/ directory previously started at 002 —
-- see 002_dead_letter_log.sql — because no prior migration had ever
-- actually been added; that migration itself is currently unwired dead
-- code within this service, see the persistence audit notes).
--
-- id is generated application-side (AlertStore.create: `alert-<ts>-<seq>`
-- or a caller-supplied id), matching the pre-existing in-memory Map's key.
-- created_at/updated_at/acknowledged_at/resolved_at are stored as
-- DOUBLE PRECISION (not BIGINT): the in-memory implementation stores them
-- as JS `Date.now()` numbers, and node-postgres returns BIGINT/int8
-- columns as strings (to avoid silent precision loss on the wider type),
-- which would change the field's type on every DB-backed read. Millisecond
-- epoch timestamps fit safely in a float64 well beyond any realistic
-- retention horizon, so DOUBLE PRECISION preserves the original `number`
-- type through node-postgres's default type parsing.
CREATE TABLE IF NOT EXISTS alerts (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  service             TEXT NOT NULL,
  severity            TEXT NOT NULL,
  status              TEXT NOT NULL,
  message             TEXT,
  metric              TEXT,
  threshold           DOUBLE PRECISION,
  current_value       DOUBLE PRECISION,
  labels              JSONB NOT NULL DEFAULT '{}',
  notifications_sent  JSONB NOT NULL DEFAULT '[]',
  created_at          DOUBLE PRECISION NOT NULL,
  updated_at          DOUBLE PRECISION NOT NULL,
  acknowledged_at     DOUBLE PRECISION,
  acknowledged_by     TEXT,
  resolved_at         DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_service ON alerts(service);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);

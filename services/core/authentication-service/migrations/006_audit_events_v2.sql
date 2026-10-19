-- Extend audit_events with columns expected by the updated AuditService.
-- The original table (001_audit_log.sql) used actor/target/message/severity;
-- the new service writes user_id, username, and user_agent instead.
-- ADD COLUMN IF NOT EXISTS is idempotent so this migration is safe to re-run.

ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS user_id    VARCHAR(128),
  ADD COLUMN IF NOT EXISTS username   VARCHAR(256),
  ADD COLUMN IF NOT EXISTS user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC);

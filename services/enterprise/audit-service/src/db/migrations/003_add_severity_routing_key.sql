-- Migration 003: Add severity and routing_key columns to audit_events
-- These columns enable efficient filtering of high-severity events and
-- traceability back to the originating event bus routing key.

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS severity VARCHAR(20) DEFAULT 'info';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS routing_key VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity);
CREATE INDEX IF NOT EXISTS idx_audit_routing_key ON audit_events(routing_key);

-- Migration 006: Directory Audit Trail
-- Comprehensive audit log for all directory object changes and auth events.

CREATE TABLE IF NOT EXISTS directory_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_time TIMESTAMPTZ DEFAULT NOW(),
  actor_id VARCHAR(255),
  actor_dn VARCHAR(500),
  target_dn VARCHAR(500),
  target_type VARCHAR(50), -- 'user', 'group', 'computer', 'ou', 'gpo', 'domain'
  operation VARCHAR(50) NOT NULL,
  attributes_changed JSONB,
  ip_address INET,
  request_id VARCHAR(255),
  success BOOLEAN DEFAULT true,
  failure_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_event_time ON directory_audit_log(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON directory_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON directory_audit_log(target_dn);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON directory_audit_log(operation);

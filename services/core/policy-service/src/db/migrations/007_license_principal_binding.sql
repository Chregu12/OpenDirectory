ALTER TABLE license_requests ADD COLUMN IF NOT EXISTS identity_bound BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE license_requests ADD COLUMN IF NOT EXISTS requester_issuer TEXT;
ALTER TABLE license_requests ADD COLUMN IF NOT EXISTS requester_subject VARCHAR(255);
ALTER TABLE license_audit_events ADD COLUMN IF NOT EXISTS actor_issuer TEXT;
ALTER TABLE license_audit_events ADD COLUMN IF NOT EXISTS actor_subject VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_license_request_canonical_owner ON license_requests(requester_id) WHERE identity_bound;

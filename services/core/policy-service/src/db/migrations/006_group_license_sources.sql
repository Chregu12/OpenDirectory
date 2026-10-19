CREATE TABLE IF NOT EXISTS license_group_rules (
  license_id UUID NOT NULL REFERENCES license_catalog(id) ON DELETE CASCADE,
  group_id VARCHAR(255) NOT NULL,
  group_name VARCHAR(255),
  enabled BOOLEAN NOT NULL DEFAULT true,
  expires_at TIMESTAMPTZ,
  source_revision BIGINT,
  source_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  desired_users INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  last_synced_at TIMESTAMPTZ,
  configured_by VARCHAR(255) NOT NULL,
  PRIMARY KEY(license_id, group_id)
);
CREATE TABLE IF NOT EXISTS license_assignment_sources (
  license_id UUID NOT NULL REFERENCES license_catalog(id) ON DELETE CASCADE,
  user_id VARCHAR(255) NOT NULL,
  source_type TEXT NOT NULL CHECK(source_type IN ('direct','group')),
  source_id VARCHAR(255) NOT NULL,
  assigned_by VARCHAR(255) NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY(license_id, user_id, source_type, source_id)
);
CREATE INDEX IF NOT EXISTS idx_license_source_user ON license_assignment_sources(user_id, license_id);
CREATE INDEX IF NOT EXISTS idx_license_source_group ON license_assignment_sources(license_id, source_id) WHERE source_type='group';
CREATE TABLE IF NOT EXISTS license_schema_versions(version INTEGER PRIMARY KEY);

DO $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=6) THEN
    CREATE TEMP TABLE license_legacy_users ON COMMIT DROP AS
      SELECT MIN(id::text)::uuid AS id,license_id,
        CASE WHEN assignee_id ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' THEN lower(assignee_id) ELSE assignee_id END AS user_id,
        MAX(assignee_name) AS assignee_name,MIN(assigned_at) AS assigned_at,MIN(COALESCE(assigned_by,'migration')) AS assigned_by,
        CASE WHEN BOOL_OR(expires_at IS NULL) THEN NULL ELSE MAX(expires_at) END AS expires_at
      FROM license_assignments WHERE assignee_type='user' GROUP BY license_id,user_id;
    INSERT INTO license_audit_events(license_id,action,actor,details)
      SELECT license_id,'legacy-user-normalized','migration',jsonb_build_object('userId',lower(assignee_id),'assignmentIds',jsonb_agg(id))
      FROM license_assignments WHERE assignee_type='user' AND assignee_id ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
      GROUP BY license_id,lower(assignee_id) HAVING COUNT(*)>1 OR BOOL_OR(assignee_id<>lower(assignee_id));
    DELETE FROM license_assignments WHERE assignee_type='user';
    INSERT INTO license_assignments(id,license_id,assignee_type,assignee_id,assignee_name,assigned_at,assigned_by,expires_at)
      SELECT id,license_id,'user',user_id,assignee_name,assigned_at,assigned_by,expires_at FROM license_legacy_users;
    INSERT INTO license_assignment_sources(license_id,user_id,source_type,source_id,assigned_by,expires_at)
      SELECT license_id,assignee_id,'direct','direct',COALESCE(assigned_by,'migration'),expires_at FROM license_assignments WHERE assignee_type='user';
    INSERT INTO license_group_rules(license_id,group_id,group_name,expires_at,configured_by)
      SELECT license_id,CASE WHEN assignee_id ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' THEN lower(assignee_id) ELSE assignee_id END AS group_id,
        MAX(assignee_name),CASE WHEN BOOL_OR(expires_at IS NULL) THEN NULL ELSE MAX(expires_at) END,MIN(COALESCE(assigned_by,'migration'))
      FROM license_assignments WHERE assignee_type='group' GROUP BY license_id,group_id;
    INSERT INTO license_audit_events(license_id,action,actor,details)
      SELECT license_id,'legacy-group-pending','migration',to_jsonb(license_assignments) FROM license_assignments WHERE assignee_type='group';
    DELETE FROM license_assignments WHERE assignee_type='group';
    UPDATE license_requests SET assignee_id=lower(assignee_id) WHERE assignee_type IN ('user','group') AND assignee_id ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$';
    INSERT INTO license_schema_versions(version) VALUES(6);
  END IF;
END;
$$;

ALTER TABLE license_requests ADD COLUMN IF NOT EXISTS allocation_status TEXT;

CREATE OR REPLACE FUNCTION license_assignment_capacity() RETURNS trigger AS $$
DECLARE maximum INTEGER;
DECLARE active_count INTEGER;
BEGIN
  IF NEW.assignee_type='group' THEN
    RAISE EXCEPTION 'Group licenses require per-user sources' USING ERRCODE='23514';
  END IF;
  SELECT total_seats INTO maximum FROM license_catalog WHERE id=NEW.license_id FOR UPDATE;
  IF NEW.expires_at IS NULL OR NEW.expires_at>clock_timestamp() THEN
    SELECT COUNT(*) INTO active_count FROM license_assignments WHERE license_id=NEW.license_id AND id<>NEW.id
      AND (expires_at IS NULL OR expires_at>clock_timestamp());
    IF maximum>0 AND active_count>=maximum THEN RAISE EXCEPTION 'No seats available' USING ERRCODE='23514'; END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_assignment_capacity_guard ON license_assignments;
CREATE TRIGGER license_assignment_capacity_guard BEFORE INSERT OR UPDATE OF expires_at ON license_assignments
  FOR EACH ROW EXECUTE FUNCTION license_assignment_capacity();

CREATE OR REPLACE FUNCTION license_assignment_no_update() RETURNS trigger AS $$
DECLARE expected_expiry TIMESTAMPTZ;
DECLARE source_count INTEGER;
BEGIN
  SELECT COUNT(*),CASE WHEN BOOL_OR(expires_at IS NULL) THEN NULL ELSE MAX(expires_at) END INTO source_count,expected_expiry
    FROM license_assignment_sources WHERE license_id=NEW.license_id AND user_id=NEW.assignee_id
    AND (expires_at IS NULL OR expires_at>clock_timestamp());
  IF NEW.assignee_type='user' AND source_count>0 AND (to_jsonb(NEW)-'expires_at')=(to_jsonb(OLD)-'expires_at')
    AND NEW.expires_at IS NOT DISTINCT FROM expected_expiry THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'Only source-derived expiry updates are permitted' USING ERRCODE='42501';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_assignment_counter_update ON license_assignments;
CREATE TRIGGER license_assignment_counter_update AFTER UPDATE OF expires_at ON license_assignments
  FOR EACH ROW EXECUTE FUNCTION license_assignment_counter();

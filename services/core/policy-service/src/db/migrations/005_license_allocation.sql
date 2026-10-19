CREATE TABLE IF NOT EXISTS license_subjects (
  user_id VARCHAR(255) PRIMARY KEY,
  disabled BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS license_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id UUID,
  action VARCHAR(64) NOT NULL,
  actor VARCHAR(255) NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_license_audit_pool ON license_audit_events(license_id, created_at);
CREATE INDEX IF NOT EXISTS idx_license_assignment_user ON license_assignments(assignee_type, assignee_id);
CREATE INDEX IF NOT EXISTS idx_license_assignment_expiry ON license_assignments(expires_at) WHERE expires_at IS NOT NULL;

CREATE OR REPLACE FUNCTION license_validate_capacity() RETURNS trigger AS $$
DECLARE active_count INTEGER;
BEGIN
  IF NEW.total_seats IS NULL OR NEW.total_seats < 0 THEN
    RAISE EXCEPTION 'total_seats must be a nonnegative integer' USING ERRCODE = '23514';
  END IF;
  SELECT COUNT(*) INTO active_count FROM license_assignments
    WHERE license_id = NEW.id AND (expires_at IS NULL OR expires_at > clock_timestamp());
  IF NEW.total_seats > 0 AND active_count > NEW.total_seats THEN
    RAISE EXCEPTION 'Capacity cannot be reduced below active assignments' USING ERRCODE = '23514';
  END IF;
  NEW.used_seats := active_count;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS license_capacity_guard ON license_catalog;
CREATE TRIGGER license_capacity_guard BEFORE INSERT OR UPDATE ON license_catalog
  FOR EACH ROW EXECUTE FUNCTION license_validate_capacity();

CREATE OR REPLACE FUNCTION license_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'License audit events are append-only' USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS license_audit_immutable ON license_audit_events;
CREATE TRIGGER license_audit_immutable BEFORE UPDATE OR DELETE ON license_audit_events
  FOR EACH ROW EXECUTE FUNCTION license_audit_append_only();

UPDATE license_catalog SET used_seats = used_seats;

CREATE OR REPLACE FUNCTION license_assignment_capacity() RETURNS trigger AS $$
DECLARE maximum INTEGER;
DECLARE active_count INTEGER;
BEGIN
  SELECT total_seats INTO maximum FROM license_catalog WHERE id = NEW.license_id FOR UPDATE;
  IF NEW.expires_at IS NULL OR NEW.expires_at > clock_timestamp() THEN
    SELECT COUNT(*) INTO active_count FROM license_assignments
      WHERE license_id = NEW.license_id AND (expires_at IS NULL OR expires_at > clock_timestamp());
    IF maximum > 0 AND active_count >= maximum THEN
      RAISE EXCEPTION 'No seats available for this license' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS license_assignment_capacity_guard ON license_assignments;
CREATE TRIGGER license_assignment_capacity_guard BEFORE INSERT ON license_assignments
  FOR EACH ROW EXECUTE FUNCTION license_assignment_capacity();

CREATE OR REPLACE FUNCTION license_assignment_counter() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE license_catalog SET updated_at = clock_timestamp() WHERE id = OLD.license_id;
    RETURN OLD;
  END IF;
  UPDATE license_catalog SET updated_at = clock_timestamp() WHERE id = NEW.license_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS license_assignment_counter_sync ON license_assignments;
CREATE TRIGGER license_assignment_counter_sync AFTER INSERT OR DELETE ON license_assignments
  FOR EACH ROW EXECUTE FUNCTION license_assignment_counter();

CREATE OR REPLACE FUNCTION license_assignment_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Revoke and reassign instead of modifying an allocation' USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS license_assignment_immutable ON license_assignments;
CREATE TRIGGER license_assignment_immutable BEFORE UPDATE ON license_assignments
  FOR EACH ROW EXECUTE FUNCTION license_assignment_no_update();

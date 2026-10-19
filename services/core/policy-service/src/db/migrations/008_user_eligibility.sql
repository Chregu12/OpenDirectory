ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_revision BIGINT;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_enabled BOOLEAN;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_deleted BOOLEAN;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_checked_at TIMESTAMPTZ;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_attempted_at TIMESTAMPTZ;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS directory_error TEXT;

CREATE OR REPLACE FUNCTION license_subject_directory_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'License subject identifiers cannot be changed' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.directory_revision IS NOT NULL THEN
    IF NEW.directory_revision IS NULL OR NEW.directory_revision < OLD.directory_revision THEN
      RAISE EXCEPTION 'Directory revision cannot regress' USING ERRCODE = '23514';
    END IF;
    IF NEW.directory_revision = OLD.directory_revision AND (NEW.directory_enabled IS DISTINCT FROM OLD.directory_enabled OR NEW.directory_deleted IS DISTINCT FROM OLD.directory_deleted) THEN
      RAISE EXCEPTION 'Directory revision content cannot change' USING ERRCODE = '23514';
    END IF;
    IF OLD.directory_deleted AND NOT NEW.directory_deleted THEN
      RAISE EXCEPTION 'A deleted identity cannot be reactivated' USING ERRCODE = '23514';
    END IF;
  END IF;
  IF NEW.directory_revision IS NOT NULL AND (NEW.directory_revision <= 0 OR NEW.directory_enabled IS NULL OR NEW.directory_deleted IS NULL OR (NEW.directory_deleted AND NEW.directory_enabled)) THEN
    RAISE EXCEPTION 'Invalid directory eligibility state' USING ERRCODE = '23514';
  END IF;
  IF NEW.directory_revision IS NULL AND (NEW.directory_enabled IS NOT NULL OR NEW.directory_deleted IS NOT NULL) THEN
    RAISE EXCEPTION 'Directory eligibility requires a version' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_subject_directory_guard ON license_subjects;
CREATE TRIGGER license_subject_directory_guard BEFORE INSERT OR UPDATE ON license_subjects FOR EACH ROW EXECUTE FUNCTION license_subject_directory_guard();

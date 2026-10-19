CREATE SEQUENCE IF NOT EXISTS identity_user_record_revision_seq;
ALTER TABLE users ADD COLUMN IF NOT EXISTS record_revision BIGINT NOT NULL DEFAULT nextval('identity_user_record_revision_seq');
CREATE INDEX IF NOT EXISTS identity_users_page_idx ON users(created_at,id);
CREATE TABLE IF NOT EXISTS identity_user_record_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS identity_user_record_audit_user ON identity_user_record_audit(user_id,revision);

CREATE OR REPLACE FUNCTION identity_user_record_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.record_revision := nextval('identity_user_record_revision_seq');
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_user_record_version ON users;
CREATE TRIGGER identity_user_record_version BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION identity_user_record_version();

CREATE OR REPLACE FUNCTION identity_user_record_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE snapshot JSONB;
DECLARE previous JSONB;
DECLARE identifier UUID;
DECLARE version BIGINT;
BEGIN
  IF TG_OP='DELETE' THEN
    identifier := OLD.id;
    version := nextval('identity_user_record_revision_seq');
  ELSE
    identifier := NEW.id;
    version := NEW.record_revision;
    snapshot := jsonb_build_object('username',NEW.username,'email',NEW.email,'displayName',NEW.display_name,'department',NEW.department,'title',NEW.title,'enabled',NEW.enabled);
  END IF;
  IF TG_OP<>'INSERT' THEN
    previous := jsonb_build_object('username',OLD.username,'email',OLD.email,'displayName',OLD.display_name,'department',OLD.department,'title',OLD.title,'enabled',OLD.enabled);
  END IF;
  INSERT INTO identity_user_record_audit(user_id,revision,action,actor,details)
    VALUES(identifier,version,lower(TG_OP),COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),
      jsonb_build_object('before',previous,'after',snapshot));
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_user_record_changed ON users;
CREATE TRIGGER identity_user_record_changed AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_user_record_changed();
DROP TRIGGER IF EXISTS identity_user_record_audit_guard ON identity_user_record_audit;
CREATE TRIGGER identity_user_record_audit_guard BEFORE UPDATE OR DELETE ON identity_user_record_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

CREATE SEQUENCE IF NOT EXISTS identity_authorization_revision_seq;
ALTER TABLE users ADD COLUMN IF NOT EXISTS authorization_revision BIGINT NOT NULL DEFAULT nextval('identity_authorization_revision_seq');
ALTER TABLE identity_subject_links ADD COLUMN IF NOT EXISTS authorization_revision BIGINT NOT NULL DEFAULT nextval('identity_authorization_revision_seq');

CREATE TABLE IF NOT EXISTS identity_authorization_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS identity_authorization_audit_user ON identity_authorization_audit(user_id,revision);

CREATE OR REPLACE FUNCTION identity_authorization_user_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    NEW.authorization_revision := nextval('identity_authorization_revision_seq');
  ELSIF NEW.enabled IS DISTINCT FROM OLD.enabled OR NEW.authorization_revision IS DISTINCT FROM OLD.authorization_revision THEN
    NEW.authorization_revision := nextval('identity_authorization_revision_seq');
  ELSE
    NEW.authorization_revision := OLD.authorization_revision;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_authorization_user_guard ON users;
CREATE TRIGGER identity_authorization_user_guard BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION identity_authorization_user_guard();

CREATE OR REPLACE FUNCTION identity_authorization_user_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE reason TEXT;
DECLARE identifier UUID;
DECLARE version BIGINT;
BEGIN
  IF TG_OP='UPDATE' AND NEW.authorization_revision IS NOT DISTINCT FROM OLD.authorization_revision THEN RETURN NULL; END IF;
  IF TG_OP='DELETE' THEN
    identifier := OLD.id;
    version := nextval('identity_authorization_revision_seq');
    reason := 'deleted';
  ELSE
    identifier := NEW.id;
    version := NEW.authorization_revision;
    reason := CASE WHEN TG_OP='INSERT' THEN 'created'
      WHEN NEW.enabled IS DISTINCT FROM OLD.enabled THEN 'enabled_changed' ELSE 'security_reset' END;
  END IF;
  INSERT INTO identity_authorization_audit(user_id,revision,actor,reason,details)
    VALUES(identifier,version,COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),reason,
      jsonb_build_object('enabled',CASE WHEN TG_OP='DELETE' THEN false ELSE NEW.enabled END));
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_authorization_user_record ON users;
CREATE TRIGGER identity_authorization_user_record AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_authorization_user_record();

CREATE OR REPLACE FUNCTION identity_authorization_link_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.authorization_revision := nextval('identity_authorization_revision_seq');
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_authorization_link_guard ON identity_subject_links;
CREATE TRIGGER identity_authorization_link_guard BEFORE INSERT ON identity_subject_links FOR EACH ROW EXECUTE FUNCTION identity_authorization_link_guard();

DROP TRIGGER IF EXISTS identity_authorization_audit_guard ON identity_authorization_audit;
CREATE TRIGGER identity_authorization_audit_guard BEFORE UPDATE OR DELETE ON identity_authorization_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

CREATE SEQUENCE IF NOT EXISTS identity_user_revision_seq;
ALTER TABLE users ADD COLUMN IF NOT EXISTS eligibility_revision BIGINT NOT NULL DEFAULT nextval('identity_user_revision_seq');
CREATE TABLE IF NOT EXISTS identity_deleted_users (
  user_id UUID PRIMARY KEY,
  revision BIGINT NOT NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identity_user_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identity_user_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_identity_user_outbox_pending ON identity_user_outbox(created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_user_audit_revision ON identity_user_audit(user_id, revision);

CREATE OR REPLACE FUNCTION identity_user_eligibility_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM identity_deleted_users WHERE user_id=NEW.id) THEN
      RAISE EXCEPTION 'A deleted identity user identifier cannot be reused' USING ERRCODE = '23514';
    END IF;
    NEW.eligibility_revision := nextval('identity_user_revision_seq');
  ELSE
    IF NEW.id IS DISTINCT FROM OLD.id THEN
      RAISE EXCEPTION 'Identity user identifiers cannot be changed' USING ERRCODE = '42501';
    END IF;
    NEW.eligibility_revision := CASE WHEN NEW.enabled IS DISTINCT FROM OLD.enabled THEN nextval('identity_user_revision_seq') ELSE OLD.eligibility_revision END;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_user_eligibility_guard ON users;
CREATE TRIGGER identity_user_eligibility_guard BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION identity_user_eligibility_guard();

CREATE OR REPLACE FUNCTION identity_user_eligibility_record() RETURNS trigger AS $$
DECLARE identifier UUID;
DECLARE version BIGINT;
DECLARE deleted BOOLEAN := TG_OP = 'DELETE';
DECLARE event_payload JSONB;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.enabled IS NOT DISTINCT FROM OLD.enabled THEN RETURN NULL; END IF;
  IF deleted THEN
    identifier := OLD.id;
    version := nextval('identity_user_revision_seq');
    INSERT INTO identity_deleted_users(user_id,revision) VALUES(identifier,version);
  ELSE
    identifier := NEW.id;
    version := NEW.eligibility_revision;
  END IF;
  event_payload := jsonb_build_object('userId',identifier,'revision',version::text,'deleted',deleted,'enabled',CASE WHEN deleted THEN false ELSE NEW.enabled END);
  INSERT INTO identity_user_audit(user_id,revision,actor,details)
    VALUES(identifier,version,COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),event_payload);
  INSERT INTO identity_user_outbox(user_id,revision,event_type,payload) VALUES(identifier,version,'identity.user.eligibility.changed',event_payload);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_user_eligibility_record ON users;
CREATE TRIGGER identity_user_eligibility_record AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_user_eligibility_record();

CREATE OR REPLACE FUNCTION identity_user_evidence_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'User eligibility evidence is append-only' USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_user_audit_guard ON identity_user_audit;
CREATE TRIGGER identity_user_audit_guard BEFORE UPDATE OR DELETE ON identity_user_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();
DROP TRIGGER IF EXISTS identity_deleted_user_guard ON identity_deleted_users;
CREATE TRIGGER identity_deleted_user_guard BEFORE UPDATE OR DELETE ON identity_deleted_users FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

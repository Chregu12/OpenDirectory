BEGIN;

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS secret_hash VARCHAR(64);
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

UPDATE oauth_clients SET secret_hash=encode(sha256(convert_to(secret,'UTF8')),'hex'),
  secret=NULL, token_endpoint_auth_method='client_secret_post' WHERE secret IS NOT NULL;
UPDATE oauth_clients SET token_endpoint_auth_method='none' WHERE secret_hash IS NULL AND token_endpoint_auth_method <> 'none';

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='oauth_clients'::regclass AND conname='oauth_client_authority_shape') THEN
    ALTER TABLE oauth_clients ADD CONSTRAINT oauth_client_authority_shape CHECK (
      secret IS NULL AND revision > 0 AND id ~ '^[A-Za-z0-9._~-]{1,255}$' AND token_endpoint_auth_method IS NOT NULL
      AND ((token_endpoint_auth_method='none' AND secret_hash IS NULL)
        OR (token_endpoint_auth_method='client_secret_post' AND secret_hash IS NOT NULL AND secret_hash ~ '^[a-f0-9]{64}$'))
      AND jsonb_typeof(redirect_uris)='array' AND jsonb_typeof(grants)='array' AND jsonb_typeof(scopes)='array'
      AND (deleted_at IS NULL OR NOT enabled));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS oauth_client_registry (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  initialized BOOLEAN NOT NULL
);
INSERT INTO oauth_client_registry(singleton,initialized) VALUES(TRUE,EXISTS(SELECT 1 FROM oauth_clients)) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS oauth_client_audit (
  id BIGSERIAL PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(id),
  revision BIGINT NOT NULL CHECK (revision > 0),
  action TEXT NOT NULL CHECK (action IN ('bootstrap','created','updated','rotated','deleted')),
  actor_issuer TEXT NOT NULL,
  actor_subject VARCHAR(255) NOT NULL,
  actor_user_id UUID,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user','bootstrap')),
  details JSONB NOT NULL CHECK (jsonb_typeof(details)='object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS oauth_client_audit_client ON oauth_client_audit(client_id,id);

CREATE OR REPLACE FUNCTION guard_oauth_client() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OAuth client evidence cannot be deleted'; END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
      OR NEW.token_endpoint_auth_method IS DISTINCT FROM OLD.token_endpoint_auth_method
      OR OLD.deleted_at IS NOT NULL OR NEW.revision IS DISTINCT FROM OLD.revision + 1
      OR NEW.secret IS NOT NULL THEN RAISE EXCEPTION 'Invalid OAuth client transition'; END IF;
    IF NEW.deleted_at IS NOT NULL AND NEW.enabled THEN RAISE EXCEPTION 'Deleted client cannot be enabled'; END IF;
    NEW.updated_at := clock_timestamp();
  ELSIF NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL THEN RAISE EXCEPTION 'Invalid initial OAuth client state';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS oauth_client_guard ON oauth_clients;
CREATE TRIGGER oauth_client_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION guard_oauth_client();

CREATE OR REPLACE FUNCTION guard_oauth_client_evidence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME='oauth_client_registry' AND TG_OP='UPDATE' AND NEW.singleton=OLD.singleton AND NOT OLD.initialized AND NEW.initialized THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'OAuth client evidence cannot be rewritten';
END $$;
DROP TRIGGER IF EXISTS oauth_client_registry_guard ON oauth_client_registry;
CREATE TRIGGER oauth_client_registry_guard BEFORE UPDATE OR DELETE ON oauth_client_registry FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();
DROP TRIGGER IF EXISTS oauth_client_audit_guard ON oauth_client_audit;
CREATE TRIGGER oauth_client_audit_guard BEFORE UPDATE OR DELETE ON oauth_client_audit FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();

COMMIT;

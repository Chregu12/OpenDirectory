BEGIN;
CREATE TABLE IF NOT EXISTS oauth_application_assignments (
  id UUID PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(id),
  target_type TEXT NOT NULL CHECK (target_type IN ('user','group')),
  target_id UUID NOT NULL,
  target_revision TEXT NOT NULL CHECK (target_revision ~ '^[1-9][0-9]{0,18}$' AND target_revision::numeric <= 9223372036854775807),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  duration_seconds INTEGER NOT NULL CHECK (duration_seconds BETWEEN 60 AND 2592000),
  created_actor JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CHECK (expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX IF NOT EXISTS oauth_application_assignments_target ON oauth_application_assignments(client_id,target_type,target_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS oauth_application_access_audit (
  id BIGSERIAL PRIMARY KEY,
  assignment_id UUID NOT NULL REFERENCES oauth_application_assignments(id),
  action TEXT NOT NULL CHECK (action IN ('granted','revoked','bootstrap')),
  actor JSONB NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS oauth_application_access_audit_assignment ON oauth_application_access_audit(assignment_id,id);

CREATE OR REPLACE FUNCTION guard_oauth_application_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor JSONB;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Application assignments are retained evidence'; END IF;
  actor := NULLIF(current_setting('opendirectory.actor',true),'')::jsonb;
  IF actor IS NULL OR jsonb_typeof(actor) <> 'object' OR NOT (actor ?& ARRAY['issuer','subject','userId','type'])
    OR actor->>'type' IS NULL OR actor->>'type' NOT IN ('user','bootstrap')
    OR COALESCE(length(actor->>'issuer'),0) NOT BETWEEN 1 AND 2048 OR COALESCE(length(actor->>'subject'),0) NOT BETWEEN 1 AND 255
    OR (actor->>'type'='user' AND (actor->>'userId' IS NULL OR actor->>'userId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'))
    OR (actor->>'type'='bootstrap' AND actor->'userId' IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'Verified application actor required'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.revoked_at IS NOT NULL OR (actor->>'type'='bootstrap' AND (NEW.target_type <> 'user' OR NEW.duration_seconds > 28800))
      OR (actor->>'type'='user' AND NEW.target_type='user' AND NEW.target_id::text=actor->>'userId') THEN RAISE EXCEPTION 'Invalid application grant'; END IF;
    NEW.created_at := clock_timestamp();
    NEW.expires_at := NEW.created_at + NEW.duration_seconds * interval '1 second';
    NEW.created_actor := actor;
  ELSE
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.client_id IS DISTINCT FROM OLD.client_id OR NEW.target_type IS DISTINCT FROM OLD.target_type
      OR NEW.target_id IS DISTINCT FROM OLD.target_id OR NEW.target_revision IS DISTINCT FROM OLD.target_revision
      OR NEW.reason IS DISTINCT FROM OLD.reason OR NEW.duration_seconds IS DISTINCT FROM OLD.duration_seconds OR NEW.created_actor IS DISTINCT FROM OLD.created_actor
      OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
      OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN RAISE EXCEPTION 'Only one-way application revocation is allowed'; END IF;
    IF actor->>'type'='user' AND NEW.target_type='user' AND NEW.target_id::text=actor->>'userId' THEN RAISE EXCEPTION 'Self administration denied'; END IF;
    NEW.revoked_at := clock_timestamp();
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS oauth_application_assignment_guard ON oauth_application_assignments;
CREATE TRIGGER oauth_application_assignment_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_application_assignments FOR EACH ROW EXECUTE FUNCTION guard_oauth_application_assignment();

CREATE OR REPLACE FUNCTION record_oauth_application_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor JSONB;
BEGIN
  actor := current_setting('opendirectory.actor',true)::jsonb;
  INSERT INTO oauth_application_access_audit(assignment_id,action,actor,details)
    VALUES(NEW.id,CASE WHEN TG_OP='UPDATE' THEN 'revoked' WHEN actor->>'type'='bootstrap' THEN 'bootstrap' ELSE 'granted' END,actor,
      jsonb_build_object('clientId',NEW.client_id,'targetType',NEW.target_type,'targetId',NEW.target_id,'targetRevision',NEW.target_revision,
        'reason',NEW.reason,'expiresAt',NEW.expires_at,'revokedAt',NEW.revoked_at));
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS oauth_application_assignment_record ON oauth_application_assignments;
CREATE TRIGGER oauth_application_assignment_record AFTER INSERT OR UPDATE ON oauth_application_assignments FOR EACH ROW EXECUTE FUNCTION record_oauth_application_assignment();
DROP TRIGGER IF EXISTS oauth_application_access_audit_guard ON oauth_application_access_audit;
CREATE TRIGGER oauth_application_access_audit_guard BEFORE UPDATE OR DELETE ON oauth_application_access_audit FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();
COMMIT;

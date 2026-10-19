ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS mfa_max_age_seconds INTEGER NOT NULL DEFAULT 3600;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='oauth_clients'::regclass AND conname='oauth_client_mfa_age') THEN
    ALTER TABLE oauth_clients ADD CONSTRAINT oauth_client_mfa_age CHECK (mfa_max_age_seconds BETWEEN 300 AND 86400);
  END IF;
END $$;
ALTER TABLE oauth_client_audit DROP CONSTRAINT IF EXISTS oauth_client_audit_action_check;
ALTER TABLE oauth_client_audit ADD CONSTRAINT oauth_client_audit_action_check
  CHECK (action IN ('bootstrap','created','updated','rotated','deleted','authentication_changed'));

CREATE TABLE IF NOT EXISTS oauth_mfa_enrollments (
  id UUID PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  factor_revision BIGINT NOT NULL CHECK (factor_revision >= 0),
  issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  identity_context JSONB NOT NULL CHECK ((jsonb_typeof(identity_context)='object' AND identity_context->>'userId'=user_id::text) IS TRUE),
  client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(id),
  client_revision BIGINT NOT NULL CHECK (client_revision > 0),
  application_context JSONB NOT NULL CHECK ((jsonb_typeof(application_context)='object' AND application_context->>'userId'=user_id::text AND application_context->>'clientId'=client_id) IS TRUE),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ,
  CHECK (consumed_at IS NULL OR superseded_at IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_mfa_enrollment_pending ON oauth_mfa_enrollments(user_id)
  WHERE consumed_at IS NULL AND superseded_at IS NULL;
CREATE TABLE IF NOT EXISTS oauth_mfa_enrollment_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  enrollment_id UUID NOT NULL REFERENCES oauth_mfa_enrollments(id),
  action TEXT NOT NULL CHECK (action IN ('started','completed','verification_failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION guard_oauth_mfa_enrollment() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Enrollment evidence cannot be deleted'; END IF;
  IF TG_OP='INSERT' THEN
    NEW.created_at := clock_timestamp(); NEW.expires_at := NEW.created_at + interval '10 minutes';
    NEW.consumed_at := NULL; NEW.superseded_at := NULL; RETURN NEW;
  END IF;
  IF (to_jsonb(NEW)-ARRAY['consumed_at','superseded_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','superseded_at'])
    OR ((OLD.consumed_at IS NOT NULL OR OLD.superseded_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
    OR (NEW.consumed_at IS NOT NULL AND (NEW.consumed_at < OLD.created_at OR NEW.consumed_at > OLD.expires_at))
  THEN RAISE EXCEPTION 'Invalid enrollment transition'; END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS oauth_mfa_enrollment_guard ON oauth_mfa_enrollments;
CREATE TRIGGER oauth_mfa_enrollment_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_mfa_enrollments
FOR EACH ROW EXECUTE FUNCTION guard_oauth_mfa_enrollment();
DROP TRIGGER IF EXISTS oauth_mfa_enrollment_audit_guard ON oauth_mfa_enrollment_audit;
CREATE TRIGGER oauth_mfa_enrollment_audit_guard BEFORE UPDATE OR DELETE ON oauth_mfa_enrollment_audit
FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();

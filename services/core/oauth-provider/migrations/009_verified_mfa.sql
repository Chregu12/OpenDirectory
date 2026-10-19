CREATE TABLE IF NOT EXISTS oauth_mfa_factors (
  user_id UUID PRIMARY KEY,
  revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
  enabled BOOLEAN NOT NULL DEFAULT false,
  encrypted_seed TEXT,
  pending_seed TEXT,
  pending_session UUID,
  pending_expires_at TIMESTAMPTZ,
  last_counter BIGINT NOT NULL DEFAULT -1 CHECK (last_counter >= -1),
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  locked_until TIMESTAMPTZ,
  CHECK (enabled = (encrypted_seed IS NOT NULL)),
  CHECK (encrypted_seed IS NULL OR length(encrypted_seed) <= 512),
  CHECK (pending_seed IS NULL OR length(pending_seed) <= 512),
  CHECK ((pending_seed IS NULL AND pending_session IS NULL AND pending_expires_at IS NULL)
    OR (NOT enabled AND pending_seed IS NOT NULL AND pending_session IS NOT NULL AND pending_expires_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS oauth_mfa_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  revision BIGINT NOT NULL,
  session_id UUID,
  action TEXT NOT NULL CHECK (action IN ('setup_started','enabled','disabled','verified','verification_failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION oauth_mfa_factor_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'MFA factor incarnations cannot be deleted'; END IF;
  IF NEW.user_id IS DISTINCT FROM OLD.user_id
    OR (NEW.enabled IS DISTINCT FROM OLD.enabled AND NEW.revision <> OLD.revision + 1)
    OR (NEW.enabled = OLD.enabled AND NEW.revision <> OLD.revision)
    OR (OLD.enabled AND NEW.enabled AND NEW.encrypted_seed IS DISTINCT FROM OLD.encrypted_seed)
    OR (NEW.enabled AND OLD.enabled AND NEW.last_counter < OLD.last_counter)
  THEN RAISE EXCEPTION 'Invalid MFA factor transition'; END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS oauth_mfa_factor_guard ON oauth_mfa_factors;
CREATE TRIGGER oauth_mfa_factor_guard BEFORE UPDATE OR DELETE ON oauth_mfa_factors
FOR EACH ROW EXECUTE FUNCTION oauth_mfa_factor_guard();

DROP TRIGGER IF EXISTS oauth_mfa_audit_immutable ON oauth_mfa_audit;
CREATE TRIGGER oauth_mfa_audit_immutable BEFORE UPDATE OR DELETE ON oauth_mfa_audit
FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();

CREATE TABLE IF NOT EXISTS oauth_mfa_recovery_codes (
  code_hash TEXT PRIMARY KEY CHECK (code_hash ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  factor_revision BIGINT NOT NULL CHECK (factor_revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  consumed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX IF NOT EXISTS oauth_mfa_recovery_codes_owner ON oauth_mfa_recovery_codes(user_id,factor_revision);

CREATE TABLE IF NOT EXISTS oauth_mfa_recovery_challenges (
  id UUID PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  factor_revision BIGINT NOT NULL CHECK (factor_revision > 0),
  issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  identity_context JSONB NOT NULL CHECK ((jsonb_typeof(identity_context)='object' AND identity_context->>'userId'=user_id::text) IS TRUE),
  encrypted_seed TEXT NOT NULL CHECK (length(encrypted_seed) BETWEEN 1 AND 512),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ,
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  locked_until TIMESTAMPTZ,
  CHECK (consumed_at IS NULL OR superseded_at IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_mfa_recovery_one_pending ON oauth_mfa_recovery_challenges(user_id)
  WHERE consumed_at IS NULL AND superseded_at IS NULL;

CREATE TABLE IF NOT EXISTS oauth_mfa_recovery_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES oauth_mfa_factors(user_id),
  factor_revision BIGINT NOT NULL,
  session_id UUID,
  challenge_id UUID REFERENCES oauth_mfa_recovery_challenges(id),
  action TEXT NOT NULL CHECK (action IN ('codes_rotated','started','completed','verification_failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION guard_oauth_mfa_recovery_code() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Recovery evidence cannot be deleted'; END IF;
  IF (to_jsonb(NEW)-ARRAY['consumed_at','revoked_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','revoked_at'])
    OR ((OLD.consumed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
    OR (NEW.consumed_at IS NOT NULL AND NEW.consumed_at < OLD.created_at)
    OR (NEW.revoked_at IS NOT NULL AND NEW.revoked_at < OLD.created_at)
  THEN RAISE EXCEPTION 'Invalid recovery code transition'; END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS oauth_mfa_recovery_code_guard ON oauth_mfa_recovery_codes;
CREATE TRIGGER oauth_mfa_recovery_code_guard BEFORE UPDATE OR DELETE ON oauth_mfa_recovery_codes
FOR EACH ROW EXECUTE FUNCTION guard_oauth_mfa_recovery_code();

CREATE OR REPLACE FUNCTION guard_oauth_mfa_recovery_challenge() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Recovery evidence cannot be deleted'; END IF;
  IF TG_OP='INSERT' THEN
    NEW.created_at := clock_timestamp(); NEW.expires_at := NEW.created_at + interval '10 minutes';
    NEW.consumed_at := NULL; NEW.superseded_at := NULL; NEW.failed_attempts := 0; NEW.locked_until := NULL;
    RETURN NEW;
  END IF;
  IF (to_jsonb(NEW)-ARRAY['consumed_at','superseded_at','failed_attempts','locked_until']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['consumed_at','superseded_at','failed_attempts','locked_until'])
    OR ((OLD.consumed_at IS NOT NULL OR OLD.superseded_at IS NOT NULL) AND NEW IS DISTINCT FROM OLD)
    OR (NEW.consumed_at IS NOT NULL AND (NEW.consumed_at < OLD.created_at OR NEW.consumed_at > OLD.expires_at))
  THEN RAISE EXCEPTION 'Invalid recovery challenge transition'; END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS oauth_mfa_recovery_challenge_guard ON oauth_mfa_recovery_challenges;
CREATE TRIGGER oauth_mfa_recovery_challenge_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_mfa_recovery_challenges
FOR EACH ROW EXECUTE FUNCTION guard_oauth_mfa_recovery_challenge();

DROP TRIGGER IF EXISTS oauth_mfa_recovery_audit_immutable ON oauth_mfa_recovery_audit;
CREATE TRIGGER oauth_mfa_recovery_audit_immutable BEFORE UPDATE OR DELETE ON oauth_mfa_recovery_audit
FOR EACH ROW EXECUTE FUNCTION guard_oauth_client_evidence();

ALTER TABLE oauth_mfa_audit DROP CONSTRAINT IF EXISTS oauth_mfa_audit_action_check;
ALTER TABLE oauth_mfa_audit ADD CONSTRAINT oauth_mfa_audit_action_check
  CHECK (action IN ('setup_started','enabled','disabled','verified','verification_failed','recovered'));

CREATE OR REPLACE FUNCTION oauth_mfa_factor_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE recovery BOOLEAN := false;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'MFA factor incarnations cannot be deleted'; END IF;
  IF OLD.enabled AND NEW.enabled AND NEW.revision=OLD.revision+1 AND NEW.encrypted_seed IS DISTINCT FROM OLD.encrypted_seed THEN
    SELECT EXISTS(SELECT 1 FROM oauth_mfa_recovery_challenges
      WHERE id::text=current_setting('opendirectory.mfa_recovery',true) AND user_id=OLD.user_id
        AND factor_revision=OLD.revision AND consumed_at IS NOT NULL AND superseded_at IS NULL) INTO recovery;
  END IF;
  IF NEW.user_id IS DISTINCT FROM OLD.user_id
    OR (NEW.enabled IS DISTINCT FROM OLD.enabled AND NEW.revision <> OLD.revision+1)
    OR (NEW.enabled=OLD.enabled AND NEW.revision <> OLD.revision AND NOT recovery)
    OR (OLD.enabled AND NEW.enabled AND NEW.encrypted_seed IS DISTINCT FROM OLD.encrypted_seed AND NOT recovery)
    OR (OLD.enabled AND NEW.enabled AND NEW.last_counter < OLD.last_counter AND NOT recovery)
  THEN RAISE EXCEPTION 'Invalid MFA factor transition'; END IF;
  RETURN NEW;
END;
$$;

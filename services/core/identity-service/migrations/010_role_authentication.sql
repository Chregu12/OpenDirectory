CREATE TABLE IF NOT EXISTS identity_role_authentication (
  role TEXT PRIMARY KEY CHECK (role ~ '^[a-z][a-z-]{0,63}$'),
  version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
  mfa_required BOOLEAN NOT NULL DEFAULT false,
  max_age_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (max_age_seconds BETWEEN 300 AND 86400),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (role <> 'authentication-policy-administrator' OR (mfa_required AND max_age_seconds = 300))
);
INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds)
SELECT role,role='authentication-policy-administrator',CASE WHEN role='authentication-policy-administrator' THEN 300 ELSE 3600 END
FROM unnest(ARRAY[
  'admin','role-administrator','role-reader','user','directory-reader','user-administrator','user-lifecycle-operator',
  'user-profile-editor','group-administrator','ou-administrator','session-administrator','license-reader','license-manager',
  'license-administrator','license-approver','license-group-reader','license-eligibility-reader','application-reader',
  'application-administrator','device-enrollment-operator','policy-deployment-operator','compliance-reader','operations-reader',
  'gateway-reader','gateway-administrator','gateway-key-administrator','gateway-webhook-administrator',
  'pim-administrator','pim-approver','pim-reader','application-access-administrator','application-access-reader',
  'application-authentication-administrator','application-authentication-reader',
  'authentication-policy-administrator','authentication-policy-reader'
]) AS catalog(role) ON CONFLICT(role) DO NOTHING;

CREATE TABLE IF NOT EXISTS identity_role_authentication_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  previous JSONB NOT NULL,
  current JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION identity_role_authentication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Authentication policy is retained evidence' USING ERRCODE='23514'; END IF;
  IF NEW.role IS DISTINCT FROM OLD.role OR NEW.version IS DISTINCT FROM OLD.version+1 THEN
    RAISE EXCEPTION 'Authentication policy requires the next immutable version' USING ERRCODE='23514';
  END IF;
  IF OLD.role='authentication-policy-administrator' THEN
    RAISE EXCEPTION 'Policy administration has a fixed fresh MFA minimum' USING ERRCODE='23514';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_authentication_guard ON identity_role_authentication;
CREATE TRIGGER identity_role_authentication_guard BEFORE UPDATE OR DELETE ON identity_role_authentication
FOR EACH ROW EXECUTE FUNCTION identity_role_authentication_guard();

CREATE OR REPLACE FUNCTION identity_role_authentication_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operator TEXT; explanation TEXT;
BEGIN
  operator := NULLIF(current_setting('opendirectory.actor',true),'');
  explanation := NULLIF(current_setting('opendirectory.authentication_reason',true),'');
  IF operator IS NULL OR explanation IS NULL OR length(explanation) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Authentication policy requires operator and reason' USING ERRCODE='23514';
  END IF;
  INSERT INTO identity_role_authentication_audit(role,actor,reason,previous,current)
    VALUES(NEW.role,operator,explanation,to_jsonb(OLD),to_jsonb(NEW));
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_authentication_changed ON identity_role_authentication;
CREATE TRIGGER identity_role_authentication_changed AFTER UPDATE ON identity_role_authentication
FOR EACH ROW EXECUTE FUNCTION identity_role_authentication_changed();
DROP TRIGGER IF EXISTS identity_role_authentication_audit_guard ON identity_role_authentication_audit;
CREATE TRIGGER identity_role_authentication_audit_guard BEFORE UPDATE OR DELETE ON identity_role_authentication_audit
FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

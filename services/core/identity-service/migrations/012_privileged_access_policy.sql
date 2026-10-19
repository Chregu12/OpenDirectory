INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
  ('privileged-access-policy-administrator',true,300),('privileged-access-policy-reader',false,3600)
ON CONFLICT(role) DO NOTHING;

CREATE OR REPLACE FUNCTION identity_activation_reviewers_valid(identifiers UUID[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT identifiers IS NOT NULL AND cardinality(identifiers)<=20 AND COALESCE(array_ndims(identifiers),1)=1
    AND identifiers=ARRAY(SELECT DISTINCT identifier FROM unnest(identifiers) AS identifier WHERE identifier IS NOT NULL ORDER BY identifier);
$$;

CREATE TABLE IF NOT EXISTS identity_role_activation_policies (
  role TEXT PRIMARY KEY REFERENCES identity_role_authentication(role),
  version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
  activation_required BOOLEAN NOT NULL DEFAULT false,
  max_duration_seconds INTEGER NOT NULL DEFAULT 28800 CHECK(max_duration_seconds BETWEEN 60 AND 28800),
  reviewer_user_ids UUID[] NOT NULL DEFAULT '{}' CHECK(identity_activation_reviewers_valid(reviewer_user_ids)),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK(role<>'user' OR (NOT activation_required AND max_duration_seconds=28800 AND cardinality(reviewer_user_ids)=0)),
  CHECK(role<>'admin' OR NOT activation_required OR cardinality(reviewer_user_ids)>0)
);
INSERT INTO identity_role_activation_policies(role) SELECT role FROM identity_role_authentication ON CONFLICT(role) DO NOTHING;
ALTER TABLE identity_role_assignments ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 1 CHECK(policy_version>0);
ALTER TABLE identity_pim_requests ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 1 CHECK(policy_version>0);

CREATE TABLE IF NOT EXISTS identity_role_activation_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
  previous JSONB NOT NULL,
  current JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION identity_role_activation_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Activation policy is retained evidence' USING ERRCODE='23514'; END IF;
  IF NEW.role IS DISTINCT FROM OLD.role OR NEW.version IS DISTINCT FROM OLD.version+1 OR OLD.role='user' THEN
    RAISE EXCEPTION 'Activation policy requires a mutable catalog role and next version' USING ERRCODE='23514';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_activation_policy_guard ON identity_role_activation_policies;
CREATE TRIGGER identity_role_activation_policy_guard BEFORE UPDATE OR DELETE ON identity_role_activation_policies
FOR EACH ROW EXECUTE FUNCTION identity_role_activation_policy_guard();
CREATE OR REPLACE FUNCTION identity_role_activation_policy_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operator TEXT; explanation TEXT;
BEGIN
  operator := NULLIF(current_setting('opendirectory.actor',true),'');
  explanation := NULLIF(current_setting('opendirectory.activation_reason',true),'');
  IF operator IS NULL OR explanation IS NULL OR length(explanation) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Activation policy requires reviewed actor and reason' USING ERRCODE='23514';
  END IF;
  INSERT INTO identity_role_activation_audit(role,actor,reason,previous,current) VALUES(NEW.role,operator,explanation,to_jsonb(OLD),to_jsonb(NEW));
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_activation_policy_changed ON identity_role_activation_policies;
CREATE TRIGGER identity_role_activation_policy_changed AFTER UPDATE ON identity_role_activation_policies
FOR EACH ROW EXECUTE FUNCTION identity_role_activation_policy_changed();
DROP TRIGGER IF EXISTS identity_role_activation_audit_guard ON identity_role_activation_audit;
CREATE TRIGGER identity_role_activation_audit_guard BEFORE UPDATE OR DELETE ON identity_role_activation_audit
FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

CREATE OR REPLACE FUNCTION identity_role_activation_assignment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy identity_role_activation_policies%ROWTYPE; request_version BIGINT;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.policy_version IS DISTINCT FROM OLD.policy_version THEN RAISE EXCEPTION 'Assignment policy origin is immutable' USING ERRCODE='23514'; END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO policy FROM identity_role_activation_policies WHERE role=NEW.role FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Catalog activation policy required' USING ERRCODE='23514'; END IF;
  IF NEW.activation_request_id IS NULL AND policy.activation_required THEN
    RAISE EXCEPTION 'Approved PIM activation required' USING ERRCODE='23514';
  END IF;
  IF NEW.activation_request_id IS NOT NULL THEN
    SELECT policy_version INTO request_version FROM identity_pim_requests WHERE id=NEW.activation_request_id;
    IF request_version IS DISTINCT FROM policy.version OR NEW.expires_at IS NULL
      OR NEW.expires_at>NEW.created_at+policy.max_duration_seconds*interval '1 second' THEN
      RAISE EXCEPTION 'Current bounded activation policy required' USING ERRCODE='23514';
    END IF;
  END IF;
  NEW.policy_version := policy.version;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_policy_guard ON identity_role_assignments;
CREATE TRIGGER identity_role_policy_guard BEFORE INSERT OR UPDATE ON identity_role_assignments
FOR EACH ROW EXECUTE FUNCTION identity_role_activation_assignment_guard();

CREATE OR REPLACE FUNCTION identity_role_activation_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy identity_role_activation_policies%ROWTYPE;
BEGIN
  SELECT activation.* INTO policy FROM identity_role_activation_policies activation JOIN identity_pim_eligibilities eligibility
    ON eligibility.role=activation.role WHERE eligibility.id=NEW.eligibility_id FOR SHARE OF activation;
  IF NOT FOUND THEN RAISE EXCEPTION 'Catalog activation policy required' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.duration_seconds>policy.max_duration_seconds THEN RAISE EXCEPTION 'Activation duration exceeds policy' USING ERRCODE='23514'; END IF;
    NEW.policy_version := policy.version;
  ELSE
    IF NEW.policy_version IS DISTINCT FROM OLD.policy_version THEN RAISE EXCEPTION 'Request policy origin is immutable' USING ERRCODE='23514'; END IF;
    IF NEW.state IN ('approved','active') AND (NEW.policy_version<>policy.version OR NEW.duration_seconds>policy.max_duration_seconds) THEN
      RAISE EXCEPTION 'Request activation policy changed' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_activation_request_guard ON identity_pim_requests;
CREATE TRIGGER identity_role_activation_request_guard BEFORE INSERT OR UPDATE ON identity_pim_requests
FOR EACH ROW EXECUTE FUNCTION identity_role_activation_request_guard();

CREATE OR REPLACE FUNCTION identity_privileged_policy_authentication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.role='privileged-access-policy-administrator' THEN
    RAISE EXCEPTION 'Privileged policy administration has fixed fresh MFA' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_privileged_policy_authentication_guard ON identity_role_authentication;
CREATE TRIGGER identity_privileged_policy_authentication_guard BEFORE UPDATE ON identity_role_authentication
FOR EACH ROW EXECUTE FUNCTION identity_privileged_policy_authentication_guard();

INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('access-review-administrator',true,300),('access-reviewer',true,300),('access-review-reader',false,3600)
ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES
 ('access-review-administrator'),('access-reviewer'),('access-review-reader') ON CONFLICT(role) DO NOTHING;

CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE TABLE IF NOT EXISTS identity_role_review_policies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 role TEXT NOT NULL REFERENCES identity_role_authentication(role) CHECK(role<>'user'),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 3600 AND 31536000),
 window_seconds INTEGER NOT NULL CHECK(window_seconds BETWEEN 60 AND 604800 AND window_seconds<interval_seconds),
 reviewer_user_ids UUID[] NOT NULL CHECK(cardinality(reviewer_user_ids)>0 AND identity_activation_reviewers_valid(reviewer_user_ids)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT identity_role_review_now(),
 retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_role_review_active ON identity_role_review_policies(role) WHERE retired_at IS NULL;
CREATE INDEX IF NOT EXISTS identity_role_review_policy_members ON identity_role_review_policies USING gin(reviewer_user_ids);
CREATE TABLE IF NOT EXISTS identity_role_review_leases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 policy_id UUID NOT NULL REFERENCES identity_role_review_policies(id),
 target_kind TEXT NOT NULL CHECK(target_kind IN ('assignment','eligibility')),
 target_id UUID NOT NULL,
 user_id UUID NOT NULL,
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 cycle BIGINT NOT NULL DEFAULT 1 CHECK(cycle>0),
 due_at TIMESTAMPTZ,
 deadline_at TIMESTAMPTZ,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','denied','exempt')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT identity_role_review_now(),
 UNIQUE(target_kind,target_id),
 CHECK((state='exempt' AND due_at IS NULL AND deadline_at IS NULL) OR (state<>'exempt' AND due_at IS NOT NULL AND deadline_at>due_at))
);
CREATE INDEX IF NOT EXISTS identity_role_review_due ON identity_role_review_leases(deadline_at,id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS identity_role_review_policy_leases ON identity_role_review_leases(policy_id,deadline_at,id);
CREATE TABLE IF NOT EXISTS identity_role_review_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 policy_id UUID NOT NULL REFERENCES identity_role_review_policies(id),
 lease_id UUID,
 action TEXT NOT NULL,
 actor TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT identity_role_review_now()
);
CREATE OR REPLACE FUNCTION identity_role_review_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Review policy is retained evidence' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.retired_at IS NOT NULL THEN RAISE EXCEPTION 'New active policy required' USING ERRCODE='23514'; END IF;
  NEW.created_at:=identity_role_review_now();
 ELSE
  IF (to_jsonb(NEW)-ARRAY['version','retired_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','retired_at'])
   OR NEW.version<>OLD.version+1 OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL THEN
   RAISE EXCEPTION 'Only one-way policy retirement is allowed' USING ERRCODE='23514';
  END IF;
  NEW.retired_at:=identity_role_review_now();
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_review_policy_guard ON identity_role_review_policies;
CREATE TRIGGER identity_role_review_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_role_review_policies
FOR EACH ROW EXECUTE FUNCTION identity_role_review_policy_guard();

CREATE OR REPLACE FUNCTION identity_role_review_attach(kind TEXT,target UUID,policy UUID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE source_user UUID; source_role TEXT; rule identity_role_review_policies%ROWTYPE; previous identity_role_review_leases%ROWTYPE; observed timestamptz;
BEGIN
 observed:=identity_role_review_now();
 SELECT * INTO rule FROM identity_role_review_policies WHERE id=policy AND retired_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Active review policy required' USING ERRCODE='23514'; END IF;
 IF kind='assignment' THEN SELECT user_id,role INTO source_user,source_role FROM identity_role_assignments WHERE id=target;
 ELSIF kind='eligibility' THEN SELECT user_id,role INTO source_user,source_role FROM identity_pim_eligibilities WHERE id=target;
 ELSE RAISE EXCEPTION 'Canonical review target required' USING ERRCODE='23514'; END IF;
 IF source_role IS DISTINCT FROM rule.role OR source_user IS NULL THEN RAISE EXCEPTION 'Matching review target required' USING ERRCODE='23514'; END IF;
 IF cardinality(rule.reviewer_user_ids)=1 AND rule.reviewer_user_ids[1]=source_user THEN
  RAISE EXCEPTION 'Independent review path required' USING ERRCODE='23514';
 END IF;
 SELECT * INTO previous FROM identity_role_review_leases WHERE target_kind=kind AND target_id=target FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO identity_role_review_leases(policy_id,target_kind,target_id,user_id,due_at,deadline_at)
   VALUES(policy,kind,target,source_user,observed,observed+rule.window_seconds*interval '1 second');
 ELSIF previous.policy_id<>policy AND previous.state<>'denied' AND (previous.deadline_at IS NULL OR previous.deadline_at>observed) THEN
  UPDATE identity_role_review_leases SET policy_id=policy,version=version+1,cycle=1,state='pending',due_at=observed,
   deadline_at=LEAST(COALESCE(previous.deadline_at,'infinity'::timestamptz),observed+rule.window_seconds*interval '1 second') WHERE id=previous.id;
 END IF;
END;
$$;
CREATE OR REPLACE FUNCTION identity_role_review_lease_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rule identity_role_review_policies%ROWTYPE; source_user UUID; source_role TEXT; action TEXT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Review lease is retained evidence' USING ERRCODE='23514'; END IF;
 SELECT * INTO rule FROM identity_role_review_policies WHERE id=NEW.policy_id FOR SHARE;
 IF NEW.target_kind='assignment' THEN SELECT user_id,role INTO source_user,source_role FROM identity_role_assignments WHERE id=NEW.target_id;
 ELSE SELECT user_id,role INTO source_user,source_role FROM identity_pim_eligibilities WHERE id=NEW.target_id; END IF;
 IF source_user IS DISTINCT FROM NEW.user_id OR source_role IS DISTINCT FROM rule.role THEN RAISE EXCEPTION 'Bound review target required' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF rule.retired_at IS NOT NULL OR NEW.version<>1 OR NEW.cycle<>1 OR NEW.state<>'pending' OR NEW.due_at>identity_role_review_now()
   OR NEW.deadline_at>NEW.due_at+rule.window_seconds*interval '1 second' THEN RAISE EXCEPTION 'Initial bounded review required' USING ERRCODE='23514'; END IF;
  NEW.created_at:=identity_role_review_now();
 ELSE
  IF NEW.id<>OLD.id OR NEW.target_id<>OLD.target_id OR NEW.target_kind<>OLD.target_kind OR NEW.user_id<>OLD.user_id OR NEW.created_at<>OLD.created_at
   OR NEW.version<>OLD.version+1 OR OLD.state='denied' OR (OLD.deadline_at IS NOT NULL AND OLD.deadline_at<=identity_role_review_now()) THEN
   RAISE EXCEPTION 'Expired or immutable review cannot be revived' USING ERRCODE='23514';
  END IF;
  action:=current_setting('opendirectory.review_action',true);
  IF NEW.policy_id<>OLD.policy_id THEN
   IF EXISTS(SELECT 1 FROM identity_role_review_policies WHERE id=OLD.policy_id AND retired_at IS NULL) OR rule.retired_at IS NOT NULL
    OR NEW.cycle<>1 OR NEW.state<>'pending' OR NEW.deadline_at>COALESCE(OLD.deadline_at,'infinity'::timestamptz)
    OR NEW.deadline_at>identity_role_review_now()+rule.window_seconds*interval '1 second' THEN RAISE EXCEPTION 'Bounded policy replacement required' USING ERRCODE='23514'; END IF;
  ELSIF action='retain' THEN
   IF OLD.state<>'pending' OR OLD.due_at>identity_role_review_now() OR NEW.cycle<>OLD.cycle+1
    OR (rule.retired_at IS NULL AND (NEW.state<>'pending' OR NEW.due_at IS DISTINCT FROM OLD.due_at+rule.interval_seconds*interval '1 second'
      OR NEW.deadline_at IS DISTINCT FROM NEW.due_at+rule.window_seconds*interval '1 second'))
    OR (rule.retired_at IS NOT NULL AND (NEW.state<>'exempt' OR NEW.due_at IS NOT NULL OR NEW.deadline_at IS NOT NULL)) THEN
    RAISE EXCEPTION 'Current independent review required' USING ERRCODE='23514'; END IF;
  ELSIF action='revoke' THEN
   IF OLD.state<>'pending' OR OLD.due_at>identity_role_review_now() OR NEW.state<>'denied' OR NEW.cycle<>OLD.cycle
    OR NEW.due_at IS DISTINCT FROM OLD.due_at OR NEW.deadline_at IS DISTINCT FROM OLD.deadline_at THEN RAISE EXCEPTION 'Current revocation review required' USING ERRCODE='23514'; END IF;
   IF (NEW.target_kind='assignment' AND NOT EXISTS(SELECT 1 FROM identity_role_assignments WHERE id=NEW.target_id AND revoked_at IS NOT NULL))
    OR (NEW.target_kind='eligibility' AND NOT EXISTS(SELECT 1 FROM identity_pim_eligibilities WHERE id=NEW.target_id AND revoked_at IS NOT NULL)) THEN
    RAISE EXCEPTION 'Canonical revocation required' USING ERRCODE='23514'; END IF;
  ELSE RAISE EXCEPTION 'Reviewed transition required' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_review_lease_guard ON identity_role_review_leases;
CREATE TRIGGER identity_role_review_lease_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_role_review_leases FOR EACH ROW EXECUTE FUNCTION identity_role_review_lease_guard();

CREATE OR REPLACE FUNCTION identity_role_review_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operator TEXT; explanation TEXT;
BEGIN
 operator:=NULLIF(current_setting('opendirectory.actor',true),'');
 explanation:=NULLIF(current_setting('opendirectory.review_reason',true),'');
 IF operator IS NULL OR explanation IS NULL OR length(explanation) NOT BETWEEN 10 AND 500 THEN RAISE EXCEPTION 'Review actor and reason required' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='identity_role_review_policies' THEN
  INSERT INTO identity_role_review_audit(policy_id,action,actor,reason,details) VALUES(NEW.id,'policy:'||lower(TG_OP),operator,explanation,to_jsonb(NEW));
  IF TG_OP='INSERT' THEN
   PERFORM identity_role_review_attach('assignment',assignment.id,NEW.id) FROM identity_role_assignments assignment
    JOIN users ON users.id=assignment.user_id JOIN identity_role_activation_policies activation ON activation.role=assignment.role
    WHERE assignment.role=NEW.role AND assignment.revoked_at IS NULL AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
    AND assignment.policy_version=activation.version AND (NOT activation.activation_required OR assignment.activation_request_id IS NOT NULL) ORDER BY assignment.id;
   PERFORM identity_role_review_attach('eligibility',eligibility.id,NEW.id) FROM identity_pim_eligibilities eligibility JOIN users ON users.id=eligibility.user_id
    WHERE eligibility.role=NEW.role AND eligibility.revoked_at IS NULL AND eligibility.expires_at>clock_timestamp() ORDER BY eligibility.id;
  END IF;
 ELSE
  INSERT INTO identity_role_review_audit(policy_id,lease_id,action,actor,reason,details)
   VALUES(NEW.policy_id,NEW.id,COALESCE(NULLIF(current_setting('opendirectory.review_action',true),''),'attached'),operator,explanation,
     jsonb_build_object('lease',to_jsonb(NEW),'proof',NULLIF(current_setting('opendirectory.review_proof',true),'')::jsonb));
 END IF;
 RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_review_policy_changed ON identity_role_review_policies;
CREATE TRIGGER identity_role_review_policy_changed AFTER INSERT OR UPDATE ON identity_role_review_policies FOR EACH ROW EXECUTE FUNCTION identity_role_review_changed();
DROP TRIGGER IF EXISTS identity_role_review_lease_changed ON identity_role_review_leases;
CREATE TRIGGER identity_role_review_lease_changed AFTER INSERT OR UPDATE ON identity_role_review_leases FOR EACH ROW EXECUTE FUNCTION identity_role_review_changed();
DROP TRIGGER IF EXISTS identity_role_review_audit_guard ON identity_role_review_audit;
CREATE TRIGGER identity_role_review_audit_guard BEFORE UPDATE OR DELETE ON identity_role_review_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();

CREATE OR REPLACE FUNCTION identity_role_review_granted() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy UUID;
BEGIN
 SELECT id INTO policy FROM identity_role_review_policies WHERE role=NEW.role AND retired_at IS NULL FOR SHARE;
 IF FOUND THEN
  PERFORM set_config('opendirectory.review_reason',NEW.reason,true);
  PERFORM identity_role_review_attach(CASE WHEN TG_TABLE_NAME='identity_role_assignments' THEN 'assignment' ELSE 'eligibility' END,NEW.id,policy);
 END IF;
 RETURN NULL;
END;
$$;
CREATE OR REPLACE FUNCTION identity_role_review_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('od-role-reviews:'||NEW.role,0));
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_aa_review_gate ON identity_role_assignments;
CREATE TRIGGER identity_aa_review_gate BEFORE INSERT ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_role_review_gate();
DROP TRIGGER IF EXISTS identity_aa_review_gate ON identity_pim_eligibilities;
CREATE TRIGGER identity_aa_review_gate BEFORE INSERT ON identity_pim_eligibilities FOR EACH ROW EXECUTE FUNCTION identity_role_review_gate();
DROP TRIGGER IF EXISTS identity_role_review_granted ON identity_role_assignments;
CREATE TRIGGER identity_role_review_granted AFTER INSERT ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_role_review_granted();
DROP TRIGGER IF EXISTS identity_role_review_granted ON identity_pim_eligibilities;
CREATE TRIGGER identity_role_review_granted AFTER INSERT ON identity_pim_eligibilities FOR EACH ROW EXECUTE FUNCTION identity_role_review_granted();

CREATE OR REPLACE FUNCTION identity_role_review_eligible(target UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM identity_role_review_leases WHERE target_kind='eligibility' AND target_id=target
  AND (state='denied' OR deadline_at<=identity_role_review_now()));
$$;
CREATE OR REPLACE FUNCTION identity_role_review_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state IN ('pending','approved','active') AND NOT identity_role_review_eligible(NEW.eligibility_id) THEN
  RAISE EXCEPTION 'Eligibility review expired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_review_request_guard ON identity_pim_requests;
CREATE TRIGGER identity_role_review_request_guard BEFORE INSERT OR UPDATE ON identity_pim_requests FOR EACH ROW EXECUTE FUNCTION identity_role_review_request_guard();
CREATE OR REPLACE FUNCTION identity_role_review_authentication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.role IN ('access-review-administrator','access-reviewer') THEN RAISE EXCEPTION 'Review duties require fixed fresh MFA' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_review_authentication_guard ON identity_role_authentication;
CREATE TRIGGER identity_role_review_authentication_guard BEFORE UPDATE ON identity_role_authentication FOR EACH ROW EXECUTE FUNCTION identity_role_review_authentication_guard();

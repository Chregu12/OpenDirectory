CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
ALTER TABLE license_grants ADD COLUMN IF NOT EXISTS eligibility_revision BIGINT;
CREATE OR REPLACE FUNCTION license_review_grant_origin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.eligibility_revision IS NOT NULL THEN RAISE EXCEPTION 'Grant eligibility origin is server-derived' USING ERRCODE='42501'; END IF;
 IF NEW.kind='direct' THEN
  SELECT directory_revision INTO NEW.eligibility_revision FROM license_subjects WHERE user_id=NEW.recipient_id
   AND NOT disabled AND directory_enabled AND directory_deleted IS NOT TRUE;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS b_license_review_grant_origin ON license_grants;
CREATE TRIGGER b_license_review_grant_origin BEFORE INSERT ON license_grants FOR EACH ROW EXECUTE FUNCTION license_review_grant_origin();
CREATE TABLE IF NOT EXISTS license_review_policies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 license_id UUID NOT NULL REFERENCES license_catalog(id),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 3600 AND 31536000),
 window_seconds INTEGER NOT NULL CHECK(window_seconds BETWEEN 60 AND 604800 AND window_seconds<interval_seconds),
 reviewer_user_ids UUID[] NOT NULL CHECK(cardinality(reviewer_user_ids) BETWEEN 1 AND 20),
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(),
 retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS license_review_active_policy ON license_review_policies(license_id) WHERE retired_at IS NULL;
CREATE INDEX IF NOT EXISTS license_review_policy_members ON license_review_policies USING gin(reviewer_user_ids);
CREATE TABLE IF NOT EXISTS license_review_leases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 policy_id UUID NOT NULL REFERENCES license_review_policies(id),
 grant_id UUID NOT NULL UNIQUE REFERENCES license_grants(id),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 cycle BIGINT NOT NULL DEFAULT 1 CHECK(cycle>0),
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','exempt','denied')),
 due_at TIMESTAMPTZ,
 deadline_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(),
 CHECK((state='exempt' AND due_at IS NULL AND deadline_at IS NULL) OR (state<>'exempt' AND due_at IS NOT NULL AND deadline_at>due_at))
);
CREATE INDEX IF NOT EXISTS license_review_due ON license_review_leases(deadline_at,id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS license_review_policy_leases ON license_review_leases(policy_id,deadline_at,id);
CREATE TABLE IF NOT EXISTS license_review_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 policy_id UUID NOT NULL REFERENCES license_review_policies(id),
 lease_id UUID,
 action TEXT NOT NULL,
 actor JSONB NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
DROP TRIGGER IF EXISTS license_review_audit_guard ON license_review_audit;
CREATE TRIGGER license_review_audit_guard BEFORE UPDATE OR DELETE ON license_review_audit FOR EACH ROW EXECUTE FUNCTION license_audit_append_only();

CREATE OR REPLACE FUNCTION license_source_expiry(grant_identity UUID,base_expiry TIMESTAMPTZ) RETURNS timestamptz LANGUAGE sql STABLE AS $$
 SELECT date_trunc('milliseconds',LEAST(base_expiry,(SELECT CASE WHEN state='pending' THEN deadline_at WHEN state='denied' THEN '-infinity'::timestamptz ELSE NULL END
   FROM license_review_leases WHERE grant_id=grant_identity)));
$$;
DO $$
DECLARE signature TEXT;
BEGIN
 FOREACH signature IN ARRAY ARRAY['license_validate_capacity()','license_assignment_capacity()','license_assignment_counter()',
   'license_source_grant_before()','license_group_grant_before()','license_fulfillment_refresh(uuid,uuid,jsonb,boolean)'] LOOP
  IF signature='license_fulfillment_refresh(uuid,uuid,jsonb,boolean)' THEN
   EXECUTE replace(pg_get_functiondef(signature::regprocedure),'assignment.expires_at>clock_timestamp()','assignment.expires_at>license_now()');
  ELSE EXECUTE replace(pg_get_functiondef(signature::regprocedure),'clock_timestamp()','license_now()'); END IF;
 END LOOP;
END;
$$;
CREATE OR REPLACE FUNCTION license_assignment_no_update() RETURNS trigger AS $$
DECLARE expected_expiry TIMESTAMPTZ; source_count INTEGER;
BEGIN
 SELECT COUNT(*),CASE WHEN BOOL_OR(expiry IS NULL) THEN NULL ELSE MAX(expiry) END INTO source_count,expected_expiry
 FROM (SELECT license_source_expiry(grant_id,expires_at) AS expiry FROM license_assignment_sources WHERE license_id=NEW.license_id AND user_id=NEW.assignee_id) sources
 WHERE expiry IS NULL OR expiry>license_now();
 IF NEW.assignee_type='user' AND source_count>0 AND (to_jsonb(NEW)-'expires_at')=(to_jsonb(OLD)-'expires_at')
   AND NEW.expires_at IS NOT DISTINCT FROM expected_expiry THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Only source-derived expiry updates are permitted' USING ERRCODE='42501';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION license_review_attach(grant_identity UUID,policy_identity UUID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE policy license_review_policies; target license_grants; previous license_review_leases;
BEGIN
 SELECT * INTO policy FROM license_review_policies WHERE id=policy_identity AND retired_at IS NULL;
 SELECT * INTO target FROM license_grants WHERE id=grant_identity;
 IF policy.id IS NULL OR target.license_id<>policy.license_id THEN RAISE EXCEPTION 'Review policy scope mismatch' USING ERRCODE='23514'; END IF;
 IF target.recipient_id !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  OR (target.kind='direct' AND NOT EXISTS(SELECT 1 FROM unnest(policy.reviewer_user_ids) reviewer WHERE reviewer::text<>target.recipient_id)) THEN
  RAISE EXCEPTION 'Canonical independent review path required' USING ERRCODE='23514';
 END IF;
 SELECT * INTO previous FROM license_review_leases WHERE grant_id=grant_identity;
 IF previous.id IS NOT NULL AND (previous.state='denied' OR previous.state='pending' AND previous.deadline_at<=license_now()) THEN RETURN; END IF;
 IF previous.id IS NULL THEN
  INSERT INTO license_review_leases(policy_id,grant_id,due_at,deadline_at) VALUES(policy.id,target.id,license_now(),license_now()+policy.window_seconds*interval '1 second');
 ELSE
  UPDATE license_review_leases SET policy_id=policy.id,version=version+1 WHERE id=previous.id;
 END IF;
END;
$$;
CREATE OR REPLACE FUNCTION license_review_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Review policy is retained evidence' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.retired_at IS NOT NULL OR NEW.reviewer_user_ids IS DISTINCT FROM
    ARRAY(SELECT DISTINCT reviewer FROM unnest(NEW.reviewer_user_ids) reviewer WHERE reviewer IS NOT NULL ORDER BY reviewer) THEN
   RAISE EXCEPTION 'New policy and sorted unique reviewers required' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription'))
    OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=NEW.license_id AND assignee_type<>'user') THEN
   RAISE EXCEPTION 'Canonical human license pool required' USING ERRCODE='23514';
  END IF;
  NEW.created_at=license_now();
 ELSE
  IF (to_jsonb(NEW)-ARRAY['version','retired_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','retired_at'])
    OR NEW.version<>OLD.version+1 OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL THEN
   RAISE EXCEPTION 'Review policies only permit one-way retirement' USING ERRCODE='42501';
  END IF;
  NEW.retired_at=license_now();
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION license_review_lease_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy license_review_policies; action TEXT; operator UUID;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Review leases are retained evidence' USING ERRCODE='42501'; END IF;
 SELECT * INTO policy FROM license_review_policies WHERE id=NEW.policy_id;
 IF NOT EXISTS(SELECT 1 FROM license_grants WHERE id=NEW.grant_id AND license_id=policy.license_id) THEN
  RAISE EXCEPTION 'Review target mismatch' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.cycle<>1 OR NEW.state<>'pending' OR policy.retired_at IS NOT NULL THEN
   RAISE EXCEPTION 'New pending review required' USING ERRCODE='23514';
  END IF;
  NEW.created_at=license_now(); NEW.due_at=license_now(); NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';
 ELSE
  action=current_setting('opendirectory.license_review_action',true);
  IF action IN ('retain','deny') THEN
   operator=(NULLIF(current_setting('opendirectory.license_review_proof',true),'')::jsonb->>'userId')::uuid;
   IF operator IS NULL OR NOT operator=ANY(policy.reviewer_user_ids)
    OR EXISTS(SELECT 1 FROM license_grants WHERE id=NEW.grant_id AND kind='direct' AND recipient_id=operator::text)
    OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=NEW.grant_id AND user_id=operator::text) THEN
    RAISE EXCEPTION 'Named independent reviewer required' USING ERRCODE='42501';
   END IF;
  END IF;
  IF ROW(NEW.id,NEW.grant_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.grant_id,OLD.created_at) OR NEW.version<>OLD.version+1
    OR OLD.state='denied' OR OLD.state='pending' AND OLD.deadline_at<=license_now() THEN
   RAISE EXCEPTION 'Expired or immutable review target' USING ERRCODE='42501';
  END IF;
  IF NEW.policy_id<>OLD.policy_id AND action='configure' AND policy.retired_at IS NULL THEN
   NEW.state='pending'; NEW.cycle=1; NEW.due_at=LEAST(OLD.due_at,license_now());
   NEW.deadline_at=LEAST(CASE WHEN OLD.state='pending' THEN OLD.deadline_at END,license_now()+policy.window_seconds*interval '1 second');
  ELSIF NEW.policy_id=OLD.policy_id AND OLD.state='pending' AND OLD.due_at<=license_now() AND action='retain' THEN
   NEW.cycle=OLD.cycle+1;
   IF policy.retired_at IS NULL THEN
    NEW.state='pending'; NEW.due_at=license_now()+policy.interval_seconds*interval '1 second'; NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';
   ELSE NEW.state='exempt'; NEW.due_at=NULL; NEW.deadline_at=NULL; END IF;
  ELSIF NEW.policy_id=OLD.policy_id AND OLD.state='pending' AND OLD.due_at<=license_now() AND action='deny'
    AND NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=NEW.grant_id)
    AND NOT EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=NEW.grant_id AND enabled) THEN
   NEW.state='denied'; NEW.cycle=OLD.cycle; NEW.due_at=OLD.due_at; NEW.deadline_at=OLD.deadline_at;
  ELSE RAISE EXCEPTION 'Reviewed decision required' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION license_review_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE operator JSONB; explanation TEXT;
BEGIN
 operator=NULLIF(current_setting('opendirectory.license_review_proof',true),'')::jsonb;
 explanation=NULLIF(current_setting('opendirectory.license_review_reason',true),'');
 IF TG_TABLE_NAME='license_review_policies' THEN
  IF operator IS NULL OR explanation IS NULL THEN RAISE EXCEPTION 'Review actor and reason required' USING ERRCODE='23514'; END IF;
  INSERT INTO license_review_audit(policy_id,action,actor,reason,details) VALUES(NEW.id,'policy:'||lower(TG_OP),operator,explanation,to_jsonb(NEW));
  IF TG_OP='INSERT' THEN
   PERFORM license_review_attach(grants.id,NEW.id) FROM license_grants grants WHERE grants.license_id=NEW.license_id AND
    (EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=grants.id AND enabled AND (expires_at IS NULL OR expires_at>license_now()))
     OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=grants.id AND source_type='direct' AND (expires_at IS NULL OR expires_at>license_now())));
  END IF;
 ELSE
  IF TG_OP='UPDATE' THEN
   IF operator IS NULL OR explanation IS NULL THEN RAISE EXCEPTION 'Review actor and reason required' USING ERRCODE='23514'; END IF;
   INSERT INTO license_review_audit(policy_id,lease_id,action,actor,reason,details) VALUES(NEW.policy_id,NEW.id,current_setting('opendirectory.license_review_action',true),operator,explanation,to_jsonb(NEW));
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_review_policy_guard ON license_review_policies;
CREATE TRIGGER license_review_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON license_review_policies FOR EACH ROW EXECUTE FUNCTION license_review_policy_guard();
DROP TRIGGER IF EXISTS license_review_policy_changed ON license_review_policies;
CREATE TRIGGER license_review_policy_changed AFTER INSERT OR UPDATE ON license_review_policies FOR EACH ROW EXECUTE FUNCTION license_review_changed();
DROP TRIGGER IF EXISTS license_review_lease_guard ON license_review_leases;
CREATE TRIGGER license_review_lease_guard BEFORE INSERT OR UPDATE OR DELETE ON license_review_leases FOR EACH ROW EXECUTE FUNCTION license_review_lease_guard();
DROP TRIGGER IF EXISTS license_review_lease_changed ON license_review_leases;
CREATE TRIGGER license_review_lease_changed AFTER INSERT OR UPDATE ON license_review_leases FOR EACH ROW EXECUTE FUNCTION license_review_changed();
CREATE OR REPLACE FUNCTION license_review_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy_id UUID;
BEGIN
 SELECT id INTO policy_id FROM license_review_policies WHERE license_id=NEW.license_id AND retired_at IS NULL;
 IF policy_id IS NOT NULL THEN PERFORM license_review_attach(NEW.id,policy_id); END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_review_capture ON license_grants;
CREATE TRIGGER license_review_capture AFTER INSERT ON license_grants FOR EACH ROW EXECUTE FUNCTION license_review_capture();
CREATE OR REPLACE FUNCTION license_review_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE reviewers UUID[];
BEGIN
 IF license_source_expiry(NEW.grant_id,NEW.expires_at)<=license_now() AND EXISTS(SELECT 1 FROM license_review_leases WHERE grant_id=NEW.grant_id) THEN
  RAISE EXCEPTION 'Expired review cannot license recipients' USING ERRCODE='23514';
 END IF;
 SELECT policy.reviewer_user_ids INTO reviewers FROM license_review_leases lease JOIN license_review_policies policy ON policy.id=lease.policy_id
  WHERE lease.grant_id=NEW.grant_id AND lease.state='pending';
 IF NEW.source_type='group' AND reviewers IS NOT NULL AND NOT EXISTS(SELECT 1 FROM unnest(reviewers) reviewer
   WHERE NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=NEW.grant_id AND user_id=reviewer::text)) THEN
  RAISE EXCEPTION 'Independent group reviewer required' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS zz_license_review_source_guard ON license_assignment_sources;
CREATE TRIGGER zz_license_review_source_guard AFTER INSERT OR UPDATE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION license_review_source_guard();
CREATE OR REPLACE FUNCTION license_review_pool_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID; expected_expiry TIMESTAMPTZ; source_count INTEGER;
BEGIN
 IF TG_TABLE_NAME='license_catalog' THEN pool_id=NEW.id; ELSE pool_id=NEW.license_id; END IF;
 IF EXISTS(SELECT 1 FROM license_review_policies WHERE license_id=pool_id) THEN
  IF TG_TABLE_NAME='license_catalog' THEN
   IF NEW.license_type NOT IN ('per_user','subscription') THEN RAISE EXCEPTION 'Reviewed human pool cannot change scope' USING ERRCODE='23514'; END IF;
  ELSE
   IF NEW.assignee_type<>'user' THEN RAISE EXCEPTION 'Reviewed pool requires human user sources' USING ERRCODE='23514'; END IF;
   SELECT COUNT(*),CASE WHEN BOOL_OR(expiry IS NULL) THEN NULL ELSE MAX(expiry) END INTO source_count,expected_expiry
    FROM (SELECT license_source_expiry(grant_id,expires_at) AS expiry FROM license_assignment_sources WHERE license_id=NEW.license_id AND user_id=NEW.assignee_id) sources
    WHERE expiry IS NULL OR expiry>license_now();
   IF source_count=0 OR NEW.expires_at IS DISTINCT FROM expected_expiry THEN RAISE EXCEPTION 'Reviewed assignment must derive from live capped sources' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_review_pool_guard ON license_catalog;
CREATE TRIGGER license_review_pool_guard BEFORE UPDATE ON license_catalog FOR EACH ROW EXECUTE FUNCTION license_review_pool_guard();
DROP TRIGGER IF EXISTS license_review_assignment_guard ON license_assignments;
CREATE TRIGGER license_review_assignment_guard BEFORE INSERT ON license_assignments FOR EACH ROW EXECUTE FUNCTION license_review_pool_guard();
CREATE OR REPLACE FUNCTION license_review_pool_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  PERFORM 1 FROM license_catalog WHERE id=OLD.license_id FOR UPDATE;
  RETURN OLD;
 END IF;
 PERFORM 1 FROM license_catalog WHERE id=NEW.license_id FOR UPDATE;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS a_license_review_pool_gate ON license_assignment_sources;
CREATE TRIGGER a_license_review_pool_gate BEFORE INSERT OR UPDATE OR DELETE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION license_review_pool_gate();
DROP TRIGGER IF EXISTS a_license_review_pool_gate ON license_group_rules;
CREATE TRIGGER a_license_review_pool_gate BEFORE INSERT OR UPDATE OR DELETE ON license_group_rules FOR EACH ROW EXECUTE FUNCTION license_review_pool_gate();
DROP TRIGGER IF EXISTS a_license_review_pool_gate ON license_grants;
CREATE TRIGGER a_license_review_pool_gate BEFORE INSERT ON license_grants FOR EACH ROW EXECUTE FUNCTION license_review_pool_gate();

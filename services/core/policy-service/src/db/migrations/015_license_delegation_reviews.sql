CREATE TABLE IF NOT EXISTS license_scope_review_policies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),license_id UUID NOT NULL REFERENCES license_catalog(id),issuer TEXT NOT NULL,duty TEXT NOT NULL CHECK(duty IN ('reader','allocator','approver')),
 target_kind TEXT NOT NULL CHECK(target_kind IN ('grant','eligibility')),version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),window_seconds INTEGER NOT NULL CHECK(window_seconds BETWEEN 60 AND 604800 AND window_seconds<=interval_seconds),
 reviewer_user_ids UUID[] NOT NULL CHECK(cardinality(reviewer_user_ids) BETWEEN 1 AND 10),created_by UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(),retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS license_scope_review_active_policy ON license_scope_review_policies(license_id,duty,target_kind,issuer) WHERE retired_at IS NULL;
CREATE TABLE IF NOT EXISTS license_scope_review_leases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),policy_id UUID NOT NULL REFERENCES license_scope_review_policies(id),target_kind TEXT NOT NULL CHECK(target_kind IN ('grant','eligibility')),
 target_id UUID NOT NULL,version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),cycle BIGINT NOT NULL DEFAULT 1 CHECK(cycle>0),state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','denied')),
 due_at TIMESTAMPTZ NOT NULL,deadline_at TIMESTAMPTZ NOT NULL CHECK(deadline_at>due_at),created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(),UNIQUE(target_kind,target_id)
);
CREATE TABLE IF NOT EXISTS license_scope_review_fences (
 grant_id UUID PRIMARY KEY REFERENCES license_scope_grants(id),review_id UUID NOT NULL REFERENCES license_scope_review_leases(id),ceiling TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS license_scope_review_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),policy_id UUID NOT NULL REFERENCES license_scope_review_policies(id),review_id UUID REFERENCES license_scope_review_leases(id),
 action TEXT NOT NULL,actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
ALTER TABLE license_scope_activation_requests ADD COLUMN IF NOT EXISTS eligibility_review_version BIGINT NOT NULL DEFAULT 0 CHECK(eligibility_review_version>=0);
ALTER TABLE license_scope_activation_requests ADD COLUMN IF NOT EXISTS eligibility_review_policy_version BIGINT NOT NULL DEFAULT 0 CHECK(eligibility_review_policy_version>=0);
DO $$ BEGIN
 IF to_regprocedure('license_scope_eligibility_policy_usable(uuid,bigint)') IS NULL THEN ALTER FUNCTION license_scope_eligibility_usable(uuid,bigint) RENAME TO license_scope_eligibility_policy_usable;END IF;
 IF to_regprocedure('license_scope_request_policy_current(uuid)') IS NULL THEN ALTER FUNCTION license_scope_request_current(uuid) RENAME TO license_scope_request_policy_current;END IF;
 IF to_regprocedure('license_scope_grant_policy_usable(uuid)') IS NULL THEN ALTER FUNCTION license_scope_grant_usable(uuid) RENAME TO license_scope_grant_policy_usable;END IF;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_review_allowed(kind TEXT,identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM license_scope_review_leases WHERE target_kind=kind AND target_id=identity AND (state='denied' OR deadline_at<=license_now()));
$$;
CREATE OR REPLACE FUNCTION license_scope_review_deadline(kind TEXT,identity UUID) RETURNS timestamptz LANGUAGE sql VOLATILE AS $$
 SELECT CASE WHEN state='denied' THEN '-infinity'::timestamptz ELSE deadline_at END FROM license_scope_review_leases WHERE target_kind=kind AND target_id=identity;
$$;
CREATE OR REPLACE FUNCTION license_scope_eligibility_usable(eligibility UUID,origin BIGINT) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT license_scope_eligibility_policy_usable(eligibility,origin) AND license_scope_review_allowed('eligibility',eligibility);
$$;
CREATE OR REPLACE FUNCTION license_scope_request_current(request_id UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT license_scope_request_policy_current(request_id) AND EXISTS(SELECT 1 FROM license_scope_activation_requests request
  LEFT JOIN license_scope_review_leases lease ON lease.target_kind='eligibility' AND lease.target_id=request.eligibility_id
  LEFT JOIN license_scope_review_policies policy ON policy.id=lease.policy_id WHERE request.id=request_id
  AND (request.status='activated' OR request.eligibility_review_version=COALESCE(lease.version,0) AND request.eligibility_review_policy_version=COALESCE(policy.version,0)));
$$;
CREATE OR REPLACE FUNCTION license_scope_grant_usable(lease UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT license_scope_grant_policy_usable(lease) AND license_scope_review_allowed('grant',lease)
  AND NOT EXISTS(SELECT 1 FROM license_scope_review_fences WHERE grant_id=lease AND ceiling<=license_now());
$$;
CREATE OR REPLACE FUNCTION license_scope_review_target(kind TEXT,identity UUID) RETURNS TABLE(
 license_id UUID,user_id UUID,issuer TEXT,duty TEXT,target_version BIGINT,base_expiry TIMESTAMPTZ,revoked_at TIMESTAMPTZ,creator UUID,activation_reviewer UUID,
 eligibility_revision BIGINT,delegation_revision TEXT,usable BOOLEAN) LANGUAGE sql VOLATILE AS $$
 SELECT eligible.license_id,eligible.user_id,eligible.issuer,eligible.duty,eligible.version,eligible.expires_at,eligible.revoked_at,eligible.created_by,NULL::uuid,
  eligible.eligibility_revision,eligible.delegation_revision,license_scope_eligibility_policy_usable(eligible.id,eligible.version)
  FROM license_scope_eligibilities eligible WHERE kind='eligibility' AND eligible.id=identity
 UNION ALL SELECT grants.license_id,grants.user_id,grants.issuer,grants.duty,grants.version,grants.expires_at,grants.revoked_at,
  COALESCE(eligible.created_by,(SELECT (actor->>'userId')::uuid FROM license_scope_audit WHERE grant_id=grants.id AND action='insert' ORDER BY created_at,id LIMIT 1)),request.reviewed_by,
  grants.eligibility_revision,grants.delegation_revision,license_scope_grant_policy_usable(grants.id) AND NOT EXISTS(SELECT 1 FROM license_scope_review_fences WHERE grant_id=grants.id AND ceiling<=license_now())
  FROM license_scope_grants grants LEFT JOIN license_scope_activation_requests request ON request.id=grants.activation_request_id
  LEFT JOIN license_scope_eligibilities eligible ON eligible.id=request.eligibility_id WHERE kind='grant' AND grants.id=identity;
$$;
CREATE OR REPLACE FUNCTION license_scope_review_independent(actor UUID,kind TEXT,identity UUID,policy_creator UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_review_target(kind,identity) target WHERE actor<>target.user_id AND actor IS DISTINCT FROM target.creator
  AND actor IS DISTINCT FROM target.activation_reviewer AND actor<>policy_creator);
$$;
CREATE OR REPLACE FUNCTION license_scope_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;actor_id UUID;action TEXT;policy license_scope_review_policies;target RECORD;
BEGIN
 IF TG_OP='DELETE' OR NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Scope review history/control is retained' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='license_scope_review_leases' AND TG_OP='INSERT' THEN
  SELECT * INTO policy FROM license_scope_review_policies WHERE id=NEW.policy_id;
  SELECT * INTO target FROM license_scope_review_target(NEW.target_kind,NEW.target_id);
  IF pg_trigger_depth()<2 OR policy.retired_at IS NOT NULL OR target.license_id IS DISTINCT FROM policy.license_id OR target.duty IS DISTINCT FROM policy.duty
   OR target.issuer IS DISTINCT FROM policy.issuer OR NEW.target_kind<>policy.target_kind OR target.revoked_at IS NOT NULL OR target.base_expiry<=license_now() OR NEW.version<>1 OR NEW.cycle<>1 OR NEW.state<>'pending'
   OR NOT EXISTS(SELECT 1 FROM unnest(policy.reviewer_user_ids) reviewer WHERE license_scope_review_independent(reviewer,NEW.target_kind,NEW.target_id,policy.created_by))
   THEN RAISE EXCEPTION 'Independent original review capture required' USING ERRCODE='23514';END IF;
  NEW.due_at=date_trunc('milliseconds',license_now());NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';RETURN NEW;
 END IF;
 proof=NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb;action=current_setting('opendirectory.scope_review_action',true);
 IF proof IS NULL OR COALESCE(proof->>'userId','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR COALESCE(proof->>'issuer','')='' OR COALESCE(proof->>'subject','')='' THEN RAISE EXCEPTION 'Canonical review authority required' USING ERRCODE='42501';END IF;
 actor_id=(proof->>'userId')::uuid;
 IF TG_TABLE_NAME='license_scope_review_policies' THEN
  PERFORM 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription') FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Human license pool required' USING ERRCODE='23514';END IF;
  IF TG_OP='INSERT' THEN
   IF action IS DISTINCT FROM 'create' OR NEW.issuer IS DISTINCT FROM proof->>'issuer' OR NEW.version<>1 OR NEW.retired_at IS NOT NULL OR NEW.created_by<>actor_id OR actor_id=ANY(NEW.reviewer_user_ids)
    OR array_position(NEW.reviewer_user_ids,NULL) IS NOT NULL OR (SELECT count(DISTINCT reviewer) FROM unnest(NEW.reviewer_user_ids) reviewer)<>cardinality(NEW.reviewer_user_ids)
    THEN RAISE EXCEPTION 'Independent bounded review policy required' USING ERRCODE='23514';END IF;
   NEW.created_at=license_now();
  ELSE
   IF action IS DISTINCT FROM 'retire' OR (to_jsonb(NEW)-ARRAY['version','retired_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','retired_at'])
    OR NEW.version<>OLD.version+1 OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL THEN RAISE EXCEPTION 'Review policy permits one-way retirement only' USING ERRCODE='42501';END IF;
   NEW.retired_at=license_now();
  END IF;
 ELSE
  SELECT * INTO policy FROM license_scope_review_policies WHERE id=NEW.policy_id;
  SELECT * INTO target FROM license_scope_review_target(NEW.target_kind,NEW.target_id);
  IF (to_jsonb(NEW)-ARRAY['version','cycle','state','due_at','deadline_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','cycle','state','due_at','deadline_at'])
   OR NEW.version<>OLD.version+1 OR OLD.state<>'pending' OR OLD.due_at>license_now() OR OLD.deadline_at<=license_now()
   OR proof->>'reviewedPolicyVersion' IS DISTINCT FROM policy.version::text OR proof->>'reviewedTargetVersion' IS DISTINCT FROM target.target_version::text
   OR target.issuer IS DISTINCT FROM proof->>'issuer' OR target.revoked_at IS NOT NULL OR target.base_expiry<=license_now()
   OR NOT(actor_id=ANY(policy.reviewer_user_ids)) OR NOT license_scope_review_independent(actor_id,NEW.target_kind,NEW.target_id,policy.created_by)
   THEN RAISE EXCEPTION 'Current independent conditional review required' USING ERRCODE='42501';END IF;
  IF action='retain' THEN
   IF NOT target.usable OR policy.retired_at IS NOT NULL OR NEW.state<>'pending' OR NEW.cycle<>OLD.cycle+1 THEN RAISE EXCEPTION 'Timely current retention required' USING ERRCODE='42501';END IF;
   NEW.due_at=date_trunc('milliseconds',license_now())+policy.interval_seconds*interval '1 second';NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';
  ELSIF action='deny' THEN
   IF NEW.state<>'denied' OR NEW.cycle<>OLD.cycle OR NEW.due_at<>OLD.due_at OR NEW.deadline_at<>OLD.deadline_at THEN RAISE EXCEPTION 'One-way review denial required' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'Review decision required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_review_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy license_scope_review_policies;target RECORD;kind TEXT;
BEGIN
 IF TG_TABLE_NAME='license_scope_review_policies' THEN
  FOR target IN SELECT id FROM license_scope_grants WHERE NEW.target_kind='grant' AND issuer=NEW.issuer AND license_id=NEW.license_id AND duty=NEW.duty AND revoked_at IS NULL AND expires_at>license_now()
   UNION ALL SELECT id FROM license_scope_eligibilities WHERE NEW.target_kind='eligibility' AND issuer=NEW.issuer AND license_id=NEW.license_id AND duty=NEW.duty AND revoked_at IS NULL AND expires_at>license_now() LOOP
   INSERT INTO license_scope_review_leases(policy_id,target_kind,target_id,due_at,deadline_at) VALUES(NEW.id,NEW.target_kind,target.id,license_now(),license_now()+interval '1 second') ON CONFLICT(target_kind,target_id) DO NOTHING;
  END LOOP;
 ELSE
  kind=CASE WHEN TG_TABLE_NAME='license_scope_grants' THEN 'grant' ELSE 'eligibility' END;
  SELECT * INTO policy FROM license_scope_review_policies WHERE license_id=NEW.license_id AND issuer=NEW.issuer AND duty=NEW.duty AND target_kind=kind AND retired_at IS NULL;
  IF policy.id IS NOT NULL THEN INSERT INTO license_scope_review_leases(policy_id,target_kind,target_id,due_at,deadline_at) VALUES(policy.id,kind,NEW.id,license_now(),license_now()+interval '1 second') ON CONFLICT(target_kind,target_id) DO NOTHING;END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_review_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE action TEXT;policy_id UUID;review_id UUID;
BEGIN
 IF TG_TABLE_NAME='license_scope_review_policies' THEN policy_id=NEW.id;action=CASE WHEN TG_OP='INSERT' THEN 'create' ELSE 'retire' END;
 ELSE policy_id=NEW.policy_id;review_id=NEW.id;action=CASE WHEN TG_OP='INSERT' THEN 'capture' ELSE current_setting('opendirectory.scope_review_action',true) END;
  IF TG_OP='INSERT' AND NEW.target_kind='eligibility' THEN
   INSERT INTO license_scope_review_fences(grant_id,review_id,ceiling) SELECT grants.id,NEW.id,NEW.deadline_at FROM license_scope_grants grants JOIN license_scope_activation_requests request ON request.id=grants.activation_request_id
    WHERE request.eligibility_id=NEW.target_id AND grants.revoked_at IS NULL ON CONFLICT(grant_id) DO NOTHING;
  ELSIF TG_OP='UPDATE' AND NEW.state='denied' THEN
   IF NEW.target_kind='grant' THEN UPDATE license_scope_grants SET revoked_at=license_now(),version=version+1 WHERE id=NEW.target_id AND revoked_at IS NULL;
   ELSE PERFORM set_config('opendirectory.scope_pim_action','eligibility.revoke',true);UPDATE license_scope_eligibilities SET revoked_at=license_now(),version=version+1 WHERE id=NEW.target_id AND revoked_at IS NULL;END IF;
  END IF;
 END IF;
 INSERT INTO license_scope_review_audit(policy_id,review_id,action,actor,reason,details) VALUES(policy_id,review_id,action,COALESCE(NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb,'{}'::jsonb),COALESCE(NULLIF(current_setting('opendirectory.scope_reason',true),''),'Automatic original target review capture'),to_jsonb(NEW));RETURN NEW;
END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_scope_review_policies','license_scope_review_leases'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_scope_review_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_scope_review_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_review_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS license_scope_review_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_scope_review_changed AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_review_changed()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['license_scope_review_policies','license_scope_grants','license_scope_eligibilities'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS zz_license_scope_review_capture ON %I',table_name);
  EXECUTE format('CREATE TRIGGER zz_license_scope_review_capture AFTER INSERT ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_review_capture()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['license_scope_review_audit','license_scope_review_fences'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_scope_review_append_only ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_scope_review_append_only BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_audit_append_only()',table_name);
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_review_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF pg_trigger_depth()<2 OR NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Review evidence requires its actual control transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_scope_review_insert_guard ON license_scope_review_audit;
CREATE TRIGGER license_scope_review_insert_guard BEFORE INSERT ON license_scope_review_audit FOR EACH ROW EXECUTE FUNCTION license_scope_review_insert_guard();
DROP TRIGGER IF EXISTS license_scope_review_fence_insert ON license_scope_review_fences;
CREATE TRIGGER license_scope_review_fence_insert BEFORE INSERT ON license_scope_review_fences FOR EACH ROW EXECUTE FUNCTION license_scope_review_insert_guard();
CREATE OR REPLACE FUNCTION license_scope_review_origin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE lease license_scope_review_leases;policy_version BIGINT;request license_scope_activation_requests;
BEGIN
 IF TG_TABLE_NAME='license_scope_activation_requests' THEN
  SELECT * INTO lease FROM license_scope_review_leases WHERE target_kind='eligibility' AND target_id=NEW.eligibility_id;SELECT version INTO policy_version FROM license_scope_review_policies WHERE id=lease.policy_id;
  IF TG_OP='INSERT' THEN NEW.eligibility_review_version=COALESCE(lease.version,0);NEW.eligibility_review_policy_version=COALESCE(policy_version,0);
  ELSIF NEW.eligibility_review_version<>OLD.eligibility_review_version OR NEW.eligibility_review_policy_version<>OLD.eligibility_review_policy_version THEN RAISE EXCEPTION 'Eligibility review origin is immutable' USING ERRCODE='42501';END IF;
 ELSE
  IF NEW.activation_request_id IS NOT NULL THEN
   SELECT * INTO request FROM license_scope_activation_requests WHERE id=NEW.activation_request_id;NEW.expires_at=LEAST(NEW.expires_at,license_scope_review_deadline('eligibility',request.eligibility_id));
  END IF;
 END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS a00_license_scope_review_origin ON license_scope_activation_requests;
CREATE TRIGGER a00_license_scope_review_origin BEFORE INSERT OR UPDATE ON license_scope_activation_requests FOR EACH ROW EXECUTE FUNCTION license_scope_review_origin();
DROP TRIGGER IF EXISTS a00_license_scope_review_grant_origin ON license_scope_grants;
CREATE TRIGGER a00_license_scope_review_grant_origin BEFORE INSERT ON license_scope_grants FOR EACH ROW EXECUTE FUNCTION license_scope_review_origin();
CREATE OR REPLACE FUNCTION license_scope_review_prepared_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM license_scope_eligibilities WHERE id=ANY(NEW.prepared_eligibility_ids) AND (NOT license_scope_review_allowed('eligibility',id) OR LEAST(expires_at,license_scope_review_deadline('eligibility',id))<=license_now()+interval '5 minutes'))
  THEN RAISE EXCEPTION 'Prepared path must retain effective review lifetime' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS a00_license_scope_review_prepared ON license_scope_activation_policies;
CREATE TRIGGER a00_license_scope_review_prepared BEFORE INSERT OR UPDATE ON license_scope_activation_policies FOR EACH ROW EXECUTE FUNCTION license_scope_review_prepared_guard();

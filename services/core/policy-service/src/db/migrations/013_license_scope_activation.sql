CREATE TABLE IF NOT EXISTS license_scope_eligibilities (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), license_id UUID NOT NULL REFERENCES license_catalog(id), user_id UUID NOT NULL, issuer TEXT NOT NULL,
 duty TEXT NOT NULL CHECK(duty IN ('reader','allocator','approver')), version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0), delegation_revision TEXT NOT NULL CHECK(delegation_revision ~ '^[a-f0-9]{64}$'),
 created_by UUID NOT NULL, reviewer_user_ids UUID[] NOT NULL CHECK(cardinality(reviewer_user_ids) BETWEEN 1 AND 10),
 max_duration_seconds INTEGER NOT NULL CHECK(max_duration_seconds BETWEEN 60 AND 28800),
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(), expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS license_scope_eligibility_incarnation ON license_scope_eligibilities(license_id,user_id,duty) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS license_scope_activation_requests (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), eligibility_id UUID NOT NULL REFERENCES license_scope_eligibilities(id),
 eligibility_version BIGINT NOT NULL CHECK(eligibility_version>0), version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 requested_duration_seconds INTEGER NOT NULL CHECK(requested_duration_seconds BETWEEN 60 AND 28800),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','activated','deactivated','cancelled')),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT license_now(), approval_deadline TIMESTAMPTZ NOT NULL,
 reviewed_by UUID, reviewed_at TIMESTAMPTZ, activated_at TIMESTAMPTZ,
 reviewer_eligibility_revision BIGINT CHECK(reviewer_eligibility_revision>0), reviewer_role_revision TEXT CHECK(reviewer_role_revision ~ '^[a-f0-9]{64}$')
);
CREATE UNIQUE INDEX IF NOT EXISTS license_scope_pending_activation ON license_scope_activation_requests(eligibility_id) WHERE status IN ('pending','approved');
ALTER TABLE license_scope_grants ADD COLUMN IF NOT EXISTS activation_request_id UUID REFERENCES license_scope_activation_requests(id);
CREATE UNIQUE INDEX IF NOT EXISTS license_scope_activation_once ON license_scope_grants(activation_request_id) WHERE activation_request_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS license_scope_pim_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), eligibility_id UUID NOT NULL REFERENCES license_scope_eligibilities(id),
 request_id UUID REFERENCES license_scope_activation_requests(id), actor JSONB NOT NULL, reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 action TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
CREATE OR REPLACE FUNCTION license_scope_eligibility_usable(eligibility UUID, origin BIGINT) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_eligibilities eligible JOIN license_catalog catalog ON catalog.id=eligible.license_id
  LEFT JOIN license_subjects subject ON subject.user_id=eligible.user_id::text
  WHERE eligible.id=eligibility AND eligible.version=origin AND eligible.revoked_at IS NULL AND eligible.expires_at>license_now()
   AND catalog.license_type IN ('per_user','subscription') AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false);
$$;
CREATE OR REPLACE FUNCTION license_scope_grant_usable(lease UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_grants grants WHERE grants.id=lease AND grants.revoked_at IS NULL AND grants.expires_at>license_now()
  AND (grants.activation_request_id IS NULL OR EXISTS(SELECT 1 FROM license_scope_activation_requests request
   JOIN license_scope_eligibilities eligible ON eligible.id=request.eligibility_id WHERE request.id=grants.activation_request_id AND request.status='activated'
    AND eligible.license_id=grants.license_id AND eligible.user_id=grants.user_id AND eligible.issuer=grants.issuer AND eligible.duty=grants.duty
    AND eligible.eligibility_revision=grants.eligibility_revision AND eligible.delegation_revision=grants.delegation_revision
    AND license_scope_eligibility_usable(eligible.id,request.eligibility_version))));
$$;
CREATE OR REPLACE FUNCTION license_scope_pim_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB; actor_id UUID; eligible license_scope_eligibilities; lease license_scope_grants; command TEXT;
BEGIN
 IF TG_OP='DELETE' OR NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Scope activation history/control is not delegated' USING ERRCODE='42501'; END IF;
 proof=NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb;
 IF proof IS NULL OR COALESCE(proof->>'userId','') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  OR COALESCE(proof->>'issuer','')='' OR COALESCE(proof->>'subject','')='' THEN RAISE EXCEPTION 'Canonical activation authority required' USING ERRCODE='42501'; END IF;
 actor_id=(proof->>'userId')::uuid; command=current_setting('opendirectory.scope_pim_action',true);
 IF TG_TABLE_NAME='license_scope_eligibilities' THEN
  IF TG_OP='INSERT' THEN
   IF command IS DISTINCT FROM 'eligibility.create' OR NEW.version<>1 OR NEW.revoked_at IS NOT NULL OR NEW.user_id=actor_id OR NEW.created_by<>actor_id
    OR NEW.issuer<>proof->>'issuer' OR NEW.expires_at<=license_now() OR NEW.expires_at>license_now()+interval '30 days'
    OR NEW.user_id=ANY(NEW.reviewer_user_ids) OR actor_id=ANY(NEW.reviewer_user_ids)
    OR array_position(NEW.reviewer_user_ids,NULL) IS NOT NULL OR (SELECT count(DISTINCT identifier) FROM unnest(NEW.reviewer_user_ids) identifier)<>cardinality(NEW.reviewer_user_ids)
    OR NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription'))
    OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=NEW.license_id AND assignee_type<>'user') THEN RAISE EXCEPTION 'Independent bounded eligibility required' USING ERRCODE='23514'; END IF;
   NEW.created_at=license_now();
  ELSE
   IF command IS DISTINCT FROM 'eligibility.revoke' OR (to_jsonb(NEW)-ARRAY['version','revoked_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','revoked_at'])
    OR NEW.version<>OLD.version+1 OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN RAISE EXCEPTION 'Eligibility is immutable except one-way revocation' USING ERRCODE='42501'; END IF;
   NEW.revoked_at=license_now();
  END IF;
 ELSE
  SELECT * INTO eligible FROM license_scope_eligibilities WHERE id=NEW.eligibility_id;
  IF TG_OP='INSERT' THEN
   IF command IS DISTINCT FROM 'request' OR NEW.status<>'pending' OR NEW.version<>1 OR NEW.reviewed_by IS NOT NULL OR NEW.reviewed_at IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.reviewer_eligibility_revision IS NOT NULL OR NEW.reviewer_role_revision IS NOT NULL
    OR actor_id<>eligible.user_id OR proof->>'issuer'<>eligible.issuer OR NOT license_scope_eligibility_usable(eligible.id,NEW.eligibility_version)
    OR NEW.requested_duration_seconds>eligible.max_duration_seconds OR NEW.approval_deadline<=license_now()
    OR NEW.approval_deadline>LEAST(eligible.expires_at,license_now()+interval '15 minutes') THEN RAISE EXCEPTION 'Current own activation request required' USING ERRCODE='23514'; END IF;
   NEW.requested_at=license_now();
  ELSE
   IF (to_jsonb(NEW)-ARRAY['version','status','reviewed_by','reviewed_at','activated_at','reviewer_eligibility_revision','reviewer_role_revision']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','status','reviewed_by','reviewed_at','activated_at','reviewer_eligibility_revision','reviewer_role_revision'])
    OR NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'Activation origin is immutable' USING ERRCODE='42501'; END IF;
   IF OLD.status='pending' AND NEW.status IN ('approved','denied') THEN
    IF command IS DISTINCT FROM 'review.'||NEW.status OR proof->>'issuer'<>eligible.issuer OR NOT(actor_id=ANY(eligible.reviewer_user_ids)) OR actor_id IN (eligible.user_id,eligible.created_by)
     OR NEW.reviewed_by IS DISTINCT FROM actor_id OR NEW.reviewer_eligibility_revision IS NULL OR NEW.reviewer_role_revision IS NULL OR NEW.activated_at IS NOT NULL OR OLD.approval_deadline<=license_now()
     OR NOT license_scope_eligibility_usable(eligible.id,OLD.eligibility_version) THEN RAISE EXCEPTION 'Independent timely reviewer required' USING ERRCODE='42501'; END IF;
    NEW.reviewed_at=license_now();
   ELSIF OLD.status='approved' AND NEW.status='activated' THEN
    SELECT * INTO lease FROM license_scope_grants WHERE activation_request_id=OLD.id;
    IF command IS DISTINCT FROM 'activate' OR actor_id<>eligible.user_id OR proof->>'issuer'<>eligible.issuer OR OLD.approval_deadline<=license_now()
     OR NOT license_scope_eligibility_usable(eligible.id,OLD.eligibility_version) OR lease.id IS NULL OR lease.revoked_at IS NOT NULL
     OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at OR NEW.reviewer_eligibility_revision IS DISTINCT FROM OLD.reviewer_eligibility_revision OR NEW.reviewer_role_revision IS DISTINCT FROM OLD.reviewer_role_revision THEN RAISE EXCEPTION 'Current own approved activation required' USING ERRCODE='42501'; END IF;
    NEW.activated_at=license_now();
   ELSIF (OLD.status IN ('pending','approved') AND NEW.status='cancelled' AND command='cancel')
    OR (OLD.status='activated' AND NEW.status='deactivated' AND command='deactivate') THEN
    IF actor_id<>eligible.user_id OR proof->>'issuer'<>eligible.issuer OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
     OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.reviewer_eligibility_revision IS DISTINCT FROM OLD.reviewer_eligibility_revision OR NEW.reviewer_role_revision IS DISTINCT FROM OLD.reviewer_role_revision OR NEW.status='deactivated' AND EXISTS(SELECT 1 FROM license_scope_grants WHERE activation_request_id=OLD.id AND revoked_at IS NULL)
     THEN RAISE EXCEPTION 'Own one-way cancellation/deactivation required' USING ERRCODE='42501'; END IF;
   ELSE RAISE EXCEPTION 'Invalid activation transition' USING ERRCODE='42501'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION license_scope_pim_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO license_scope_pim_audit(eligibility_id,request_id,actor,reason,action,details) VALUES(
  CASE WHEN TG_TABLE_NAME='license_scope_eligibilities' THEN NEW.id ELSE (to_jsonb(NEW)->>'eligibility_id')::uuid END,
  CASE WHEN TG_TABLE_NAME='license_scope_eligibilities' THEN NULL ELSE NEW.id END,
  NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb,NULLIF(current_setting('opendirectory.scope_reason',true),''),
  current_setting('opendirectory.scope_pim_action',true),to_jsonb(NEW)); RETURN NEW;
END;
$$;
DO $$ DECLARE table_name TEXT; BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_scope_eligibilities','license_scope_activation_requests'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_scope_pim_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_scope_pim_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_pim_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS license_scope_pim_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_scope_pim_changed AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_pim_changed()',table_name);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS license_scope_pim_audit_guard ON license_scope_pim_audit;
CREATE TRIGGER license_scope_pim_audit_guard BEFORE UPDATE OR DELETE ON license_scope_pim_audit FOR EACH ROW EXECUTE FUNCTION license_audit_append_only();
CREATE OR REPLACE FUNCTION license_scope_pim_audit_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL
  OR NEW.actor IS DISTINCT FROM NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb
  OR NEW.action IS DISTINCT FROM current_setting('opendirectory.scope_pim_action',true) THEN RAISE EXCEPTION 'Activation evidence requires its original control operation' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_scope_pim_audit_insert_guard ON license_scope_pim_audit;
CREATE TRIGGER license_scope_pim_audit_insert_guard BEFORE INSERT ON license_scope_pim_audit FOR EACH ROW EXECUTE FUNCTION license_scope_pim_audit_insert_guard();
CREATE OR REPLACE FUNCTION license_scope_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB; request license_scope_activation_requests; eligible license_scope_eligibilities;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Delegation history is retained' USING ERRCODE='42501'; END IF;
 proof=NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb;
 IF proof IS NULL OR COALESCE(proof->>'userId','') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  OR COALESCE(proof->>'issuer','')='' OR COALESCE(proof->>'subject','')='' THEN RAISE EXCEPTION 'Canonical delegation authority required' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.revoked_at IS NOT NULL OR NEW.issuer<>proof->>'issuer' OR NEW.expires_at<=license_now() OR NEW.expires_at>license_now()+interval '8 hours'
   OR NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription'))
   OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=NEW.license_id AND assignee_type<>'user') THEN RAISE EXCEPTION 'Bounded human-pool delegation required' USING ERRCODE='23514'; END IF;
  IF NEW.activation_request_id IS NULL THEN
   IF NEW.user_id::text=proof->>'userId' THEN RAISE EXCEPTION 'Independent delegation required' USING ERRCODE='23514'; END IF;
  ELSE
   SELECT * INTO request FROM license_scope_activation_requests WHERE id=NEW.activation_request_id;
   SELECT * INTO eligible FROM license_scope_eligibilities WHERE id=request.eligibility_id;
   IF current_setting('opendirectory.scope_pim_action',true) IS DISTINCT FROM 'activate' OR request.status IS DISTINCT FROM 'approved' OR request.approval_deadline<=license_now()
    OR NOT license_scope_eligibility_usable(eligible.id,request.eligibility_version) OR eligible.user_id::text IS DISTINCT FROM proof->>'userId'
    OR NEW.license_id IS DISTINCT FROM eligible.license_id OR NEW.user_id IS DISTINCT FROM eligible.user_id OR NEW.issuer IS DISTINCT FROM eligible.issuer OR NEW.duty IS DISTINCT FROM eligible.duty
    OR NEW.eligibility_revision IS DISTINCT FROM eligible.eligibility_revision OR NEW.delegation_revision IS DISTINCT FROM eligible.delegation_revision
    OR NEW.expires_at>LEAST(eligible.expires_at,license_now()+request.requested_duration_seconds*interval '1 second') THEN RAISE EXCEPTION 'Approved own resource activation required' USING ERRCODE='42501'; END IF;
  END IF;
  NEW.created_at=license_now();
 ELSE
  IF (to_jsonb(NEW)-ARRAY['revoked_at','version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revoked_at','version'])
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'Delegation permits only one-way conditional revocation' USING ERRCODE='42501'; END IF;
  NEW.revoked_at=license_now();
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_pool_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID; BEGIN
 IF TG_TABLE_NAME='license_catalog' THEN pool_id=NEW.id; ELSE pool_id=NEW.license_id; END IF;
 IF EXISTS(SELECT 1 FROM license_scope_grants WHERE license_id=pool_id) OR EXISTS(SELECT 1 FROM license_scope_eligibilities WHERE license_id=pool_id) THEN
  IF TG_TABLE_NAME='license_catalog' THEN
   IF NEW.license_type NOT IN ('per_user','subscription') THEN RAISE EXCEPTION 'Delegated human pool cannot change scope' USING ERRCODE='23514'; END IF;
  ELSIF NEW.assignee_type<>'user' THEN RAISE EXCEPTION 'Delegated pool requires human user sources' USING ERRCODE='23514'; END IF;
 END IF; RETURN NEW;
END; $$;

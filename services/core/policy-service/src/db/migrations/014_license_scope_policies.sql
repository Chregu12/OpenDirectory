CREATE TABLE IF NOT EXISTS license_scope_activation_policies (
 license_id UUID NOT NULL REFERENCES license_catalog(id), duty TEXT NOT NULL CHECK(duty IN ('reader','allocator','approver')),
 version BIGINT NOT NULL CHECK(version>=2), activation_required BOOLEAN NOT NULL, max_duration_seconds INTEGER NOT NULL CHECK(max_duration_seconds BETWEEN 60 AND 28800),
 prepared_eligibility_ids UUID[] NOT NULL, updated_by UUID NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT license_now(), PRIMARY KEY(license_id,duty)
);
CREATE TABLE IF NOT EXISTS license_scope_policy_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), license_id UUID NOT NULL REFERENCES license_catalog(id), duty TEXT NOT NULL,
 version BIGINT NOT NULL, actor JSONB NOT NULL, reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500), details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
ALTER TABLE license_scope_grants ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 1 CHECK(policy_version>0);
ALTER TABLE license_scope_eligibilities ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 1 CHECK(policy_version>0);
ALTER TABLE license_scope_activation_requests ADD COLUMN IF NOT EXISTS policy_version BIGINT NOT NULL DEFAULT 1 CHECK(policy_version>0);
CREATE OR REPLACE FUNCTION license_scope_policy_version(pool UUID, task TEXT) RETURNS bigint LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE((SELECT version FROM license_scope_activation_policies WHERE license_id=pool AND duty=task),1::bigint);
$$;
CREATE OR REPLACE FUNCTION license_scope_eligibility_usable(eligibility UUID, origin BIGINT) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_eligibilities eligible JOIN license_catalog catalog ON catalog.id=eligible.license_id
  LEFT JOIN license_subjects subject ON subject.user_id=eligible.user_id::text
  LEFT JOIN license_scope_activation_policies policy ON policy.license_id=eligible.license_id AND policy.duty=eligible.duty
  WHERE eligible.id=eligibility AND eligible.version=origin AND eligible.revoked_at IS NULL AND eligible.expires_at>license_now()
   AND (eligible.policy_version=COALESCE(policy.version,1) OR eligible.id=ANY(policy.prepared_eligibility_ids))
   AND eligible.max_duration_seconds<=COALESCE(policy.max_duration_seconds,28800)
   AND catalog.license_type IN ('per_user','subscription') AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false);
$$;
CREATE OR REPLACE FUNCTION license_scope_request_current(request_id UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_activation_requests request JOIN license_scope_eligibilities eligible ON eligible.id=request.eligibility_id
  WHERE request.id=request_id AND request.policy_version=license_scope_policy_version(eligible.license_id,eligible.duty)
   AND license_scope_eligibility_usable(eligible.id,request.eligibility_version));
$$;
CREATE OR REPLACE FUNCTION license_scope_grant_usable(lease UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM license_scope_grants grants LEFT JOIN license_scope_activation_policies policy ON policy.license_id=grants.license_id AND policy.duty=grants.duty
  WHERE grants.id=lease AND grants.revoked_at IS NULL AND grants.expires_at>license_now() AND grants.policy_version=COALESCE(policy.version,1)
   AND (grants.activation_request_id IS NULL AND NOT COALESCE(policy.activation_required,false) OR grants.activation_request_id IS NOT NULL AND EXISTS(
    SELECT 1 FROM license_scope_activation_requests request JOIN license_scope_eligibilities eligible ON eligible.id=request.eligibility_id
    WHERE request.id=grants.activation_request_id AND request.status='activated' AND request.policy_version=grants.policy_version
     AND eligible.license_id=grants.license_id AND eligible.user_id=grants.user_id AND eligible.issuer=grants.issuer AND eligible.duty=grants.duty
     AND eligible.eligibility_revision=grants.eligibility_revision AND eligible.delegation_revision=grants.delegation_revision
     AND license_scope_request_current(request.id))));
$$;
CREATE OR REPLACE FUNCTION license_scope_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB; actor_id UUID;
BEGIN
 IF TG_OP='DELETE' OR NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Pool policy history/control is retained' USING ERRCODE='42501'; END IF;
 proof=NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb;
 IF proof IS NULL OR COALESCE(proof->>'userId','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR COALESCE(proof->>'issuer','')='' OR COALESCE(proof->>'subject','')='' OR current_setting('opendirectory.scope_policy_action',true) IS DISTINCT FROM 'set' THEN RAISE EXCEPTION 'Original policy authority required' USING ERRCODE='42501'; END IF;
 actor_id=(proof->>'userId')::uuid;PERFORM 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription') FOR UPDATE;
 IF NOT FOUND OR NEW.updated_by<>actor_id OR cardinality(NEW.prepared_eligibility_ids)>10 OR array_position(NEW.prepared_eligibility_ids,NULL) IS NOT NULL
  OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=NEW.license_id AND assignee_type<>'user')
  OR (SELECT count(DISTINCT identifier) FROM unnest(NEW.prepared_eligibility_ids) identifier)<>cardinality(NEW.prepared_eligibility_ids)
  OR NEW.activation_required AND cardinality(NEW.prepared_eligibility_ids)=0 THEN RAISE EXCEPTION 'Bounded independent activation path required' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>2 THEN RAISE EXCEPTION 'Initial pool policy must fence the implicit origin' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.license_id<>OLD.license_id OR NEW.duty<>OLD.duty OR NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'Conditional immutable policy origin required' USING ERRCODE='42501'; END IF;
 END IF;
 IF (SELECT count(*) FROM license_scope_eligibilities eligible LEFT JOIN license_subjects subject ON subject.user_id=eligible.user_id::text
  WHERE eligible.id=ANY(NEW.prepared_eligibility_ids) AND eligible.license_id=NEW.license_id AND eligible.duty=NEW.duty AND eligible.issuer=proof->>'issuer'
   AND eligible.revoked_at IS NULL AND eligible.expires_at>license_now()+interval '5 minutes' AND eligible.max_duration_seconds<=NEW.max_duration_seconds
   AND eligible.user_id<>actor_id AND eligible.created_by<>actor_id AND NOT(actor_id=ANY(eligible.reviewer_user_ids))
   AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false)<>cardinality(NEW.prepared_eligibility_ids)
  THEN RAISE EXCEPTION 'Independent usable prepared eligibility required' USING ERRCODE='23514'; END IF;
 NEW.updated_at=license_now();RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_policy_catalog_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.license_type NOT IN ('per_user','subscription') AND EXISTS(SELECT 1 FROM license_scope_activation_policies WHERE license_id=NEW.id)
  THEN RAISE EXCEPTION 'Governed human pool cannot change scope' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_scope_policy_catalog_guard ON license_catalog;
CREATE TRIGGER license_scope_policy_catalog_guard BEFORE UPDATE ON license_catalog FOR EACH ROW EXECUTE FUNCTION license_scope_policy_catalog_guard();
CREATE OR REPLACE FUNCTION license_scope_policy_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO license_scope_policy_audit(license_id,duty,version,actor,reason,details) VALUES(NEW.license_id,NEW.duty,NEW.version,
  NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb,NULLIF(current_setting('opendirectory.scope_reason',true),''),to_jsonb(NEW));RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_scope_policy_guard ON license_scope_activation_policies;
CREATE TRIGGER license_scope_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON license_scope_activation_policies FOR EACH ROW EXECUTE FUNCTION license_scope_policy_guard();
DROP TRIGGER IF EXISTS license_scope_policy_changed ON license_scope_activation_policies;
CREATE TRIGGER license_scope_policy_changed AFTER INSERT OR UPDATE ON license_scope_activation_policies FOR EACH ROW EXECUTE FUNCTION license_scope_policy_changed();
DROP TRIGGER IF EXISTS license_scope_policy_audit_guard ON license_scope_policy_audit;
CREATE TRIGGER license_scope_policy_audit_guard BEFORE UPDATE OR DELETE ON license_scope_policy_audit FOR EACH ROW EXECUTE FUNCTION license_audit_append_only();
CREATE OR REPLACE FUNCTION license_scope_policy_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.scope_pool',true),'') IS NOT NULL OR NEW.actor IS DISTINCT FROM NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb
  OR current_setting('opendirectory.scope_policy_action',true) IS DISTINCT FROM 'set' THEN RAISE EXCEPTION 'Original pool policy evidence required' USING ERRCODE='42501'; END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS license_scope_policy_audit_insert ON license_scope_policy_audit;
CREATE TRIGGER license_scope_policy_audit_insert BEFORE INSERT ON license_scope_policy_audit FOR EACH ROW EXECUTE FUNCTION license_scope_policy_audit_insert();
CREATE OR REPLACE FUNCTION license_scope_policy_origin_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID; task TEXT; current_version BIGINT; maximum INTEGER; mandatory BOOLEAN; request license_scope_activation_requests;
BEGIN
 IF TG_TABLE_NAME='license_scope_activation_requests' THEN SELECT license_id,duty INTO pool_id,task FROM license_scope_eligibilities WHERE id=NEW.eligibility_id;
 ELSE pool_id=NEW.license_id;task=NEW.duty;END IF;
 PERFORM 1 FROM license_catalog WHERE id=pool_id FOR UPDATE;current_version=license_scope_policy_version(pool_id,task);
 SELECT max_duration_seconds,activation_required INTO maximum,mandatory FROM license_scope_activation_policies WHERE license_id=pool_id AND duty=task;maximum=COALESCE(maximum,28800);
 IF TG_OP='UPDATE' THEN
  IF NEW.policy_version<>OLD.policy_version THEN RAISE EXCEPTION 'Policy birth origin is immutable' USING ERRCODE='42501'; END IF;
  IF TG_TABLE_NAME='license_scope_activation_requests' THEN
   IF NEW.status IN ('approved','denied','activated') AND NEW.status IS DISTINCT FROM OLD.status AND NOT license_scope_request_current(OLD.id)
    THEN RAISE EXCEPTION 'Activation policy origin changed' USING ERRCODE='42501';END IF;
  END IF;
 ELSE
  NEW.policy_version=current_version;
  IF TG_TABLE_NAME='license_scope_grants' THEN
   IF NEW.activation_request_id IS NULL THEN
    IF mandatory OR NEW.expires_at>license_now()+maximum*interval '1 second' THEN RAISE EXCEPTION 'Pool policy requires bounded PIM instead of standing authority' USING ERRCODE='42501'; END IF;
   ELSE
    SELECT * INTO request FROM license_scope_activation_requests WHERE id=NEW.activation_request_id;
    IF request.id IS NULL OR NOT license_scope_request_current(request.id) OR NEW.expires_at>license_now()+maximum*interval '1 second' THEN RAISE EXCEPTION 'Current activation policy origin required' USING ERRCODE='42501'; END IF;
   END IF;
  ELSIF TG_TABLE_NAME='license_scope_eligibilities' THEN
   IF NEW.max_duration_seconds>maximum THEN RAISE EXCEPTION 'Eligibility exceeds pool activation policy' USING ERRCODE='23514'; END IF;
  ELSIF NEW.requested_duration_seconds>maximum THEN RAISE EXCEPTION 'Request exceeds pool activation policy' USING ERRCODE='23514'; END IF;
 END IF;RETURN NEW;
END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_scope_grants','license_scope_eligibilities','license_scope_activation_requests'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS a0_license_scope_policy_origin ON %I',table_name);
  EXECUTE format('CREATE TRIGGER a0_license_scope_policy_origin BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_policy_origin_guard()',table_name);
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION license_scope_auto_approval_allowed(pool UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM license_scope_activation_policies WHERE license_id=pool AND duty IN ('allocator','approver') AND activation_required);
$$;
CREATE OR REPLACE FUNCTION license_scope_require_operation(pool UUID, operation TEXT) RETURNS void LANGUAGE plpgsql AS $$
DECLARE task TEXT; mandatory BOOLEAN; lease UUID; actor TEXT;
BEGIN
 IF operation NOT IN ('assignments.manage','requests.review') THEN RAISE EXCEPTION 'Unknown license policy operation' USING ERRCODE='42501'; END IF;
 task=CASE WHEN operation='requests.review' THEN 'approver' ELSE 'allocator' END;
 mandatory=EXISTS(SELECT 1 FROM license_scope_activation_policies WHERE license_id=pool AND activation_required AND (duty=task OR operation='requests.review' AND duty='allocator'));
 IF mandatory THEN
  lease=NULLIF(current_setting('opendirectory.scope_grant',true),'')::uuid;actor=current_setting('opendirectory.scope_user',true);
  IF current_setting('opendirectory.scope_pool',true) IS DISTINCT FROM pool::text OR current_setting('opendirectory.scope_permission',true) IS DISTINCT FROM operation
   OR NOT EXISTS(SELECT 1 FROM license_scope_grants WHERE id=lease AND license_id=pool AND user_id::text=actor AND duty=task AND activation_request_id IS NOT NULL AND license_scope_grant_usable(id))
   THEN RAISE EXCEPTION 'Approved active pool PIM scope required' USING ERRCODE='42501'; END IF;
 END IF;
 PERFORM set_config('opendirectory.license_admin_operation',operation,true);
END; $$;
CREATE OR REPLACE FUNCTION license_scope_review_reduction(grant_identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(current_setting('opendirectory.license_review_action',true)='deny',false) AND EXISTS(
  SELECT 1 FROM license_review_leases lease JOIN license_review_policies policy ON policy.id=lease.policy_id JOIN license_grants grants ON grants.id=lease.grant_id
  CROSS JOIN LATERAL (SELECT NULLIF(current_setting('opendirectory.license_review_proof',true),'')::jsonb AS proof) authority
  WHERE lease.grant_id=grant_identity AND lease.state='pending' AND lease.deadline_at>license_now()
   AND authority.proof->>'reviewedPolicyVersion'=policy.version::text AND authority.proof->>'reviewedSourceVersion' ~ '^[1-9][0-9]{0,18}$'
   AND authority.proof->>'userId'=current_setting('opendirectory.license_actor_user',true) AND authority.proof->>'issuer'=current_setting('opendirectory.license_actor_issuer',true)
   AND authority.proof->>'subject'=current_setting('opendirectory.license_actor_subject',true)
   AND (authority.proof->>'userId')::uuid=ANY(policy.reviewer_user_ids)
   AND (grants.kind<>'direct' OR grants.recipient_id<>authority.proof->>'userId')
   AND NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=grant_identity AND user_id=authority.proof->>'userId'));
$$;
CREATE OR REPLACE FUNCTION license_scope_business_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID; operation TEXT; maintenance BOOLEAN; payload JSONB; derivation JSONB;
BEGIN
 payload=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;pool_id=(payload->>'license_id')::uuid;
 PERFORM 1 FROM license_catalog WHERE id=pool_id FOR UPDATE;operation=COALESCE(NULLIF(current_setting('opendirectory.license_admin_operation',true),''),'assignments.manage');
 IF TG_TABLE_NAME='license_assignments' THEN
  IF payload->>'assignee_type'<>'user' AND EXISTS(SELECT 1 FROM license_scope_activation_policies WHERE license_id=pool_id) THEN RAISE EXCEPTION 'Governed human pool rejects device materialization' USING ERRCODE='42501';END IF;
  IF TG_OP='DELETE' THEN
   maintenance=OLD.expires_at<=license_now() OR EXISTS(SELECT 1 FROM license_subjects WHERE user_id=OLD.assignee_id AND (disabled OR directory_enabled=false))
    OR NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=pool_id AND user_id=OLD.assignee_id AND (license_source_expiry(grant_id,expires_at) IS NULL OR license_source_expiry(grant_id,expires_at)>license_now()));
   IF NOT COALESCE(maintenance,false) THEN PERFORM license_scope_require_operation(pool_id,operation);END IF;
  END IF;
 ELSIF TG_TABLE_NAME='license_requests' THEN
  IF TG_OP='INSERT' AND NEW.status='approved' OR TG_OP='UPDATE' AND NEW.status IN ('approved','denied') AND NEW.status IS DISTINCT FROM OLD.status THEN PERFORM license_scope_require_operation(pool_id,'requests.review');END IF;
 ELSIF TG_TABLE_NAME='license_grants' THEN PERFORM license_scope_require_operation(pool_id,operation);
 ELSIF TG_TABLE_NAME='license_group_rules' THEN
  IF TG_OP='INSERT' OR TG_OP='UPDATE' AND (NEW.enabled AND NOT OLD.enabled OR NEW.expires_at IS DISTINCT FROM OLD.expires_at) THEN PERFORM license_scope_require_operation(pool_id,operation);
  ELSIF TG_OP='DELETE' OR TG_OP='UPDATE' AND OLD.enabled AND NOT NEW.enabled THEN
   derivation=NULLIF(current_setting('opendirectory.group_derivation',true),'')::jsonb;
   maintenance=license_source_expiry(OLD.grant_id,OLD.expires_at)<=license_now() OR license_scope_review_reduction(OLD.grant_id) OR derivation->>'licenseId'=pool_id::text AND derivation->>'groupId'=OLD.group_id;
   IF NOT COALESCE(maintenance,false) THEN PERFORM license_scope_require_operation(pool_id,operation);END IF;
  END IF;
 ELSIF payload->>'source_type'='direct' THEN
  IF TG_OP='DELETE' THEN
   maintenance=license_source_expiry(OLD.grant_id,OLD.expires_at)<=license_now() OR license_scope_review_reduction(OLD.grant_id) OR EXISTS(SELECT 1 FROM license_subjects WHERE user_id=OLD.user_id AND (disabled OR directory_enabled=false));
   IF NOT COALESCE(maintenance,false) THEN PERFORM license_scope_require_operation(pool_id,operation);END IF;
  ELSE PERFORM license_scope_require_operation(pool_id,operation);END IF;
 ELSE
  derivation=NULLIF(current_setting('opendirectory.group_derivation',true),'')::jsonb;
  maintenance=derivation->>'licenseId'=pool_id::text AND derivation->>'groupId'=payload->>'source_id';
  IF TG_OP='DELETE' THEN maintenance=maintenance OR license_source_expiry(OLD.grant_id,OLD.expires_at)<=license_now()
   OR EXISTS(SELECT 1 FROM license_subjects WHERE user_id=OLD.user_id AND (disabled OR directory_enabled=false))
   OR EXISTS(SELECT 1 FROM license_group_rules WHERE license_id=pool_id AND group_id=OLD.source_id AND NOT enabled);END IF;
  IF NOT COALESCE(maintenance,false) THEN PERFORM license_scope_require_operation(pool_id,operation);END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_grants','license_group_rules','license_assignment_sources','license_requests','license_assignments'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS a1_license_scope_business ON %I',table_name);
  EXECUTE format('CREATE TRIGGER a1_license_scope_business BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_business_guard()',table_name);
 END LOOP;
END; $$;

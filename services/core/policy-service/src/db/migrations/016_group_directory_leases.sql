CREATE TABLE IF NOT EXISTS license_group_observations (
 grant_id UUID PRIMARY KEY REFERENCES license_grants(id),license_id UUID NOT NULL,group_id UUID NOT NULL,version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 source_revision BIGINT NOT NULL CHECK(source_revision>0),source_hash TEXT NOT NULL CHECK(source_hash ~ '^[a-f0-9]{64}$'),observed_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL CHECK(valid_until=observed_at+interval '300 seconds')
);
CREATE TABLE IF NOT EXISTS license_group_member_leases (
 grant_id UUID NOT NULL REFERENCES license_group_observations(grant_id),user_id UUID NOT NULL,membership_id UUID NOT NULL,eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),
 observation_version BIGINT NOT NULL CHECK(observation_version>0),source_revision BIGINT NOT NULL CHECK(source_revision>0),review_deadline_at TIMESTAMPTZ,valid_until TIMESTAMPTZ NOT NULL,PRIMARY KEY(grant_id,user_id)
);
CREATE TABLE IF NOT EXISTS license_group_lease_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),grant_id UUID NOT NULL REFERENCES license_grants(id),kind TEXT NOT NULL,actor JSONB NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
CREATE OR REPLACE FUNCTION license_member_source_expiry(grant_identity UUID,canonical_user TEXT,base_expiry TIMESTAMPTZ) RETURNS timestamptz LANGUAGE sql VOLATILE AS $$
 SELECT date_trunc('milliseconds',LEAST(license_source_expiry(grant_identity,base_expiry),CASE WHEN grants.kind='group' THEN
  COALESCE((SELECT member.valid_until FROM license_group_member_leases member JOIN license_group_observations observation ON observation.grant_id=member.grant_id
   JOIN license_group_rules rule ON rule.grant_id=member.grant_id AND rule.enabled JOIN license_subjects subject ON subject.user_id=member.user_id::text
   WHERE member.grant_id=grant_identity AND member.user_id::text=canonical_user AND member.observation_version=observation.version
    AND subject.directory_revision=member.eligibility_revision AND NOT subject.disabled AND subject.directory_enabled IS DISTINCT FROM false AND subject.directory_deleted IS DISTINCT FROM true),'-infinity'::timestamptz)
  ELSE NULL END)) FROM license_grants grants WHERE grants.id=grant_identity
 UNION ALL SELECT '-infinity'::timestamptz WHERE NOT EXISTS(SELECT 1 FROM license_grants WHERE id=grant_identity);
$$;
CREATE OR REPLACE FUNCTION license_group_lease_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;observation license_group_observations;parent license_group_rules;member JSONB;derivation JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Directory lease evidence is retained' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.group_snapshot',true),'')::jsonb;
 SELECT * INTO parent FROM license_group_rules WHERE grant_id=NEW.grant_id AND enabled FOR SHARE;
 IF proof IS NULL OR proof->>'schemaVersion' IS DISTINCT FROM '2' OR parent.grant_id IS NULL OR proof->>'groupId' IS DISTINCT FROM parent.group_id
  OR proof->>'licenseId' IS DISTINCT FROM parent.license_id::text OR proof->>'grantId' IS DISTINCT FROM parent.grant_id::text
  THEN RAISE EXCEPTION 'Current source-bound directory observation required' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM license_catalog WHERE id=parent.license_id FOR UPDATE;
 derivation=NULLIF(current_setting('opendirectory.group_derivation',true),'')::jsonb;
 IF derivation->>'licenseId' IS DISTINCT FROM parent.license_id::text OR derivation->>'groupId' IS DISTINCT FROM parent.group_id THEN
  PERFORM license_scope_require_operation(parent.license_id,COALESCE(NULLIF(current_setting('opendirectory.license_admin_operation',true),''),'assignments.manage'));
 END IF;
 IF TG_TABLE_NAME='license_group_observations' THEN
  IF NEW.license_id<>parent.license_id OR NEW.group_id::text<>parent.group_id OR NEW.source_revision::text IS DISTINCT FROM proof->>'revision' OR NEW.source_hash IS DISTINCT FROM proof->>'hash'
   OR NEW.observed_at IS DISTINCT FROM (proof->>'observedAt')::timestamptz OR NEW.valid_until IS DISTINCT FROM (proof->>'validUntil')::timestamptz
   OR NEW.observed_at>license_now()+interval '5 seconds' OR NEW.valid_until<=license_now() OR NEW.valid_until<>NEW.observed_at+interval '300 seconds'
   THEN RAISE EXCEPTION 'Fresh bounded exact observation required' USING ERRCODE='23514';END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.version<>1 THEN RAISE EXCEPTION 'Original observation generation required' USING ERRCODE='23514';END IF;
  ELSE
   IF ROW(NEW.grant_id,NEW.license_id,NEW.group_id) IS DISTINCT FROM ROW(OLD.grant_id,OLD.license_id,OLD.group_id) OR NEW.version<>OLD.version+1
    OR NEW.source_revision<OLD.source_revision OR NEW.source_revision=OLD.source_revision AND NEW.source_hash<>OLD.source_hash OR NEW.observed_at<OLD.observed_at
    THEN RAISE EXCEPTION 'Directory observations cannot regress or retarget' USING ERRCODE='23514';END IF;
  END IF;
 ELSE
  SELECT * INTO observation FROM license_group_observations WHERE grant_id=NEW.grant_id;
  SELECT value INTO member FROM jsonb_array_elements(proof->'memberships') WHERE value->>'userId'=NEW.user_id::text;
  IF member IS NULL OR NEW.observation_version<>observation.version OR NEW.source_revision<>observation.source_revision
   OR NEW.membership_id::text IS DISTINCT FROM member->>'membershipId' OR NEW.eligibility_revision::text IS DISTINCT FROM member->>'eligibilityRevision'
   OR NEW.review_deadline_at IS DISTINCT FROM (member->>'reviewDeadlineAt')::timestamptz
   OR NEW.valid_until IS DISTINCT FROM LEAST(observation.valid_until,NEW.review_deadline_at) OR NEW.valid_until<=license_now()
   OR observation.source_hash IS DISTINCT FROM proof->>'hash' OR observation.observed_at IS DISTINCT FROM (proof->>'observedAt')::timestamptz
   OR NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=NEW.user_id::text AND directory_revision=NEW.eligibility_revision AND NOT disabled AND directory_enabled AND directory_deleted IS NOT TRUE)
   THEN RAISE EXCEPTION 'Exact current member incarnation and deadline required' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' THEN
   IF ROW(NEW.grant_id,NEW.user_id) IS DISTINCT FROM ROW(OLD.grant_id,OLD.user_id) OR NEW.observation_version<=OLD.observation_version OR NEW.source_revision<OLD.source_revision
    OR NEW.source_revision=OLD.source_revision AND ROW(NEW.membership_id,NEW.eligibility_revision,NEW.review_deadline_at) IS DISTINCT FROM ROW(OLD.membership_id,OLD.eligibility_revision,OLD.review_deadline_at)
    THEN RAISE EXCEPTION 'Member leases cannot regress or change within a source revision' USING ERRCODE='23514';END IF;
  END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_group_lease_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO license_group_lease_audit(grant_id,kind,actor,details) VALUES(NEW.grant_id,TG_TABLE_NAME||':'||lower(TG_OP),
  jsonb_build_object('userId',NULLIF(current_setting('opendirectory.license_actor_user',true),''),'issuer',NULLIF(current_setting('opendirectory.license_actor_issuer',true),''),'subject',NULLIF(current_setting('opendirectory.license_actor_subject',true),'')),to_jsonb(NEW));RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_group_lease_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Directory lease evidence is append-only and transition-derived' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_group_observations','license_group_member_leases'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_group_lease_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_group_lease_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_group_lease_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS license_group_lease_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_group_lease_changed AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION license_group_lease_changed()',table_name);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS license_group_lease_audit_guard ON license_group_lease_audit;
CREATE TRIGGER license_group_lease_audit_guard BEFORE INSERT OR UPDATE OR DELETE ON license_group_lease_audit FOR EACH ROW EXECUTE FUNCTION license_group_lease_audit_guard();
CREATE OR REPLACE FUNCTION license_group_source_lease_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.source_type='group' AND license_member_source_expiry(NEW.grant_id,NEW.user_id,NEW.expires_at)<=license_now()
  THEN RAISE EXCEPTION 'Live observed membership lease required' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS zz_license_group_source_lease ON license_assignment_sources;
CREATE TRIGGER zz_license_group_source_lease AFTER INSERT OR UPDATE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION license_group_source_lease_guard();
DO $$ DECLARE signature TEXT;definition TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY['license_assignment_no_update()','license_review_pool_guard()','license_scope_business_guard()'] LOOP
  definition=pg_get_functiondef(signature::regprocedure);
  definition=replace(definition,'license_source_expiry(grant_id,expires_at)','license_member_source_expiry(grant_id,user_id,expires_at)');
  definition=replace(definition,$pattern$IF TG_OP='DELETE' THEN maintenance=maintenance OR license_source_expiry(OLD.grant_id,OLD.expires_at)$pattern$,$replacement$IF TG_OP='DELETE' THEN maintenance=maintenance OR license_member_source_expiry(OLD.grant_id,OLD.user_id,OLD.expires_at)$replacement$);
  EXECUTE definition;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION license_lease_projection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expiry TIMESTAMPTZ;source_count INTEGER;
BEGIN
 IF NEW.assignee_type<>'user' THEN RETURN NEW;END IF;
 SELECT count(*),CASE WHEN bool_or(effective IS NULL) THEN NULL ELSE max(effective) END INTO source_count,expiry
  FROM(SELECT license_member_source_expiry(grant_id,user_id,expires_at) AS effective FROM license_assignment_sources WHERE license_id=NEW.license_id AND user_id=NEW.assignee_id) sources
  WHERE effective IS NULL OR effective>license_now();
 IF source_count=0 OR NEW.expires_at IS DISTINCT FROM expiry THEN RAISE EXCEPTION 'Human projection requires exact effective source leases' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS zz_license_lease_projection_guard ON license_assignments;
CREATE TRIGGER zz_license_lease_projection_guard BEFORE INSERT OR UPDATE ON license_assignments FOR EACH ROW EXECUTE FUNCTION license_lease_projection_guard();
CREATE OR REPLACE FUNCTION license_group_lease_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM license_group_rules WHERE grant_id=NEW.grant_id AND enabled AND (NEW.valid_until<=license_now() OR license_source_expiry(grant_id,expires_at)<=license_now()))
  THEN RAISE EXCEPTION 'Directory lease expired before commit' USING ERRCODE='23514',CONSTRAINT='license_group_directory_lease';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_group_observations','license_group_member_leases'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_group_lease_commit_guard ON %I',table_name);
  EXECUTE format('CREATE CONSTRAINT TRIGGER license_group_lease_commit_guard AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION license_group_lease_commit_guard()',table_name);
 END LOOP;
END; $$;
DO $$ DECLARE target RECORD;expiry TIMESTAMPTZ;source_count INTEGER;BEGIN
 IF NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=16) THEN
  FOR target IN SELECT DISTINCT license_id,user_id FROM license_assignment_sources WHERE source_type='group' ORDER BY license_id,user_id LOOP
   PERFORM 1 FROM license_catalog WHERE id=target.license_id FOR UPDATE;
   SELECT count(*),CASE WHEN bool_or(effective IS NULL) THEN NULL ELSE max(effective) END INTO source_count,expiry
    FROM(SELECT license_member_source_expiry(grant_id,user_id,expires_at) AS effective FROM license_assignment_sources WHERE license_id=target.license_id AND user_id=target.user_id) sources WHERE effective IS NULL OR effective>license_now();
   IF source_count=0 THEN DELETE FROM license_assignments WHERE license_id=target.license_id AND assignee_type='user' AND assignee_id=target.user_id;
   ELSE UPDATE license_assignments SET expires_at=expiry WHERE license_id=target.license_id AND assignee_type='user' AND assignee_id=target.user_id AND expires_at IS DISTINCT FROM expiry;END IF;
   INSERT INTO license_audit_events(license_id,action,actor,details) VALUES(target.license_id,'unobserved-group-projection-fenced','system:group-lease-migration',jsonb_build_object('userId',target.user_id));
  END LOOP;
  INSERT INTO license_schema_versions(version) VALUES(16);
 END IF;
END; $$;

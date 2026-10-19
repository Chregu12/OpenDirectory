CREATE TABLE IF NOT EXISTS license_scope_grants (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 license_id UUID NOT NULL REFERENCES license_catalog(id),
 user_id UUID NOT NULL,
 issuer TEXT NOT NULL,
 duty TEXT NOT NULL CHECK(duty IN ('reader','allocator','approver')),
 eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),
 delegation_revision TEXT NOT NULL CHECK(delegation_revision ~ '^[a-f0-9]{64}$'),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now(),
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS license_scope_incarnation ON license_scope_grants(license_id,user_id,duty) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS license_scope_subject ON license_scope_grants(user_id,issuer,license_id,expires_at);
CREATE TABLE IF NOT EXISTS license_scope_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 grant_id UUID NOT NULL REFERENCES license_scope_grants(id),
 action TEXT NOT NULL,
 actor JSONB NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_now()
);
CREATE OR REPLACE FUNCTION license_scope_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Delegation history is retained' USING ERRCODE='42501'; END IF;
 proof=NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb;
 IF proof IS NULL OR COALESCE(proof->>'userId','') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  OR COALESCE(proof->>'issuer','')='' OR COALESCE(proof->>'subject','')='' THEN RAISE EXCEPTION 'Canonical delegation authority required' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.revoked_at IS NOT NULL OR NEW.user_id::text=proof->>'userId' OR NEW.issuer<>proof->>'issuer'
   OR NEW.expires_at<=license_now() OR NEW.expires_at>license_now()+interval '8 hours'
   OR NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=NEW.license_id AND license_type IN ('per_user','subscription'))
   OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=NEW.license_id AND assignee_type<>'user') THEN
   RAISE EXCEPTION 'Independent bounded human-pool delegation required' USING ERRCODE='23514';
  END IF;
  NEW.created_at=license_now();
 ELSE
  IF (to_jsonb(NEW)-ARRAY['revoked_at','version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revoked_at','version'])
    OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.version<>OLD.version+1 THEN
   RAISE EXCEPTION 'Delegation permits only one-way conditional revocation' USING ERRCODE='42501';
  END IF;
  NEW.revoked_at=license_now();
 END IF;
 RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION license_scope_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO license_scope_audit(grant_id,action,actor,reason,details) VALUES(NEW.id,lower(TG_OP),
   NULLIF(current_setting('opendirectory.scope_proof',true),'')::jsonb,NULLIF(current_setting('opendirectory.scope_reason',true),''),to_jsonb(NEW));
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_scope_guard ON license_scope_grants;
CREATE TRIGGER license_scope_guard BEFORE INSERT OR UPDATE OR DELETE ON license_scope_grants FOR EACH ROW EXECUTE FUNCTION license_scope_guard();
DROP TRIGGER IF EXISTS license_scope_changed ON license_scope_grants;
CREATE TRIGGER license_scope_changed AFTER INSERT OR UPDATE ON license_scope_grants FOR EACH ROW EXECUTE FUNCTION license_scope_changed();
DROP TRIGGER IF EXISTS license_scope_audit_guard ON license_scope_audit;
CREATE TRIGGER license_scope_audit_guard BEFORE UPDATE OR DELETE ON license_scope_audit FOR EACH ROW EXECUTE FUNCTION license_audit_append_only();
CREATE OR REPLACE FUNCTION license_scope_pool_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID;
BEGIN
 IF TG_TABLE_NAME='license_catalog' THEN pool_id=NEW.id; ELSE pool_id=NEW.license_id; END IF;
 IF EXISTS(SELECT 1 FROM license_scope_grants WHERE license_id=pool_id) THEN
  IF TG_TABLE_NAME='license_catalog' THEN
   IF NEW.license_type NOT IN ('per_user','subscription') THEN RAISE EXCEPTION 'Delegated human pool cannot change scope' USING ERRCODE='23514'; END IF;
  ELSIF NEW.assignee_type<>'user' THEN RAISE EXCEPTION 'Delegated pool requires human user sources' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_scope_pool_guard ON license_catalog;
CREATE TRIGGER license_scope_pool_guard BEFORE UPDATE ON license_catalog FOR EACH ROW EXECUTE FUNCTION license_scope_pool_guard();
DROP TRIGGER IF EXISTS license_scope_assignment_guard ON license_assignments;
CREATE TRIGGER license_scope_assignment_guard BEFORE INSERT ON license_assignments FOR EACH ROW EXECUTE FUNCTION license_scope_pool_guard();
CREATE OR REPLACE FUNCTION license_scope_resource_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pool_id UUID; record_pool UUID; payload JSONB; permission TEXT;
BEGIN
 pool_id=NULLIF(current_setting('opendirectory.scope_pool',true),'')::uuid;
 IF pool_id IS NULL THEN IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END IF;
 permission=current_setting('opendirectory.scope_permission',true);
 IF permission IS NULL OR permission NOT IN ('assignments.manage','requests.review') OR TG_TABLE_NAME='license_scope_grants' THEN
  RAISE EXCEPTION 'Delegated operation cannot mutate this resource' USING ERRCODE='42501';
 END IF;
 payload=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 IF TG_TABLE_NAME='license_catalog' THEN
  record_pool=(payload->>'id')::uuid;
  IF TG_OP<>'UPDATE' OR (to_jsonb(NEW)-ARRAY['used_seats','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['used_seats','updated_at']) THEN
   RAISE EXCEPTION 'Delegation cannot manage the catalog' USING ERRCODE='42501';
  END IF;
 ELSIF TG_TABLE_NAME='license_grant_events' THEN
  SELECT license_id INTO record_pool FROM license_grants WHERE id=(payload->>'grant_id')::uuid;
 ELSIF TG_TABLE_NAME='license_scope_audit' THEN
  SELECT license_id INTO record_pool FROM license_scope_grants WHERE id=(payload->>'grant_id')::uuid;
  IF TG_OP<>'INSERT' OR NEW.action<>'use' OR NEW.grant_id::text IS DISTINCT FROM current_setting('opendirectory.scope_grant',true)
    OR NEW.actor->>'userId' IS DISTINCT FROM current_setting('opendirectory.scope_user',true) OR NEW.details->>'permission' IS DISTINCT FROM permission THEN
   RAISE EXCEPTION 'Delegation evidence must match its captured authority' USING ERRCODE='42501';
  END IF;
 ELSE record_pool=(payload->>'license_id')::uuid; END IF;
 IF record_pool IS DISTINCT FROM pool_id THEN RAISE EXCEPTION 'Delegated write exceeds its license pool' USING ERRCODE='42501'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;
DO $$
DECLARE table_name TEXT;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_catalog','license_assignments','license_assignment_sources','license_group_rules','license_requests',
   'license_grants','license_grant_events','license_audit_events','license_scope_grants','license_scope_audit'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS a_license_scope_resource_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER a_license_scope_resource_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_scope_resource_guard()',table_name);
 END LOOP;
END;
$$;

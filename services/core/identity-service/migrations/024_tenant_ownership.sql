CREATE SEQUENCE IF NOT EXISTS identity_tenant_generation_seq;
CREATE TABLE IF NOT EXISTS identity_tenants (
 id UUID PRIMARY KEY,external_key TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT false,
 version BIGINT NOT NULL DEFAULT 1,generation BIGINT NOT NULL DEFAULT nextval('identity_tenant_generation_seq'),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_tenant_ownership (
 resource_kind TEXT NOT NULL CHECK(resource_kind IN('user','group','ou')),resource_id UUID NOT NULL,
 tenant_id UUID NOT NULL REFERENCES identity_tenants(id),reviewed_version BIGINT NOT NULL,
 generation BIGINT NOT NULL DEFAULT nextval('identity_tenant_generation_seq'),reason TEXT NOT NULL,
 adopted_by NAME NOT NULL DEFAULT session_user,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(resource_kind,resource_id)
);
CREATE INDEX IF NOT EXISTS identity_tenant_resources ON identity_tenant_ownership(tenant_id,resource_kind,resource_id);
CREATE TABLE IF NOT EXISTS identity_tenant_retirements (
 resource_kind TEXT NOT NULL,resource_id UUID NOT NULL,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),retired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(resource_kind,resource_id),FOREIGN KEY(resource_kind,resource_id) REFERENCES identity_tenant_ownership(resource_kind,resource_id)
);
CREATE TABLE IF NOT EXISTS identity_tenant_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL,
 actor JSONB NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_tenant_outbox (
 id UUID PRIMARY KEY REFERENCES identity_tenant_events(id),tenant_id UUID NOT NULL,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_generation BIGINT NOT NULL DEFAULT 0;
CREATE OR REPLACE FUNCTION identity_tenant_id(kind TEXT,identity UUID) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT tenant_id FROM identity_tenant_ownership WHERE resource_kind=kind AND resource_id=identity;
$$;
CREATE OR REPLACE FUNCTION identity_tenant_user_enabled(identity UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT COALESCE((SELECT account.enabled AND tenant.enabled FROM users account JOIN identity_tenant_ownership ownership
  ON ownership.resource_kind='user' AND ownership.resource_id=account.id JOIN identity_tenants tenant ON tenant.id=ownership.tenant_id WHERE account.id=identity),false);
$$;
CREATE OR REPLACE FUNCTION identity_tenant_review(relation_identity OID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE owner_role NAME;explanation TEXT;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO owner_role FROM pg_class WHERE oid=relation_identity;
 explanation=current_setting('opendirectory.tenant_reason',true);
 IF owner_role IS NULL OR NOT pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  OR current_setting('opendirectory.tenant_review',true) IS DISTINCT FROM 'explicit-offline-owner-review'
  OR explanation IS NULL OR length(btrim(explanation)) NOT BETWEEN 10 AND 500 OR explanation ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'Explicit actual-owner tenant review required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_lock(resources TEXT[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE resource TEXT;
BEGIN
 FOR resource IN SELECT DISTINCT unnest(resources) ORDER BY 1 LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('identity-tenant-resource:'||resource,0));
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Tenant identities are retained' USING ERRCODE='42501';END IF;
 PERFORM identity_tenant_review(TG_RELID);
 IF TG_OP='INSERT' THEN
  IF NEW.enabled OR NEW.external_key!~'^[a-z0-9][a-z0-9._-]{0,63}$' OR length(btrim(NEW.display_name)) NOT BETWEEN 1 AND 255 OR NEW.display_name ~ '[[:cntrl:]]'
   THEN RAISE EXCEPTION 'Create a bounded disabled tenant before reviewed enablement' USING ERRCODE='23514';END IF;NEW.version=1;NEW.created_at=clock_timestamp();
 ELSE
  IF (to_jsonb(NEW)-ARRAY['enabled','version','generation']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','version','generation']) OR NEW.version<>OLD.version+1
   THEN RAISE EXCEPTION 'Tenant identity is immutable and enablement conditional' USING ERRCODE='23514';END IF;
 END IF;
 NEW.generation=nextval('identity_tenant_generation_seq');RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_record(tenant_identity UUID,transition TEXT,evidence JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event UUID;
BEGIN
 INSERT INTO identity_tenant_events(tenant_id,action,actor,details) VALUES(tenant_identity,transition,jsonb_build_object('databaseRole',session_user),evidence) RETURNING id INTO event;
 INSERT INTO identity_tenant_outbox(id,tenant_id,action) VALUES(event,tenant_identity,transition);
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_tenant_record(NEW.id,'tenant-'||lower(TG_OP),jsonb_build_object('enabled',NEW.enabled,'version',NEW.version::text,'generation',NEW.generation::text,'reason',current_setting('opendirectory.tenant_reason',true)));
 IF TG_OP='UPDATE' THEN
  UPDATE users SET updated_at=updated_at WHERE id IN(SELECT resource_id FROM identity_tenant_ownership WHERE tenant_id=NEW.id AND resource_kind='user');
  UPDATE groups SET name=name WHERE id IN(SELECT resource_id FROM identity_tenant_ownership WHERE tenant_id=NEW.id AND resource_kind='group');
 END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_ownership_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tenant identity_tenants%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Canonical tenant ownership cannot be moved or erased' USING ERRCODE='42501';END IF;
 PERFORM identity_tenant_review(TG_RELID);
 PERFORM identity_tenant_lock(ARRAY[NEW.resource_kind||':'||NEW.resource_id::text]);
 SELECT * INTO tenant FROM identity_tenants WHERE id=NEW.tenant_id FOR SHARE;
 IF tenant.id IS NULL OR NEW.reviewed_version<>tenant.version OR NEW.reason IS DISTINCT FROM btrim(current_setting('opendirectory.tenant_reason',true))
  THEN RAISE EXCEPTION 'Current exact tenant adoption review required' USING ERRCODE='23514';END IF;
 NEW.generation=nextval('identity_tenant_generation_seq');NEW.adopted_by=session_user;NEW.created_at=clock_timestamp();RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_ownership_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_tenant_record(NEW.tenant_id,'resource-adopted',jsonb_build_object('kind',NEW.resource_kind,'resourceId',NEW.resource_id,'generation',NEW.generation::text,'reviewedVersion',NEW.reviewed_version::text,'reason',NEW.reason));
 IF NEW.resource_kind='user' THEN UPDATE users SET updated_at=updated_at WHERE id=NEW.resource_id;
 ELSIF NEW.resource_kind='group' THEN UPDATE groups SET name=name WHERE id=NEW.resource_id;
 ELSE UPDATE ous SET name=name WHERE id=NEW.resource_id;END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_ownership_check() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE present BOOLEAN;
BEGIN
 IF NEW.resource_kind='user' THEN
  present=EXISTS(SELECT 1 FROM users WHERE id=NEW.resource_id);
  IF EXISTS(SELECT 1 FROM group_members WHERE user_id=NEW.resource_id::text AND identity_tenant_id('group',group_id) IS DISTINCT FROM NEW.tenant_id)
   THEN RAISE EXCEPTION 'Adopt the complete reviewed same-tenant membership component' USING ERRCODE='23514';END IF;
 ELSIF NEW.resource_kind='group' THEN
  present=EXISTS(SELECT 1 FROM groups WHERE id=NEW.resource_id);
  IF EXISTS(SELECT 1 FROM group_members WHERE group_id=NEW.resource_id AND CASE WHEN user_id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
   THEN identity_tenant_id('user',user_id::uuid) IS DISTINCT FROM NEW.tenant_id ELSE true END) THEN RAISE EXCEPTION 'Adopt only fully resolved same-tenant group members' USING ERRCODE='23514';END IF;
 ELSE
  present=EXISTS(SELECT 1 FROM ous WHERE id=NEW.resource_id);
  IF EXISTS(SELECT 1 FROM ous WHERE id=NEW.resource_id AND parent_id IS NOT NULL AND identity_tenant_id('ou',parent_id) IS DISTINCT FROM NEW.tenant_id)
   OR EXISTS(SELECT 1 FROM ous WHERE parent_id=NEW.resource_id AND identity_tenant_id('ou',id) IS DISTINCT FROM NEW.tenant_id)
   THEN RAISE EXCEPTION 'Adopt the complete reviewed OU ownership component' USING ERRCODE='23514';END IF;
 END IF;
 IF NOT present AND NOT EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind=NEW.resource_kind AND resource_id=NEW.resource_id AND tenant_id=NEW.tenant_id)
  THEN RAISE EXCEPTION 'Adoption cannot invent a canonical resource' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_user_generation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE generation BIGINT;
BEGIN
 SELECT GREATEST(ownership.generation,tenant.generation) INTO generation FROM identity_tenant_ownership ownership JOIN identity_tenants tenant ON tenant.id=ownership.tenant_id
  WHERE ownership.resource_kind='user' AND ownership.resource_id=NEW.id;
 NEW.tenant_generation=COALESCE(generation,0);
 IF TG_OP='UPDATE' AND NEW.tenant_generation IS DISTINCT FROM OLD.tenant_generation THEN
  NEW.eligibility_revision=nextval('identity_user_revision_seq');NEW.authorization_revision=nextval('identity_authorization_revision_seq');
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_user_generation_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE evidence JSONB;
BEGIN
 IF NEW.tenant_generation IS NOT DISTINCT FROM OLD.tenant_generation THEN RETURN NULL;END IF;
 evidence=jsonb_build_object('userId',NEW.id,'revision',NEW.eligibility_revision::text,'enabled',identity_tenant_user_enabled(NEW.id),'deleted',false,'tenantGeneration',NEW.tenant_generation::text);
 INSERT INTO identity_user_audit(user_id,revision,actor,details) VALUES(NEW.id,NEW.eligibility_revision,session_user,evidence);
 INSERT INTO identity_user_outbox(user_id,revision,event_type,payload) VALUES(NEW.id,NEW.eligibility_revision,'identity.user.eligibility.changed',evidence);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_user_evidence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF TG_TABLE_NAME='identity_user_audit' THEN
  IF NEW.details ? 'enabled' THEN NEW.details=jsonb_set(NEW.details,'{enabled}',to_jsonb(identity_tenant_user_enabled(NEW.user_id)));END IF;
 ELSIF TG_TABLE_NAME='identity_user_outbox' THEN
  IF NEW.payload ? 'enabled' THEN NEW.payload=jsonb_set(NEW.payload,'{enabled}',to_jsonb(identity_tenant_user_enabled(NEW.user_id)));END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_membership_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE group_owner UUID;user_owner UUID;
BEGIN
 PERFORM identity_tenant_lock(ARRAY['group:'||NEW.group_id::text,'user:'||NEW.user_id]);
 IF NOT EXISTS(SELECT 1 FROM users WHERE id::text=NEW.user_id) THEN RAISE EXCEPTION 'Canonical membership user required' USING ERRCODE='23503';END IF;
 group_owner=identity_tenant_id('group',NEW.group_id);
 IF NEW.user_id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN user_owner=identity_tenant_id('user',NEW.user_id::uuid);END IF;
 IF group_owner IS DISTINCT FROM user_owner THEN RAISE EXCEPTION 'Cross-owner or unresolved owned membership forbidden' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_ou_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NEW.parent_id IS NOT NULL THEN
  PERFORM identity_tenant_lock(ARRAY['ou:'||NEW.id::text,'ou:'||NEW.parent_id::text]);
  IF identity_tenant_id('ou',NEW.id) IS DISTINCT FROM identity_tenant_id('ou',NEW.parent_id) THEN RAISE EXCEPTION 'Cross-owner OU parent forbidden' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_resource_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE kind TEXT;owner UUID;
BEGIN
 kind=CASE TG_TABLE_NAME WHEN 'users' THEN 'user' WHEN 'groups' THEN 'group' ELSE 'ou' END;
 IF TG_OP='UPDATE' THEN
  IF NEW.id IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'Canonical resource identifiers cannot be retargeted' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind=kind AND resource_id=NEW.id) THEN RAISE EXCEPTION 'Retired owned identifiers cannot be reused' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 owner=identity_tenant_id(kind,OLD.id);
 IF owner IS NOT NULL THEN
  INSERT INTO identity_tenant_retirements(resource_kind,resource_id,tenant_id) VALUES(kind,OLD.id,owner);
  PERFORM identity_tenant_record(owner,'resource-retired',jsonb_build_object('kind',kind,'resourceId',OLD.id));
 END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_enable(identity UUID,expected_version BIGINT,wanted BOOLEAN) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE tenant identity_tenants%ROWTYPE;
BEGIN
 PERFORM identity_tenant_review('identity_tenants'::regclass);
 SELECT * INTO tenant FROM identity_tenants WHERE id=identity FOR UPDATE;
 IF tenant.id IS NULL OR tenant.version<>expected_version OR wanted IS NULL THEN RAISE EXCEPTION 'Exact current tenant version required' USING ERRCODE='23514';END IF;
 UPDATE identity_tenants SET enabled=wanted,version=version+1 WHERE id=identity RETURNING * INTO tenant;
 RETURN jsonb_build_object('id',tenant.id,'enabled',tenant.enabled,'version',tenant.version::text,'generation',tenant.generation::text);
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Tenant evidence requires its actual transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_adopt(tenant_identity UUID,expected_version BIGINT,manifest JSONB) RETURNS void LANGUAGE plpgsql AS $$
DECLARE item JSONB;resources TEXT[];tenant identity_tenants%ROWTYPE;
BEGIN
 PERFORM identity_tenant_review('identity_tenant_ownership'::regclass);
 IF jsonb_typeof(manifest) IS DISTINCT FROM 'array' OR jsonb_array_length(manifest) NOT BETWEEN 1 AND 1000 OR octet_length(manifest::text)>131072
  THEN RAISE EXCEPTION 'Bounded explicit canonical adoption manifest required' USING ERRCODE='23514';END IF;
 FOR item IN SELECT * FROM jsonb_array_elements(manifest) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR NOT COALESCE(item->>'kind' IN('user','group','ou'),false)
   OR NOT COALESCE(item->>'resourceId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) THEN RAISE EXCEPTION 'Exact canonical resource identity required' USING ERRCODE='23514';END IF;
 END LOOP;
 SELECT * INTO tenant FROM identity_tenants WHERE id=tenant_identity FOR SHARE;
 IF tenant.id IS NULL OR tenant.version<>expected_version THEN RAISE EXCEPTION 'Tenant review generation changed' USING ERRCODE='23514';END IF;
 SELECT array_agg(entry->>'kind'||':'||(entry->>'resourceId')) INTO resources FROM jsonb_array_elements(manifest) entry;
 PERFORM identity_tenant_lock(resources);
 INSERT INTO identity_tenant_ownership(resource_kind,resource_id,tenant_id,reviewed_version,reason)
  SELECT entry->>'kind',(entry->>'resourceId')::uuid,tenant_identity,expected_version,btrim(current_setting('opendirectory.tenant_reason')) FROM jsonb_array_elements(manifest) entry ORDER BY entry->>'kind',entry->>'resourceId';
END; $$;
DROP TRIGGER IF EXISTS identity_tenant_guard ON identity_tenants;
CREATE TRIGGER identity_tenant_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_tenants FOR EACH ROW EXECUTE FUNCTION identity_tenant_guard();
DROP TRIGGER IF EXISTS identity_tenant_changed ON identity_tenants;
CREATE TRIGGER identity_tenant_changed AFTER INSERT OR UPDATE ON identity_tenants FOR EACH ROW EXECUTE FUNCTION identity_tenant_changed();
DROP TRIGGER IF EXISTS identity_tenant_ownership_guard ON identity_tenant_ownership;
CREATE TRIGGER identity_tenant_ownership_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_tenant_ownership FOR EACH ROW EXECUTE FUNCTION identity_tenant_ownership_guard();
DROP TRIGGER IF EXISTS identity_tenant_ownership_changed ON identity_tenant_ownership;
CREATE TRIGGER identity_tenant_ownership_changed AFTER INSERT ON identity_tenant_ownership FOR EACH ROW EXECUTE FUNCTION identity_tenant_ownership_changed();
DROP TRIGGER IF EXISTS identity_tenant_ownership_check ON identity_tenant_ownership;
CREATE CONSTRAINT TRIGGER identity_tenant_ownership_check AFTER INSERT ON identity_tenant_ownership DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_tenant_ownership_check();
DROP TRIGGER IF EXISTS zz_identity_tenant_user_generation ON users;
CREATE TRIGGER zz_identity_tenant_user_generation BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION identity_tenant_user_generation();
DROP TRIGGER IF EXISTS identity_tenant_user_generation_changed ON users;
CREATE TRIGGER identity_tenant_user_generation_changed AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION identity_tenant_user_generation_changed();
DROP TRIGGER IF EXISTS aaa_identity_tenant_membership_guard ON group_members;
CREATE TRIGGER aaa_identity_tenant_membership_guard BEFORE INSERT OR UPDATE ON group_members FOR EACH ROW EXECUTE FUNCTION identity_tenant_membership_guard();
DROP TRIGGER IF EXISTS identity_tenant_ou_guard ON ous;
CREATE TRIGGER identity_tenant_ou_guard BEFORE INSERT OR UPDATE OF parent_id ON ous FOR EACH ROW EXECUTE FUNCTION identity_tenant_ou_guard();
DO $$ DECLARE table_name TEXT;function_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['users','groups','ous'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_tenant_resource_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_tenant_resource_guard BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION identity_tenant_resource_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_tenant_resource_retired ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_tenant_resource_retired AFTER DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_tenant_resource_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_tenant_resource_identity ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_tenant_resource_identity BEFORE UPDATE OF id ON %I FOR EACH ROW EXECUTE FUNCTION identity_tenant_resource_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_tenant_resource_deletion_lock ON %I',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['identity_user_audit','identity_user_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_tenant_user_evidence ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_tenant_user_evidence BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION identity_tenant_user_evidence()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['identity_tenant_events','identity_tenant_outbox','identity_tenant_retirements'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_tenant_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_tenant_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_tenant_evidence_guard()',table_name);
 END LOOP;
 FOREACH function_name IN ARRAY ARRAY['identity_tenant_id(text,uuid)','identity_tenant_user_enabled(uuid)','identity_tenant_review(oid)','identity_tenant_lock(text[])',
  'identity_tenant_guard()','identity_tenant_record(uuid,text,jsonb)','identity_tenant_changed()','identity_tenant_ownership_guard()','identity_tenant_ownership_changed()',
  'identity_tenant_ownership_check()','identity_tenant_user_generation()','identity_tenant_user_generation_changed()','identity_tenant_user_evidence()',
  'identity_tenant_membership_guard()','identity_tenant_ou_guard()','identity_tenant_resource_guard()','identity_tenant_adopt(uuid,bigint,jsonb)','identity_tenant_enable(uuid,bigint,boolean)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path=%I,pg_catalog,pg_temp',function_name,current_schema());EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',function_name);
 END LOOP;
END; $$;

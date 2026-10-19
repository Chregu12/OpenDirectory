CREATE OR REPLACE FUNCTION identity_directory_creation_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor UUID;owner UUID;
BEGIN
 actor=(proof->'context'->>'userId')::uuid;owner=(proof->'tenant'->>'id')::uuid;
 IF proof IS NULL OR proof->>'issuer' IS NULL OR proof->>'subject' IS NULL OR proof->>'validUntil' IS NULL
  OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR NOT EXISTS(SELECT 1 FROM users account JOIN identity_subject_links link ON link.user_id=account.id
   JOIN identity_tenants tenant ON tenant.id=identity_tenant_id('user',account.id)
   JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=tenant.id
   WHERE account.id=actor AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject' AND account.enabled AND tenant.enabled
   AND tenant.id=owner AND tenant.version::text=proof->'tenant'->>'version' AND tenant.generation::text=proof->'tenant'->>'generation'
   AND account.authorization_revision::text=proof->'context'->>'revision' AND link.authorization_revision::text=proof->'context'->>'linkRevision')
  OR identity_subject_link_role_state(actor) IS DISTINCT FROM proof->'rolesSnapshot'
  THEN RAISE EXCEPTION 'Original directory creation authority is no longer current' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_creation_values(kind TEXT,data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE kind WHEN 'user' THEN jsonb_build_object('username',data->'username','email',data->'email','displayName',data->'display_name',
  'department',data->'department','title',data->'title','enabled',data->'enabled')
 WHEN 'group' THEN jsonb_build_object('name',data->'name','description',data->'description')
 WHEN 'ou' THEN jsonb_build_object('name',data->'name','description',data->'description','parentId',data->'parent_id') END;
$$;

CREATE OR REPLACE FUNCTION identity_directory_creation_row(kind TEXT,identity UUID) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE result JSONB;
BEGIN
 IF kind='user' THEN SELECT to_jsonb(account) INTO result FROM users account WHERE account.id=identity;
 ELSIF kind='group' THEN SELECT to_jsonb(collection) INTO result FROM groups collection WHERE collection.id=identity;
 ELSIF kind='ou' THEN SELECT to_jsonb(unit) INTO result FROM ous unit WHERE unit.id=identity;
 ELSE RAISE EXCEPTION 'Canonical resource kind required' USING ERRCODE='23514';END IF;RETURN result;
END; $$;

CREATE OR REPLACE FUNCTION identity_tenant_ownership_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tenant identity_tenants%ROWTYPE;proof JSONB;runtime BOOLEAN;owner_role NAME;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Canonical tenant ownership cannot be moved or erased' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 runtime=COALESCE(proof IS NOT NULL AND pg_trigger_depth()>1 AND current_setting('opendirectory.directory_creation_claim',true)=NEW.resource_kind||':'||NEW.resource_id::text,false);
 IF runtime THEN
  SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid=TG_RELID;
  IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
   THEN RAISE EXCEPTION 'Actual database owner required for original-actor creation' USING ERRCODE='42501';END IF;
  PERFORM identity_directory_creation_actor(proof);
  IF proof->'resource'->>'kind' IS DISTINCT FROM NEW.resource_kind OR proof->'resource'->>'id' IS DISTINCT FROM NEW.resource_id::text
   OR proof->'tenant'->>'id' IS DISTINCT FROM NEW.tenant_id::text OR NEW.reason IS DISTINCT FROM 'Original-token-bound new-resource creation'
   OR identity_directory_creation_row(NEW.resource_kind,NEW.resource_id) IS NOT NULL
   OR EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind=NEW.resource_kind AND resource_id=NEW.resource_id)
   THEN RAISE EXCEPTION 'Runtime creation cannot adopt an existing or retired namespace' USING ERRCODE='23514';END IF;
 ELSE PERFORM identity_tenant_review(TG_RELID);END IF;
 PERFORM identity_tenant_lock(ARRAY[NEW.resource_kind||':'||NEW.resource_id::text]);
 SELECT * INTO tenant FROM identity_tenants WHERE id=NEW.tenant_id FOR SHARE;
 IF tenant.id IS NULL OR NEW.reviewed_version<>tenant.version OR runtime AND (NOT tenant.enabled OR tenant.version::text IS DISTINCT FROM proof->'tenant'->>'version')
  OR NOT runtime AND NEW.reason IS DISTINCT FROM btrim(current_setting('opendirectory.tenant_reason',true))
  THEN RAISE EXCEPTION 'Current exact tenant adoption review required' USING ERRCODE='23514';END IF;
 NEW.generation=nextval('identity_tenant_generation_seq');NEW.adopted_by=session_user;NEW.created_at=clock_timestamp();RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_tenant_ownership_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;event UUID;
BEGIN
 proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 IF proof IS NOT NULL AND proof->'resource'->>'kind'=NEW.resource_kind AND proof->'resource'->>'id'=NEW.resource_id::text
  AND current_setting('opendirectory.directory_creation_claim',true)=NEW.resource_kind||':'||NEW.resource_id::text THEN
  INSERT INTO identity_tenant_events(tenant_id,action,actor,details) VALUES(NEW.tenant_id,'resource-created',
   jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId'),
   jsonb_build_object('kind',NEW.resource_kind,'resourceId',NEW.resource_id,'generation',NEW.generation::text,'tenantVersion',NEW.reviewed_version::text,
    'origin','original-token-directory-creation','contentSha256',encode(sha256(convert_to((proof->'resource'->'values')::text,'UTF8')),'hex'))) RETURNING id INTO event;
  INSERT INTO identity_tenant_outbox(id,tenant_id,action) VALUES(event,NEW.tenant_id,'resource-created');
 ELSE
  PERFORM identity_tenant_record(NEW.tenant_id,'resource-adopted',jsonb_build_object('kind',NEW.resource_kind,'resourceId',NEW.resource_id,'generation',NEW.generation::text,'reviewedVersion',NEW.reviewed_version::text,'reason',NEW.reason));
 END IF;
 IF NEW.resource_kind='user' THEN UPDATE users SET updated_at=updated_at WHERE id=NEW.resource_id;
 ELSIF NEW.resource_kind='group' THEN UPDATE groups SET name=name WHERE id=NEW.resource_id;
 ELSE UPDATE ous SET name=name WHERE id=NEW.resource_id;END IF;RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_creation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;kind TEXT;actual JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 IF proof IS NULL THEN IF TG_WHEN='BEFORE' THEN RETURN NEW;ELSE RETURN NULL;END IF;END IF;
 kind=CASE TG_TABLE_NAME WHEN 'users' THEN 'user' WHEN 'groups' THEN 'group' ELSE 'ou' END;
 PERFORM identity_directory_creation_actor(proof);
 IF proof->'resource'->>'kind' IS DISTINCT FROM kind OR proof->'resource'->>'id' IS DISTINCT FROM NEW.id::text
  OR jsonb_typeof(proof->'resource'->'values') IS DISTINCT FROM 'object'
  THEN RAISE EXCEPTION 'Exact server-generated creation origin required' USING ERRCODE='23514';END IF;
 IF TG_WHEN='BEFORE' THEN
  PERFORM identity_tenant_lock(ARRAY[kind||':'||NEW.id::text]);
  IF EXISTS(SELECT 1 FROM identity_tenant_ownership WHERE resource_kind=kind AND resource_id=NEW.id)
   OR identity_directory_creation_row(kind,NEW.id) IS NOT NULL
   OR EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind=kind AND resource_id=NEW.id)
   THEN RAISE EXCEPTION 'Creation requires a brand-new canonical namespace' USING ERRCODE='23514';END IF;
  actual=to_jsonb(NEW);
 ELSE
  actual=identity_directory_creation_row(kind,NEW.id);
  IF identity_tenant_id(kind,NEW.id)::text IS DISTINCT FROM proof->'tenant'->>'id'
   THEN RAISE EXCEPTION 'New resource owner changed' USING ERRCODE='23514';END IF;
 END IF;
 IF actual IS NULL OR identity_directory_creation_values(kind,actual) IS DISTINCT FROM proof->'resource'->'values'
  OR kind='user' AND actual->'enabled' IS DISTINCT FROM 'false'::jsonb
  THEN RAISE EXCEPTION 'Exact new resource content and disabled-first user required' USING ERRCODE='23514';END IF;
 IF TG_WHEN='BEFORE' THEN
  PERFORM set_config('opendirectory.directory_creation_claim',kind||':'||NEW.id::text,true);
  INSERT INTO identity_tenant_ownership(resource_kind,resource_id,tenant_id,reviewed_version,reason)
   VALUES(kind,NEW.id,(proof->'tenant'->>'id')::uuid,(proof->'tenant'->>'version')::bigint,'Original-token-bound new-resource creation');
  PERFORM set_config('opendirectory.directory_creation_claim','',true);RETURN NEW;
 END IF;RETURN NULL;
END; $$;

DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['users','groups','ous'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_directory_creation ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_directory_creation BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_creation_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_creation_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_directory_creation_commit AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_creation_guard()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_directory_creation_actor(jsonb)','identity_directory_creation_values(text,jsonb)','identity_directory_creation_row(text,uuid)',
  'identity_tenant_ownership_guard()','identity_tenant_ownership_changed()','identity_directory_creation_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;

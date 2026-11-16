-- Company cloud delivery is separate from the legacy provider namespace.
CREATE TABLE IF NOT EXISTS company_microsoft_connections (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,tenant_generation BIGINT NOT NULL CHECK(tenant_generation>0),
 microsoft_tenant_id UUID NOT NULL,read_client_id UUID NOT NULL,write_client_id UUID NOT NULL,
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),status TEXT NOT NULL CHECK(status IN('active','disconnected')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_company ON company_microsoft_connections(tenant_id) WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_directory ON company_microsoft_connections(microsoft_tenant_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS company_microsoft_pools (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,connection_id UUID NOT NULL REFERENCES company_microsoft_connections(id),
 pool_id UUID NOT NULL REFERENCES license_catalog(id),sku_id UUID NOT NULL,disabled_plans JSONB NOT NULL DEFAULT '[]',
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),status TEXT NOT NULL CHECK(status IN('active','retired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_pool ON company_microsoft_pools(pool_id) WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_sku ON company_microsoft_pools(connection_id,sku_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS company_microsoft_users (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,connection_id UUID NOT NULL REFERENCES company_microsoft_connections(id),user_id UUID NOT NULL,object_id UUID NOT NULL,
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),status TEXT NOT NULL CHECK(status IN('active','retired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_user ON company_microsoft_users(tenant_id,user_id) WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS company_microsoft_one_object ON company_microsoft_users(connection_id,object_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS company_microsoft_targets (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,connection_id UUID NOT NULL REFERENCES company_microsoft_connections(id),
 pool_binding_id UUID NOT NULL REFERENCES company_microsoft_pools(id),user_binding_id UUID NOT NULL REFERENCES company_microsoft_users(id),
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),status TEXT NOT NULL CHECK(status IN('processing','verifying','confirmed','conflict','failed','unknown')),
 owned BOOLEAN NOT NULL DEFAULT false,last_operation_id UUID NOT NULL,uncertain_operation_id UUID,
 observation JSONB,checked_at TIMESTAMPTZ,error_code TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(pool_binding_id,user_binding_id)
);
CREATE TABLE IF NOT EXISTS company_microsoft_operations (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,connection_id UUID NOT NULL REFERENCES company_microsoft_connections(id) DEFERRABLE INITIALLY DEFERRED,
 resource_id UUID NOT NULL,action TEXT NOT NULL CHECK(action IN('connect','renew','disconnect','bind_pool','retire_pool','bind_user','retire_user','sync','adopt','retry')),
 source JSONB NOT NULL,request JSONB NOT NULL,permit_hash TEXT NOT NULL CHECK(permit_hash ~ '^[a-f0-9]{64}$'),
 phase TEXT NOT NULL CHECK(phase IN('prepared','dispatched','finished')),desired BOOLEAN,local_state JSONB,before_state JSONB,outcome JSONB,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),finished_at TIMESTAMPTZ,
 CHECK((phase='finished')=(outcome IS NOT NULL AND finished_at IS NOT NULL))
);
ALTER TABLE company_microsoft_targets ADD COLUMN IF NOT EXISTS pending_operation_id UUID;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='company_microsoft_targets'::regclass AND conname='company_microsoft_target_operation') THEN
  ALTER TABLE company_microsoft_targets ADD CONSTRAINT company_microsoft_target_operation FOREIGN KEY(last_operation_id) REFERENCES company_microsoft_operations(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE company_microsoft_targets ADD CONSTRAINT company_microsoft_target_uncertainty FOREIGN KEY(uncertain_operation_id) REFERENCES company_microsoft_operations(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='company_microsoft_targets'::regclass AND conname='company_microsoft_target_pending') THEN
  ALTER TABLE company_microsoft_targets ADD CONSTRAINT company_microsoft_target_pending FOREIGN KEY(pending_operation_id) REFERENCES company_microsoft_operations(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END $$;
CREATE TABLE IF NOT EXISTS company_microsoft_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id UUID NOT NULL,operation_id UUID NOT NULL REFERENCES company_microsoft_operations(id),
 sequence INTEGER NOT NULL CHECK(sequence>0),type TEXT NOT NULL,actor JSONB NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(operation_id,sequence)
);
CREATE TABLE IF NOT EXISTS company_microsoft_outbox (
 id UUID PRIMARY KEY REFERENCES company_microsoft_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS company_microsoft_receiver_manifest (signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION company_microsoft_source_valid(source JSONB,operation UUID,reason TEXT) RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
 SELECT license_company_proof_valid(source,jsonb_build_object('id',operation,'correlationId',operation,'licenseId',operation,
  'action',CASE WHEN source->'target'='null'::jsonb THEN 'create' ELSE 'revoke' END,
  'expectedVersion',CASE WHEN source->'target'='null'::jsonb THEN '0' ELSE '1' END,'reason',reason,
  'values',CASE WHEN source->'target'='null'::jsonb THEN jsonb_build_object('name','Microsoft connection','vendor','Microsoft','description','','totalSeats',1) ELSE 'null'::jsonb END,
  'assignmentId',CASE WHEN source->'target'='null'::jsonb THEN NULL ELSE operation END));
$$;
CREATE OR REPLACE FUNCTION company_microsoft_scope() RETURNS company_microsoft_operations LANGUAGE plpgsql STABLE AS $$
DECLARE original company_microsoft_operations;nonce TEXT=current_setting('opendirectory.company_microsoft_permit',true);
BEGIN
 IF nonce IS NULL OR nonce !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Original company Microsoft permit required' USING ERRCODE='42501';END IF;
 SELECT * INTO original FROM company_microsoft_operations WHERE id=current_setting('opendirectory.company_microsoft_operation',true)::uuid;
 IF NOT FOUND OR original.permit_hash<>encode(sha256(convert_to(nonce,'UTF8')),'hex') THEN
  RAISE EXCEPTION 'Original company Microsoft operation required' USING ERRCODE='42501';END IF;
 RETURN original;
END $$;
CREATE OR REPLACE FUNCTION company_microsoft_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE original company_microsoft_operations;purpose TEXT=current_setting('opendirectory.company_microsoft_purpose',true);payload JSONB=to_jsonb(NEW);old_data JSONB=to_jsonb(OLD);nonce TEXT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Company Microsoft history is retained' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_microsoft_operations' AND TG_OP='INSERT' THEN
  nonce=current_setting('opendirectory.company_microsoft_permit',true);
  IF NEW.id::text IS DISTINCT FROM current_setting('opendirectory.company_microsoft_operation',true)
   OR nonce IS NULL OR nonce !~ '^[a-f0-9]{64}$' OR NEW.permit_hash<>encode(sha256(convert_to(nonce,'UTF8')),'hex')
   OR NEW.tenant_id::text IS DISTINCT FROM NEW.source#>>'{tenant,id}' OR NEW.phase<>'prepared'
   OR NOT company_microsoft_source_valid(NEW.source,NEW.id,NEW.request->>'reason') THEN
   RAISE EXCEPTION 'Original current company Microsoft authority required' USING ERRCODE='42501';END IF;
  RETURN NEW;
 END IF;
 original=company_microsoft_scope();
 IF payload->>'tenant_id' IS DISTINCT FROM original.tenant_id::text THEN RAISE EXCEPTION 'Company Microsoft tenant mismatch' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_microsoft_operations' THEN
  IF NEW.id<>original.id OR TG_OP<>'UPDATE' OR OLD.phase='finished'
   OR (payload-ARRAY['phase','outcome','updated_at','finished_at']) IS DISTINCT FROM (old_data-ARRAY['phase','outcome','updated_at','finished_at'])
   OR NOT (OLD.phase='prepared' AND NEW.phase='dispatched' AND purpose='dispatch' OR NEW.phase='finished' AND purpose IN('change','finish')) THEN
   RAISE EXCEPTION 'Exact company Microsoft operation transition required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('company_microsoft_events','company_microsoft_outbox') THEN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Company Microsoft evidence is append only' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='company_microsoft_events' THEN
   IF NEW.operation_id<>original.id OR NEW.sequence IS DISTINCT FROM (SELECT COALESCE(max(sequence),0)+1 FROM company_microsoft_events WHERE operation_id=original.id)
    THEN RAISE EXCEPTION 'Original Microsoft event sequence required' USING ERRCODE='42501';END IF;
   IF NOT (license_company_exact(NEW.actor,ARRAY['kind','userId']) AND NEW.actor->>'kind'='human' AND NEW.actor->>'userId'=original.source->>'actorUserId'
    OR license_company_exact(NEW.actor,ARRAY['kind','operationId']) AND NEW.actor->>'kind'='workload' AND NEW.actor->>'operationId'=original.id::text) THEN
    RAISE EXCEPTION 'Original Microsoft audit actor required' USING ERRCODE='42501';END IF;
  ELSE
   IF payload IS DISTINCT FROM (SELECT jsonb_build_object('id',event.id,'tenant_id',event.tenant_id,'status','pending','created_at',event.created_at) FROM company_microsoft_events event WHERE event.id=NEW.id AND event.operation_id=original.id)
    THEN RAISE EXCEPTION 'Exact company Microsoft outbox required' USING ERRCODE='42501';END IF;
  END IF;
 ELSE
  IF payload->>'id' IS DISTINCT FROM original.resource_id::text OR original.phase='finished' THEN RAISE EXCEPTION 'Original Microsoft resource required' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='company_microsoft_targets' THEN
   IF original.action NOT IN('sync','adopt','retry') OR purpose NOT IN('prepare','finish')
    OR payload->>'connection_id' IS DISTINCT FROM original.connection_id::text
    OR TG_OP='UPDATE' AND (payload-ARRAY['revision','status','owned','last_operation_id','pending_operation_id','uncertain_operation_id','observation','checked_at','error_code','updated_at']) IS DISTINCT FROM (old_data-ARRAY['revision','status','owned','last_operation_id','pending_operation_id','uncertain_operation_id','observation','checked_at','error_code','updated_at'])
    OR TG_OP='INSERT' AND (NEW.owned OR NEW.status<>'processing' OR NEW.revision<>1)
    OR TG_OP='UPDATE' AND NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Exact company Microsoft target transition required' USING ERRCODE='42501';END IF;
  ELSE
   IF purpose<>'change' OR original.phase<>'prepared'
    OR TG_TABLE_NAME='company_microsoft_connections' AND original.action NOT IN('connect','renew','disconnect')
    OR TG_TABLE_NAME='company_microsoft_pools' AND original.action NOT IN('bind_pool','retire_pool')
    OR TG_TABLE_NAME='company_microsoft_users' AND original.action NOT IN('bind_user','retire_user')
    OR TG_OP='INSERT' AND NEW.revision<>1 OR TG_OP='UPDATE' AND NEW.revision<>OLD.revision+1 THEN
    RAISE EXCEPTION 'Exact company Microsoft binding transition required' USING ERRCODE='42501';END IF;
   IF TG_OP='UPDATE' AND (OLD.status<>'active' OR (payload-CASE WHEN TG_TABLE_NAME='company_microsoft_connections'
      THEN ARRAY['revision','status','updated_at','tenant_generation','read_client_id','write_client_id'] ELSE ARRAY['revision','status','updated_at'] END)
     IS DISTINCT FROM (old_data-CASE WHEN TG_TABLE_NAME='company_microsoft_connections'
      THEN ARRAY['revision','status','updated_at','tenant_generation','read_client_id','write_client_id'] ELSE ARRAY['revision','status','updated_at'] END)) THEN
    RAISE EXCEPTION 'Microsoft remote identity bindings are immutable' USING ERRCODE='42501';END IF;
   IF TG_TABLE_NAME<>'company_microsoft_connections' AND (payload->>'connection_id' IS DISTINCT FROM original.connection_id::text
    OR NOT EXISTS(SELECT 1 FROM company_microsoft_connections WHERE id=original.connection_id AND tenant_id=original.tenant_id AND status='active')) THEN
    RAISE EXCEPTION 'Own Microsoft mapping connection required' USING ERRCODE='42501';END IF;
   IF TG_TABLE_NAME='company_microsoft_pools' AND NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=(payload->>'pool_id')::uuid AND business_tenant_id=original.tenant_id AND license_company_pool_valid(id)) THEN
    RAISE EXCEPTION 'Own retained company pool required' USING ERRCODE='42501';END IF;
   IF TG_TABLE_NAME='company_microsoft_users' AND TG_OP='INSERT' AND original.source#>>'{target,id}' IS DISTINCT FROM payload->>'user_id' THEN
    RAISE EXCEPTION 'Original own Microsoft user required' USING ERRCODE='42501';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION company_microsoft_commit_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 -- Delivery receipts can finish an already admitted operation after its human lease expires.
 IF (NEW.phase IN('prepared','dispatched') OR NEW.action NOT IN('sync','retry'))
  AND NOT company_microsoft_source_valid(NEW.source,NEW.id,NEW.request->>'reason') THEN
  RAISE EXCEPTION 'Company Microsoft authority expired before commit' USING ERRCODE='42501';END IF;
 IF NEW.action='sync' AND NEW.phase IN('prepared','dispatched') THEN
  IF company_microsoft_admission(NEW.source,NEW.request,NEW.local_state,NEW.before_state->'capture') IS DISTINCT FROM NEW.desired THEN
   RAISE EXCEPTION 'Company Microsoft entitlement changed before commit' USING ERRCODE='42501';END IF;
 END IF;
 IF NEW.phase='finished' AND NOT EXISTS(SELECT 1 FROM company_microsoft_events event JOIN company_microsoft_outbox box ON box.id=event.id
   WHERE event.operation_id=NEW.id AND box.status='pending') THEN RAISE EXCEPTION 'Company Microsoft receipt missing' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION company_microsoft_truncate_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE retained BOOLEAN;BEGIN
 EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.%I)',TG_TABLE_SCHEMA,TG_TABLE_NAME) INTO retained;
 IF retained THEN RAISE EXCEPTION 'Company Microsoft evidence is retained' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['company_microsoft_connections','company_microsoft_pools','company_microsoft_users','company_microsoft_targets','company_microsoft_operations','company_microsoft_events','company_microsoft_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS company_microsoft_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER company_microsoft_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_microsoft_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS company_microsoft_truncate_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER company_microsoft_truncate_guard BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_microsoft_truncate_guard()',relation);
 END LOOP;
END $$;
DROP TRIGGER IF EXISTS company_microsoft_commit_guard ON company_microsoft_operations;
CREATE CONSTRAINT TRIGGER company_microsoft_commit_guard AFTER INSERT OR UPDATE ON company_microsoft_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_microsoft_commit_guard();

CREATE OR REPLACE FUNCTION company_microsoft_audit(operation UUID,event_type TEXT,actor JSONB,details JSONB) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE original company_microsoft_operations;event_id UUID=gen_random_uuid();created TIMESTAMPTZ=clock_timestamp();
BEGIN
 original=company_microsoft_scope();IF original.id<>operation THEN RAISE EXCEPTION 'Original Microsoft audit operation required' USING ERRCODE='42501';END IF;
 INSERT INTO company_microsoft_events VALUES(event_id,original.tenant_id,operation,(SELECT COALESCE(max(sequence),0)+1 FROM company_microsoft_events WHERE operation_id=operation),event_type,actor,details,created);
 INSERT INTO company_microsoft_outbox VALUES(event_id,original.tenant_id,'pending',created);RETURN event_id;
END $$;
CREATE OR REPLACE FUNCTION company_microsoft_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 PERFORM license_company_receiving();
 IF (SELECT count(*) FROM company_microsoft_receiver_manifest)<>9 OR EXISTS(SELECT 1 FROM company_microsoft_receiver_manifest manifest
  WHERE to_regprocedure(manifest.signature) IS NULL OR manifest.digest<>md5(pg_get_functiondef(to_regprocedure(manifest.signature))))
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['company_microsoft_connections','company_microsoft_pools','company_microsoft_users','company_microsoft_targets','company_microsoft_operations','company_microsoft_events','company_microsoft_outbox']) relation
   WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='company_microsoft_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid=to_regprocedure('company_microsoft_guard()'))
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='company_microsoft_truncate_guard' AND tgenabled='O' AND tgtype=34 AND tgfoid=to_regprocedure('company_microsoft_truncate_guard()')))
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='company_microsoft_operations'::regclass AND tgname='company_microsoft_commit_guard' AND tgdeferrable AND tginitdeferred AND tgenabled='O' AND tgtype=21 AND tgfoid=to_regprocedure('company_microsoft_commit_guard()')) THEN
  RAISE EXCEPTION 'Company Microsoft receiving evidence unavailable' USING ERRCODE='42501';END IF;
END $$;
CREATE OR REPLACE FUNCTION company_microsoft_row_view(value JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT value||jsonb_build_object('revision',value->>'revision')||CASE WHEN value?'tenant_generation' THEN jsonb_build_object('tenant_generation',value->>'tenant_generation') ELSE '{}'::jsonb END;
$$;

CREATE OR REPLACE FUNCTION company_microsoft_change(source JSONB,operation UUID,nonce TEXT,action_name TEXT,resource UUID,connection UUID,request JSONB,expected BIGINT DEFAULT NULL) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE tenant UUID=(source#>>'{tenant,id}')::uuid;current_connection company_microsoft_connections;result JSONB;
BEGIN
 PERFORM company_microsoft_receiving();
 IF nonce !~ '^[a-f0-9]{64}$' OR NOT company_microsoft_source_valid(source,operation,request->>'reason') OR request->'confirm' IS DISTINCT FROM 'true'::jsonb THEN
  RAISE EXCEPTION 'Current reviewed company Microsoft change required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(operation::text,0));
 IF EXISTS(SELECT 1 FROM company_microsoft_operations WHERE id=operation) THEN RAISE EXCEPTION 'Microsoft operation already exists; inspect its result' USING ERRCODE='40001';END IF;
 PERFORM set_config('opendirectory.company_microsoft_operation',operation::text,true);PERFORM set_config('opendirectory.company_microsoft_permit',nonce,true);PERFORM set_config('opendirectory.company_microsoft_purpose','change',true);
 INSERT INTO company_microsoft_operations(id,tenant_id,connection_id,resource_id,action,source,request,permit_hash,phase)
  VALUES(operation,tenant,connection,resource,action_name,source,request,encode(sha256(convert_to(nonce,'UTF8')),'hex'),'prepared');
 IF action_name='connect' THEN
  IF connection<>resource OR source->'target' IS DISTINCT FROM 'null'::jsonb OR expected IS NOT NULL THEN RAISE EXCEPTION 'Exact new connection required' USING ERRCODE='23514';END IF;
  INSERT INTO company_microsoft_connections(id,tenant_id,tenant_generation,microsoft_tenant_id,read_client_id,write_client_id,status)
   VALUES(resource,tenant,(source#>>'{tenant,generation}')::bigint,(request->>'microsoftTenantId')::uuid,(request->>'readClientId')::uuid,(request->>'writeClientId')::uuid,'active') RETURNING to_jsonb(company_microsoft_connections.*) INTO result;
 ELSE
  SELECT * INTO current_connection FROM company_microsoft_connections WHERE id=connection AND tenant_id=tenant AND status='active' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Own active Microsoft connection not found' USING ERRCODE='P0002';END IF;
  IF action_name IN('renew','disconnect') THEN
   IF resource<>connection OR current_connection.revision IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Microsoft connection version changed' USING ERRCODE='40001';END IF;
   IF EXISTS(SELECT 1 FROM company_microsoft_targets WHERE connection_id=connection AND (status IN('processing','unknown') OR uncertain_operation_id IS NOT NULL OR action_name='disconnect' AND (owned OR pending_operation_id IS NOT NULL))) THEN
    RAISE EXCEPTION 'Finish or review Microsoft deliveries before changing the connection' USING ERRCODE='23514';END IF;
   IF action_name='renew' AND current_connection.microsoft_tenant_id IS DISTINCT FROM (request->>'microsoftTenantId')::uuid THEN RAISE EXCEPTION 'Microsoft tenant binding is immutable' USING ERRCODE='23514';END IF;
   IF action_name='disconnect' AND (EXISTS(SELECT 1 FROM company_microsoft_pools WHERE connection_id=connection AND status='active') OR EXISTS(SELECT 1 FROM company_microsoft_users WHERE connection_id=connection AND status='active')) THEN
    RAISE EXCEPTION 'Retire pool and user mappings before disconnecting Microsoft' USING ERRCODE='23514';END IF;
   UPDATE company_microsoft_connections SET tenant_generation=(source#>>'{tenant,generation}')::bigint,revision=revision+1,
    status=CASE WHEN action_name='disconnect' THEN 'disconnected' ELSE 'active' END,
    read_client_id=CASE WHEN action_name='renew' THEN (request->>'readClientId')::uuid ELSE read_client_id END,
    write_client_id=CASE WHEN action_name='renew' THEN (request->>'writeClientId')::uuid ELSE write_client_id END,updated_at=clock_timestamp()
    WHERE id=resource RETURNING to_jsonb(company_microsoft_connections.*) INTO result;
  ELSIF action_name='bind_pool' THEN
   IF current_connection.revision IS DISTINCT FROM expected OR current_connection.tenant_generation<>(source#>>'{tenant,generation}')::bigint
    OR NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=(request->>'poolId')::uuid AND business_tenant_id=tenant AND license_company_pool_valid(id))
    OR request->'disabledPlans' IS DISTINCT FROM '[]'::jsonb THEN RAISE EXCEPTION 'Current own company pool and supported plan policy required' USING ERRCODE='23514';END IF;
   INSERT INTO company_microsoft_pools(id,tenant_id,connection_id,pool_id,sku_id,status)
    VALUES(resource,tenant,connection,(request->>'poolId')::uuid,(request->>'skuId')::uuid,'active') RETURNING to_jsonb(company_microsoft_pools.*) INTO result;
  ELSIF action_name='bind_user' THEN
   IF current_connection.revision IS DISTINCT FROM expected OR current_connection.tenant_generation<>(source#>>'{tenant,generation}')::bigint OR source#>>'{target,id}' IS DISTINCT FROM request->>'userId'
    OR source#>'{target,deleted}' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'Current own company user required' USING ERRCODE='23514';END IF;
   INSERT INTO company_microsoft_users(id,tenant_id,connection_id,user_id,object_id,status)
    VALUES(resource,tenant,connection,(request->>'userId')::uuid,(request->>'objectId')::uuid,'active') RETURNING to_jsonb(company_microsoft_users.*) INTO result;
  ELSIF action_name IN('retire_pool','retire_user') THEN
   IF EXISTS(SELECT 1 FROM company_microsoft_targets WHERE connection_id=connection AND (pool_binding_id=resource OR user_binding_id=resource)
    AND (owned OR status IN('processing','unknown') OR pending_operation_id IS NOT NULL OR uncertain_operation_id IS NOT NULL)) THEN RAISE EXCEPTION 'Return owned licenses and review unknown results first' USING ERRCODE='23514';END IF;
   IF action_name='retire_pool' THEN
    UPDATE company_microsoft_pools SET status='retired',revision=revision+1,updated_at=clock_timestamp() WHERE id=resource AND connection_id=connection AND status='active' AND revision=expected RETURNING to_jsonb(company_microsoft_pools.*) INTO result;
   ELSE
    UPDATE company_microsoft_users SET status='retired',revision=revision+1,updated_at=clock_timestamp() WHERE id=resource AND connection_id=connection AND status='active' AND revision=expected RETURNING to_jsonb(company_microsoft_users.*) INTO result;
   END IF;
   IF result IS NULL THEN RAISE EXCEPTION 'Microsoft mapping version changed' USING ERRCODE='40001';END IF;
  ELSE RAISE EXCEPTION 'Unsupported Microsoft configuration action' USING ERRCODE='23514';END IF;
 END IF;
 IF request->'expectedRevision' IS DISTINCT FROM COALESCE(to_jsonb(expected::text),'null'::jsonb)
  OR NOT license_company_exact(request,ARRAY['reason','confirm','expectedRevision']||CASE
   WHEN action_name IN('connect','renew') THEN ARRAY['microsoftTenantId','readClientId','writeClientId']
   WHEN action_name='bind_pool' THEN ARRAY['poolId','skuId','disabledPlans','exclusiveDirectManagement','observedSku','checkedAt']
   WHEN action_name='bind_user' THEN ARRAY['userId','objectId','exclusiveDirectManagement','accountEnabled','checkedAt']
   ELSE ARRAY[]::text[] END)
  OR action_name IN('bind_pool','bind_user') AND request->'exclusiveDirectManagement' IS DISTINCT FROM 'true'::jsonb
  OR action_name='bind_pool' AND (NOT license_company_exact(request->'observedSku',ARRAY['skuId','skuPartNumber','appliesTo','capabilityStatus','prepaidUnits','consumedUnits'])
   OR request#>>'{observedSku,skuId}' IS DISTINCT FROM request->>'skuId' OR request#>>'{observedSku,appliesTo}' IS DISTINCT FROM 'User'
   OR request#>>'{observedSku,capabilityStatus}' IS DISTINCT FROM 'Enabled')
  OR action_name='bind_user' AND jsonb_typeof(request->'accountEnabled') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'Exact reviewed Microsoft configuration request required' USING ERRCODE='23514';END IF;
 result=company_microsoft_row_view(result);
 UPDATE company_microsoft_operations SET phase='finished',outcome=jsonb_build_object('kind','configuration','resource',result),finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=operation;
 PERFORM company_microsoft_audit(operation,action_name,jsonb_build_object('kind','human','userId',source->>'actorUserId'),jsonb_build_object('resource',result,'source',source));
 RETURN result;
END $$;

INSERT INTO company_microsoft_receiver_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'company_microsoft_source_valid(jsonb,uuid,text)','company_microsoft_scope()','company_microsoft_guard()',
 'company_microsoft_commit_guard()','company_microsoft_truncate_guard()','company_microsoft_audit(uuid,text,jsonb,jsonb)','company_microsoft_receiving()','company_microsoft_row_view(jsonb)',
 'company_microsoft_change(jsonb,uuid,text,text,uuid,uuid,jsonb,bigint)']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
DO $$ DECLARE signature TEXT;BEGIN
 FOR signature IN SELECT manifest.signature FROM company_microsoft_receiver_manifest manifest LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',to_regprocedure(signature));
 END LOOP;
END $$;

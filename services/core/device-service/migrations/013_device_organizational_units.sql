BEGIN;
CREATE TABLE IF NOT EXISTS device_ou_assignments (
 device_id TEXT PRIMARY KEY REFERENCES devices(id),tenant_id UUID NOT NULL,revision BIGINT NOT NULL CHECK(revision>0),
 ou JSONB,updated_at TIMESTAMPTZ NOT NULL,updated_by UUID NOT NULL
);
CREATE INDEX IF NOT EXISTS device_ou_tenant ON device_ou_assignments(tenant_id,device_id);
CREATE TABLE IF NOT EXISTS device_ou_events (
 id UUID PRIMARY KEY,device_id TEXT NOT NULL REFERENCES devices(id),tenant_id UUID NOT NULL,
 actor_user_id UUID NOT NULL,correlation_id UUID NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 created_at TIMESTAMPTZ NOT NULL,before_state JSONB,after_state JSONB NOT NULL,source JSONB NOT NULL,
 transaction_id BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS device_ou_history ON device_ou_events(tenant_id,device_id,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS device_ou_outbox (
 id UUID PRIMARY KEY REFERENCES device_ou_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS device_ou_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION device_ou_source(proof JSONB,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;unit JSONB;directory JSONB;virtual_source JSONB;deadline NUMERIC;
BEGIN
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Original device OU source required' USING ERRCODE='42501';END IF;
 IF proof-ARRAY['schemaVersion','deviceOuProtocol','inventory','ou','directoryGrant','validUntil']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(proof))<>6 OR proof->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR proof->'deviceOuProtocol' IS DISTINCT FROM '1'::jsonb
  OR jsonb_typeof(proof->'validUntil') IS DISTINCT FROM 'number' OR NOT coalesce(proof->>'validUntil' ~ '^[1-9][0-9]{0,15}$',false)
  THEN RAISE EXCEPTION 'Exact device OU source required' USING ERRCODE='42501';END IF;
 source=proof->'inventory';unit=proof->'ou';directory=proof->'directoryGrant';deadline=(proof->>'validUntil')::numeric;
 PERFORM device_returns_source(source,false,false);
 IF NOT coalesce(source->'permissions' ? 'devices.inventory.create',false) OR deadline>9007199254740991 OR deadline>(source->>'validUntil')::numeric
  OR live AND (deadline<=extract(epoch FROM clock_timestamp()) OR deadline>extract(epoch FROM clock_timestamp())+300)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(source#>'{delegation,grants}','[]'::jsonb)) grant_row WHERE grant_row->>'permission'='devices.inventory.create' AND grant_row#>>'{source,scopeType}' IS DISTINCT FROM 'tenant')
  THEN RAISE EXCEPTION 'Current tenant inventory maintenance required' USING ERRCODE='42501';END IF;
 IF unit='null'::jsonb THEN
  IF directory IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Untargeted OU removal required' USING ERRCODE='42501';END IF;
 ELSE
  IF jsonb_typeof(unit) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Canonical OU required' USING ERRCODE='42501';END IF;
  IF unit-ARRAY['id','generation','revision','name','parentId']<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(unit))<>5
   OR jsonb_typeof(unit->'id') IS DISTINCT FROM 'string' OR NOT coalesce(unit->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR jsonb_typeof(unit->'generation') IS DISTINCT FROM 'string' OR NOT coalesce(unit->>'generation' ~ '^[1-9][0-9]{0,18}$',false)
   OR jsonb_typeof(unit->'revision') IS DISTINCT FROM 'string' OR NOT coalesce(unit->>'revision' ~ '^[1-9][0-9]{0,18}$',false)
   OR (unit->>'generation')::numeric>9223372036854775807 OR (unit->>'revision')::numeric>9223372036854775807
   OR jsonb_typeof(unit->'name') IS DISTINCT FROM 'string' OR length(btrim(unit->>'name')) NOT BETWEEN 1 AND 255 OR unit->>'name' ~ '[[:cntrl:]]'
   OR unit->'parentId'<>'null'::jsonb AND (jsonb_typeof(unit->'parentId') IS DISTINCT FROM 'string' OR NOT coalesce(unit->>'parentId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) OR unit->>'parentId'=unit->>'id')
   THEN RAISE EXCEPTION 'Exact canonical own OU snapshot required' USING ERRCODE='42501';END IF;
  IF directory<>'null'::jsonb THEN
   virtual_source=source||jsonb_build_object('permissions',jsonb_build_array('ous.read'),'validUntil',deadline,'delegation',jsonb_build_object('grants',jsonb_build_array(jsonb_build_object('permission','ous.read','source',directory))));
   IF NOT device_delegation_valid(virtual_source) THEN RAISE EXCEPTION 'Original directory grant required' USING ERRCODE='42501';END IF;
  END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 IF TG_TABLE_NAME='device_ou_manifest' OR TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Device OU evidence is retained' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.device_ou',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text THEN RAISE EXCEPTION 'Original device OU command required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_source(proof->'source');
 IF TG_TABLE_NAME='device_ou_assignments' THEN
  IF to_jsonb(NEW) IS DISTINCT FROM proof->'after' OR TG_OP='UPDATE' AND to_jsonb(OLD) IS DISTINCT FROM proof->'before' THEN RAISE EXCEPTION 'Exact device OU effect required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='device_ou_events' THEN
  IF TG_OP<>'INSERT' OR to_jsonb(NEW) IS DISTINCT FROM proof->'event' THEN RAISE EXCEPTION 'Exact immutable device OU event required' USING ERRCODE='42501';END IF;
 ELSIF TG_OP<>'INSERT' OR to_jsonb(NEW) IS DISTINCT FROM proof->'outbox' THEN RAISE EXCEPTION 'Exact pending device OU receipt required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;entry RECORD;
BEGIN
 PERFORM device_inventory_receiving();
 IF to_regclass('device_ou_manifest') IS NULL OR (SELECT count(*) FROM device_ou_manifest)<>5 THEN RAISE EXCEPTION 'Complete device OU manifest required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_ou_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device OU receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['device_ou_assignments','device_ou_events','device_ou_outbox','device_ou_manifest'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_ou_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_ou_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_ou_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_ou_guard()'::regprocedure)
   OR relation<>'device_ou_manifest' AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_ou_commit' AND tgenabled='O' AND tgtype=21 AND tgdeferrable AND tginitdeferred AND tgfoid='device_ou_commit()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete device OU receiving guards required' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;actual device_ou_assignments;unit devices;
BEGIN
 PERFORM device_ou_receiving();proof=NULLIF(current_setting('opendirectory.device_ou',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text THEN RAISE EXCEPTION 'Original device OU transaction required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_source(proof->'source');
 SELECT * INTO actual FROM device_ou_assignments WHERE device_id=proof#>>'{after,device_id}';
 SELECT * INTO unit FROM devices WHERE id=actual.device_id;
 IF to_jsonb(actual) IS DISTINCT FROM proof->'after' OR unit.tenant_id IS DISTINCT FROM actual.tenant_id OR unit.inventory_revision::text IS DISTINCT FROM proof->>'deviceRevision'
  OR NOT EXISTS(SELECT 1 FROM device_ou_events event WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(event)=proof->'event')
  OR NOT EXISTS(SELECT 1 FROM device_ou_outbox outbox WHERE id=(proof#>>'{outbox,id}')::uuid AND to_jsonb(outbox)=proof->'outbox')
  THEN RAISE EXCEPTION 'Actual device OU effect and retained pending receipt required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_ou_assignments;next_state device_ou_assignments;event device_ou_events;outbox device_ou_outbox;unit devices;proof JSONB;moment TIMESTAMPTZ;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','') OR NULLIF(current_setting('opendirectory.device_ou',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Original inventory database owner command required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_receiving();PERFORM device_ou_source(command->'source');
 IF jsonb_typeof(command) IS DISTINCT FROM 'object' OR command-ARRAY['id','deviceId','deviceRevision','revision','selectedOu','source','reason','confirm','correlationId']<>'{}'::jsonb
  OR (SELECT count(*) FROM jsonb_object_keys(command))<>9 OR command->'confirm' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(command->'reason') IS DISTINCT FROM 'string'
  OR length(btrim(command->>'reason')) NOT BETWEEN 10 AND 500 OR command->>'reason' ~ '[[:cntrl:]]'
  OR command->'selectedOu' IS DISTINCT FROM (CASE WHEN command#>'{source,ou}'='null'::jsonb THEN 'null'::jsonb ELSE (command#>'{source,ou}')-ARRAY['name','parentId'] END)
  THEN RAISE EXCEPTION 'Exact confirmed device OU command required' USING ERRCODE='23514';END IF;
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' AND tenant_id=(command#>>'{source,inventory,tenant,id}')::uuid FOR UPDATE;
 IF unit.id IS NULL OR unit.inventory_revision::text IS DISTINCT FROM command->>'deviceRevision' THEN RAISE EXCEPTION 'Exact current owned device required' USING ERRCODE='23514';END IF;
 SELECT * INTO previous FROM device_ou_assignments WHERE device_id=unit.id FOR UPDATE;
 IF previous.device_id IS NOT NULL AND previous.tenant_id<>unit.tenant_id OR coalesce(previous.revision,0)::text IS DISTINCT FROM command->>'revision'
  OR previous.ou IS NOT DISTINCT FROM NULLIF(command#>'{source,ou}','null'::jsonb) THEN RAISE EXCEPTION 'Changed current OU assignment required' USING ERRCODE='23514';END IF;
 moment=clock_timestamp();next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=coalesce(previous.revision,0)+1;
 next_state.ou=NULLIF(command#>'{source,ou}','null'::jsonb);next_state.updated_at=moment;next_state.updated_by=(command#>>'{source,inventory,actorUserId}')::uuid;
 event.id=(command->>'id')::uuid;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.actor_user_id=next_state.updated_by;event.correlation_id=(command->>'correlationId')::uuid;
 event.reason=btrim(command->>'reason');event.created_at=moment;event.before_state=CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous) END;event.after_state=to_jsonb(next_state);event.source=command->'source';event.transaction_id=txid_current();
 outbox.id=event.id;outbox.tenant_id=unit.tenant_id;outbox.status='pending';outbox.created_at=moment;
 proof=jsonb_build_object('transactionId',txid_current()::text,'source',command->'source','deviceRevision',unit.inventory_revision::text,'before',event.before_state,'after',event.after_state,'event',to_jsonb(event),'outbox',to_jsonb(outbox));
 PERFORM set_config('opendirectory.device_ou',proof::text,true);
 INSERT INTO device_ou_assignments SELECT next_state.* ON CONFLICT(device_id) DO UPDATE SET revision=EXCLUDED.revision,ou=EXCLUDED.ou,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by;
 INSERT INTO device_ou_events SELECT event.*;INSERT INTO device_ou_outbox SELECT outbox.*;
 IF NOT EXISTS(SELECT 1 FROM device_ou_assignments WHERE device_id=unit.id AND to_jsonb(device_ou_assignments)=event.after_state)
  OR NOT EXISTS(SELECT 1 FROM device_ou_events WHERE id=event.id AND to_jsonb(device_ou_events)=to_jsonb(event))
  OR NOT EXISTS(SELECT 1 FROM device_ou_outbox WHERE id=outbox.id AND to_jsonb(device_ou_outbox)=to_jsonb(outbox)) THEN RAISE EXCEPTION 'Actual device OU receipt required' USING ERRCODE='42501';END IF;
 RETURN event.id;
END; $$;

DO $$ DECLARE relation TEXT;signature TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['device_ou_assignments','device_ou_events','device_ou_outbox','device_ou_manifest'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER device_ou_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION device_ou_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER device_ou_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION device_ou_guard()',relation);
  IF relation<>'device_ou_manifest' THEN
   EXECUTE format('DROP TRIGGER IF EXISTS device_ou_commit ON %I',relation);
   EXECUTE format('CREATE CONSTRAINT TRIGGER device_ou_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION device_ou_commit()',relation);
  END IF;
 END LOOP;
 ALTER TABLE device_ou_manifest DISABLE TRIGGER device_ou_guard;
 FOREACH signature IN ARRAY ARRAY['device_ou_source(jsonb,boolean)','device_ou_guard()','device_ou_receiving()','device_ou_commit()','device_ou_change(jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  INSERT INTO device_ou_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT device_ou_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 ALTER TABLE device_ou_manifest ENABLE TRIGGER device_ou_guard;
END; $$;
COMMIT;

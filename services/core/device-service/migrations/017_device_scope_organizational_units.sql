BEGIN;
-- OU changes retain the original scope and compare the before association at admission and physical commit.
CREATE TABLE IF NOT EXISTS device_ou_scope_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION device_ou_scope_manifest_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN RAISE EXCEPTION 'Sealed device OU scope manifest cannot be changed' USING ERRCODE='42501';END; $$;
CREATE OR REPLACE TRIGGER device_ou_scope_manifest_guard BEFORE INSERT OR UPDATE OR DELETE ON device_ou_scope_manifest FOR EACH ROW EXECUTE FUNCTION device_ou_scope_manifest_guard();
CREATE OR REPLACE TRIGGER device_ou_scope_manifest_truncate BEFORE TRUNCATE ON device_ou_scope_manifest FOR EACH STATEMENT EXECUTE FUNCTION device_ou_scope_manifest_guard();
CREATE OR REPLACE FUNCTION device_scope_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF to_regclass('device_scope_manifest') IS NULL OR (SELECT count(*) FROM device_scope_manifest)<>14
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_scope_manifest'::regclass AND tgname='device_scope_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_scope_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_scope_manifest'::regclass AND tgname='device_scope_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_scope_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Complete sealed device scope receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_scope_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device scope receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
 IF to_regclass('device_control_manifest') IS NULL OR (SELECT count(*) FROM device_control_manifest)<>14
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_control_manifest'::regclass AND tgname='device_control_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_control_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_control_manifest'::regclass AND tgname='device_control_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_control_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='device_sync_events'::regclass AND attname='source' AND atttypid='jsonb'::regtype AND NOT attisdropped)
  THEN RAISE EXCEPTION 'Complete sealed device control receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_control_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device control receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
 IF to_regclass('device_return_scope_manifest') IS NULL OR (SELECT count(*) FROM device_return_scope_manifest)<>15
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_return_scope_manifest'::regclass AND tgname='device_return_scope_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_return_scope_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_return_scope_manifest'::regclass AND tgname='device_return_scope_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_return_scope_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Complete sealed device return scope receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_return_scope_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device return scope receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
 IF to_regclass('device_ou_scope_manifest') IS NULL OR (SELECT count(*) FROM device_ou_scope_manifest)<>10
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_ou_scope_manifest'::regclass AND tgname='device_ou_scope_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_ou_scope_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_ou_scope_manifest'::regclass AND tgname='device_ou_scope_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_ou_scope_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Complete sealed device OU scope receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_ou_scope_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device OU scope receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_source_v1(proof JSONB,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
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

CREATE OR REPLACE FUNCTION device_ou_source(proof JSONB,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;unit JSONB;directory JSONB;virtual_source JSONB;deadline NUMERIC;
BEGIN
 source=proof->'inventory';
 IF proof->'schemaVersion'='1'::jsonb THEN
  IF source->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN RAISE EXCEPTION 'Original legacy OU source cannot wrap a scoped source' USING ERRCODE='42501';END IF;
  PERFORM device_ou_source_v1(proof,live);RETURN;
 END IF;
 IF NOT device_scope_shape(proof,ARRAY['schemaVersion','deviceOuProtocol','inventory','ou','directoryGrant','validUntil'])
  OR proof->'schemaVersion' IS DISTINCT FROM '2'::jsonb OR proof->'deviceOuProtocol' IS DISTINCT FROM '2'::jsonb
  OR source->'schemaVersion' IS DISTINCT FROM '2'::jsonb OR NOT device_scope_source_valid(source) OR source->'target' IS DISTINCT FROM 'null'::jsonb
  OR NOT coalesce(source->'permissions' ? 'devices.inventory.read',false) OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
  OR jsonb_typeof(proof->'validUntil') IS DISTINCT FROM 'number' OR NOT coalesce(proof->>'validUntil' ~ '^[1-9][0-9]{0,15}$',false)
  THEN RAISE EXCEPTION 'Exact original scoped device OU authority required' USING ERRCODE='42501';END IF;
 unit=proof->'ou';directory=proof->'directoryGrant';deadline=(proof->>'validUntil')::numeric;
 IF deadline>9007199254740991 OR deadline>(source->>'validUntil')::numeric
  OR live AND (deadline<=extract(epoch FROM clock_timestamp()) OR deadline>extract(epoch FROM clock_timestamp())+300)
  OR NOT device_scope_permits(source,'devices.inventory.read',unit) OR NOT device_scope_permits(source,'devices.inventory.create',unit)
  THEN RAISE EXCEPTION 'Selected OU outside original stock authority' USING ERRCODE='42501';END IF;
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

CREATE OR REPLACE FUNCTION device_ou_bound(proof JSONB,committed BOOLEAN) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;resource JSONB;previous_unit JSONB;next_unit JSONB;unit devices;association device_ou_assignments;
BEGIN
 source=proof#>'{source,inventory}';
 IF source->'schemaVersion'='1'::jsonb THEN RETURN;END IF;
 resource=source#>'{scope,resource}';
 SELECT * INTO unit FROM devices WHERE id=proof#>>'{after,device_id}' AND tenant_id=(source#>>'{tenant,id}')::uuid FOR UPDATE;
 SELECT * INTO association FROM device_ou_assignments WHERE device_id=unit.id FOR UPDATE;
 IF unit.id IS NULL OR unit.inventory_revision::text IS DISTINCT FROM proof->>'deviceRevision'
  OR (CASE WHEN association.device_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(association) END) IS DISTINCT FROM coalesce(proof->(CASE WHEN committed THEN 'after' ELSE 'before' END),'null'::jsonb)
  THEN RAISE EXCEPTION 'Original device OU or inventory version changed' USING ERRCODE='P0412';END IF;
 previous_unit=CASE WHEN proof#>'{before,ou}' IS NULL OR proof#>'{before,ou}'='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object('id',proof#>'{before,ou,id}','generation',proof#>'{before,ou,generation}') END;
 next_unit=CASE WHEN proof#>'{after,ou}'='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object('id',proof#>'{after,ou,id}','generation',proof#>'{after,ou,generation}') END;
 IF resource='null'::jsonb THEN
  IF NOT device_scope_permits(source,'devices.inventory.read',NULL) OR NOT device_scope_permits(source,'devices.inventory.create',NULL) THEN RAISE EXCEPTION 'Original bound device OU resource required' USING ERRCODE='42501';END IF;
 ELSIF resource->>'deviceId' IS DISTINCT FROM unit.id OR resource->>'deviceRevision' IS DISTINCT FROM proof->>'deviceRevision'
  OR resource->>'revision' IS DISTINCT FROM coalesce(proof#>>'{before,revision}','0') OR resource->'ou' IS DISTINCT FROM previous_unit
  THEN RAISE EXCEPTION 'Original device OU association binding changed' USING ERRCODE='P0412';END IF;
 IF NOT device_scope_permits(source,'devices.inventory.read',previous_unit) OR NOT device_scope_permits(source,'devices.inventory.create',previous_unit)
  OR NOT device_scope_permits(source,'devices.inventory.read',next_unit) OR NOT device_scope_permits(source,'devices.inventory.create',next_unit)
  THEN RAISE EXCEPTION 'Both original and selected OU must permit inventory maintenance' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_validate(event_id UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event device_ou_events;resource JSONB;source JSONB;previous_unit JSONB;
BEGIN
 SELECT * INTO event FROM device_ou_events WHERE id=event_id;
 IF event.id IS NULL THEN RAISE EXCEPTION 'Retained device OU event required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_source(event.source,false);source=event.source->'inventory';
 IF event.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR event.actor_user_id::text IS DISTINCT FROM source->>'actorUserId'
  OR event.after_state->>'device_id' IS DISTINCT FROM event.device_id OR event.after_state->>'tenant_id' IS DISTINCT FROM event.tenant_id::text
  OR event.after_state->>'updated_by' IS DISTINCT FROM event.actor_user_id::text OR (event.after_state->>'updated_at')::timestamptz IS DISTINCT FROM event.created_at
  OR event.after_state->'ou' IS DISTINCT FROM event.source->'ou' OR (event.after_state->>'revision')::numeric<>coalesce((event.before_state->>'revision')::numeric,0)+1
  OR event.before_state IS NOT NULL AND (event.before_state->>'device_id' IS DISTINCT FROM event.device_id OR event.before_state->>'tenant_id' IS DISTINCT FROM event.tenant_id::text)
  OR extract(epoch FROM event.created_at)>=(event.source->>'validUntil')::numeric
  OR NOT EXISTS(SELECT 1 FROM device_ou_outbox outbox WHERE outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' AND outbox.created_at=event.created_at)
  THEN RAISE EXCEPTION 'Original retained device OU effect and evidence required' USING ERRCODE='42501';END IF;
 IF source->'schemaVersion'='2'::jsonb THEN
  resource=source#>'{scope,resource}';
  previous_unit=CASE WHEN event.before_state->'ou' IS NULL OR event.before_state->'ou'='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object('id',event.before_state#>'{ou,id}','generation',event.before_state#>'{ou,generation}') END;
  IF resource='null'::jsonb THEN
   IF NOT device_scope_permits(source,'devices.inventory.read',NULL) OR NOT device_scope_permits(source,'devices.inventory.create',NULL) THEN RAISE EXCEPTION 'Retained tenant stock source required' USING ERRCODE='42501';END IF;
  ELSIF resource->>'deviceId' IS DISTINCT FROM event.device_id OR resource->>'revision' IS DISTINCT FROM coalesce(event.before_state->>'revision','0') OR resource->'ou' IS DISTINCT FROM previous_unit
   THEN RAISE EXCEPTION 'Retained original device OU binding required' USING ERRCODE='42501';END IF;
  IF NOT device_scope_permits(source,'devices.inventory.read',previous_unit) OR NOT device_scope_permits(source,'devices.inventory.create',previous_unit) THEN RAISE EXCEPTION 'Retained original OU stock authority required' USING ERRCODE='42501';END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_receiving(protocol INTEGER) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF protocol IS DISTINCT FROM 2 THEN RAISE EXCEPTION 'Exact scoped device OU receiver protocol required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_receiving();
 IF to_regclass('device_ou_scope_manifest') IS NULL OR (SELECT count(*) FROM device_ou_scope_manifest)<>10
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_ou_scope_manifest'::regclass AND tgname='device_ou_scope_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_ou_scope_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_ou_scope_manifest'::regclass AND tgname='device_ou_scope_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_ou_scope_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Complete sealed device OU scope receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_ou_scope_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device OU scope receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION device_ou_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;actual device_ou_assignments;unit devices;
BEGIN
 PERFORM device_ou_receiving(2);proof=NULLIF(current_setting('opendirectory.device_ou',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text THEN RAISE EXCEPTION 'Original device OU transaction required' USING ERRCODE='42501';END IF;
 PERFORM device_ou_source(proof->'source');PERFORM device_ou_bound(proof,true);PERFORM device_ou_validate((proof#>>'{event,id}')::uuid);
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
 PERFORM device_ou_receiving(2);PERFORM device_ou_source(command->'source');
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
 PERFORM device_ou_bound(proof,false);
 PERFORM set_config('opendirectory.device_ou',proof::text,true);
 INSERT INTO device_ou_assignments SELECT next_state.* ON CONFLICT(device_id) DO UPDATE SET revision=EXCLUDED.revision,ou=EXCLUDED.ou,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by;
 INSERT INTO device_ou_events SELECT event.*;INSERT INTO device_ou_outbox SELECT outbox.*;
 IF NOT EXISTS(SELECT 1 FROM device_ou_assignments WHERE device_id=unit.id AND to_jsonb(device_ou_assignments)=event.after_state)
  OR NOT EXISTS(SELECT 1 FROM device_ou_events WHERE id=event.id AND to_jsonb(device_ou_events)=to_jsonb(event))
  OR NOT EXISTS(SELECT 1 FROM device_ou_outbox WHERE id=outbox.id AND to_jsonb(device_ou_outbox)=to_jsonb(outbox)) THEN RAISE EXCEPTION 'Actual device OU receipt required' USING ERRCODE='42501';END IF;
 RETURN event.id;
END; $$;

DO $$ DECLARE routine_signature TEXT;signatures TEXT[]=ARRAY[
 'device_ou_scope_manifest_guard()','device_ou_source_v1(jsonb,boolean)','device_ou_bound(jsonb,boolean)','device_ou_validate(uuid)','device_ou_receiving(integer)',
 'device_ou_source(jsonb,boolean)','device_ou_guard()','device_ou_receiving()','device_ou_commit()','device_ou_change(jsonb)'];
BEGIN
 ALTER TABLE device_ou_scope_manifest DISABLE TRIGGER ALL;ALTER TABLE device_ou_manifest DISABLE TRIGGER ALL;
 FOREACH routine_signature IN ARRAY signatures LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine_signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine_signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine_signature);
  INSERT INTO device_ou_scope_manifest VALUES(routine_signature,md5(pg_get_functiondef(to_regprocedure(routine_signature)))) ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
  UPDATE device_ou_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(routine_signature))) WHERE signature=routine_signature;
 END LOOP;
 ALTER TABLE device_ou_manifest ENABLE TRIGGER ALL;ALTER TABLE device_ou_scope_manifest ENABLE TRIGGER ALL;
 ALTER TABLE device_scope_manifest DISABLE TRIGGER ALL;
 EXECUTE format('ALTER FUNCTION device_scope_receiving() SET search_path TO %I,pg_catalog',current_schema());
 ALTER FUNCTION device_scope_receiving() SET timezone TO 'UTC';
 UPDATE device_scope_manifest SET digest=md5(pg_get_functiondef('device_scope_receiving()'::regprocedure)) WHERE signature='device_scope_receiving()';
 ALTER TABLE device_scope_manifest ENABLE TRIGGER ALL;
 PERFORM device_scope_receiving();PERFORM device_ou_receiving(2);
END; $$;
COMMIT;

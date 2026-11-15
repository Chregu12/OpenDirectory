BEGIN;
-- Preserve original nested scoped sources and retain the existing request/event/outbox authority.
CREATE TABLE IF NOT EXISTS device_return_scope_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION device_return_scope_manifest_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN RAISE EXCEPTION 'Sealed device return scope manifest cannot be changed' USING ERRCODE='42501';END; $$;
CREATE OR REPLACE TRIGGER device_return_scope_manifest_guard BEFORE INSERT OR UPDATE OR DELETE ON device_return_scope_manifest FOR EACH ROW EXECUTE FUNCTION device_return_scope_manifest_guard();
CREATE OR REPLACE TRIGGER device_return_scope_manifest_truncate BEFORE TRUNCATE ON device_return_scope_manifest FOR EACH STATEMENT EXECUTE FUNCTION device_return_scope_manifest_guard();

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
END; $$;

CREATE OR REPLACE FUNCTION device_returns_actor(source JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN source->'schemaVersion'='2'::jsonb AND source->'deviceOffboardingReturnsProtocol'='2'::jsonb THEN source->'inventory' ELSE source END;
$$;

CREATE OR REPLACE FUNCTION device_returns_source_v1(source JSONB,offboarding BOOLEAN,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent JSONB;target JSONB;expected_keys TEXT[];
BEGIN
 expected_keys=ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'];
 IF offboarding THEN expected_keys=expected_keys||ARRAY['deviceOffboardingReturnsProtocol','parent'];END IF;
 IF source ? 'delegation' THEN expected_keys=expected_keys||ARRAY['delegation'];END IF;
 IF jsonb_typeof(source) IS DISTINCT FROM 'object' OR source-expected_keys<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(source))<>cardinality(expected_keys)
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(source->'issuer') IS DISTINCT FROM 'string' OR length(source->>'issuer')=0
  OR jsonb_typeof(source->'subject') IS DISTINCT FROM 'string' OR length(source->>'subject')=0 OR jsonb_typeof(source->'tokenId') IS DISTINCT FROM 'string' OR length(source->>'tokenId')=0
  OR jsonb_typeof(source->'expiresAt') IS DISTINCT FROM 'number' OR jsonb_typeof(source->'validUntil') IS DISTINCT FROM 'number'
  OR NOT(source->>'expiresAt' ~ '^[1-9][0-9]*$') OR NOT(source->>'validUntil' ~ '^[1-9][0-9]*$')
  OR (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric
  OR (CASE WHEN source ? 'delegation' THEN NOT device_delegation_valid(source) OR NOT source->'permissions' ? 'devices.inventory.read'
    OR source->'permissions' IS DISTINCT FROM (SELECT jsonb_agg(permission ORDER BY ordinal) FROM jsonb_array_elements_text('["devices.inventory.read","devices.inventory.create","devices.inventory.assign"]'::jsonb) WITH ORDINALITY AS duties(permission,ordinal) WHERE source->'permissions' ? permission)
    ELSE source->'permissions' IS DISTINCT FROM '["devices.inventory.read","devices.inventory.create","devices.inventory.assign"]'::jsonb END)
  OR live AND NOT coalesce(source->'permissions' ? 'devices.inventory.assign',false)
  OR jsonb_typeof(source->'context') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(source->'context'))<>4
  OR (source->'context')-ARRAY['userId','revision','linkRevision','rolesRevision']<>'{}'::jsonb
  OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId' OR NOT(source->>'actorUserId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(source->'actorUserId') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,userId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(source#>'{context,revision}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,linkRevision}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,rolesRevision}') IS DISTINCT FROM 'string'
  OR NOT(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$')
  OR NOT(source#>>'{context,revision}' ~ '^[1-9][0-9]{0,18}$') OR NOT(source#>>'{context,linkRevision}' ~ '^[1-9][0-9]{0,18}$')
  OR (source#>>'{context,revision}')::numeric>9223372036854775807 OR (source#>>'{context,linkRevision}')::numeric>9223372036854775807
  OR jsonb_typeof(source->'tenant') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(source->'tenant'))<>3
  OR (source->'tenant')-ARRAY['id','version','generation']<>'{}'::jsonb OR NOT(source#>>'{tenant,id}' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(source#>'{tenant,id}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{tenant,version}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{tenant,generation}') IS DISTINCT FROM 'string'
  OR NOT(source#>>'{tenant,version}' ~ '^[1-9][0-9]{0,18}$') OR NOT(source#>>'{tenant,generation}' ~ '^[1-9][0-9]{0,18}$')
  OR (source#>>'{tenant,version}')::numeric>9223372036854775807 OR (source#>>'{tenant,generation}')::numeric>9223372036854775807
  OR live AND ((source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300)
  THEN RAISE EXCEPTION 'Exact original device return authority required' USING ERRCODE='42501';END IF;
 IF NOT offboarding THEN
  IF source->'target' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Untargeted inventory authority required' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 parent=source->'parent';target=source->'target';
 IF source->'deviceOffboardingReturnsProtocol' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(target) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(target))<>3 OR target-ARRAY['id','enabled','eligibilityRevision']<>'{}'::jsonb
  OR target->'enabled' IS DISTINCT FROM 'false'::jsonb OR NOT(target->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(target->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(target->'eligibilityRevision') IS DISTINCT FROM 'string'
  OR target->>'id'=source->>'actorUserId' OR NOT(target->>'eligibilityRevision' ~ '^[1-9][0-9]{0,18}$') OR (target->>'eligibilityRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parent))<>9
  OR parent-ARRAY['workflowId','tenantId','userId','action','operationId','afterRevision','afterEligibilityRevision','createdAt','deliveryStatus']<>'{}'::jsonb
  OR jsonb_typeof(parent->'workflowId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'tenantId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'userId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(parent->'action') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterRevision') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterEligibilityRevision') IS DISTINCT FROM 'string'
  OR NOT(parent->>'workflowId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') OR parent->>'tenantId' IS DISTINCT FROM source#>>'{tenant,id}'
  OR parent->>'userId' IS DISTINCT FROM target->>'id' OR parent->>'afterEligibilityRevision' IS DISTINCT FROM target->>'eligibilityRevision'
  OR parent->>'deliveryStatus' IS DISTINCT FROM 'pending' OR parent->>'action' NOT IN('disabled','already_disabled')
  OR parent->>'action'='disabled' AND NOT(parent->>'operationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR parent->>'action'='disabled' AND jsonb_typeof(parent->'operationId') IS DISTINCT FROM 'string'
  OR parent->>'action'='already_disabled' AND parent->'operationId' IS DISTINCT FROM 'null'::jsonb
  OR NOT(parent->>'afterRevision' ~ '^[1-9][0-9]{0,18}$') OR (parent->>'afterRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent->'createdAt') IS DISTINCT FROM 'string' OR (parent->>'createdAt')::timestamptz>clock_timestamp()
  THEN RAISE EXCEPTION 'Retained disabled original parent authority required' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_source(source JSONB,offboarding BOOLEAN,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor JSONB;parent JSONB;target JSONB;
BEGIN
 IF source->'schemaVersion'='1'::jsonb THEN PERFORM device_returns_source_v1(source,offboarding,live);RETURN;END IF;
 actor=device_returns_actor(source);
 IF offboarding AND (NOT device_scope_shape(source,ARRAY['schemaVersion','deviceOffboardingReturnsProtocol','inventory','target','parent']) OR source->'schemaVersion' IS DISTINCT FROM '2'::jsonb OR source->'deviceOffboardingReturnsProtocol' IS DISTINCT FROM '2'::jsonb)
  OR actor->'schemaVersion' IS DISTINCT FROM '2'::jsonb OR NOT device_scope_source_valid(actor)
  OR NOT coalesce(actor->'permissions' ? 'devices.inventory.read',false)
  OR (live OR offboarding) AND NOT coalesce(actor->'permissions' ? 'devices.inventory.assign',false)
  OR live AND ((actor->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (actor->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300)
  THEN RAISE EXCEPTION 'Exact original scoped return authority required' USING ERRCODE='42501';END IF;
 IF NOT offboarding THEN
  IF actor IS DISTINCT FROM source OR actor->'target' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Untargeted return decision source required' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 parent=source->'parent';target=source->'target';
 IF actor#>'{target,id}' IS DISTINCT FROM target->'id' OR actor#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'Original targeted disabled inventory source required' USING ERRCODE='42501';END IF;
 IF source->'deviceOffboardingReturnsProtocol' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(target) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(target))<>3 OR target-ARRAY['id','enabled','eligibilityRevision']<>'{}'::jsonb
  OR target->'enabled' IS DISTINCT FROM 'false'::jsonb OR NOT(target->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(target->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(target->'eligibilityRevision') IS DISTINCT FROM 'string'
  OR target->>'id'=actor->>'actorUserId' OR NOT(target->>'eligibilityRevision' ~ '^[1-9][0-9]{0,18}$') OR (target->>'eligibilityRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parent))<>9
  OR parent-ARRAY['workflowId','tenantId','userId','action','operationId','afterRevision','afterEligibilityRevision','createdAt','deliveryStatus']<>'{}'::jsonb
  OR jsonb_typeof(parent->'workflowId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'tenantId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'userId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(parent->'action') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterRevision') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterEligibilityRevision') IS DISTINCT FROM 'string'
  OR NOT(parent->>'workflowId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') OR parent->>'tenantId' IS DISTINCT FROM actor#>>'{tenant,id}'
  OR parent->>'userId' IS DISTINCT FROM target->>'id' OR parent->>'afterEligibilityRevision' IS DISTINCT FROM target->>'eligibilityRevision'
  OR parent->>'deliveryStatus' IS DISTINCT FROM 'pending' OR parent->>'action' NOT IN('disabled','already_disabled')
  OR parent->>'action'='disabled' AND NOT(parent->>'operationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR parent->>'action'='disabled' AND jsonb_typeof(parent->'operationId') IS DISTINCT FROM 'string'
  OR parent->>'action'='already_disabled' AND parent->'operationId' IS DISTINCT FROM 'null'::jsonb
  OR NOT(parent->>'afterRevision' ~ '^[1-9][0-9]{0,18}$') OR (parent->>'afterRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent->'createdAt') IS DISTINCT FROM 'string' OR (parent->>'createdAt')::timestamptz>clock_timestamp()
  THEN RAISE EXCEPTION 'Retained disabled original parent authority required' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_receiving(protocol INTEGER) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF protocol IS DISTINCT FROM 2 THEN RAISE EXCEPTION 'Exact scoped return receiver protocol required' USING ERRCODE='42501';END IF;
 PERFORM device_returns_receiving();
 IF to_regclass('device_return_scope_manifest') IS NULL OR (SELECT count(*) FROM device_return_scope_manifest)<>15
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_return_scope_manifest'::regclass AND tgname='device_return_scope_manifest_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='device_return_scope_manifest_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_return_scope_manifest'::regclass AND tgname='device_return_scope_manifest_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='device_return_scope_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Complete sealed device return scope receiver required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM device_return_scope_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original device return scope receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_bound(receipt device_return_events) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor JSONB;original_revision TEXT;current_revision TEXT;parts TEXT[];inventory device_inventory_events;
BEGIN
 PERFORM device_returns_source(receipt.proof->'source',receipt.type='device.return.requested');
 actor=device_returns_actor(receipt.proof->'source');
 IF actor->'schemaVersion'='1'::jsonb THEN RETURN;END IF;
 IF receipt.type='device.return.requested' THEN
  original_revision=receipt.proof#>>'{item,deviceRevision}';current_revision=original_revision;
 ELSIF receipt.type='device.return.confirmed' THEN
  SELECT * INTO inventory FROM device_inventory_events WHERE id=receipt.inventory_operation_id;
  original_revision=inventory.before_state->>'inventory_revision';current_revision=inventory.after_state->>'inventory_revision';
 ELSE
  parts=regexp_match(receipt.proof->>'expected','^"device-return-([a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12})-([1-9][0-9]{0,18})-([1-9][0-9]{0,18})"$');
  original_revision=parts[4];current_revision=original_revision;
 END IF;
 IF original_revision IS NULL OR current_revision IS NULL THEN RAISE EXCEPTION 'Exact return inventory version binding required' USING ERRCODE='42501';END IF;
 PERFORM device_scope_require(actor,'devices.inventory.assign',receipt.device_id,original_revision,current_revision);
END; $$;

CREATE OR REPLACE FUNCTION device_returns_row(data device_return_requests) RETURNS JSONB LANGUAGE SQL STABLE AS $$
 SELECT to_jsonb(data)||jsonb_build_object('revision',(data).revision::text,'device_revision',(data).device_revision::text,'eligibility_revision',(data).eligibility_revision::text);
$$;

CREATE OR REPLACE FUNCTION device_returns_scope() RETURNS device_return_events LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_return_events;
BEGIN
 SELECT * INTO receipt FROM device_return_events WHERE transaction_id=txid_current();
 IF receipt.id IS NULL OR receipt.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.device_returns',true),'') OR receipt.valid_until<=clock_timestamp()
  THEN RAISE EXCEPTION 'Original device return admission required' USING ERRCODE='42501';END IF;
 PERFORM device_returns_source(receipt.proof->'source',receipt.type='device.return.requested');RETURN receipt;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_return_events;before_data JSONB;after_data JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Device returns are retained' USING ERRCODE='42501';END IF;
 IF TG_OP<>'INSERT' THEN before_data=to_jsonb(OLD);END IF;IF TG_OP<>'DELETE' THEN after_data=to_jsonb(NEW);END IF;
 IF TG_TABLE_NAME='device_return_events' THEN
  IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','') OR TG_OP<>'INSERT'
   OR NEW.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.device_returns',true),'') OR NEW.transaction_id<>txid_current() OR NEW.valid_until<=clock_timestamp()
   OR NEW.id::text IS DISTINCT FROM NEW.proof->>'id' OR NEW.actor_user_id::text IS DISTINCT FROM (device_returns_actor(NEW.proof->'source')->>'actorUserId')
   OR NEW.tenant_id::text IS DISTINCT FROM (device_returns_actor(NEW.proof->'source')#>>'{tenant,id}') OR NEW.valid_until IS DISTINCT FROM to_timestamp(((device_returns_actor(NEW.proof->'source')->>'validUntil'))::double precision)
   THEN RAISE EXCEPTION 'Immutable original device return event required' USING ERRCODE='42501';END IF;
  PERFORM device_returns_source(NEW.proof->'source',NEW.type='device.return.requested');RETURN NEW;
 END IF;
 receipt=device_returns_scope();
 IF TG_TABLE_NAME='device_return_requests' THEN
  IF TG_OP<>'INSERT' THEN before_data=device_returns_row(OLD);END IF;IF TG_OP<>'DELETE' THEN after_data=device_returns_row(NEW);END IF;
  IF TG_OP='DELETE' OR before_data IS DISTINCT FROM receipt.before_request OR after_data IS DISTINCT FROM receipt.after_request
   THEN RAISE EXCEPTION 'Exact device return request effect required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='device_return_outbox' THEN
  IF TG_OP<>'INSERT' OR after_data IS DISTINCT FROM jsonb_build_object('id',receipt.id,'tenant_id',receipt.tenant_id,'status','pending','created_at',receipt.created_at)
   THEN RAISE EXCEPTION 'Exact pending return outbox required' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'Unknown device return effect' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM device_inventory_receiving();
 FOREACH relation IN ARRAY ARRAY['device_return_requests','device_return_events','device_return_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_returns_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_returns_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_returns_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_returns_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Device return row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_return_events'::regclass AND tgname='device_returns_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_returns_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Device return commit receiver unavailable' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='devices'::regclass AND tgname='device_returns_device_effect' AND tgtype=29 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_returns_device_effect()'::regprocedure)
  THEN RAISE EXCEPTION 'Device return inventory effect fence unavailable' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_device_effect() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_return_events;inventory device_inventory_events;
BEGIN
 SELECT * INTO receipt FROM device_return_events WHERE transaction_id=txid_current();
 IF receipt.id IS NULL THEN RETURN NULL;END IF;
 PERFORM device_returns_receiving();
 SELECT * INTO inventory FROM device_inventory_events WHERE id=receipt.inventory_operation_id;
 IF receipt.type<>'device.return.confirmed' OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'Return metadata cannot hide another device effect' USING ERRCODE='23514';END IF;
 IF inventory.id IS NULL OR inventory.device_id<>NEW.id OR device_inventory_row(OLD) IS DISTINCT FROM inventory.before_state OR device_inventory_row(NEW) IS DISTINCT FROM inventory.after_state
  THEN RAISE EXCEPTION 'Only exact composed original device effect allowed' USING ERRCODE='23514';END IF;
 RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_release(link device_inventory_assignments) RETURNS device_inventory_events LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;
BEGIN
 SELECT * INTO receipt FROM device_inventory_events WHERE id=(link).released_by_command_id;
 IF receipt.id IS NULL OR receipt.tenant_id<>(link).tenant_id OR receipt.device_id<>(link).device_id OR receipt.action NOT IN('assign','release')
  OR receipt.created_at IS DISTINCT FROM (link).released_at OR receipt.before_assignment IS DISTINCT FROM (to_jsonb(link)||jsonb_build_object('released_at',NULL,'released_by_command_id',NULL))
  OR receipt.after_state->>'inventory_revision' IS DISTINCT FROM ((receipt.before_state->>'inventory_revision')::bigint+1)::text
  OR NOT EXISTS(SELECT 1 FROM device_inventory_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at)
  THEN RAISE EXCEPTION 'Actual retained original assignment release required' USING ERRCODE='23514';END IF;
 RETURN receipt;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_validate(identifier UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE task device_return_requests;creation device_return_events;decision device_return_events;link device_inventory_assignments;release device_inventory_events;initial JSONB;
BEGIN
 PERFORM device_returns_receiving();SELECT * INTO task FROM device_return_requests WHERE id=identifier;
 IF task.id IS NULL THEN RAISE EXCEPTION 'Retained return task required' USING ERRCODE='23514';END IF;
 SELECT * INTO creation FROM device_return_events WHERE id=task.operation_id;SELECT * INTO link FROM device_inventory_assignments WHERE id=task.assignment_id;
 initial=device_returns_row(task)||jsonb_build_object('revision','1','status','requested','closed_at',NULL,'closed_by_user_id',NULL,'closing_operation_id',NULL,'inventory_operation_id',NULL);
 IF creation.id IS NULL OR creation.version IS DISTINCT FROM 1 OR creation.type<>'device.return.requested' OR creation.request_id<>task.id OR creation.tenant_id<>task.tenant_id OR creation.device_id<>task.device_id OR creation.assignment_id<>task.assignment_id
  OR creation.actor_user_id<>task.actor_user_id OR creation.created_at<>task.requested_at OR creation.reason<>task.reason OR creation.before_request IS NOT NULL OR creation.after_request IS DISTINCT FROM initial
  OR creation.before_state IS NOT NULL OR creation.after_state IS DISTINCT FROM jsonb_build_object('revision','1','status','requested') OR creation.inventory_operation_id IS NOT NULL
  OR creation.valid_until IS DISTINCT FROM to_timestamp(((device_returns_actor(creation.proof->'source')->>'validUntil'))::double precision) OR creation.created_at>=creation.valid_until
  OR creation.proof->>'requestId' IS DISTINCT FROM task.id::text OR creation.proof#>>'{source,parent,workflowId}' IS DISTINCT FROM task.workflow_id::text
  OR creation.proof#>>'{source,target,id}' IS DISTINCT FROM task.user_id::text OR creation.proof#>>'{source,target,eligibilityRevision}' IS DISTINCT FROM task.eligibility_revision::text
  OR creation.proof#>>'{item,deviceId}' IS DISTINCT FROM task.device_id OR creation.proof#>>'{item,assignmentId}' IS DISTINCT FROM task.assignment_id::text
  OR creation.proof#>>'{item,deviceRevision}' IS DISTINCT FROM task.device_revision::text OR creation.proof#>>'{item,requestId}' IS DISTINCT FROM task.id::text
  OR creation.proof->>'reason' IS DISTINCT FROM task.reason OR creation.proof->>'id' IS DISTINCT FROM creation.id::text
  OR (device_returns_actor(creation.proof->'source')->>'actorUserId') IS DISTINCT FROM creation.actor_user_id::text OR (device_returns_actor(creation.proof->'source')#>>'{tenant,id}') IS DISTINCT FROM task.tenant_id::text
  OR link.id IS NULL OR link.tenant_id<>task.tenant_id OR link.device_id<>task.device_id OR link.user_id<>task.user_id
  OR NOT EXISTS(SELECT 1 FROM device_return_outbox WHERE id=creation.id AND tenant_id=task.tenant_id AND status='pending' AND created_at=creation.created_at)
  THEN RAISE EXCEPTION 'Exact retained original return request evidence required' USING ERRCODE='23514';END IF;
 PERFORM device_returns_source(creation.proof->'source',true,false);
 IF link.released_at IS NOT NULL THEN release=device_returns_release(link);END IF;
 IF task.status='requested' THEN RETURN;END IF;
 SELECT * INTO decision FROM device_return_events WHERE id=task.closing_operation_id;
 IF decision.id IS NULL OR decision.version IS DISTINCT FROM 1 OR decision.request_id<>task.id OR decision.tenant_id<>task.tenant_id OR decision.device_id<>task.device_id OR decision.assignment_id<>task.assignment_id
  OR decision.type IS DISTINCT FROM (CASE task.status WHEN 'returned' THEN 'device.return.confirmed' ELSE 'device.return.cancelled' END)
  OR decision.actor_user_id<>task.closed_by_user_id OR decision.created_at<>task.closed_at OR decision.before_request IS DISTINCT FROM initial OR decision.after_request IS DISTINCT FROM device_returns_row(task)
  OR decision.before_state IS DISTINCT FROM jsonb_build_object('revision','1','status','requested') OR decision.after_state IS DISTINCT FROM jsonb_build_object('revision','2','status',task.status)
  OR decision.proof->>'id' IS DISTINCT FROM decision.id::text OR decision.proof->>'requestId' IS DISTINCT FROM task.id::text OR decision.proof->>'action' IS DISTINCT FROM task.status
  OR decision.proof->>'reason' IS DISTINCT FROM decision.reason OR (device_returns_actor(decision.proof->'source')->>'actorUserId') IS DISTINCT FROM decision.actor_user_id::text OR (device_returns_actor(decision.proof->'source')#>>'{tenant,id}') IS DISTINCT FROM task.tenant_id::text
  OR decision.valid_until IS DISTINCT FROM to_timestamp(((device_returns_actor(decision.proof->'source')->>'validUntil'))::double precision) OR decision.created_at>=decision.valid_until
  OR decision.inventory_operation_id IS DISTINCT FROM task.inventory_operation_id
  OR NOT EXISTS(SELECT 1 FROM device_return_outbox WHERE id=decision.id AND tenant_id=task.tenant_id AND status='pending' AND created_at=decision.created_at)
  THEN RAISE EXCEPTION 'Exact retained return decision evidence required' USING ERRCODE='23514';END IF;
 PERFORM device_returns_source(decision.proof->'source',false,false);
 IF task.status='returned' AND (release.id IS DISTINCT FROM task.inventory_operation_id OR release.action IS DISTINCT FROM 'release' OR release.actor_user_id IS DISTINCT FROM decision.actor_user_id
  OR release.transaction_id<>decision.transaction_id OR release.proof->'source' IS DISTINCT FROM decision.proof->'source')
  THEN RAISE EXCEPTION 'Actual composed inventory release required' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_return_events;inventory_count INTEGER;
BEGIN
 PERFORM device_returns_receiving(2);receipt=device_returns_scope();PERFORM device_returns_validate(receipt.request_id);
 IF receipt IS DISTINCT FROM NEW OR NOT EXISTS(SELECT 1 FROM device_return_requests WHERE id=receipt.request_id AND device_returns_row(device_return_requests)=receipt.after_request)
  THEN RAISE EXCEPTION 'Exact original return physical effect required' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO inventory_count FROM device_inventory_events WHERE transaction_id=txid_current();
 IF receipt.type='device.return.confirmed' THEN
  IF inventory_count<>1 OR NOT EXISTS(SELECT 1 FROM device_inventory_events WHERE id=receipt.inventory_operation_id AND transaction_id=txid_current() AND action='release'
   AND tenant_id=receipt.tenant_id AND device_id=receipt.device_id AND before_assignment->>'id'=receipt.assignment_id::text)
   THEN RAISE EXCEPTION 'Only composed original inventory release allowed' USING ERRCODE='23514';END IF;
 ELSIF inventory_count<>0 THEN RAISE EXCEPTION 'Metadata return action cannot change inventory' USING ERRCODE='23514';END IF;
 PERFORM device_returns_bound(receipt);
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION device_returns_change(proof JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_return_events;task device_return_requests;previous device_return_requests;unit devices;link device_inventory_assignments;inventory device_inventory_events;source JSONB;actor JSONB;action TEXT;parts TEXT[];
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  THEN RAISE EXCEPTION 'Device return database owner required' USING ERRCODE='42501';END IF;
 PERFORM device_returns_receiving(2);source=proof->'source';actor=device_returns_actor(source);action=proof->>'action';
 IF action NOT IN('requested','returned','cancelled') OR action IS NULL OR NULLIF(current_setting('opendirectory.device_returns',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM device_return_events WHERE transaction_id=txid_current()) OR jsonb_typeof(proof->'reason') IS DISTINCT FROM 'string' OR length(proof->>'reason') NOT BETWEEN 10 AND 500
  THEN RAISE EXCEPTION 'One exact original return intent required' USING ERRCODE='42501';END IF;
 PERFORM device_returns_source(source,action='requested');
 receipt.id=(proof->>'id')::uuid;receipt.tenant_id=(actor#>>'{tenant,id}')::uuid;receipt.request_id=(proof->>'requestId')::uuid;
 receipt.actor_user_id=(actor->>'actorUserId')::uuid;receipt.correlation_id=(proof->>'correlationId')::uuid;receipt.reason=proof->>'reason';receipt.proof=proof;
 receipt.created_at=clock_timestamp();receipt.version=1;receipt.valid_until=to_timestamp((actor->>'validUntil')::double precision);receipt.transaction_id=txid_current();
 IF action='requested' THEN
  SELECT * INTO unit FROM devices WHERE id=proof#>>'{item,deviceId}' AND tenant_id=receipt.tenant_id FOR UPDATE;
  SELECT * INTO link FROM device_inventory_assignments WHERE id=(proof#>>'{item,assignmentId}')::uuid FOR UPDATE;
  IF unit.id IS NULL OR link.id IS NULL OR link.device_id<>unit.id OR link.tenant_id<>receipt.tenant_id OR link.user_id::text IS DISTINCT FROM source#>>'{target,id}'
   OR unit.inventory_revision::text IS DISTINCT FROM proof#>>'{item,deviceRevision}' OR unit.assigned_user IS DISTINCT FROM link.user_id::text OR unit.inventory_lifecycle<>'assigned'
   OR link.released_at IS NOT NULL OR proof#>>'{item,requestId}' IS DISTINCT FROM receipt.request_id::text OR proof->>'eligibilityRevision' IS DISTINCT FROM source#>>'{target,eligibilityRevision}'
   OR EXISTS(SELECT 1 FROM device_return_requests WHERE id=receipt.request_id OR assignment_id=link.id AND status='requested')
   OR EXISTS(SELECT 1 FROM device_inventory_events WHERE transaction_id=txid_current())
   THEN RAISE EXCEPTION 'Exact current original assignment required' USING ERRCODE='23514';END IF;
  task.id=receipt.request_id;task.tenant_id=receipt.tenant_id;task.workflow_id=(source#>>'{parent,workflowId}')::uuid;task.user_id=link.user_id;
  task.device_id=unit.id;task.assignment_id=link.id;task.asset_id=unit.asset_id;task.serial_number=unit.serial_number;task.revision=1;task.device_revision=unit.inventory_revision;
  task.status='requested';task.reason=receipt.reason;task.actor_user_id=receipt.actor_user_id;task.requested_at=receipt.created_at;task.eligibility_revision=(source#>>'{target,eligibilityRevision}')::bigint;task.operation_id=receipt.id;
  receipt.type='device.return.requested';
 ELSE
  SELECT * INTO previous FROM device_return_requests WHERE id=receipt.request_id AND tenant_id=receipt.tenant_id;
  SELECT * INTO unit FROM devices WHERE id=previous.device_id AND tenant_id=receipt.tenant_id FOR UPDATE;
  SELECT * INTO previous FROM device_return_requests WHERE id=receipt.request_id AND tenant_id=receipt.tenant_id FOR UPDATE;
  SELECT * INTO link FROM device_inventory_assignments WHERE id=previous.assignment_id FOR UPDATE;
  PERFORM device_returns_validate(previous.id);
  IF previous.id IS NULL OR unit.id IS NULL OR previous.status<>'requested' THEN RAISE EXCEPTION 'Pending original return task required' USING ERRCODE='23514';END IF;
  parts=regexp_match(proof->>'expected','^"device-return-([a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12})-([1-9][0-9]{0,18})-([1-9][0-9]{0,18})"$');
  IF parts IS NULL OR parts[1]<>previous.id::text OR parts[3]<>previous.revision::text THEN RAISE EXCEPTION 'Original combined return version required' USING ERRCODE='23514';END IF;
  IF action='returned' THEN
   SELECT * INTO inventory FROM device_inventory_events WHERE id=(device_returns_change.proof->>'inventoryOperationId')::uuid;
   IF inventory.id IS NULL OR inventory.transaction_id<>txid_current() OR inventory.action<>'release' OR inventory.tenant_id<>receipt.tenant_id OR inventory.device_id<>unit.id
    OR inventory.before_assignment->>'id' IS DISTINCT FROM link.id::text OR inventory.before_assignment->>'user_id' IS DISTINCT FROM previous.user_id::text
    OR inventory.before_state->>'inventory_revision' IS DISTINCT FROM parts[4] OR inventory.proof->'source' IS DISTINCT FROM source OR inventory.actor_user_id<>receipt.actor_user_id
    OR unit.assigned_user IS NOT NULL OR link.released_by_command_id IS DISTINCT FROM inventory.id
    THEN RAISE EXCEPTION 'Actual original nested inventory release required' USING ERRCODE='23514';END IF;
   receipt.inventory_operation_id=inventory.id;receipt.type='device.return.confirmed';
  ELSE
   IF unit.inventory_revision::text IS DISTINCT FROM parts[4] OR link.released_at IS NOT NULL OR unit.assigned_user IS DISTINCT FROM previous.user_id::text
    OR proof->'inventoryOperationId' IS DISTINCT FROM 'null'::jsonb OR EXISTS(SELECT 1 FROM device_inventory_events WHERE transaction_id=txid_current())
    THEN RAISE EXCEPTION 'Cancellation requires unchanged original assignment and no device effect' USING ERRCODE='23514';END IF;
   receipt.type='device.return.cancelled';
  END IF;
  task=previous;task.status=action;task.revision=2;task.closed_at=receipt.created_at;task.closed_by_user_id=receipt.actor_user_id;task.closing_operation_id=receipt.id;task.inventory_operation_id=receipt.inventory_operation_id;
  receipt.before_request=device_returns_row(previous);receipt.before_state=jsonb_build_object('revision',previous.revision::text,'status',previous.status);
 END IF;
 receipt.device_id=task.device_id;receipt.assignment_id=task.assignment_id;receipt.after_request=device_returns_row(task);receipt.after_state=jsonb_build_object('revision',task.revision::text,'status',task.status);
 PERFORM device_returns_bound(receipt);
 PERFORM set_config('opendirectory.device_returns',receipt.id::text,true);INSERT INTO device_return_events SELECT receipt.*;
 IF action='requested' THEN INSERT INTO device_return_requests SELECT task.*;
 ELSE UPDATE device_return_requests SET status=task.status,revision=task.revision,closed_at=task.closed_at,closed_by_user_id=task.closed_by_user_id,closing_operation_id=task.closing_operation_id,inventory_operation_id=task.inventory_operation_id WHERE id=task.id;END IF;
 INSERT INTO device_return_outbox VALUES(receipt.id,receipt.tenant_id,'pending',receipt.created_at);RETURN receipt.id;
END; $$;

DO $$ DECLARE routine_signature TEXT;signatures TEXT[]=ARRAY[
 'device_return_scope_manifest_guard()','device_returns_actor(jsonb)','device_returns_source_v1(jsonb,boolean,boolean)',
 'device_returns_source(jsonb,boolean,boolean)','device_returns_bound(device_return_events)','device_returns_row(device_return_requests)',
 'device_returns_scope()','device_returns_guard()','device_returns_receiving()','device_returns_receiving(integer)','device_returns_device_effect()',
 'device_returns_release(device_inventory_assignments)','device_returns_validate(uuid)','device_returns_commit()','device_returns_change(jsonb)'];
BEGIN
 ALTER TABLE device_return_scope_manifest DISABLE TRIGGER ALL;
 FOREACH routine_signature IN ARRAY signatures LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine_signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine_signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine_signature);
  INSERT INTO device_return_scope_manifest VALUES(routine_signature,md5(pg_get_functiondef(to_regprocedure(routine_signature)))) ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 ALTER TABLE device_return_scope_manifest ENABLE TRIGGER ALL;
 ALTER TABLE device_scope_manifest DISABLE TRIGGER ALL;
 EXECUTE format('ALTER FUNCTION device_scope_receiving() SET search_path TO %I,pg_catalog',current_schema());
 ALTER FUNCTION device_scope_receiving() SET timezone TO 'UTC';
 UPDATE device_scope_manifest SET digest=md5(pg_get_functiondef('device_scope_receiving()'::regprocedure)) WHERE signature='device_scope_receiving()';
 ALTER TABLE device_scope_manifest ENABLE TRIGGER ALL;
 PERFORM device_scope_receiving();PERFORM device_returns_receiving();
END; $$;
COMMIT;

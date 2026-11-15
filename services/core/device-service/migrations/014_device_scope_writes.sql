BEGIN;
CREATE TABLE IF NOT EXISTS device_scope_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION device_scope_shape(value JSONB,keys TEXT[]) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 RETURN value-keys='{}'::jsonb AND (SELECT count(*) FROM jsonb_object_keys(value))=cardinality(keys);
END; $$;
CREATE OR REPLACE FUNCTION device_scope_uuid(value JSONB) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(jsonb_typeof(value)='string' AND value#>>'{}' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false);
$$;
CREATE OR REPLACE FUNCTION device_scope_revision(value JSONB,zero BOOLEAN DEFAULT false) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'string' OR NOT coalesce(value#>>'{}' ~ '^(0|[1-9][0-9]{0,18})$',false) THEN RETURN false;END IF;
 RETURN (zero OR value#>>'{}'<>'0') AND (value#>>'{}')::numeric<=9223372036854775807;
END; $$;
CREATE OR REPLACE FUNCTION device_scope_source_valid(source JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE keys TEXT[];available TEXT[]=ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign'];
 scope JSONB;grant_row JSONB;selected JSONB;unit JSONB;root JSONB;resource JSONB;wanted JSONB;
 previous TEXT;sort_key TEXT;scoped BOOLEAN;pim BOOLEAN;has_scope BOOLEAN=false;
BEGIN
 keys=ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'];
 IF source->'schemaVersion'='2'::jsonb THEN keys=keys||ARRAY['scope'];
 ELSIF source->'schemaVersion'='1'::jsonb THEN IF source ? 'delegation' THEN keys=keys||ARRAY['delegation'];END IF;
 ELSE RETURN false;END IF;
 IF NOT device_scope_shape(source,keys)
  OR jsonb_typeof(source->'issuer') IS DISTINCT FROM 'string' OR length(source->>'issuer')=0
  OR jsonb_typeof(source->'subject') IS DISTINCT FROM 'string' OR length(source->>'subject')=0
  OR jsonb_typeof(source->'tokenId') IS DISTINCT FROM 'string' OR length(source->>'tokenId')=0
  OR jsonb_typeof(source->'expiresAt') IS DISTINCT FROM 'number' OR NOT coalesce(source->>'expiresAt' ~ '^[1-9][0-9]{0,15}$',false)
  OR jsonb_typeof(source->'validUntil') IS DISTINCT FROM 'number' OR NOT coalesce(source->>'validUntil' ~ '^[1-9][0-9]{0,15}$',false)
  OR (source->>'expiresAt')::numeric>9007199254740991 OR (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric
  OR NOT device_scope_uuid(source->'actorUserId')
  OR NOT device_scope_shape(source->'context',ARRAY['userId','revision','linkRevision','rolesRevision'])
  OR source#>'{context,userId}' IS DISTINCT FROM source->'actorUserId'
  OR NOT device_scope_revision(source#>'{context,revision}') OR NOT device_scope_revision(source#>'{context,linkRevision}')
  OR jsonb_typeof(source#>'{context,rolesRevision}') IS DISTINCT FROM 'string' OR NOT coalesce(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$',false)
  OR NOT device_scope_shape(source->'tenant',ARRAY['id','version','generation']) OR NOT device_scope_uuid(source#>'{tenant,id}')
  OR NOT device_scope_revision(source#>'{tenant,version}') OR NOT device_scope_revision(source#>'{tenant,generation}')
  OR jsonb_typeof(source->'permissions') IS DISTINCT FROM 'array' OR jsonb_array_length(source->'permissions') NOT BETWEEN 1 AND 3
  OR NOT source->'permissions' ? 'devices.inventory.read'
  OR source->'permissions' IS DISTINCT FROM (SELECT jsonb_agg(permission ORDER BY ordinal) FROM unnest(available) WITH ORDINALITY AS duties(permission,ordinal) WHERE source->'permissions' ? permission)
  THEN RETURN false;END IF;
 IF source->'target'<>'null'::jsonb AND (NOT device_scope_shape(source->'target',ARRAY['id','revision','enabled'])
  OR NOT device_scope_uuid(source#>'{target,id}') OR NOT device_scope_revision(source#>'{target,revision}') OR jsonb_typeof(source#>'{target,enabled}') IS DISTINCT FROM 'boolean') THEN RETURN false;END IF;
 IF source->'schemaVersion'='1'::jsonb THEN
  RETURN CASE WHEN source ? 'delegation' THEN device_delegation_valid(source) ELSE source->'permissions'=to_jsonb(available) END;
 END IF;
 scope=source->'scope';
 IF NOT device_scope_shape(scope,ARRAY['protocol','inherent','grants','units','resource']) OR scope->'protocol' IS DISTINCT FROM '1'::jsonb
  OR jsonb_typeof(scope->'inherent') IS DISTINCT FROM 'array'
  OR scope->'inherent' IS DISTINCT FROM coalesce((SELECT jsonb_agg(permission ORDER BY ordinal) FROM unnest(available) WITH ORDINALITY AS duties(permission,ordinal) WHERE scope->'inherent' ? permission),'[]'::jsonb)
  OR jsonb_typeof(scope->'grants') IS DISTINCT FROM 'array' OR jsonb_array_length(scope->'grants') NOT BETWEEN 1 AND 128
  OR jsonb_typeof(scope->'units') IS DISTINCT FROM 'array' OR jsonb_array_length(scope->'units') NOT BETWEEN 1 AND 1000 THEN RETURN false;END IF;
 previous=NULL;
 FOR grant_row IN SELECT value FROM jsonb_array_elements(scope->'grants') LOOP
  selected=grant_row->'source';scoped=selected->>'scopeType'='device-ou';pim=selected ? 'activationId';
  keys=ARRAY['id','roleId','roleRevision','scopeType','ouId','targetType','targetId','membershipId','validUntil'];
  IF scoped THEN keys=keys||ARRAY['ouGeneration'];has_scope=true;END IF;
  IF pim THEN keys=keys||ARRAY['activationId','mfaRevision','authTime','issuer','subject','actorContext'];END IF;
  IF NOT device_scope_shape(grant_row,ARRAY['permission','source']) OR NOT coalesce(grant_row->>'permission'=ANY(available),false)
   OR NOT device_scope_shape(selected,keys) OR NOT device_scope_uuid(selected->'id') OR NOT device_scope_uuid(selected->'roleId') OR NOT device_scope_revision(selected->'roleRevision')
   OR NOT coalesce(selected->>'scopeType' IN('tenant','device-ou'),false)
   OR (CASE WHEN scoped THEN NOT device_scope_uuid(selected->'ouId') OR NOT device_scope_revision(selected->'ouGeneration') ELSE selected->'ouId' IS DISTINCT FROM 'null'::jsonb END)
   OR NOT device_scope_uuid(selected->'targetId') OR NOT device_scope_revision(selected->'validUntil')
   OR (selected->>'validUntil')::numeric>9007199254740991 OR (selected->>'validUntil')::numeric<(source->>'validUntil')::numeric
   OR (CASE WHEN selected->>'targetType'='user' THEN selected->'targetId' IS DISTINCT FROM source->'actorUserId' OR selected->'membershipId' IS DISTINCT FROM 'null'::jsonb
       ELSE selected->>'targetType' IS DISTINCT FROM 'group' OR NOT device_scope_uuid(selected->'membershipId') END)
   OR pim AND (NOT device_scope_uuid(selected->'activationId') OR NOT device_scope_revision(selected->'mfaRevision') OR NOT device_scope_revision(selected->'authTime')
       OR selected->'issuer' IS DISTINCT FROM source->'issuer' OR selected->'subject' IS DISTINCT FROM source->'subject' OR selected->'actorContext' IS DISTINCT FROM source->'context') THEN RETURN false;END IF;
  sort_key=lpad(array_position(available,grant_row->>'permission')::text,2,'0')||':'||(selected->>'id')||':'||coalesce(selected->>'activationId','');
  IF previous IS NOT NULL AND previous COLLATE "C">=sort_key COLLATE "C" THEN RETURN false;END IF;previous=sort_key;
 END LOOP;
 IF NOT has_scope THEN RETURN false;END IF;
 SELECT jsonb_agg(permission ORDER BY ordinal) INTO wanted FROM unnest(available) WITH ORDINALITY AS duties(permission,ordinal)
 WHERE scope->'inherent' ? permission OR EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'grants') AS candidates(item) WHERE candidates.item->>'permission'=permission);
 IF source->'permissions' IS DISTINCT FROM wanted THEN RETURN false;END IF;
 previous=NULL;
 FOR unit IN SELECT value FROM jsonb_array_elements(scope->'units') LOOP
  IF NOT device_scope_shape(unit,ARRAY['id','generation','roots']) OR NOT device_scope_uuid(unit->'id') OR NOT device_scope_revision(unit->'generation')
   OR jsonb_typeof(unit->'roots') IS DISTINCT FROM 'array' OR jsonb_array_length(unit->'roots') NOT BETWEEN 1 AND 128
   OR previous IS NOT NULL AND previous COLLATE "C">=unit->>'id' COLLATE "C" THEN RETURN false;END IF;
  previous=unit->>'id';sort_key=NULL;
  FOR root IN SELECT value FROM jsonb_array_elements(unit->'roots') LOOP
   IF NOT device_scope_uuid(root) OR sort_key IS NOT NULL AND sort_key COLLATE "C">=root#>>'{}' COLLATE "C"
    OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'grants') AS candidates(item) WHERE candidates.item#>>'{source,scopeType}'='device-ou' AND candidates.item#>'{source,ouId}'=root) THEN RETURN false;END IF;
   sort_key=root#>>'{}';
  END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'grants') AS candidates(item) WHERE candidates.item#>>'{source,scopeType}'='device-ou'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'units') AS targets(item) WHERE targets.item->'id'=candidates.item#>'{source,ouId}' AND targets.item->'generation'=candidates.item#>'{source,ouGeneration}' AND targets.item->'roots' ? (targets.item->>'id'))) THEN RETURN false;END IF;
 resource=scope->'resource';
 IF resource<>'null'::jsonb AND (NOT device_scope_shape(resource,ARRAY['deviceId','deviceRevision','revision','ou']) OR NOT device_scope_uuid(resource->'deviceId')
  OR NOT device_scope_revision(resource->'deviceRevision') OR NOT device_scope_revision(resource->'revision',true)
  OR resource->'ou'<>'null'::jsonb AND (resource->>'revision'='0' OR NOT device_scope_shape(resource->'ou',ARRAY['id','generation']) OR NOT device_scope_uuid(resource#>'{ou,id}') OR NOT device_scope_revision(resource#>'{ou,generation}'))) THEN RETURN false;END IF;
 RETURN true;
 EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

CREATE OR REPLACE FUNCTION device_scope_permits(source JSONB,permission TEXT,unit JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF NOT coalesce(source->'permissions' ? permission,false) THEN RETURN false;END IF;
 IF source->'schemaVersion'='1'::jsonb THEN RETURN true;END IF;
 IF source->'schemaVersion' IS DISTINCT FROM '2'::jsonb THEN RETURN false;END IF;
 RETURN coalesce(source#>'{scope,inherent}' ? permission,false)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(source#>'{scope,grants}') grant_row WHERE grant_row->>'permission'=permission AND grant_row#>>'{source,scopeType}'='tenant')
  OR unit IS NOT NULL AND unit<>'null'::jsonb AND EXISTS(SELECT 1 FROM jsonb_array_elements(source#>'{scope,units}') allowed
    WHERE allowed->'id'=unit->'id' AND allowed->'generation'=unit->'generation' AND EXISTS(SELECT 1 FROM jsonb_array_elements(source#>'{scope,grants}') grant_row
      WHERE grant_row->>'permission'=permission AND grant_row#>>'{source,scopeType}'='device-ou' AND allowed->'roots' ? (grant_row#>>'{source,ouId}')));
END; $$;

CREATE OR REPLACE FUNCTION device_scope_manifest_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN RAISE EXCEPTION 'Device scope receiver manifest is sealed' USING ERRCODE='42501';END; $$;
CREATE OR REPLACE TRIGGER device_scope_manifest_guard BEFORE INSERT OR UPDATE OR DELETE ON device_scope_manifest FOR EACH ROW EXECUTE FUNCTION device_scope_manifest_guard();
CREATE OR REPLACE TRIGGER device_scope_manifest_truncate BEFORE TRUNCATE ON device_scope_manifest FOR EACH STATEMENT EXECUTE FUNCTION device_scope_manifest_guard();

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
END; $$;

CREATE OR REPLACE FUNCTION device_scope_require(source JSONB,permission TEXT,device_id TEXT,original_revision TEXT,current_revision TEXT) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE resource JSONB;actual devices;association device_ou_assignments;actual_unit JSONB;
BEGIN
 PERFORM device_scope_receiving();
 IF NOT device_scope_source_valid(source) OR NOT coalesce(source->'permissions' ? permission,false)
  OR (source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300
  THEN RAISE EXCEPTION 'Original current device scope source required' USING ERRCODE='42501';END IF;
 IF source->'schemaVersion'='1'::jsonb THEN RETURN;END IF;
 resource=source#>'{scope,resource}';
 IF original_revision IS NULL AND current_revision IS NULL THEN
  IF permission<>'devices.inventory.create' OR resource IS DISTINCT FROM 'null'::jsonb OR NOT device_scope_permits(source,permission,NULL) OR NOT device_scope_permits(source,'devices.inventory.read',NULL) THEN RAISE EXCEPTION 'Tenant-wide new inventory duty required' USING ERRCODE='42501';END IF;
  RETURN;
 END IF;
 IF resource='null'::jsonb AND device_scope_permits(source,permission,NULL) AND device_scope_permits(source,'devices.inventory.read',NULL) THEN RETURN;END IF;
 PERFORM device_ou_receiving();
 SELECT * INTO actual FROM devices WHERE id=device_id AND tenant_id=(source#>>'{tenant,id}')::uuid FOR UPDATE;
 SELECT * INTO association FROM device_ou_assignments row WHERE row.device_id=device_scope_require.device_id AND row.tenant_id=(source#>>'{tenant,id}')::uuid FOR SHARE;
 actual_unit=CASE WHEN association.ou IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',association.ou->'id','generation',association.ou->'generation') END;
 IF actual.id IS NULL OR actual.inventory_revision::text IS DISTINCT FROM current_revision
  OR resource->>'deviceId' IS DISTINCT FROM device_id OR resource->>'deviceRevision' IS DISTINCT FROM original_revision
  OR resource->>'revision' IS DISTINCT FROM coalesce(association.revision::text,'0') OR resource->'ou' IS DISTINCT FROM actual_unit
  THEN RAISE EXCEPTION 'Original device scope association changed' USING ERRCODE='P0412';END IF;
 IF NOT device_scope_permits(source,'devices.inventory.read',actual_unit) OR NOT device_scope_permits(source,permission,actual_unit)
  THEN RAISE EXCEPTION 'Actual device outside original scope' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_inventory_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM device_scope_receiving();
 FOREACH relation IN ARRAY ARRAY['devices','device_inventory_events','device_inventory_assignments','device_inventory_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_inventory_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_inventory_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_inventory_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_inventory_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Inventory row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_inventory_events'::regclass AND tgname='device_inventory_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_inventory_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Inventory commit receiver unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_change(proof JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;before_row devices;after_row devices;old_link device_inventory_assignments;new_link device_inventory_assignments;values JSONB;source JSONB;permission TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  THEN RAISE EXCEPTION 'Inventory database owner required' USING ERRCODE='42501';END IF;
 PERFORM device_inventory_receiving();source=proof->'source';values=proof->'values';permission=CASE proof->>'action' WHEN 'create' THEN 'devices.inventory.create' WHEN 'update' THEN 'devices.inventory.create' WHEN 'lifecycle' THEN 'devices.inventory.create' WHEN 'assign' THEN 'devices.inventory.assign' WHEN 'release' THEN 'devices.inventory.assign' END;
 IF permission IS NULL OR NOT device_scope_source_valid(source)
  OR NOT source->'permissions' ? permission OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
  OR NOT(source->>'validUntil' ~ '^[0-9]+$') OR (source->>'validUntil')::double precision>extract(epoch FROM clock_timestamp())+300
  OR (source->>'validUntil')::double precision>(source->>'expiresAt')::double precision
  OR (source->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  OR NULLIF(current_setting('opendirectory.device_inventory',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM device_inventory_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Exact original inventory source required' USING ERRCODE='42501';END IF;
 receipt.id=(proof->>'id')::uuid;receipt.tenant_id=(source#>>'{tenant,id}')::uuid;receipt.device_id=proof->>'deviceId';receipt.action=proof->>'action';receipt.version=1;
 receipt.correlation_id=(proof->>'correlationId')::uuid;receipt.actor_user_id=(source->>'actorUserId')::uuid;receipt.proof=proof;receipt.created_at=clock_timestamp();receipt.valid_until=to_timestamp((source->>'validUntil')::double precision);receipt.transaction_id=txid_current();
 IF receipt.action='create' THEN
  PERFORM device_scope_require(source,permission,receipt.device_id,NULL,NULL);
  IF EXISTS(SELECT 1 FROM devices WHERE id=receipt.device_id) OR source->'target' IS DISTINCT FROM 'null'::jsonb OR proof->'before' IS DISTINCT FROM 'null'::jsonb
   THEN RAISE EXCEPTION 'New inventory namespace required' USING ERRCODE='23514';END IF;
  after_row.id=receipt.device_id;after_row.tenant_id=receipt.tenant_id;after_row.inventory_revision=1;after_row.name=values->>'assetId';after_row.asset_id=values->>'assetId';after_row.serial_number=values->>'serialNumber';
  after_row.manufacturer=values->>'manufacturer';after_row.model=values->>'model';after_row.platform=values->>'platform';after_row.device_class=values->>'deviceClass';after_row.os_version=values->>'osVersion';
  after_row.ownership=values->>'ownership';after_row.purchase_date=NULLIF(values->>'purchaseDate','')::date;after_row.warranty_end=NULLIF(values->>'warrantyEnd','')::date;after_row.description=values->>'description';
  after_row.inventory_lifecycle='available';after_row.status='inventory-only';after_row.compliance_status='unknown';after_row.metadata='{}'::jsonb;after_row.compliance_violations='[]'::jsonb;
  after_row.inventory_created_at=receipt.created_at;after_row.inventory_updated_at=receipt.created_at;receipt.type='device.registered';
  IF after_row.asset_id IS NULL OR length(after_row.asset_id) NOT BETWEEN 1 AND 120 OR after_row.serial_number IS NULL OR length(after_row.serial_number) NOT BETWEEN 1 AND 120
   OR after_row.manufacturer IS NULL OR length(after_row.manufacturer) NOT BETWEEN 1 AND 120 OR after_row.model IS NULL OR length(after_row.model) NOT BETWEEN 1 AND 120
   OR after_row.device_class NOT IN('smartphone','tablet','laptop','desktop','shared','kiosk','other') OR after_row.platform NOT IN('macos','ios','ipados','windows','linux','android','other') OR after_row.ownership NOT IN('corporate','byod','shared')
   OR after_row.warranty_end<after_row.purchase_date THEN RAISE EXCEPTION 'Valid inventory values required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO before_row FROM devices WHERE id=receipt.device_id AND tenant_id=receipt.tenant_id FOR UPDATE;
  IF before_row.id IS NULL OR device_inventory_row(before_row) IS DISTINCT FROM proof->'before' THEN RAISE EXCEPTION 'Exact current owned device required' USING ERRCODE='23514';END IF;
  PERFORM device_scope_require(source,permission,receipt.device_id,before_row.inventory_revision::text,before_row.inventory_revision::text);
  SELECT * INTO old_link FROM device_inventory_assignments WHERE device_id=receipt.device_id AND released_at IS NULL FOR UPDATE;
  IF (old_link.id IS NULL) IS DISTINCT FROM (before_row.assigned_user IS NULL) OR old_link.id IS NOT NULL AND (old_link.tenant_id<>receipt.tenant_id OR old_link.user_id::text IS DISTINCT FROM before_row.assigned_user)
   THEN RAISE EXCEPTION 'Coherent actual assignment required' USING ERRCODE='23514';END IF;
  after_row=before_row;after_row.inventory_revision=before_row.inventory_revision+1;after_row.inventory_updated_at=receipt.created_at;
  IF receipt.action IN('update','lifecycle') THEN
   IF source->'target' IS DISTINCT FROM 'null'::jsonb OR values->'confirm' IS DISTINCT FROM 'true'::jsonb
    OR values->>'reason' IS NULL OR length(btrim(values->>'reason')) NOT BETWEEN 10 AND 500
    THEN RAISE EXCEPTION 'Explicit bounded inventory maintenance required' USING ERRCODE='23514';END IF;
   receipt.after_assignment=receipt.before_assignment;
   IF old_link.id IS NOT NULL THEN receipt.after_assignment=to_jsonb(old_link);END IF;
   IF receipt.action='update' THEN
    after_row.name=values->>'assetId';after_row.asset_id=values->>'assetId';after_row.serial_number=values->>'serialNumber';
    after_row.manufacturer=values->>'manufacturer';after_row.model=values->>'model';after_row.platform=values->>'platform';after_row.device_class=values->>'deviceClass';after_row.os_version=values->>'osVersion';
    after_row.ownership=values->>'ownership';after_row.purchase_date=NULLIF(values->>'purchaseDate','')::date;after_row.warranty_end=NULLIF(values->>'warrantyEnd','')::date;after_row.description=values->>'description';
    IF after_row.asset_id IS NULL OR length(after_row.asset_id) NOT BETWEEN 1 AND 120 OR after_row.serial_number IS NULL OR length(after_row.serial_number) NOT BETWEEN 1 AND 120
     OR after_row.manufacturer IS NULL OR length(after_row.manufacturer) NOT BETWEEN 1 AND 120 OR after_row.model IS NULL OR length(after_row.model) NOT BETWEEN 1 AND 120
     OR after_row.device_class IS NULL OR after_row.device_class NOT IN('smartphone','tablet','laptop','desktop','shared','kiosk','other') OR after_row.platform IS NULL OR after_row.platform NOT IN('macos','ios','ipados','windows','linux','android','other')
     OR after_row.ownership IS NULL OR after_row.ownership NOT IN('corporate','byod','shared') OR after_row.warranty_end<after_row.purchase_date
     OR (device_inventory_row(after_row)-ARRAY['inventory_revision','inventory_updated_at'])=(device_inventory_row(before_row)-ARRAY['inventory_revision','inventory_updated_at'])
     THEN RAISE EXCEPTION 'Changed valid inventory values required' USING ERRCODE='23514';END IF;
    receipt.type='device.updated';
   ELSE
    IF old_link.id IS NOT NULL OR values->>'lifecycle' IS NULL OR values->>'lifecycle' NOT IN('available','maintenance','retired') OR values->>'lifecycle'=before_row.inventory_lifecycle
     THEN RAISE EXCEPTION 'Unassigned inventory lifecycle transition required' USING ERRCODE='23514';END IF;
    after_row.inventory_lifecycle=values->>'lifecycle';receipt.type='device.lifecycle.changed';
   END IF;
  ELSIF receipt.action='assign' THEN
   IF before_row.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Available inventory required' USING ERRCODE='23514';END IF;
   IF source#>>'{target,id}' IS DISTINCT FROM values->>'userId' OR old_link.user_id::text=values->>'userId'
    THEN RAISE EXCEPTION 'Own new assignment target required' USING ERRCODE='23514';END IF;
   new_link.id=(proof->>'assignmentId')::uuid;new_link.tenant_id=receipt.tenant_id;new_link.device_id=receipt.device_id;new_link.user_id=(values->>'userId')::uuid;new_link.target_snapshot=source->'target';new_link.assigned_at=receipt.created_at;new_link.command_id=receipt.id;
   after_row.assigned_user=new_link.user_id::text;after_row.inventory_lifecycle='assigned';receipt.after_assignment=to_jsonb(new_link);receipt.type='device.assigned';
  ELSE
   IF old_link.id IS NULL OR source->'target' IS DISTINCT FROM 'null'::jsonb OR values->'userId' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Current assignment required for release' USING ERRCODE='23514';END IF;
   after_row.assigned_user=NULL;after_row.inventory_lifecycle='available';receipt.type='device.assignment.released';
  END IF;
  receipt.before_state=device_inventory_row(before_row);IF old_link.id IS NOT NULL THEN receipt.before_assignment=to_jsonb(old_link);END IF;
 END IF;
 receipt.after_state=device_inventory_row(after_row);PERFORM set_config('opendirectory.device_inventory',receipt.id::text,true);
 INSERT INTO device_inventory_events SELECT receipt.*;
 IF receipt.action='create' THEN INSERT INTO devices SELECT after_row.*;
 ELSE
  IF receipt.action IN('assign','release') AND old_link.id IS NOT NULL THEN UPDATE device_inventory_assignments SET released_at=receipt.created_at,released_by_command_id=receipt.id WHERE id=old_link.id;END IF;
  IF new_link.id IS NOT NULL THEN INSERT INTO device_inventory_assignments SELECT new_link.*;END IF;
  UPDATE devices SET name=after_row.name,asset_id=after_row.asset_id,serial_number=after_row.serial_number,manufacturer=after_row.manufacturer,model=after_row.model,platform=after_row.platform,device_class=after_row.device_class,os_version=after_row.os_version,ownership=after_row.ownership,purchase_date=after_row.purchase_date,warranty_end=after_row.warranty_end,description=after_row.description,assigned_user=after_row.assigned_user,inventory_lifecycle=after_row.inventory_lifecycle,inventory_revision=after_row.inventory_revision,inventory_updated_at=after_row.inventory_updated_at WHERE id=receipt.device_id;
 END IF;
 INSERT INTO device_inventory_outbox VALUES(receipt.id,receipt.tenant_id,'pending',receipt.created_at);RETURN receipt.id;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;actual devices;link device_inventory_assignments;
BEGIN
 PERFORM device_inventory_receiving();receipt=device_inventory_scope();
 IF receipt IS DISTINCT FROM NEW THEN RAISE EXCEPTION 'Original inventory command changed' USING ERRCODE='42501';END IF;
 SELECT * INTO actual FROM devices WHERE id=receipt.device_id;
 IF actual.id IS NULL OR device_inventory_row(actual) IS DISTINCT FROM receipt.after_state
  OR NOT EXISTS(SELECT 1 FROM device_inventory_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at)
  THEN RAISE EXCEPTION 'Actual inventory effect and pending receipt required' USING ERRCODE='23514';END IF;
 PERFORM device_scope_require(receipt.proof->'source',CASE WHEN receipt.action IN('assign','release') THEN 'devices.inventory.assign' ELSE 'devices.inventory.create' END,receipt.device_id,receipt.before_state->>'inventory_revision',CASE WHEN receipt.action='create' THEN NULL ELSE actual.inventory_revision::text END);
 SELECT * INTO link FROM device_inventory_assignments WHERE device_id=receipt.device_id AND released_at IS NULL;
 IF (CASE WHEN link.id IS NULL THEN NULL ELSE to_jsonb(link) END) IS DISTINCT FROM receipt.after_assignment
  THEN RAISE EXCEPTION 'Actual exclusive assignment required' USING ERRCODE='23514';END IF;
 IF receipt.before_assignment IS NOT NULL AND receipt.before_assignment IS DISTINCT FROM receipt.after_assignment AND NOT EXISTS(SELECT 1 FROM device_inventory_assignments previous WHERE previous.id=(receipt.before_assignment->>'id')::uuid
  AND to_jsonb(previous)=(receipt.before_assignment||jsonb_build_object('released_at',receipt.created_at,'released_by_command_id',receipt.id)))
  THEN RAISE EXCEPTION 'Actual previous assignment release required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;
DO $$ DECLARE routine_signature TEXT;signatures TEXT[]=ARRAY[
 'device_scope_shape(jsonb,text[])','device_scope_uuid(jsonb)','device_scope_revision(jsonb,boolean)',
 'device_scope_source_valid(jsonb)','device_scope_permits(jsonb,text,jsonb)','device_scope_manifest_guard()',
 'device_scope_receiving()','device_scope_require(jsonb,text,text,text,text)','device_inventory_receiving()',
 'device_inventory_change(jsonb)','device_inventory_commit()','device_inventory_scope()','device_inventory_guard()','device_ou_receiving()'];
BEGIN
 ALTER TABLE device_scope_manifest DISABLE TRIGGER ALL;
 FOREACH routine_signature IN ARRAY signatures LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine_signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine_signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine_signature);
  INSERT INTO device_scope_manifest VALUES(routine_signature,md5(pg_get_functiondef(to_regprocedure(routine_signature)))) ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 ALTER TABLE device_scope_manifest ENABLE TRIGGER ALL;
 PERFORM device_scope_receiving();PERFORM device_inventory_receiving();
END; $$;
COMMIT;

ALTER TABLE device_inventory_events DROP CONSTRAINT IF EXISTS device_inventory_events_action_check;
ALTER TABLE device_inventory_events ADD CONSTRAINT device_inventory_events_action_check CHECK(action IN('create','assign','release','update','lifecycle'));
ALTER TABLE device_inventory_events DROP CONSTRAINT IF EXISTS device_inventory_events_type_check;
ALTER TABLE device_inventory_events ADD CONSTRAINT device_inventory_events_type_check CHECK(type IN('device.registered','device.assigned','device.assignment.released','device.updated','device.lifecycle.changed'));
CREATE OR REPLACE FUNCTION device_inventory_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;actual devices;link device_inventory_assignments;
BEGIN
 PERFORM device_inventory_receiving();receipt=device_inventory_scope();
 IF receipt IS DISTINCT FROM NEW THEN RAISE EXCEPTION 'Original inventory command changed' USING ERRCODE='42501';END IF;
 SELECT * INTO actual FROM devices WHERE id=receipt.device_id;
 IF actual.id IS NULL OR device_inventory_row(actual) IS DISTINCT FROM receipt.after_state
  OR NOT EXISTS(SELECT 1 FROM device_inventory_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at)
  THEN RAISE EXCEPTION 'Actual inventory effect and pending receipt required' USING ERRCODE='23514';END IF;
 SELECT * INTO link FROM device_inventory_assignments WHERE device_id=receipt.device_id AND released_at IS NULL;
 IF (CASE WHEN link.id IS NULL THEN NULL ELSE to_jsonb(link) END) IS DISTINCT FROM receipt.after_assignment
  THEN RAISE EXCEPTION 'Actual exclusive assignment required' USING ERRCODE='23514';END IF;
 IF receipt.before_assignment IS NOT NULL AND receipt.before_assignment IS DISTINCT FROM receipt.after_assignment AND NOT EXISTS(SELECT 1 FROM device_inventory_assignments previous WHERE previous.id=(receipt.before_assignment->>'id')::uuid
  AND to_jsonb(previous)=(receipt.before_assignment||jsonb_build_object('released_at',receipt.created_at,'released_by_command_id',receipt.id)))
  THEN RAISE EXCEPTION 'Actual previous assignment release required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_change(proof JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;before_row devices;after_row devices;old_link device_inventory_assignments;new_link device_inventory_assignments;values JSONB;source JSONB;permission TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  THEN RAISE EXCEPTION 'Inventory database owner required' USING ERRCODE='42501';END IF;
 PERFORM device_inventory_receiving();source=proof->'source';values=proof->'values';permission=CASE proof->>'action' WHEN 'create' THEN 'devices.inventory.create' WHEN 'update' THEN 'devices.inventory.create' WHEN 'lifecycle' THEN 'devices.inventory.create' WHEN 'assign' THEN 'devices.inventory.assign' WHEN 'release' THEN 'devices.inventory.assign' END;
 IF permission IS NULL OR jsonb_typeof(source) IS DISTINCT FROM 'object' OR source->>'schemaVersion' IS DISTINCT FROM '1'
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
DO $$ DECLARE routine RECORD;BEGIN
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'device_inventory_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine.signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
END; $$;

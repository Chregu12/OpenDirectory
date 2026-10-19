ALTER TABLE devices ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_revision BIGINT NOT NULL DEFAULT 1 CHECK(inventory_revision>0);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS asset_id TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS manufacturer TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_class TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ownership TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_date DATE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS warranty_end DATE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_lifecycle TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_created_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS inventory_updated_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS device_inventory_asset ON devices(tenant_id,lower(asset_id)) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS device_inventory_serial ON devices(tenant_id,lower(serial_number)) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS device_inventory_page ON devices(tenant_id,inventory_created_at,id) WHERE tenant_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS device_inventory_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,device_id VARCHAR(255) NOT NULL REFERENCES devices(id) DEFERRABLE INITIALLY DEFERRED,
 action TEXT NOT NULL CHECK(action IN('create','assign','release')),type TEXT NOT NULL CHECK(type IN('device.registered','device.assigned','device.assignment.released')),
 version INTEGER NOT NULL DEFAULT 1 CHECK(version=1),correlation_id UUID NOT NULL,actor_user_id UUID NOT NULL,proof JSONB NOT NULL,
 before_state JSONB,after_state JSONB NOT NULL,before_assignment JSONB,after_assignment JSONB,
 created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS device_inventory_history ON device_inventory_events(tenant_id,device_id,created_at,id);
CREATE TABLE IF NOT EXISTS device_inventory_assignments (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,device_id VARCHAR(255) NOT NULL REFERENCES devices(id),user_id UUID NOT NULL,
 target_snapshot JSONB NOT NULL,assigned_at TIMESTAMPTZ NOT NULL,released_at TIMESTAMPTZ,
 command_id UUID NOT NULL REFERENCES device_inventory_events(id),released_by_command_id UUID REFERENCES device_inventory_events(id),
 CHECK((released_at IS NULL)=(released_by_command_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS device_inventory_exclusive_assignment ON device_inventory_assignments(device_id) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS device_inventory_recipient ON device_inventory_assignments(tenant_id,user_id) WHERE released_at IS NULL;
CREATE TABLE IF NOT EXISTS device_inventory_outbox (
 id UUID PRIMARY KEY REFERENCES device_inventory_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE OR REPLACE FUNCTION device_inventory_row(data devices) RETURNS JSONB LANGUAGE SQL STABLE AS $$ SELECT to_jsonb(data)||jsonb_build_object('inventory_revision',(data).inventory_revision::text); $$;
CREATE OR REPLACE FUNCTION device_inventory_scope() RETURNS device_inventory_events LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;identifier TEXT;
BEGIN
 identifier=NULLIF(current_setting('opendirectory.device_inventory',true),'');
 SELECT * INTO receipt FROM device_inventory_events WHERE transaction_id=txid_current();
 IF receipt.id IS NULL OR identifier IS DISTINCT FROM receipt.id::text OR receipt.valid_until<=clock_timestamp()
  THEN RAISE EXCEPTION 'Original device inventory admission required' USING ERRCODE='42501';END IF;
 RETURN receipt;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;before_data JSONB;after_data JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Device inventory history cannot be truncated' USING ERRCODE='42501';END IF;
 IF TG_OP<>'INSERT' THEN before_data=to_jsonb(OLD);END IF;IF TG_OP<>'DELETE' THEN after_data=to_jsonb(NEW);END IF;
 IF TG_TABLE_NAME='devices' THEN
  IF TG_OP<>'INSERT' THEN before_data=device_inventory_row(OLD);END IF;
  IF TG_OP<>'DELETE' THEN after_data=device_inventory_row(NEW);END IF;
 END IF;
 IF TG_TABLE_NAME='devices' AND before_data->>'tenant_id' IS NULL AND after_data->>'tenant_id' IS NULL
  AND NOT EXISTS(SELECT 1 FROM device_inventory_events WHERE transaction_id=txid_current()) THEN
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_TABLE_NAME='device_inventory_events' THEN
  IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
   OR TG_OP<>'INSERT' OR NEW.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.device_inventory',true),'') OR NEW.transaction_id<>txid_current()
   OR NEW.valid_until<=clock_timestamp() OR NEW.actor_user_id::text IS DISTINCT FROM NEW.proof#>>'{source,actorUserId}'
   OR NEW.tenant_id::text IS DISTINCT FROM NEW.proof#>>'{source,tenant,id}' OR NEW.valid_until IS DISTINCT FROM to_timestamp((NEW.proof#>>'{source,validUntil}')::double precision)
   THEN RAISE EXCEPTION 'Immutable original inventory event required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 receipt=device_inventory_scope();
 IF TG_TABLE_NAME='devices' THEN
  IF TG_OP='DELETE' OR before_data IS DISTINCT FROM receipt.before_state OR after_data IS DISTINCT FROM receipt.after_state
   THEN RAISE EXCEPTION 'Exact inventory device effect required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='device_inventory_assignments' THEN
  IF TG_OP='INSERT' THEN
   IF after_data IS DISTINCT FROM receipt.after_assignment THEN RAISE EXCEPTION 'Exact new assignment required' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='UPDATE' THEN
   IF before_data IS DISTINCT FROM receipt.before_assignment OR after_data IS DISTINCT FROM (receipt.before_assignment||jsonb_build_object('released_at',receipt.created_at,'released_by_command_id',receipt.id))
    THEN RAISE EXCEPTION 'Exact old assignment release required' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'Retained assignment cannot be deleted' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='device_inventory_outbox' THEN
  IF TG_OP<>'INSERT' OR after_data IS DISTINCT FROM jsonb_build_object('id',receipt.id,'tenant_id',receipt.tenant_id,'status','pending','created_at',receipt.created_at)
   THEN RAISE EXCEPTION 'Exact pending inventory receipt required' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'Unknown inventory effect' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 FOREACH relation IN ARRAY ARRAY['devices','device_inventory_events','device_inventory_assignments','device_inventory_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_inventory_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_inventory_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_inventory_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_inventory_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Inventory row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_inventory_events'::regclass AND tgname='device_inventory_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_inventory_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Inventory commit receiver unavailable' USING ERRCODE='42501';END IF;
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
 SELECT * INTO link FROM device_inventory_assignments WHERE device_id=receipt.device_id AND released_at IS NULL;
 IF (CASE WHEN link.id IS NULL THEN NULL ELSE to_jsonb(link) END) IS DISTINCT FROM receipt.after_assignment
  THEN RAISE EXCEPTION 'Actual exclusive assignment required' USING ERRCODE='23514';END IF;
 IF receipt.before_assignment IS NOT NULL AND NOT EXISTS(SELECT 1 FROM device_inventory_assignments previous WHERE previous.id=(receipt.before_assignment->>'id')::uuid
  AND to_jsonb(previous)=(receipt.before_assignment||jsonb_build_object('released_at',receipt.created_at,'released_by_command_id',receipt.id)))
  THEN RAISE EXCEPTION 'Actual previous assignment release required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_inventory_change(proof JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt device_inventory_events;before_row devices;after_row devices;old_link device_inventory_assignments;new_link device_inventory_assignments;values JSONB;source JSONB;permission TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  THEN RAISE EXCEPTION 'Inventory database owner required' USING ERRCODE='42501';END IF;
 PERFORM device_inventory_receiving();source=proof->'source';values=proof->'values';permission=CASE proof->>'action' WHEN 'create' THEN 'devices.inventory.create' WHEN 'assign' THEN 'devices.inventory.assign' WHEN 'release' THEN 'devices.inventory.assign' END;
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
  IF receipt.action='assign' THEN
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
  IF old_link.id IS NOT NULL THEN UPDATE device_inventory_assignments SET released_at=receipt.created_at,released_by_command_id=receipt.id WHERE id=old_link.id;END IF;
  IF new_link.id IS NOT NULL THEN INSERT INTO device_inventory_assignments SELECT new_link.*;END IF;
  UPDATE devices SET assigned_user=after_row.assigned_user,inventory_lifecycle=after_row.inventory_lifecycle,inventory_revision=after_row.inventory_revision,inventory_updated_at=after_row.inventory_updated_at WHERE id=receipt.device_id;
 END IF;
 INSERT INTO device_inventory_outbox VALUES(receipt.id,receipt.tenant_id,'pending',receipt.created_at);RETURN receipt.id;
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['devices','device_inventory_events','device_inventory_assignments','device_inventory_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS device_inventory_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER device_inventory_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION device_inventory_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS device_inventory_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER device_inventory_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION device_inventory_guard()',relation);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS device_inventory_commit ON device_inventory_events;
CREATE CONSTRAINT TRIGGER device_inventory_commit AFTER INSERT ON device_inventory_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION device_inventory_commit();
DO $$ DECLARE routine RECORD;BEGIN
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'device_inventory_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine.signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
END; $$;

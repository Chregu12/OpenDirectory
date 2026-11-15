BEGIN;

-- Retain each human sync decision's own original source; historical or device-only events stay NULL.
ALTER TABLE device_sync_events ADD COLUMN IF NOT EXISTS source JSONB;
CREATE TABLE IF NOT EXISTS device_control_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION device_control_manifest_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN RAISE EXCEPTION 'Sealed device control manifest cannot be changed' USING ERRCODE='42501';END; $$;
CREATE OR REPLACE TRIGGER device_control_manifest_guard BEFORE INSERT OR UPDATE OR DELETE ON device_control_manifest FOR EACH ROW EXECUTE FUNCTION device_control_manifest_guard();
CREATE OR REPLACE TRIGGER device_control_manifest_truncate BEFORE TRUNCATE ON device_control_manifest FOR EACH STATEMENT EXECUTE FUNCTION device_control_manifest_guard();
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
END; $$;

CREATE OR REPLACE FUNCTION device_agent_change(command JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_agent_connections; next_state device_agent_connections; unit devices;
 source JSONB; event device_agent_events; envelope JSONB; moment TIMESTAMPTZ; deadline DOUBLE PRECISION; action TEXT; compliance_event device_compliance_events;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  OR NULLIF(current_setting('opendirectory.device_agent',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Original agent database owner command required' USING ERRCODE='42501';END IF;
 PERFORM device_scope_receiving();PERFORM device_compliance_receiving();action=command->>'action';source=command->'source';
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' FOR UPDATE;
 SELECT * INTO previous FROM device_agent_connections WHERE device_id=unit.id FOR UPDATE;
 IF unit.id IS NULL OR unit.tenant_id IS NULL THEN RAISE EXCEPTION 'Agent device unavailable' USING ERRCODE='42501';END IF;
 moment=clock_timestamp();next_state=previous;
 next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=coalesce(previous.revision,0)+1;
 IF action IN('issue','revoke') THEN
  deadline=(source->>'validUntil')::double precision;
  PERFORM device_scope_require(source,'devices.inventory.create',unit.id,unit.inventory_revision::text,unit.inventory_revision::text);
  IF source->>'schemaVersion' NOT IN('1','2') OR source->'target' IS DISTINCT FROM 'null'::jsonb OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
   OR source#>>'{tenant,id}' IS DISTINCT FROM unit.tenant_id::text OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
   OR deadline IS NULL OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::double precision OR deadline<=extract(epoch FROM moment)
   OR command->>'expectedRevision' IS DISTINCT FROM coalesce(previous.revision,0)::text OR length(command->>'reason') NOT BETWEEN 10 AND 500
   THEN RAISE EXCEPTION 'Original inventory authority and exact agent revision required' USING ERRCODE='42501';END IF;
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;next_state.credential_hash=NULL;next_state.credential_expires_at=NULL;
  next_state.revoked_at=moment;
  IF action='issue' THEN
   IF unit.platform NOT IN('windows','macos','linux') OR unit.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Available desktop platform required' USING ERRCODE='23514';END IF;
   next_state.bootstrap_hash=command->>'newHash';next_state.bootstrap_expires_at=moment+interval '10 minutes';
  END IF;
 ELSIF action='register' THEN
  deadline=extract(epoch FROM previous.bootstrap_expires_at);
  IF previous.bootstrap_hash IS NULL OR previous.bootstrap_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'One-time agent enrollment rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;
  next_state.credential_hash=command->>'newHash';next_state.credential_expires_at=moment+interval '90 days';next_state.enrolled_at=moment;next_state.revoked_at=NULL;
 ELSIF action='heartbeat' THEN
  deadline=extract(epoch FROM previous.credential_expires_at);
  IF previous.credential_hash IS NULL OR previous.credential_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR previous.revoked_at IS NOT NULL OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'Agent credential rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
 ELSE RAISE EXCEPTION 'Unsupported agent command' USING ERRCODE='42501';END IF;
 IF action IN('register','heartbeat') THEN
  next_state.last_seen=moment;next_state.hostname=command#>>'{report,hostname}';next_state.platform=command#>>'{report,platform}';
  next_state.architecture=command#>>'{report,architecture}';next_state.os_version=command#>>'{report,osVersion}';next_state.agent_version=command#>>'{report,agentVersion}';
  IF next_state.hostname IS NULL OR length(next_state.hostname) NOT BETWEEN 1 AND 255 OR length(next_state.architecture) NOT BETWEEN 1 AND 40
   OR length(next_state.os_version)>120 OR length(next_state.agent_version) NOT BETWEEN 1 AND 40 THEN RAISE EXCEPTION 'Bounded agent report required' USING ERRCODE='23514';END IF;
 END IF;
 IF command ? 'inventory' THEN
  IF action<>'heartbeat' OR NOT device_agent_inventory_valid(command->'inventory') THEN RAISE EXCEPTION 'Exact bounded agent inventory required' USING ERRCODE='23514';END IF;
  next_state.inventory_report=jsonb_build_object('schemaVersion',1,'facts',command->'inventory','receivedAt',moment,'enrolledAt',next_state.enrolled_at,'revision',next_state.revision::text,'platform',next_state.platform,'agentVersion',next_state.agent_version);
 END IF;
 IF command ? 'security' THEN
  IF action<>'heartbeat' OR NOT device_security_valid(command->'security') THEN RAISE EXCEPTION 'Exact security report required' USING ERRCODE='23514';END IF;
  next_state.security_report=jsonb_build_object('schemaVersion',1,'facts',command->'security','receivedAt',moment,'enrolledAt',next_state.enrolled_at,'revision',next_state.revision::text,'platform',next_state.platform,'agentVersion',next_state.agent_version);
  next_state.compliance_report=device_compliance_evaluate(next_state,moment);
  IF previous.compliance_report->>'fingerprint' IS DISTINCT FROM next_state.compliance_report->>'fingerprint' THEN
   compliance_event.id=(command->>'complianceEventId')::uuid;compliance_event.device_id=unit.id;compliance_event.tenant_id=unit.tenant_id;compliance_event.correlation_id=(command->>'correlationId')::uuid;compliance_event.created_at=moment;compliance_event.before_state=previous.compliance_report;compliance_event.after_state=next_state.compliance_report;
  END IF;
 END IF;
 IF deadline IS NULL OR deadline<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Agent deadline elapsed' USING ERRCODE='42501';END IF;
 IF action<>'heartbeat' THEN
  event.id=(command->>'eventId')::uuid;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.action=action;
  event.actor_user_id=(source->>'actorUserId')::uuid;event.reason=command->>'reason';event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;
  event.source=CASE WHEN action IN('issue','revoke') THEN source ELSE NULL END;
  event.before_state=CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous)-ARRAY['bootstrap_hash','credential_hash'] END;
  event.after_state=to_jsonb(next_state)-ARRAY['bootstrap_hash','credential_hash'];
 END IF;
 envelope=jsonb_build_object('before',CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous) END,'after',to_jsonb(next_state),'event',CASE WHEN action='heartbeat' THEN NULL ELSE to_jsonb(event) END,'validUntil',deadline,'transactionId',txid_current()::text,'deviceRevision',unit.inventory_revision::text,'complianceEvent',CASE WHEN compliance_event.id IS NULL THEN NULL ELSE to_jsonb(compliance_event) END);
 PERFORM set_config('opendirectory.device_agent',envelope::text,true);
 IF previous.device_id IS NULL THEN INSERT INTO device_agent_connections SELECT next_state.*;
 ELSE UPDATE device_agent_connections SET (tenant_id,revision,bootstrap_hash,bootstrap_expires_at,credential_hash,credential_expires_at,enrolled_at,revoked_at,last_seen,hostname,platform,architecture,os_version,agent_version,inventory_report,security_report,compliance_report)=
  (next_state.tenant_id,next_state.revision,next_state.bootstrap_hash,next_state.bootstrap_expires_at,next_state.credential_hash,next_state.credential_expires_at,next_state.enrolled_at,next_state.revoked_at,next_state.last_seen,next_state.hostname,next_state.platform,next_state.architecture,next_state.os_version,next_state.agent_version,next_state.inventory_report,next_state.security_report,next_state.compliance_report) WHERE device_id=unit.id;END IF;
 IF action<>'heartbeat' THEN INSERT INTO device_agent_events SELECT event.*;END IF;
 IF compliance_event.id IS NOT NULL THEN INSERT INTO device_compliance_events SELECT compliance_event.*;END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_agent_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_agent_connections;
BEGIN
 PERFORM device_scope_receiving();PERFORM device_compliance_receiving();
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 SELECT * INTO actual FROM device_agent_connections WHERE device_id=NEW.device_id;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  OR to_jsonb(actual) IS DISTINCT FROM proof->'after' OR NOT EXISTS(SELECT 1 FROM devices WHERE id=actual.device_id AND tenant_id=actual.tenant_id)
  OR (proof->'event'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_agent_events WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(device_agent_events)=proof->'event'))
  OR (proof->'complianceEvent'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_compliance_events event WHERE event.id=(proof#>>'{complianceEvent,id}')::uuid AND to_jsonb(event)=proof->'complianceEvent'))
  THEN RAISE EXCEPTION 'Actual agent effect and original deadline required' USING ERRCODE='42501';END IF;
 IF proof#>>'{event,action}' IN('issue','revoke') THEN
  PERFORM device_scope_require(proof#>'{event,source}','devices.inventory.create',actual.device_id,proof->>'deviceRevision',proof->>'deviceRevision');
 END IF;
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION device_sync_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_sync_requests; next_state device_sync_requests; event device_sync_events; connection device_agent_connections; unit devices;
 source JSONB=command->'source'; action TEXT=command->>'action'; moment TIMESTAMPTZ; deadline NUMERIC; agent_proof JSONB; active TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','') OR NULLIF(current_setting('opendirectory.device_sync',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Original database owner sync command required' USING ERRCODE='42501';END IF;
 PERFORM device_scope_receiving();PERFORM device_sync_receiving();
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' FOR UPDATE;
 SELECT * INTO connection FROM device_agent_connections WHERE device_id=unit.id FOR UPDATE;
 moment=clock_timestamp();
 IF unit.id IS NULL OR unit.tenant_id IS NULL THEN RAISE EXCEPTION 'Sync device unavailable' USING ERRCODE='28000';END IF;
 IF action IN('queued','cancelled') THEN
  deadline=(source->>'validUntil')::numeric;
  PERFORM device_scope_require(source,'devices.inventory.create',unit.id,unit.inventory_revision::text,unit.inventory_revision::text);
  IF source->>'schemaVersion' NOT IN('1','2') OR source#>>'{tenant,id}' IS DISTINCT FROM unit.tenant_id::text OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId' OR source->'target' IS DISTINCT FROM 'null'::jsonb OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
   OR deadline IS NULL OR deadline<=extract(epoch FROM moment) OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::numeric OR length(command->>'reason') NOT BETWEEN 10 AND 500 THEN RAISE EXCEPTION 'Original sync human authority required' USING ERRCODE='42501';END IF;
 ELSE
  IF connection.credential_hash IS NULL OR connection.credential_hash IS DISTINCT FROM command->>'tokenHash' OR connection.revoked_at IS NOT NULL OR connection.credential_expires_at<=moment THEN RAISE EXCEPTION 'Current device credential required' USING ERRCODE='28000';END IF;
  deadline=least(extract(epoch FROM connection.credential_expires_at),extract(epoch FROM moment)+30);
 END IF;
 IF action='claimed' THEN
  SELECT * INTO previous FROM device_sync_requests WHERE device_id=unit.id AND tenant_id=unit.tenant_id AND device_sync_status(device_sync_requests,connection,moment)='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE;
  IF previous.id IS NULL THEN RETURN NULL;END IF;
 ELSE
  IF action<>'queued' THEN SELECT * INTO previous FROM device_sync_requests WHERE id=(command->>'id')::uuid AND device_id=unit.id AND tenant_id=unit.tenant_id FOR UPDATE;IF previous.id IS NULL THEN RAISE EXCEPTION 'Sync request unavailable' USING ERRCODE='23514';END IF;END IF;
 END IF;
 IF action='queued' THEN
  IF connection.credential_hash IS NULL OR connection.revoked_at IS NOT NULL OR connection.credential_expires_at<=moment OR command->>'generation' IS DISTINCT FROM device_sync_generation(connection) OR unit.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Current enrolled connection required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM device_sync_requests request WHERE request.device_id=unit.id AND request.tenant_id=unit.tenant_id AND device_sync_status(request,connection,moment) IN('queued','claimed')) THEN RAISE EXCEPTION 'A current sync request already exists' USING ERRCODE='23514';END IF;
  next_state.id=(command->>'id')::uuid;next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=1;next_state.generation=device_sync_generation(connection);next_state.status='queued';next_state.attempts=0;next_state.actor_user_id=(source->>'actorUserId')::uuid;next_state.reason=command->>'reason';next_state.source=source;next_state.created_at=moment;next_state.expires_at=least(to_timestamp(deadline),connection.credential_expires_at,moment+interval '5 minutes');
 ELSE
  next_state=previous;next_state.revision=previous.revision+1;next_state.status=action;
  active=device_sync_status(previous,connection,moment);
  IF action='cancelled' THEN
   IF command->>'expectedRevision' IS DISTINCT FROM previous.revision::text OR previous.status NOT IN('queued','claimed') THEN RAISE EXCEPTION 'Current cancellable sync revision required' USING ERRCODE='23514';END IF;
   next_state.lease_hash=NULL;next_state.lease_expires_at=NULL;
  ELSIF action='claimed' THEN
   IF active<>'queued' OR previous.attempts>=3 OR command->>'leaseHash' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Eligible sync lease required' USING ERRCODE='23514';END IF;
   next_state.attempts=previous.attempts+1;next_state.lease_hash=command->>'leaseHash';next_state.lease_expires_at=least(previous.expires_at,moment+interval '45 seconds');deadline=least(deadline,extract(epoch FROM previous.expires_at));
  ELSIF action='completed' THEN
   IF active<>'claimed' OR previous.lease_hash IS DISTINCT FROM command->>'leaseHash' OR previous.lease_expires_at<=moment THEN RAISE EXCEPTION 'Current sync lease required' USING ERRCODE='23514';END IF;
   agent_proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
   IF agent_proof IS NULL OR agent_proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR agent_proof->'after' IS DISTINCT FROM to_jsonb(connection)
    OR connection.inventory_report IS NULL OR connection.security_report IS NULL OR connection.compliance_report IS NULL
    OR (connection.inventory_report->>'receivedAt')::timestamptz IS DISTINCT FROM connection.last_seen OR (connection.security_report->>'receivedAt')::timestamptz IS DISTINCT FROM connection.last_seen
    OR (connection.inventory_report->>'enrolledAt')::timestamptz IS DISTINCT FROM connection.enrolled_at OR (connection.security_report->>'enrolledAt')::timestamptz IS DISTINCT FROM connection.enrolled_at
    OR connection.inventory_report->>'revision' IS DISTINCT FROM connection.revision::text OR connection.security_report->>'revision' IS DISTINCT FROM connection.revision::text THEN RAISE EXCEPTION 'New actual reports in the same transaction required' USING ERRCODE='42501';END IF;
   deadline=least(deadline,extract(epoch FROM previous.expires_at),extract(epoch FROM previous.lease_expires_at));next_state.completed_at=moment;next_state.lease_hash=NULL;next_state.lease_expires_at=NULL;
   next_state.result=jsonb_build_object('agentRevision',connection.revision::text,'receivedAt',connection.last_seen,'inventory',connection.inventory_report,'security',connection.security_report,'compliance',connection.compliance_report);
  ELSE RAISE EXCEPTION 'Unsupported sync operation' USING ERRCODE='42501';END IF;
 END IF;
 next_state.updated_at=moment;event.id=(command->>'eventId')::uuid;event.request_id=next_state.id;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.action=action;event.actor_user_id=CASE WHEN action IN('queued','cancelled') THEN (source->>'actorUserId')::uuid END;event.reason=CASE WHEN action IN('queued','cancelled') THEN command->>'reason' END;event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;event.source=CASE WHEN action IN('queued','cancelled') THEN source ELSE NULL END;event.before_state=CASE WHEN previous.id IS NULL THEN NULL ELSE to_jsonb(previous)-ARRAY['lease_hash','source'] END;event.after_state=to_jsonb(next_state)-ARRAY['lease_hash','source'];
 PERFORM set_config('opendirectory.device_sync',jsonb_build_object('transactionId',txid_current()::text,'validUntil',deadline,'deviceRevision',unit.inventory_revision::text,'before',CASE WHEN previous.id IS NULL THEN NULL ELSE to_jsonb(previous) END,'after',to_jsonb(next_state),'event',to_jsonb(event))::text,true);
 IF previous.id IS NULL THEN INSERT INTO device_sync_requests SELECT next_state.*;ELSE UPDATE device_sync_requests SET (revision,status,attempts,updated_at,lease_hash,lease_expires_at,completed_at,result)=(next_state.revision,next_state.status,next_state.attempts,next_state.updated_at,next_state.lease_hash,next_state.lease_expires_at,next_state.completed_at,next_state.result) WHERE id=next_state.id;END IF;
 INSERT INTO device_sync_events SELECT event.*;RETURN next_state.id;
END; $$;

CREATE OR REPLACE FUNCTION device_sync_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_sync_requests; connection device_agent_connections;
BEGIN
 PERFORM device_scope_receiving();PERFORM device_sync_receiving();proof=NULLIF(current_setting('opendirectory.device_sync',true),'')::jsonb;
 SELECT * INTO actual FROM device_sync_requests WHERE id=(proof#>>'{after,id}')::uuid;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR to_jsonb(actual) IS DISTINCT FROM proof->'after'
  OR NOT EXISTS(SELECT 1 FROM device_sync_events event WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(event)=proof->'event') THEN RAISE EXCEPTION 'Actual sync state and retained event required' USING ERRCODE='42501';END IF;
 IF actual.status='completed' THEN
  SELECT * INTO connection FROM device_agent_connections WHERE device_id=actual.device_id;
  IF actual.generation IS DISTINCT FROM device_sync_generation(connection) OR actual.result IS DISTINCT FROM jsonb_build_object('agentRevision',connection.revision::text,'receivedAt',connection.last_seen,'inventory',connection.inventory_report,'security',connection.security_report,'compliance',connection.compliance_report) THEN RAISE EXCEPTION 'Actual atomic agent reports required' USING ERRCODE='42501';END IF;
 END IF;
 IF proof#>>'{event,action}' IN('queued','cancelled') THEN
  PERFORM device_scope_require(proof#>'{event,source}','devices.inventory.create',actual.device_id,proof->>'deviceRevision',proof->>'deviceRevision');
 END IF;
 RETURN NEW;
END; $$;
DO $$ DECLARE routine_signature TEXT;signatures TEXT[]=ARRAY[
 'device_control_manifest_guard()','device_agent_receiving()','device_agent_change(jsonb)','device_agent_commit()',
 'device_agent_guard()','device_agent_inventory_guard()','device_agent_inventory_receiving()','device_compliance_receiving()',
 'device_sync_receiving()','device_sync_change(jsonb)','device_sync_commit()','device_sync_guard()',
 'device_sync_generation(device_agent_connections)','device_sync_status(device_sync_requests,device_agent_connections,timestamp with time zone)'];
BEGIN
 ALTER TABLE device_control_manifest DISABLE TRIGGER ALL;
 FOREACH routine_signature IN ARRAY signatures LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',routine_signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine_signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine_signature);
  INSERT INTO device_control_manifest VALUES(routine_signature,md5(pg_get_functiondef(to_regprocedure(routine_signature)))) ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 ALTER TABLE device_control_manifest ENABLE TRIGGER ALL;
 ALTER TABLE device_scope_manifest DISABLE TRIGGER ALL;
 EXECUTE format('ALTER FUNCTION device_scope_receiving() SET search_path TO %I,pg_catalog',current_schema());
 ALTER FUNCTION device_scope_receiving() SET timezone TO 'UTC';
 UPDATE device_scope_manifest SET digest=md5(pg_get_functiondef('device_scope_receiving()'::regprocedure)) WHERE signature='device_scope_receiving()';
 ALTER TABLE device_scope_manifest ENABLE TRIGGER ALL;
 PERFORM device_scope_receiving();PERFORM device_sync_receiving();
END; $$;
COMMIT;
